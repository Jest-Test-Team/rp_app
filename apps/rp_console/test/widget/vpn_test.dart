import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/app/strings.dart';
import 'package:rp_console/features/devices/device_screen.dart';
import 'package:rp_console/features/vpn/vpn_page.dart';

import '../support/fakes.dart';
import 'harness.dart';

Future<Harness> paired(WidgetTester t, {void Function(Harness)? prep}) async {
  await t.binding.setSurfaceSize(const Size(900, 1800));
  addTearDown(() => t.binding.setSurfaceSize(null));
  final h = Harness();
  prep?.call(h);
  await h.start(t);
  await pairViaCode(t, h, keepVpnPrompt: true);
  return h;
}

void main() {
  test('what the VPN prompt offers', () {
    const all = ['tailscale', 'wireguard', 'both'];
    expect(vpnChoices(all, null), all);
    expect(vpnChoices(all, 'tailscale'), ['both']);
    expect(vpnChoices(all, 'wireguard'), ['both']);
    expect(vpnChoices(all, 'both'), isEmpty);
    expect(vpnChoices(['tailscale'], 'tailscale'), isEmpty, reason: 'no kernel WireGuard');
  });

  test('VPN status in words, for one mode or both', () {
    final s = S(const Locale('en'));
    expect(vpnStatusLines(s, {'configured': false}).single.$1, 'No VPN set up yet');
    final both = vpnStatusLines(s, {
      'configured': true,
      'mode': 'both',
      'tailscale': {'mode': 'tailscale', 'available': true, 'backend_state': 'Running'},
      'wireguard': {
        'mode': 'wireguard',
        'available': true,
        'peers': <Object?>[{}, {}],
      },
    });
    expect(both.map((l) => '${l.$1}: ${l.$2}'), ['Tailscale: Running', 'WireGuard: 2 devices']);
  });

  testWidgets('first visit asks about a VPN; WireGuard opens the VPN tab with the endpoint and port-forward help', (
    t,
  ) async {
    final h = await paired(t);
    expect(find.byKey(const Key('vpn-prompt')), findsOneWidget);
    expect(find.text('Use a VPN?'), findsOneWidget);
    await tapKey(t, 'vpn-pick-wireguard');
    expect(find.byKey(const Key('vpn-endpoint')), findsOneWidget);
    expect(find.text('One step on your router'), findsOneWidget);
    await tapKey(t, 'vpn-detect');
    expect(t.widget<TextField>(find.byKey(const Key('vpn-endpoint'))).controller!.text, '203.0.113.7:51820');
    await tapKey(t, 'vpn-save');
    final cs = h.device.changes.values.single;
    expect(cs['patch'], {'vpn.mode': 'wireguard', 'vpn.wireguard.endpoint': '203.0.113.7:51820'});
    expect(h.state.vpnAsked(kDevice), isTrue);
  });

  testWidgets('a Pi already running Tailscale is offered both side by side; saving keeps Tailscale', (t) async {
    final h = await paired(
      t,
      prep: (h) {
        h.device.caps = {
          ...h.device.caps,
          'modules': {
            ...(h.device.caps['modules']! as Map),
            'vpn': {
              'available': true,
              'reasons': <Object?>[],
              'notes': <Object?>[],
              'options': ['tailscale', 'wireguard', 'both'],
            },
          },
        };
        h.device.config['vpn'] = {'mode': 'tailscale'};
        h.device.secrets['tailscale_auth_key'] = true;
      },
    );
    expect(find.text('Add WireGuard or Tailscale too?'), findsOneWidget);
    expect(find.byKey(const Key('vpn-pick-tailscale')), findsNothing);
    await tapKey(t, 'vpn-pick-both');
    expect(find.byKey(const Key('vpn-authkey')), findsOneWidget);
    expect(find.byKey(const Key('vpn-endpoint')), findsOneWidget);
    await enter(t, 'vpn-endpoint', 'home.example.net:51820');
    await tapKey(t, 'vpn-save');
    expect(h.device.changes.values.single['patch'], {
      'vpn.mode': 'both',
      'vpn.tailscale.auth_key_file': '/etc/rp/tailscale.key',
      'vpn.wireguard.endpoint': 'home.example.net:51820',
    });
  });

  testWidgets('"Not now" is remembered: the prompt is not shown again', (t) async {
    await paired(t);
    await tapKey(t, 'vpn-pick-later');
    expect(find.byKey(const Key('vpn-prompt')), findsNothing);
    await t.pageBack();
    await settle(t);
    await tapKey(t, 'device-$kDevice');
    expect(find.byKey(const Key('vpn-prompt')), findsNothing);
  });
}
