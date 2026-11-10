import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/features/vpn/vpn_join.dart';

import '../support/fakes.dart';
import 'harness.dart';
import 'modules_test.dart' show applySheet;

Future<Harness> onVpnTab(WidgetTester t, FakeVpn vpn, {void Function(FakeDevice)? prep}) async {
  await t.binding.setSurfaceSize(const Size(900, 2000));
  addTearDown(() => t.binding.setSurfaceSize(null));
  final h = Harness(vpn: vpn);
  prep?.call(h.device);
  await h.start(t);
  await pairViaCode(t, h);
  await tapKey(t, 'tab-VPN');
  return h;
}

const both = {
  'configured': true,
  'mode': 'both',
  'available': true,
  'tailscale': {
    'mode': 'tailscale',
    'available': true,
    'backend_state': 'Running',
    'addresses': ['198.51.100.7'],
    'dns_name': 'rp-demo.tail0000.ts.net',
  },
  'wireguard': {'mode': 'wireguard', 'available': true, 'peers': <Object?>[], 'address': '198.51.100.1'},
};

void main() {
  test('the Pi\'s address on each VPN', () {
    expect(vpnAddresses(both, 'tailscale'), ['198.51.100.7', 'rp-demo.tail0000.ts.net']);
    expect(vpnAddresses(both, 'wireguard'), ['198.51.100.1']);
    expect(
      vpnAddresses({
        'mode': 'tailscale',
        'addresses': ['198.51.100.7'],
      }, 'tailscale'),
      ['198.51.100.7'],
    );
    expect(vpnAddresses({'mode': 'tailscale'}, 'wireguard'), isEmpty);
  });

  testWidgets('tap Tailscale under Status: open Tailscale, then a Tailscale profile that always uses it', (t) async {
    final vpn = FakeVpn(tailscale: true, active: true);
    final h = await onVpnTab(t, vpn);
    expect(find.text('Tap to use it with this app'), findsOneWidget);
    await tapKey(t, 'vpn-status-tailscale');
    expect(find.byKey(const Key('join-tailscale')), findsOneWidget);
    expect(find.text('198.51.100.7\nrp-demo.tail0000.ts.net'), findsOneWidget);
    await tapKey(t, 'join-open');
    expect(vpn.opened, ['app:com.tailscale.ipn']);

    // Not connected yet: nothing answers on the tailnet.
    h.down.addAll(['198.51.100.7', 'rp-demo.tail0000.ts.net']);
    await tapKey(t, 'join-create');
    expect(find.textContaining('did not answer through Tailscale'), findsOneWidget);
    expect(h.state.devices, hasLength(1));

    // Connected: the profile is saved with the tailnet address.
    h.down.clear();
    await tapKey(t, 'join-create');
    expect(find.byKey(const Key('join-message')), findsOneWidget);
    expect(find.textContaining('Added “'), findsOneWidget);
    final p = h.state.devices.firstWhere((d) => d.profile == 'tailscale');
    expect((p.host, p.certSha256, p.deviceId), ('198.51.100.7', kCert, kDevice));
    expect(p.name, endsWith('· Tailscale'));

    // With the exit node on, the home address is gone; the profile still works.
    h.down.add('rp-demo.local');
    await t.pageBack();
    await settle(t);
    await t.pageBack();
    await settle(t);
    expect(find.byKey(Key('device-$kDevice#tailscale')), findsOneWidget);
    await tapKey(t, 'device-$kDevice#tailscale');
    expect(find.text('Via VPN · 198.51.100.7'), findsOneWidget);
    expect(find.byKey(const Key('conn-help')), findsNothing);
  });

  testWidgets('tap WireGuard under Status: this phone becomes a WireGuard device, config saved for the WireGuard app, '
      'then a WireGuard profile', (t) async {
    final vpn = FakeVpn(wireguard: true, active: true);
    final h = await onVpnTab(t, vpn, prep: (d) => d.vpnStatus = both);
    await tapKey(t, 'vpn-status-wireguard');
    expect(find.byKey(const Key('join-wireguard')), findsOneWidget);
    await tapKey(t, 'join-wg-add');
    await t.tap(find.text('Save'));
    await settle(t);
    await applySheet(t);
    final saved = vpn.saved['rp-this-phone.conf']!;
    expect(saved, contains('PrivateKey = '));
    expect(saved, contains('Endpoint = '));
    final peers = ((h.device.config['vpn']! as Map)['peers']! as List).cast<Map<String, Object?>>();
    expect(peers.single['name'], 'this-phone');
    expect(saved, isNot(contains(peers.single['public_key']! as String)), reason: 'the private key, not the public');
    expect(find.textContaining('Saved to Download/rp-this-phone.conf'), findsOneWidget);
    expect(find.byKey(const Key('join-wg-qr')), findsOneWidget);
    await tapKey(t, 'join-open');
    expect(vpn.opened, ['app:com.wireguard.android']);

    await tapKey(t, 'join-create');
    final p = h.state.devices.firstWhere((d) => d.profile == 'wireguard');
    expect(p.host, '198.51.100.1');
    expect((await h.services.vault.devices()).map((d) => d.key), containsAll([kDevice, '$kDevice#wireguard']));
  });

  testWidgets('removing RP Security from the device forgets its VPN profiles too', (t) async {
    final h = await onVpnTab(t, FakeVpn(tailscale: true, active: true));
    await tapKey(t, 'vpn-status-tailscale');
    await tapKey(t, 'join-create');
    expect(h.state.devices, hasLength(2));
    await h.state.forgetAll(kDevice);
    expect(h.state.devices, isEmpty);
    expect(await h.services.vault.devices(), isEmpty);
  });
}
