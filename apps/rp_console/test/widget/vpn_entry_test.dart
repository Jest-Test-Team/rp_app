import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'harness.dart';

void main() {
  testWidgets('no Tailscale and no WireGuard: a prompt that cannot be dismissed until one is installed', (t) async {
    final vpn = FakeVpn();
    final h = Harness(vpn: vpn);
    await h.start(t);
    expect(find.byKey(const Key('vpn-install')), findsOneWidget);
    // Not dismissable: back and tapping outside keep it.
    await t.tapAt(const Offset(5, 5));
    await settle(t);
    expect(find.byKey(const Key('vpn-install')), findsOneWidget);
    await tapKey(t, 'vpngate-tailscale');
    expect(vpn.opened, ['store:com.tailscale.ipn']);
    await tapKey(t, 'vpngate-check');
    expect(find.byKey(const Key('vpn-install')), findsOneWidget, reason: 'still not installed');
    vpn.tailscale = true;
    await tapKey(t, 'vpngate-check');
    expect(find.byKey(const Key('vpn-install')), findsNothing);
  });

  testWidgets('a VPN app installed: no prompt', (t) async {
    final h = Harness(vpn: FakeVpn(wireguard: true));
    await h.start(t);
    expect(find.byKey(const Key('vpn-install')), findsNothing);
  });

  testWidgets('the Pi\'s VPN addresses are learned while it is reachable, then used behind an exit node', (t) async {
    await t.binding.setSurfaceSize(const Size(900, 1600));
    addTearDown(() => t.binding.setSurfaceSize(null));
    final vpn = FakeVpn(tailscale: true);
    final h = Harness(vpn: vpn);
    await h.start(t);
    await pairViaCode(t, h);
    expect(find.text('Home network · rp-demo.local'), findsOneWidget);
    final saved = (await h.services.vault.devices()).single;
    expect(saved.vpnHosts, ['198.51.100.7', 'rp-demo.tail0000.ts.net']);

    // Exit node on: the home address no longer answers.
    vpn.active = true;
    h.down.add('rp-demo.local');
    h.state.reconnect(saved);
    await t.pageBack();
    await settle(t);
    await tapKey(t, 'device-${saved.deviceId}');
    expect(find.text('Via VPN · 198.51.100.7'), findsOneWidget);
    expect(find.byKey(const Key('conn-help')), findsNothing);
  });

  testWidgets('unreachable everywhere: says the VPN state; adding the Pi\'s Tailscale address connects', (t) async {
    await t.binding.setSurfaceSize(const Size(900, 1600));
    addTearDown(() => t.binding.setSurfaceSize(null));
    final vpn = FakeVpn(tailscale: true, active: true);
    final h = Harness(vpn: vpn);
    h.down.add('rp-demo.local');
    await h.start(t);
    // Paired before the exit node was on (the code path pairs over the fake).
    h.down.clear();
    await pairViaCode(t, h);
    final d = (await h.services.vault.devices()).single;
    // Forget learned addresses: simulate an app updated while away from home.
    await h.state.setVpnHosts(d, []);
    h.down.addAll(['rp-demo.local', '198.51.100.7', 'rp-demo.tail0000.ts.net']);
    h.state.reconnect(d);
    await t.pageBack();
    await settle(t);
    await tapKey(t, 'device-${d.deviceId}');
    expect(find.byKey(const Key('conn-help')), findsOneWidget);
    expect(find.text('A VPN is on on this phone'), findsOneWidget);
    await tapKey(t, 'conn-open-tailscale');
    expect(vpn.opened, ['app:com.tailscale.ipn']);
    await enter(t, 'conn-host', 'bad host!');
    await tapKey(t, 'conn-add');
    expect(find.text('That is not a host name or IP address.'), findsOneWidget);
    h.down.remove('rp-demo.tail0000.ts.net');
    await enter(t, 'conn-host', 'rp-demo.tail0000.ts.net.');
    await tapKey(t, 'conn-add');
    expect(find.byKey(const Key('conn-help')), findsNothing);
    expect(find.text('Via VPN · rp-demo.tail0000.ts.net'), findsOneWidget);
  });
}
