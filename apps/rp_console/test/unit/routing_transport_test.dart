import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/app/app_state.dart';
import 'package:rp_console/core/api/routing_transport.dart';
import 'package:rp_console/core/api/transport.dart';

import '../support/fakes.dart';

class Down implements Transport {
  @override
  String? get seenCert => null;
  @override
  Future<Object?> request(String m, String p, {Object? body, String? token}) async => throw const SocketLikeException();
}

void main() {
  RoutingTransport route({required bool vpnOn, Set<String> down = const {}, List<String>? opened}) => RoutingTransport(
    lanHost: '192.0.2.66',
    vpnHosts: const ['198.51.100.7', 'rp.tail0000.ts.net'],
    vpnActive: () async => vpnOn,
    open: (h) {
      opened?.add(h);
      return down.contains(h) ? Down() : FakeDevice();
    },
  );

  test('with the phone\'s VPN on, the VPN address is tried first', () async {
    expect(await route(vpnOn: true).candidates(), ['198.51.100.7', 'rp.tail0000.ts.net', '192.0.2.66']);
    expect(await route(vpnOn: false).candidates(), ['192.0.2.66', '198.51.100.7', 'rp.tail0000.ts.net']);
  });

  test('an exit node hides the home address: the VPN address is used', () async {
    final opened = <String>[];
    final t = route(vpnOn: false, down: {'192.0.2.66'}, opened: opened);
    await t.request('GET', '/v1/info');
    expect(t.host, '198.51.100.7');
    expect(t.viaVpn, isTrue);
    expect(opened, ['192.0.2.66', '198.51.100.7']);
  });

  test('nothing answers: the request fails as unreachable', () async {
    final t = route(vpnOn: true, down: {'192.0.2.66', '198.51.100.7', 'rp.tail0000.ts.net'});
    await expectLater(t.request('GET', '/v1/info'), throwsA(isA<Unreachable>()));
  });

  test('VPN addresses from the device, for one mode or both', () {
    expect(
      AppState.vpnHostsFrom({
        'mode': 'tailscale',
        'addresses': ['fd7a:115c:a1e0::7', '198.51.100.7'],
        'dns_name': 'rp.tail0000.ts.net',
      }),
      ['198.51.100.7', 'rp.tail0000.ts.net'],
    );
    expect(
      AppState.vpnHostsFrom({
        'mode': 'both',
        'tailscale': {
          'addresses': ['198.51.100.7'],
          'dns_name': 'rp.tail0000.ts.net',
        },
        'wireguard': {'address': '198.51.100.1'},
      }),
      ['198.51.100.7', 'rp.tail0000.ts.net', '198.51.100.1'],
    );
    expect(AppState.vpnHostsFrom({'configured': false}), isEmpty);
  });
}
