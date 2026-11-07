import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/app/release.dart';
import 'package:rp_console/features/dns/dns_page.dart';
import 'package:rp_console/features/firewall/firewall_page.dart';
import 'package:rp_console/features/vpn/vpn_page.dart';

void main() {
  test('domain normalisation', () {
    expect(normalizeDomain(' Ads.Example.COM. '), 'ads.example.com');
    for (final bad in ['', 'localhost', 'a..b.com', '-x.com', 'x.c', 'evil.com; rm -rf', 'a' * 64 + '.com']) {
      expect(normalizeDomain(bad), isNull, reason: bad);
    }
  });

  test('firewall rule validation mirrors the device rules', () {
    Map<String, Object?> r(Map<String, Object?> o) => {
      'name': 'x',
      'from': 'iot',
      'to': 'lan',
      'proto': 'tcp',
      'ports': [445],
      'action': 'drop',
      ...o,
    };
    expect(validateRule(r({})), isNull);
    expect(validateRule(r({'name': 'x;flush'})), 'name');
    expect(validateRule(r({'from': 'device'})), 'from');
    expect(validateRule(r({'to': 'iot'})), 'to');
    expect(validateRule(r({'proto': 'any'})), 'proto');
    expect(
      validateRule(
        r({
          'ports': [0],
        }),
      ),
      'ports',
    );
    expect(validateRule(r({'to': 'device', 'ports': []})), 'ports');
    expect(parsePorts('22, 443'), [22, 443]);
    expect(parsePorts(''), isEmpty);
    expect(parsePorts('22,x'), isNull);
    expect(parsePorts('70000'), isNull);
  });

  test('WireGuard helpers match rp_core::wg', () async {
    expect(peerAddress('198.51.100.0/24', 2), '198.51.100.2');
    expect(peerAddress('198.51.100.0/23', 300), '198.51.101.44');
    expect(
      nextFreeHost([
        {'host': 2},
        {'host': 3},
      ], '10.88.0.0/24'),
      4,
    );
    expect(
      () => nextFreeHost([
        {'host': 2},
      ], '10.88.0.0/30'),
      throwsStateError,
    );
    final k = await WgKeys.generate();
    expect(k.privateB64.length, 44);
    expect(k.publicB64.length, 44);
    final conf = clientConfig(
      privateKey: 'P',
      address: '198.51.100.2',
      dns: '1.1.1.1',
      serverPublic: 'S',
      endpoint: 'h:51820',
    );
    expect(
      conf,
      '[Interface]\nPrivateKey = P\nAddress = 198.51.100.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = S\nEndpoint = h:51820\n'
      '# All traffic, including IPv6, goes through the tunnel so nothing leaks.\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n',
    );
  });

  test('install.sh hash is read from SHA256SUMS', () {
    final sums = 'aaaa  rp-x.tar.gz\n${'b' * 64}  install.sh\n${'c' * 64}  install.ps1\n';
    expect(installShaFrom(sums), 'b' * 64);
    expect(installShaFrom('${'d' * 64} *install.sh'), 'd' * 64);
    expect(installShaFrom('nothing'), isNull);
  });
}
