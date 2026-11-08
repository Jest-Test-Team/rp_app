import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/app/strings.dart';
import 'package:rp_console/features/firewall/firewall_page.dart';

void main() {
  final s = S(const Locale('en'));
  Map<String, Object?> rule(Map<String, Object?> x) => {
    'name': 'r',
    'from': 'iot',
    'to': 'wan',
    'proto': 'any',
    'ports': <int>[],
    'action': 'drop',
    ...x,
  };

  test('validation mirrors the device', () {
    expect(validateRule(rule({})), isNull);
    expect(validateRule(rule({'from': 'lan', 'to': 'wan'})), 'lanwan');
    expect(validateRule(rule({'from': 'wan', 'to': 'lan'})), 'lanwan');
    expect(
      validateRule(
        rule({
          'src_mac': ['02:aa:bb'],
        }),
      ),
      'mac',
    );
    expect(
      validateRule(
        rule({
          'from': 'vpn',
          'src_mac': ['02:aa:bb:cc:dd:ee'],
        }),
      ),
      'mac',
    );
    expect(
      validateRule(
        rule({
          'to': 'lan',
          'dest': ['999.1.1.1/32'],
        }),
      ),
      'dest',
    );
    expect(validateRule(rule({'to': 'device', 'action': 'drop'})), 'ports');
  });

  test('services and sentences', () {
    expect(
      serviceOf(
        rule({
          'proto': 'tcp',
          'ports': [443, 80],
        }),
      ),
      'web',
    );
    expect(
      serviceOf(
        rule({
          'proto': 'udp',
          'ports': [5000],
        }),
      ),
      'custom',
    );
    const plug = KnownDevice(mac: '02:aa:bb:cc:dd:ee', ip: '198.51.100.150', name: 'plug', zone: 'iot');
    expect(
      describeRule(
        s,
        rule({
          'src_mac': ['02:AA:BB:CC:DD:EE'],
          'proto': 'tcp',
          'ports': [23, 2323],
          'action': 'reject',
        }),
        [plug],
      ),
      'Block and tell · Smart-home Wi-Fi (plug) → Internet · Telnet (23, 2323)',
    );
    expect(
      describeRule(
        s,
        rule({
          'from': 'vpn',
          'to': 'lan',
          'dest': ['192.0.2.20/32'],
          'action': 'accept',
        }),
        [],
      ),
      'Allow · VPN users → Home network (192.0.2.20) · Everything',
    );
  });

  test('addresses and names', () {
    expect(hostNet('192.0.2.20'), '192.0.2.20/32');
    expect(hostNet('192.0.2.0/24'), '192.0.2.0/24');
    expect(hostNet('192.0.2.300'), isNull);
    expect(hostNet('nas.local'), isNull);
    expect(ruleName("Pause Kid's iPad!"), 'Pause Kids iPad');
    expect(ruleName('x' * 60).length, 40);
  });

  test('every template builds rules the device accepts', () {
    const d = KnownDevice(mac: '02:aa:bb:cc:dd:ee', ip: '198.51.100.150', name: 'Living room TV', zone: 'iot');
    for (final t in templates) {
      for (final r in t.build(d, '192.0.2.20/32')) {
        expect(validateRule(r), isNull, reason: '${t.id}: $r');
      }
    }
  });
}
