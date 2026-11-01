import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/core/pairing/pairing.dart';

const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

void main() {
  test('parses the QR JSON from rpctl pairing new', () {
    final c = PairingCode.parse(
      jsonEncode({
        'v': 1,
        'host': 'rp-security.local',
        'port': 8443,
        'secret': secret.toUpperCase(),
        'device': '00112233445566778899aabbccddeeff',
        'cert': 'ab' * 32,
      }),
    );
    expect(c.host, 'rp-security.local');
    expect(c.secret, secret, reason: 'normalised to lower case');
    expect(c.device, '00112233445566778899aabbccddeeff');
    expect(c.cert, 'ab' * 32);
  });

  test('a bare code needs an address', () {
    expect(() => PairingCode.parse(secret), throwsFormatException);
    final c = PairingCode.parse(' $secret ', host: '192.0.2.10');
    expect(c.host, '192.0.2.10');
    expect(c.port, 8443);
  });

  test('rejects malformed or hostile input', () {
    for (final bad in [
      '',
      'not json',
      jsonEncode({'v': 2, 'host': 'h', 'port': 1, 'secret': secret}),
      jsonEncode({'v': 1, 'host': 'h/../x', 'port': 1, 'secret': secret}),
      jsonEncode({'v': 1, 'host': 'h', 'port': 70000, 'secret': secret}),
      jsonEncode({'v': 1, 'host': 'h', 'port': 1, 'secret': 'short'}),
      jsonEncode({'v': 1, 'host': 'h\nInjected: 1', 'port': 1, 'secret': secret}),
    ]) {
      expect(() => PairingCode.parse(bad), throwsFormatException, reason: bad);
    }
    expect(() => PairingCode.parse(secret, host: 'a b'), throwsFormatException);
  });

  test('ignores a malformed device id or certificate instead of trusting it', () {
    final c = PairingCode.parse(
      jsonEncode({'v': 1, 'host': 'h', 'port': 1, 'secret': secret, 'device': 'x', 'cert': 'y'}),
    );
    expect(c.device, isNull);
    expect(c.cert, isNull);
  });
}
