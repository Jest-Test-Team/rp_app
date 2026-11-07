// A device that answers on the paired address but is not the paired device
// (different certificate). Started by test/suites/84_app_security.robot:
//   RP_IMPOSTOR_API=127.0.0.1:PORT  RP_PAIRED_PIN=<the real device's cert>
//   RP_IMPOSTOR_SECRET=<a pairing secret the impostor accepts>
library;

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/core/api/client.dart';
import 'package:rp_console/core/api/transport.dart';
import 'package:rp_console/core/auth/admin_key.dart';
import 'package:rp_console/core/pairing/pairing.dart';

void main() {
  final env = Platform.environment;
  final addr = env['RP_IMPOSTOR_API'], pin = env['RP_PAIRED_PIN'], secret = env['RP_IMPOSTOR_SECRET'];
  final skip = addr == null || pin == null || secret == null ? 'impostor environment not set' : null;
  final host = addr?.split(':').first ?? '', port = int.tryParse(addr?.split(':').last ?? '') ?? 0;

  group('impostor', skip: skip, () {
    test('pinned requests to an impostor fail before any data is sent', () async {
      final t = PinnedTransport(host: host, port: port, pin: pin);
      final key = await AdminKey.fromSeed(List.filled(32, 9));
      final c = RpClient(t, key: key, deviceId: '00' * 16);
      await expectLater(c.status(), throwsA(anyOf(isA<PinMismatch>(), isA<HandshakeException>())));
      expect(t.seenCert, isNot(pin));
    });

    test('a pairing code for the real device does not pair with the impostor', () async {
      final key = await AdminKey.fromSeed(List.filled(32, 9));
      final c = RpClient(PinnedTransport(host: host, port: port, pin: pin));
      // The code names the real certificate: the impostor's TLS fails at once.
      await expectLater(
        c.pair(PairingCode(host: host, port: port, secret: secret!, cert: pin), key, 'x'),
        throwsA(anyOf(isA<PinMismatch>(), isA<HandshakeException>(), isA<PairingFailed>())),
      );
    });
  });
}
