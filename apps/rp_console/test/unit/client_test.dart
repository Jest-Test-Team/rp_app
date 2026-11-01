import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/core/api/client.dart';
import 'package:rp_console/core/api/transport.dart';
import 'package:rp_console/core/auth/admin_key.dart';
import 'package:rp_console/core/pairing/pairing.dart';

import '../support/fakes.dart';

Future<(RpClient, FakeDevice)> paired() async {
  final dev = FakeDevice();
  final c = RpClient(dev);
  final key = await AdminKey.fromSeed(List.filled(32, 1));
  await c.pair(PairingCode(host: 'h', port: 8443, secret: kSecret), key, 'test');
  return (c, dev);
}

void main() {
  test('pairing verifies the device proof and remembers the certificate', () async {
    final dev = FakeDevice();
    final c = RpClient(dev);
    final key = await AdminKey.fromSeed(List.filled(32, 1));
    final r = await c.pair(PairingCode(host: 'h', port: 1, secret: kSecret), key, 'phone');
    expect(r.certSha256, kCert);
    expect(r.deviceId, kDevice);
    expect(dev.admins.containsKey(key.adminId), isTrue);
    final body = dev.calls.firstWhere((x) => x.path == '/v1/pairing').body as Map;
    expect(body.containsKey('secret'), isFalse, reason: 'the secret itself never goes on the wire');
    expect(jsonEncode(body), isNot(contains(kSecret)));
  });

  test('a wrong code is refused by the device', () async {
    final c = RpClient(FakeDevice());
    final key = await AdminKey.fromSeed(List.filled(32, 1));
    expect(
      () => c.pair(PairingCode(host: 'h', port: 1, secret: 'ff' * 32), key, 'x'),
      throwsA(isA<ApiException>().having((e) => e.code, 'code', 'unauthorized')),
    );
  });

  test('a device that cannot prove the code is not trusted', () async {
    // A spoofed device accepts our proof but cannot compute its own.
    final c = RpClient(FakeDevice(impostor: true));
    final key = await AdminKey.fromSeed(List.filled(32, 1));
    await expectLater(
      c.pair(PairingCode(host: 'h', port: 1, secret: kSecret), key, 'x'),
      throwsA(isA<PairingFailed>().having((e) => e.reason, 'reason', contains('could not prove'))),
    );
    expect(c.deviceId, isNull, reason: 'not trusted');
  });

  test('a man in the middle (different certificate on the wire) is detected', () async {
    final key = await AdminKey.fromSeed(List.filled(32, 1));
    final mitm = FakeDevice(certSeen: 'aa' * 32);
    await expectLater(
      RpClient(mitm).pair(PairingCode(host: 'h', port: 1, secret: kSecret), key, 'x'),
      throwsA(isA<PairingFailed>()),
    );
    final pinned = FakeDevice();
    await expectLater(
      RpClient(pinned).pair(PairingCode(host: 'h', port: 1, secret: kSecret, cert: 'bb' * 32), key, 'x'),
      throwsA(isA<PairingFailed>().having((e) => e.reason, 'reason', contains('certificate'))),
    );
    expect(pinned.admins, isEmpty, reason: 'nothing was sent to a device that did not match the code');
    await expectLater(
      RpClient(FakeDevice()).pair(PairingCode(host: 'h', port: 1, secret: kSecret, device: 'ff' * 16), key, 'x'),
      throwsA(isA<PairingFailed>()),
    );
  });

  test('reads open a session lazily and renew it once on 401', () async {
    final (c, dev) = await paired();
    await c.status();
    final s1 = dev.calls.where((x) => x.path == '/v1/session').length;
    expect(s1, 1);
    dev.tokens.clear();
    await c.status();
    expect(dev.calls.where((x) => x.path == '/v1/session').length, 2);
  });

  test('every change is signed for this device and bound to its URL', () async {
    final (c, dev) = await paired();
    final cs = await c.createChangeset('dns', 1, {
      'dns.block': ['ads.example'],
    });
    await c.preflight(cs.id);
    await c.apply(cs.id, confirmSecs: 30);
    await c.confirm(cs.id);
    await c.setSecret('ap_passphrase', 'correct horse');
    for (final call in dev.calls.where((x) => x.method != 'GET' && x.path != '/v1/pairing')) {
      final env = call.body as Map;
      expect(env.keys.toSet(), {'admin_id', 'nonce', 'expires_at', 'payload', 'signature'});
      expect(call.token, isNull, reason: 'changes are authorised by the signature, not a session');
    }
    final applyPayload = jsonDecode(
      (dev.calls.firstWhere((x) => x.path.endsWith('/apply')).body as Map)['payload'] as String,
    );
    expect(applyPayload, {'op': 'apply', 'id': cs.id, 'confirm_secs': 30});
    expect(() => c.confirm('../../etc'), throwsArgumentError);
  });

  test('a replayed envelope is refused', () async {
    final (c, dev) = await paired();
    final env = await c.key!.sign(kDevice, {'op': 'session'});
    await dev.request('POST', '/v1/session', body: env.toJson());
    expect(() => dev.request('POST', '/v1/session', body: env.toJson()), throwsA(isA<ApiException>()));
  });

  test('stale revision surfaces as a conflict', () async {
    final (c, _) = await paired();
    expect(
      () => c.createChangeset('dns', 99, {'dns.block': []}),
      throwsA(isA<ApiException>().having((e) => e.isConflict, 'conflict', isTrue)),
    );
  });

  test('unpaired clients cannot sign', () {
    expect(() => RpClient(FakeDevice()).confirm('0123456789abcdef'), throwsStateError);
  });
}
