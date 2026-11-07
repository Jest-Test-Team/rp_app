// The app's admin identity: one Ed25519 key per installation. The private
// key never leaves the platform keystore (see core/storage/vault.dart); the
// device verifies every change against the public key registered at pairing.
//
// The byte formats here mirror rp-policy (Rust) exactly; the cross-language
// golden file test/fixtures/console/crypto.json pins them.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

const signingDomain = 'rp-admin-v1';

/// Requests are valid for 60 s (the device accepts at most 300 s).
const requestValidity = Duration(seconds: 60);

String hexOf(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List hexDecode(String h) {
  if (h.length.isOdd || !RegExp(r'^[0-9a-fA-F]*$').hasMatch(h)) {
    throw const FormatException('not hex');
  }
  return Uint8List.fromList([for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);
}

/// Random bytes from the platform CSPRNG, hex encoded.
String randomHex(int bytes, {Random? rng}) {
  final r = rng ?? Random.secure();
  return hexOf(List<int>.generate(bytes, (_) => r.nextInt(256)));
}

Future<String> sha256Hex(List<int> data) async => hexOf((await Sha256().hash(data)).bytes);

/// Admin id: first 8 bytes of SHA-256 over the base64 public key text.
Future<String> adminIdFor(String publicKeyB64) async =>
    (await sha256Hex(utf8.encode(publicKeyB64.trim()))).substring(0, 16);

/// A signed console request (rp_policy::admin::Signed).
class SignedEnvelope {
  SignedEnvelope({
    required this.adminId,
    required this.nonce,
    required this.expiresAt,
    required this.payload,
    required this.signature,
  });

  final String adminId;
  final String nonce;
  final int expiresAt;
  final String payload;
  final String signature;

  Map<String, Object> toJson() => {
    'admin_id': adminId,
    'nonce': nonce,
    'expires_at': expiresAt,
    'payload': payload,
    'signature': signature,
  };
}

Uint8List signingBytes(String deviceId, String adminId, String nonce, int expiresAt, String payload) =>
    Uint8List.fromList(utf8.encode('$signingDomain\n$deviceId\n$adminId\n$nonce\n$expiresAt\n$payload'));

class AdminKey {
  AdminKey._(this._pair, this.publicKeyB64, this.adminId);

  final SimpleKeyPair _pair;
  final String publicKeyB64;
  final String adminId;

  static final _ed = Ed25519();

  /// From a 32-byte seed (the stored private key).
  static Future<AdminKey> fromSeed(List<int> seed) async {
    if (seed.length != 32) throw ArgumentError('seed must be 32 bytes');
    final pair = await _ed.newKeyPairFromSeed(seed);
    final pub = await pair.extractPublicKey();
    final b64 = base64.encode(pub.bytes);
    return AdminKey._(pair, b64, await adminIdFor(b64));
  }

  static Future<(AdminKey, Uint8List)> generate({Random? rng}) async {
    final seed = hexDecode(randomHex(32, rng: rng));
    return (await fromSeed(seed), seed);
  }

  /// Sign an operation for one device. `payload` is the operation's JSON.
  Future<SignedEnvelope> sign(
    String deviceId,
    Map<String, Object?> op, {
    DateTime? now,
    String? nonce,
    String? payloadText,
  }) async {
    final payload = payloadText ?? jsonEncode(op);
    final n = nonce ?? randomHex(16);
    final exp = ((now ?? DateTime.now()).add(requestValidity).millisecondsSinceEpoch ~/ 1000);
    final sig = await _ed.sign(signingBytes(deviceId, adminId, n, exp, payload), keyPair: _pair);
    return SignedEnvelope(
      adminId: adminId,
      nonce: n,
      expiresAt: exp,
      payload: payload,
      signature: base64.encode(sig.bytes),
    );
  }

  /// Same, with an explicit expiry (tests and golden checks).
  Future<SignedEnvelope> signAt(String deviceId, String payload, String nonce, int expiresAt) async {
    final sig = await _ed.sign(signingBytes(deviceId, adminId, nonce, expiresAt, payload), keyPair: _pair);
    return SignedEnvelope(
      adminId: adminId,
      nonce: nonce,
      expiresAt: expiresAt,
      payload: payload,
      signature: base64.encode(sig.bytes),
    );
  }
}
