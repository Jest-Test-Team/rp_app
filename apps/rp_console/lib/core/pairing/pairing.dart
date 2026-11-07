// Pairing with a one-time secret (rp_policy::pairing). The device has no
// screen: the secret comes from the SD card the app wrote, or from the QR
// code / text printed by `sudo rpctl pairing new`. Both sides prove it with
// HMAC-SHA256, and the device's proof covers its TLS certificate, which the
// app then pins.

import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import '../auth/admin_key.dart';

String clientMessage(String device, String publicKey, String nonce) => 'rp-pair-v1|client|$device|$publicKey|$nonce';

String serverMessage(String device, String publicKey, String nonce, String cert, String admin) =>
    'rp-pair-v1|server|$device|$publicKey|$nonce|$cert|$admin';

Future<String> hmacHex(List<int> secret, String message) async {
  final mac = await Hmac.sha256().calculateMac(utf8.encode(message), secretKey: SecretKey(secret));
  return hexOf(mac.bytes);
}

/// Constant-time comparison of two hex strings.
bool sameHex(String a, String b) {
  final x = a.toLowerCase(), y = b.toLowerCase();
  if (x.length != y.length) return false;
  var d = 0;
  for (var i = 0; i < x.length; i++) {
    d |= x.codeUnitAt(i) ^ y.codeUnitAt(i);
  }
  return d == 0;
}

/// What a pairing code carries. `device` and `cert` are known only when the
/// code came from `rpctl pairing new` on a running device.
class PairingCode {
  PairingCode({required this.host, required this.port, required this.secret, this.device, this.cert});

  final String host;
  final int port;
  final String secret;
  final String? device;
  final String? cert;

  static final _hex64 = RegExp(r'^[0-9a-fA-F]{64}$');
  static final _host = RegExp(r'^[A-Za-z0-9.\-:\[\]]{1,253}$');

  /// Parse the QR JSON (`{"v":1,"host":..,"port":..,"secret":..}`) or a bare
  /// 64-hex code typed by hand (then `host` must be given).
  static PairingCode parse(String text, {String? host, int port = 8443}) {
    final t = text.trim();
    if (_hex64.hasMatch(t)) {
      if (host == null || !_host.hasMatch(host)) throw const FormatException('enter the device address');
      return PairingCode(host: host, port: port, secret: t.toLowerCase());
    }
    final Object? v;
    try {
      v = jsonDecode(t);
    } on FormatException {
      throw const FormatException('not a pairing code');
    }
    if (v is! Map || v['v'] != 1) throw const FormatException('not a pairing code');
    final h = v['host'], p = v['port'], s = v['secret'];
    if (h is! String || !_host.hasMatch(h)) throw const FormatException('bad host');
    if (p is! int || p < 1 || p > 65535) throw const FormatException('bad port');
    if (s is! String || !_hex64.hasMatch(s)) throw const FormatException('bad secret');
    final d = v['device'], c = v['cert'];
    return PairingCode(
      host: h,
      port: p,
      secret: s.toLowerCase(),
      device: d is String && RegExp(r'^[0-9a-f]{32}$').hasMatch(d) ? d : null,
      cert: c is String && _hex64.hasMatch(c) ? c.toLowerCase() : null,
    );
  }
}
