// HTTPS to one device with certificate pinning.
//
// No certificate authority is trusted (SecurityContext without roots), so
// every certificate reaches the pin check: a CA-signed certificate for the
// device's name or address is refused just like any other mismatch.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as c;

class ApiException implements Exception {
  ApiException(this.status, this.code, this.message, [this.details]);

  final int status;
  final String code;
  final String message;
  final Object? details;

  bool get isConflict => code == 'conflict';

  @override
  String toString() => 'ApiException($status $code: $message)';
}

/// Raised when the device presents a certificate other than the pinned one.
class PinMismatch implements Exception {
  PinMismatch(this.seen);
  final String? seen;
  @override
  String toString() => 'PinMismatch(seen: $seen)';
}

abstract class Transport {
  /// SHA-256 of the certificate seen on the last connection.
  String? get seenCert;
  Future<Object?> request(String method, String path, {Object? body, String? token});
}

class PinnedTransport implements Transport {
  PinnedTransport({required this.host, required this.port, this.pin, this.timeout = const Duration(seconds: 15)});

  final String host;
  final int port;

  /// Expected certificate SHA-256 (hex). Null only while pairing: the
  /// certificate is then accepted, recorded, and must be proven by the device.
  String? pin;
  final Duration timeout;

  @override
  String? seenCert;

  static String fingerprint(X509Certificate cert) => c.sha256.convert(cert.der).toString();

  HttpClient _client() {
    final client = HttpClient(context: SecurityContext(withTrustedRoots: false))
      ..connectionTimeout = timeout
      ..idleTimeout = const Duration(seconds: 5)
      ..findProxy = (_) => 'DIRECT';
    client.badCertificateCallback = (cert, h, p) {
      final fp = fingerprint(cert);
      seenCert = fp;
      final want = pin;
      return want == null || want.toLowerCase() == fp;
    };
    return client;
  }

  Uri _uri(String path) {
    final h = host.contains(':') && !host.startsWith('[') ? '[$host]' : host;
    return Uri.parse('https://$h:$port$path');
  }

  @override
  Future<Object?> request(String method, String path, {Object? body, String? token}) async {
    final client = _client();
    try {
      final req = await client.openUrl(method, _uri(path)).timeout(timeout);
      req.headers.set(HttpHeaders.acceptHeader, 'application/json');
      if (token != null) req.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
      if (body != null) {
        final bytes = utf8.encode(jsonEncode(body));
        req.headers.contentType = ContentType.json;
        req.contentLength = bytes.length;
        req.add(bytes);
      }
      final resp = await req.close().timeout(timeout);
      final text = await resp.transform(utf8.decoder).join().timeout(timeout);
      Object? json;
      try {
        json = text.isEmpty ? null : jsonDecode(text);
      } on FormatException {
        json = null;
      }
      if (resp.statusCode >= 200 && resp.statusCode < 300) return json;
      final err = json is Map ? json['error'] : null;
      if (err is Map) {
        throw ApiException(resp.statusCode, '${err['code']}', '${err['message']}', err['details']);
      }
      throw ApiException(resp.statusCode, 'http_${resp.statusCode}', text.length > 200 ? text.substring(0, 200) : text);
    } on HandshakeException {
      if (pin != null && seenCert != null && seenCert != pin) throw PinMismatch(seenCert);
      rethrow;
    } finally {
      client.close(force: true);
    }
  }
}
