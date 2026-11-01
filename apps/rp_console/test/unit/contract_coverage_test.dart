// The Dart client must cover every endpoint in the committed OpenAPI document
// (which a static test in the Rust repo keeps equal to what rp-api serves).
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  final spec = jsonDecode(File('api/openapi.json').readAsStringSync()) as Map<String, dynamic>;
  final client = File('lib/core/api/client.dart').readAsStringSync();

  test('every OpenAPI path and method is called by the client', () {
    final paths = (spec['paths'] as Map<String, dynamic>);
    expect(paths.length, greaterThanOrEqualTo(30));
    for (final e in paths.entries) {
      // /v1/changesets/{id}/apply  →  '/v1/changesets/${...}/apply'
      final pattern = RegExp("'${RegExp.escape(e.key).replaceAll(RegExp(r'\\\{\w+\\\}'), r"\$\{[^}]+\}")}(['?]|\\\$)");
      expect(pattern.hasMatch(client), isTrue, reason: 'client does not call ${e.key}');
      for (final m in (e.value as Map<String, dynamic>).keys) {
        expect(client.contains("'${m.toUpperCase()}'"), isTrue, reason: '${m.toUpperCase()} ${e.key}');
      }
    }
  });

  test('every signed endpoint takes the SignedEnvelope schema', () {
    final schemas = spec['components']['schemas'] as Map<String, dynamic>;
    expect((schemas['SignedEnvelope']['required'] as List).toSet(), {
      'admin_id',
      'nonce',
      'expires_at',
      'payload',
      'signature',
    });
  });
}
