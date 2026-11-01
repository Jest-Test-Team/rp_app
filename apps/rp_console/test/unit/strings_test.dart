import 'dart:io';

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/app/strings.dart';

String snake(String camel) => camel.replaceAllMapped(RegExp('[A-Z]'), (m) => '_${m[0]!.toLowerCase()}');

void main() {
  test('English and Chinese have exactly the same keys and placeholders', () {
    final en = S.tables['en']!, zh = S.tables['zh']!;
    expect(zh.keys.toSet(), en.keys.toSet());
    for (final k in en.keys) {
      final ph = RegExp(r'\{\w+\}');
      expect(ph.allMatches(zh[k]!).map((m) => m[0]).toSet(), ph.allMatches(en[k]!).map((m) => m[0]).toSet(), reason: k);
      expect(zh[k]!.trim(), isNotEmpty, reason: k);
    }
  });

  test('every capability reason the device can send is translated', () {
    final src = File('../../crates/rp-schema/src/capability.rs').readAsStringSync();
    final body = src.substring(src.indexOf('pub enum Reason {'));
    final variants = RegExp(
      r'^\s{4}([A-Z]\w+),',
      multiLine: true,
    ).allMatches(body.substring(0, body.indexOf('\n}'))).map((m) => snake(m[1]!).substring(1)).toList();
    expect(variants, isNotEmpty);
    for (final lang in ['en', 'zh']) {
      for (final v in variants) {
        expect(S.tables[lang]!.containsKey('reason.$v'), isTrue, reason: '$lang reason.$v');
      }
    }
  });

  test('every module has a name', () {
    final src = File('../../crates/rp-core/src/module.rs').readAsStringSync();
    final list = RegExp(r'pub const MODULES: &\[&str\] = &\[([^\]]+)\]').firstMatch(src)![1]!;
    for (final m in RegExp(r'"(\w+)"').allMatches(list).map((m) => m[1]!)) {
      expect(S.tables['en']!.containsKey('module.$m'), isTrue, reason: m);
    }
  });

  test('lookup, placeholders and fallbacks', () {
    final zh = S(const Locale('zh', 'TW')), en = S(const Locale('en'));
    expect(zh('onb.step', {'n': 2}), '第 2 步，共 6 步');
    expect(en('onb.step', {'n': 2}), 'Step 2 of 6');
    expect(en.reason('brand_new_reason'), 'brand new reason');
    expect(en('missing.key'), 'missing.key');
  });
}
