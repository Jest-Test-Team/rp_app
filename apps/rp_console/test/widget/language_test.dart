import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/app/app.dart';
import 'package:rp_console/app/app_state.dart';

import 'harness.dart';

void main() {
  testWidgets('language: switch to Chinese and back from the home screen; the choice is remembered', (t) async {
    final h = Harness();
    await h.state.load();
    await t.pumpWidget(RpApp(state: h.state)); // no forced locale: follows the choice
    await settle(t);
    expect(find.text('No device yet'), findsOneWidget);

    await tapKey(t, 'lang-menu');
    await tapKey(t, 'lang-zh');
    expect(find.text('No device yet'), findsNothing);
    expect(find.text('加入 Raspberry Pi'), findsWidgets);
    expect(h.state.language, 'zh');

    // A fresh start with the same storage keeps Chinese.
    final again = AppState(h.services);
    await again.load();
    expect(again.language, 'zh');
    expect(again.locale, const Locale('zh', 'TW'));

    await tapKey(t, 'lang-menu');
    await tapKey(t, 'lang-en');
    expect(find.text('No device yet'), findsOneWidget);
    await tapKey(t, 'lang-menu');
    await tapKey(t, 'lang-system');
    final third = AppState(h.services);
    await third.load();
    expect(third.language, 'system');
    expect(third.locale, isNull);
  });

  testWidgets('language: the device Settings tab offers the same choice', (t) async {
    await t.binding.setSurfaceSize(const Size(900, 1600));
    addTearDown(() => t.binding.setSurfaceSize(null));
    final h = Harness();
    await h.state.load();
    await t.pumpWidget(RpApp(state: h.state));
    await settle(t);
    await pairViaCode(t, h);
    await tapKey(t, 'tab-Settings');
    expect(find.byKey(const Key('lang-setting')), findsOneWidget);
    await tapKey(t, 'lang-seg-zh');
    expect(h.state.language, 'zh');
    expect(find.text('語言'), findsOneWidget);
  });
}
