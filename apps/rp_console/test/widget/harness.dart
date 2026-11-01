import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/app/app.dart';
import 'package:rp_console/app/app_state.dart';
import 'package:rp_console/app/release.dart';
import 'package:rp_console/app/services.dart';
import 'package:rp_console/core/discovery/discovery.dart';
import 'package:rp_console/core/provision/ssh_bootstrap.dart';
import 'package:rp_console/core/storage/vault.dart';

import '../support/fakes.dart';

class Harness {
  Harness({FakeDevice? device, this.desktop = false, FakeShell? shell})
    : device = device ?? FakeDevice(),
      shell = shell ?? FakeShell([]);

  final FakeDevice device;
  final bool desktop;
  final FakeShell shell;
  final store = MemoryStore();
  late final Services services = Services(
    vault: Vault(store),
    discoverer: StaticDiscoverer([Found(name: 'RP Security on rp-demo', host: 'rp-demo.local', port: 8443)]),
    transport: (h, p, pin) => device,
    shell: ({required host, required user, required password, required verifyHostKey}) async {
      if (!await verifyHostKey('ssh-ed25519', 'deadbeef')) throw StateError('host key refused');
      return shell;
    },
    release: () async => ReleaseInfo('v0.2.0', 'a' * 64),
    desktop: desktop,
  );
  late final AppState state = AppState(services);

  Future<void> start(WidgetTester t, {Locale? locale}) async {
    await state.load();
    await t.pumpWidget(RpApp(state: state, locale: locale));
    await settle(t);
  }
}

String qr({String secret = kSecret, String? cert}) =>
    jsonEncode({'v': 1, 'host': 'rp-demo.local', 'port': 8443, 'secret': secret, 'cert': ?cert});

/// pumpAndSettle never settles with spinners; pump a while instead.
Future<void> settle(WidgetTester t, [int frames = 30]) async {
  for (var i = 0; i < frames; i++) {
    await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 2)));
    await t.pump(const Duration(milliseconds: 20));
  }
}

Future<void> tapKey(WidgetTester t, String key) async {
  final f = find.byKey(Key(key));
  await t.ensureVisible(f.first);
  await t.tap(f.first);
  await settle(t);
}

Future<void> enter(WidgetTester t, String key, String text) async {
  await t.enterText(find.byKey(Key(key)), text);
  await settle(t, 5);
}

/// Pair through the onboarding code path; leaves the app on the home screen.
Future<void> pairViaCode(WidgetTester t, Harness h) async {
  await tapKey(t, 'home-add-first');
  await tapKey(t, 'path-code');
  await tapKey(t, 'onb-next');
  await enter(t, 'code-field', qr());
  await tapKey(t, 'onb-next');
  await tapKey(t, 'pair-button');
  await tapKey(t, 'onb-next');
  await tapKey(t, 'onb-finish');
}

ExecResult ok(String out) => ExecResult(0, out, '');
