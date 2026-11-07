import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/core/provision/ssh_bootstrap.dart';

import '../support/fakes.dart';
import 'harness.dart';

void main() {
  testWidgets('empty home → pair with a code → capabilities → verify → device listed', (t) async {
    final h = Harness();
    await h.start(t);
    expect(find.text('No device yet'), findsOneWidget);
    await tapKey(t, 'home-add-first');
    expect(find.byKey(const Key('onb-step')), findsOneWidget);
    expect(find.text('Step 1 of 6'), findsOneWidget);
    await tapKey(t, 'path-code');
    await tapKey(t, 'onb-next');
    await enter(t, 'code-field', qr());
    expect(find.text('rp-demo.local:8443'), findsWidgets);
    await tapKey(t, 'onb-next');
    expect(find.text('Step 4 of 6'), findsOneWidget, reason: 'a code already names the device: no search step');
    await enter(t, 'name-field', 'Test phone');
    await tapKey(t, 'pair-button');
    expect(find.byKey(const Key('paired-ok')), findsOneWidget);
    expect(find.byKey(const Key('cap-ap')), findsOneWidget);
    expect(find.textContaining('WPA2 only'), findsOneWidget, reason: 'reason codes are shown in words');
    await tapKey(t, 'onb-next');
    expect(find.byKey(const Key('verify-ok')), findsOneWidget);
    await tapKey(t, 'onb-finish');
    final saved = await h.services.vault.devices();
    expect(saved.single.certSha256, kCert, reason: 'the proven certificate is pinned');
    expect(h.device.admins, hasLength(1));
    await settle(t);
    expect(find.text('Overview'), findsWidgets, reason: 'the new device opens');
  });

  testWidgets('a wrong code is refused and nothing is saved', (t) async {
    final h = Harness();
    await h.start(t);
    await tapKey(t, 'home-add-first');
    await tapKey(t, 'path-code');
    await tapKey(t, 'onb-next');
    await enter(t, 'code-field', qr(secret: 'ff' * 32));
    await tapKey(t, 'onb-next');
    await tapKey(t, 'pair-button');
    expect(find.byKey(const Key('onb-error')), findsOneWidget);
    expect(await h.services.vault.devices(), isEmpty);
  });

  testWidgets('a man in the middle is detected before anything is sent', (t) async {
    final h = Harness(device: FakeDevice(certSeen: 'aa' * 32));
    await h.start(t);
    await tapKey(t, 'home-add-first');
    await tapKey(t, 'path-code');
    await tapKey(t, 'onb-next');
    await enter(t, 'code-field', qr(cert: kCert));
    await tapKey(t, 'onb-next');
    await tapKey(t, 'pair-button');
    expect(find.textContaining('certificate differs'), findsOneWidget);
    expect(h.device.calls.where((c) => c.path == '/v1/pairing'), isEmpty);
    expect(await h.services.vault.devices(), isEmpty);
  });

  testWidgets('garbage in the code field never enables Next', (t) async {
    final h = Harness();
    await h.start(t);
    await tapKey(t, 'home-add-first');
    await tapKey(t, 'path-code');
    await tapKey(t, 'onb-next');
    await enter(t, 'code-field', '{"v":1,"host":"x; rm -rf /","port":1,"secret":"00"}');
    final next = t.widget<FilledButton>(find.byKey(const Key('onb-next')));
    expect(next.onPressed, isNull);
    expect(find.byKey(const Key('onb-error')), findsOneWidget);
  });

  testWidgets('the SD-card path is desktop only', (t) async {
    final h = Harness();
    await h.start(t);
    await tapKey(t, 'home-add-first');
    await tapKey(t, 'path-card');
    final next = t.widget<FilledButton>(find.byKey(const Key('onb-next')));
    expect(next.onPressed, isNull, reason: 'phones cannot write SD cards');
  });

  testWidgets('SSH path: host key is confirmed, password cleared, code obtained', (t) async {
    final pairing = jsonEncode({
      'pairing': {
        'v': 1,
        'host': 'raspberrypi.local',
        'port': 8443,
        'device': kDevice,
        'secret': kSecret,
        'cert': kCert,
      },
    });
    final shell = FakeShell([
      ('uname -m', ok('armv7l\n')),
      ('sudo -n true', ExecResult(1, '', 'password required')),
      ('rpctl --json setup', ok('$pairing\n')),
    ]);
    final h = Harness(shell: shell);
    await h.start(t);
    await tapKey(t, 'home-add-first');
    await tapKey(t, 'path-ssh');
    await tapKey(t, 'onb-next');
    await enter(t, 'ssh-host', '192.0.2.10');
    await enter(t, 'ssh-password', 'hunter2-secret');
    await t.tap(find.byKey(const Key('ssh-run')));
    await settle(t);
    expect(find.textContaining('SHA256:deadbeef'), findsOneWidget, reason: 'host key shown before trusting it');
    await tapKey(t, 'hostkey-trust');
    expect(shell.closed, isTrue);
    expect(t.widget<TextField>(find.byKey(const Key('ssh-password'))).controller!.text, isEmpty);
    expect(shell.execs.where((e) => e.$1.contains('hunter2')), isEmpty);
    await tapKey(t, 'onb-next');
    await tapKey(t, 'pair-button');
    expect(find.byKey(const Key('paired-ok')), findsOneWidget);
    expect((await h.services.vault.devices()).single.host, '192.0.2.10');
  });

  testWidgets('Chinese UI with localized capability reasons', (t) async {
    final h = Harness();
    (h.device.caps['modules'] as Map)['ap'] = {
      'available': false,
      'reasons': ['would_drop_management_link'],
      'notes': [],
      'options': [],
    };
    await h.start(t, locale: const Locale('zh', 'TW'));
    expect(find.text('尚未加入裝置'), findsOneWidget);
    await pairViaCode(t, h);
    await tapKey(t, 'tab-IoT Wi-Fi');
    expect(find.textContaining('請先接上 Ethernet'), findsOneWidget);
    expect(find.byKey(const Key('reason-would_drop_management_link')), findsOneWidget);
  });
}
