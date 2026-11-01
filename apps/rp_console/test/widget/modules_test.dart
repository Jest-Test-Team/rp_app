import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/fakes.dart';
import 'harness.dart';

Future<Harness> onDevice(WidgetTester t, String tab, {void Function(FakeDevice)? prep}) async {
  await t.binding.setSurfaceSize(const Size(900, 1600));
  addTearDown(() => t.binding.setSurfaceSize(null));
  final h = Harness();
  prep?.call(h.device);
  await h.start(t);
  await pairViaCode(t, h);
  if (tab != 'Overview') await tapKey(t, 'tab-$tab');
  return h;
}

Future<void> applySheet(WidgetTester t) async {
  expect(find.byKey(const Key('change-apply')), findsOneWidget);
  await tapKey(t, 'change-apply');
  await settle(t, 60);
  expect(find.byKey(const Key('change-confirmed')), findsOneWidget);
  await tapKey(t, 'change-close');
}

void main() {
  testWidgets('overview shows health, power and modules', (t) async {
    await onDevice(t, 'Overview');
    expect(find.byKey(const Key('health-status')), findsOneWidget);
    expect(find.text('Healthy'), findsOneWidget);
    expect(find.byKey(const Key('health-power')), findsOneWidget);
    expect(find.byKey(const Key('cap-dns')), findsOneWidget);
  });

  testWidgets('DNS: invalid domains are refused; a valid block goes through the change sheet', (t) async {
    final h = await onDevice(t, 'DNS firewall');
    expect(find.byKey(const Key('dns-total')), findsOneWidget);
    await enter(t, 'dns-add-field', 'not a domain;');
    await tapKey(t, 'dns-add-block');
    expect(find.byKey(const Key('block-not a domain;')), findsNothing);
    await enter(t, 'dns-add-field', 'Tracker.Example.COM');
    await tapKey(t, 'dns-add-block');
    expect(find.byKey(const Key('block-tracker.example.com')), findsOneWidget);
    await tapKey(t, 'dns-save');
    expect(find.textContaining('dns.block'), findsWidgets, reason: 'the diff is reviewed before applying');
    await applySheet(t);
    expect((h.device.config['dns'] as Map)['block'], ['tracker.example.com']);
    final cs = h.device.changes.values.single;
    expect(cs['status'], 'confirmed');
  });

  testWidgets('IoT Wi-Fi: the passphrase is sent as a secret, never in the change set', (t) async {
    final h = await onDevice(t, 'IoT Wi-Fi');
    await enter(t, 'ap-ssid', 'Home-IoT');
    await tapKey(t, 'ap-save');
    expect(find.byKey(const Key('ap-error')), findsOneWidget, reason: 'a passphrase is required the first time');
    await enter(t, 'ap-pass', 'correct horse battery');
    await tapKey(t, 'ap-save');
    await applySheet(t);
    expect(h.device.secretValues['ap_passphrase'], 'correct horse battery');
    final cs = h.device.changes.values.single;
    expect(jsonEncode(cs), isNot(contains('correct horse')));
    expect((cs['patch'] as Map)['ap.ssid'], 'Home-IoT');
    final setSecret = h.device.calls.indexWhere((c) => c.path == '/v1/secrets/ap_passphrase');
    final create = h.device.calls.indexWhere((c) => c.method == 'POST' && c.path == '/v1/changesets');
    expect(setSecret, lessThan(create), reason: 'secret first, so preflight sees it');
  });

  testWidgets('IoT Wi-Fi is explained, not offered, on hardware that cannot run it', (t) async {
    await onDevice(
      t,
      'IoT Wi-Fi',
      prep: (d) {
        (d.caps['modules'] as Map)['ap'] = {
          'available': false,
          'reasons': ['no_wifi_interface'],
          'notes': [],
          'options': [],
        };
      },
    );
    expect(find.byKey(const Key('reason-no_wifi_interface')), findsOneWidget);
    expect(find.byKey(const Key('ap-save')), findsNothing);
  });

  testWidgets('Firewall: rule dialog validates; rules are saved through a change set', (t) async {
    final h = await onDevice(t, 'Firewall');
    expect(find.textContaining('Management access'), findsOneWidget);
    await tapKey(t, 'fw-add');
    await enter(t, 'fw-name', 'bad;name');
    await tapKey(t, 'fw-ok');
    expect(find.byKey(const Key('fw-error')), findsOneWidget);
    await enter(t, 'fw-name', 'No IoT to NAS');
    await enter(t, 'fw-ports', '445, 139');
    await tapKey(t, 'fw-ok');
    expect(find.text('No IoT to NAS'), findsOneWidget);
    await tapKey(t, 'fw-save');
    await applySheet(t);
    final rules = (h.device.config['firewall'] as Map)['rules'] as List;
    expect(rules.single, {
      'name': 'No IoT to NAS',
      'from': 'iot',
      'to': 'lan',
      'proto': 'tcp',
      'ports': [445, 139],
      'action': 'drop',
      'log': false,
    });
  });

  testWidgets('MCP: approve a pending request; a new client token is shown once', (t) async {
    final h = await onDevice(
      t,
      'MCP',
      prep: (d) {
        d.actions.add({
          'id': 'act1',
          'status': 'pending',
          'tool': 'block_device',
          'principal': 'mcp:claude',
          'summary': 'block 198.51.100.150 for 60 min',
        });
      },
    );
    expect(find.text('block 198.51.100.150 for 60 min'), findsOneWidget);
    await tapKey(t, 'approve-act1');
    expect(h.device.actions.single['status'], 'executed');
    final call = h.device.calls.lastWhere((c) => c.path == '/v1/actions/act1/approve');
    expect(jsonDecode((call.body as Map)['payload'] as String), {'op': 'approve', 'action_id': 'act1'});
    expect(find.byKey(const Key('mcp-none')), findsOneWidget);

    await tapKey(t, 'mcp-add');
    await tapKey(t, 'mcp-tier-active');
    await tapKey(t, 'mcp-create');
    final token = t.widget<SelectableText>(find.byKey(const Key('mcp-token'))).data!;
    expect(token, startsWith('rpt_'));
    expect(h.device.mcpClients.single['capabilities'], containsAll(['read', 'active']));
  });

  testWidgets('Settings: add another phone shows a one-time code', (t) async {
    await onDevice(t, 'Settings');
    await tapKey(t, 'add-phone');
    expect(find.byKey(const Key('pair-qr')), findsOneWidget);
    final text = t.widget<SelectableText>(find.byKey(const Key('pair-code-text'))).data!;
    final code = jsonDecode(text) as Map;
    expect(code['secret'], kSecret);
    expect(code['cert'], kCert);
  });
}
