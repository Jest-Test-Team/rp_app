import 'package:rp_console/core/hwkey/key_relay.dart';
import 'package:rp_console/demo/fake_key_relay.dart';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/fakes.dart';
import 'harness.dart';

Future<Harness> onDevice(WidgetTester t, String tab, {void Function(FakeDevice)? prep, FakeKeyRelay? keyRelay}) async {
  await t.binding.setSurfaceSize(const Size(900, 1600));
  addTearDown(() => t.binding.setSurfaceSize(null));
  final h = Harness(keyRelay: keyRelay);
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
    // The agent's real keys: load average, memory in kB (shown in MB).
    expect(find.text('0.21 · 0.18 · 0.15'), findsOneWidget);
    expect(find.text('610 / 922 MB'), findsOneWidget);
    expect(find.text('1 d 0 h'), findsOneWidget);
  });

  testWidgets('overview names alerts in plain words', (t) async {
    await onDevice(
      t,
      'Overview',
      prep: (d) => d.healthAlerts = [
        {'level': 'critical', 'kind': 'under_voltage', 'detail': 'use a 5V/2.5A supply'},
      ],
    );
    expect(find.text('Power supply too weak'), findsOneWidget);
    expect(find.text('use a 5V/2.5A supply'), findsOneWidget);
  });

  testWidgets('MCP: run a tool and read the result; a privileged tool only queues a request', (t) async {
    final h = await onDevice(t, 'MCP');
    await tapKey(t, 'tool-get_device_inventory');
    expect(find.byKey(const Key('tool-result')), findsOneWidget);
    expect(find.text('plug'), findsOneWidget);
    expect(find.text('2 devices'), findsOneWidget);
    await t.pageBack();
    await settle(t);

    await tapKey(t, 'tool-block_device');
    await tapKey(t, 'tool-run');
    expect(find.byKey(const Key('tool-error')), findsOneWidget); // IP is required
    await enter(t, 'arg-ip', '198.51.100.150');
    await enter(t, 'arg-ttl_minutes', '9999');
    await tapKey(t, 'tool-run');
    expect(find.byKey(const Key('tool-error')), findsOneWidget); // out of range
    expect(h.device.actions, isEmpty);
    await enter(t, 'arg-ttl_minutes', '30');
    await tapKey(t, 'tool-run');
    expect(find.text('Request created'), findsOneWidget);
    final run = h.device.calls.lastWhere((c) => c.path == '/v1/mcp/tools/block_device/run');
    expect(run.body, {'ip': '198.51.100.150', 'ttl_minutes': 30});
    expect(run.token, isNotNull);
    expect(h.device.actions.single['status'], 'pending');
    await t.pageBack();
    await settle(t);
    // The request waits in the queue for a signed approval.
    expect(find.byKey(Key('approve-${h.device.actions.single['id']}')), findsOneWidget);
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

  testWidgets('IoT Wi-Fi: use the least busy channel from the sentry board', (t) async {
    final h = await onDevice(t, 'IoT Wi-Fi');
    expect(find.byKey(const Key('ap-advice')), findsOneWidget);
    await tapKey(t, 'ap-advice-use');
    expect(find.byKey(const Key('ap-advice-use')), findsNothing, reason: 'channel 1 is now selected');
    await enter(t, 'ap-ssid', 'Home-IoT');
    await enter(t, 'ap-pass', 'correct horse battery');
    await tapKey(t, 'ap-save');
    await applySheet(t);
    expect((h.device.changes.values.single['patch'] as Map)['ap.channel'], 1);
  });

  testWidgets('IoT Wi-Fi: without a measurement, the app says how to get one', (t) async {
    await onDevice(t, 'IoT Wi-Fi', prep: (d) => d.channelAdvice = null);
    expect(find.byKey(const Key('ap-advice-none')), findsOneWidget);
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

  testWidgets('Firewall: rule dialog validates in words; rules are saved through a change set', (t) async {
    final h = await onDevice(t, 'Firewall');
    expect(find.textContaining('Management access'), findsOneWidget);
    await tapKey(t, 'fw-add');
    await enter(t, 'fw-name', 'bad;name');
    await tapKey(t, 'fw-ok');
    expect(find.byKey(const Key('fw-error')), findsOneWidget);
    await enter(t, 'fw-name', 'No IoT file sharing');
    await tapKey(t, 'fw-service');
    await tapKey(t, 'fw-service-files');
    await tapKey(t, 'fw-ok');
    expect(find.text('No IoT file sharing'), findsOneWidget);
    expect(find.text('Block · Smart-home Wi-Fi → Internet · File sharing (SMB 445, 139)'), findsOneWidget);
    await tapKey(t, 'fw-save');
    await applySheet(t);
    final rules = (h.device.config['firewall'] as Map)['rules'] as List;
    expect(rules.single, {
      'name': 'No IoT file sharing',
      'from': 'iot',
      'to': 'wan',
      'proto': 'tcp',
      'ports': [445, 139],
      'action': 'drop',
      'log': false,
    });
  });

  testWidgets('Firewall: home network to internet is explained, not saved', (t) async {
    await onDevice(t, 'Firewall');
    await tapKey(t, 'fw-add');
    await enter(t, 'fw-name', 'x');
    await tapKey(t, 'fw-from');
    await tapKey(t, 'fw-from-lan');
    await tapKey(t, 'fw-ok');
    expect(find.textContaining('goes through your router'), findsOneWidget);
  });

  testWidgets('Firewall: templates — pause a picked device, block Telnet', (t) async {
    final h = await onDevice(t, 'Firewall');
    expect(find.byKey(const Key('fw-tpl-vpn_nas')), findsNothing, reason: 'no VPN configured');
    await tapKey(t, 'fw-tpl-pause');
    await tapKey(t, 'fw-tpl-ok');
    expect(find.text('Pick a device'), findsWidgets, reason: 'a device is required');
    await tapKey(t, 'fw-pick-02:00:00:00:00:01');
    await tapKey(t, 'fw-tpl-ok');
    expect(find.text('Block · Smart-home Wi-Fi (plug) → Internet · Everything'), findsOneWidget);
    await tapKey(t, 'fw-tpl-telnet');
    await tapKey(t, 'fw-tpl-ok');
    await tapKey(t, 'fw-save');
    await applySheet(t);
    final rules = ((h.device.config['firewall'] as Map)['rules'] as List).cast<Map<String, Object?>>();
    expect(rules.map((r) => r['name']), ['Pause plug', 'No Telnet from smart devices']);
    expect(rules.first['src_mac'], ['02:00:00:00:00:01']);
    expect(rules.last['ports'], [23, 2323]);
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

  testWidgets('MCP: with a hardware key, approval waits for the press and reports a denial', (t) async {
    final h = await onDevice(
      t,
      'MCP',
      prep: (d) {
        d.approver = {'required': true, 'wait_seconds': 45, 'keys': 2, 'bypass_until': null};
        d.keyPress = 'deny';
        d.actions.add({
          'id': 'act2',
          'status': 'pending',
          'tool': 'block_device',
          'principal': 'mcp:claude',
          'summary': 'block 198.51.100.151 for 60 min',
        });
      },
    );
    expect(find.byKey(const Key('approver-banner')), findsOneWidget);
    await tapKey(t, 'approve-act2');
    expect(h.device.approveTimeout, const Duration(seconds: 65), reason: 'waits for the key, not 15 s');
    expect(h.device.actions.single['status'], 'denied', reason: 'a short press on the key denies');
    expect(find.byKey(const Key('approver-wait')), findsNothing, reason: 'the wait dialog closes');
    expect(find.byKey(const Key('mcp-none')), findsOneWidget);
  });

  testWidgets('MCP: approve with the key next to the user, relayed over Bluetooth', (t) async {
    final relay = FakeKeyRelay();
    final h = await onDevice(
      t,
      'MCP',
      keyRelay: relay,
      prep: (d) {
        d.approver = {'required': true, 'wait_seconds': 45, 'keys': 2};
        d.actions.add({'id': 'act5', 'status': 'pending', 'tool': 'block_device', 'principal': 'p', 'summary': 'x'});
      },
    );
    await tapKey(t, 'approve-act5');
    expect(relay.asked.single, startsWith('ASK act5 '), reason: 'the device challenge went to the key');
    expect(h.device.relayedApprovals, 1);
    expect(h.device.actions.single['status'], 'executed');
    final call = h.device.calls.lastWhere((c) => c.path == '/v1/actions/act5/approve');
    expect(jsonDecode((call.body as Map)['payload'] as String)['hwkey_decide'], startsWith('DECIDE act5 A '));
  });

  testWidgets('MCP: no key nearby falls back to the key plugged into the device', (t) async {
    final relay = FakeKeyRelay()..press = KeyRelayError.noKey;
    final h = await onDevice(
      t,
      'MCP',
      keyRelay: relay,
      prep: (d) {
        d.approver = {'required': true, 'wait_seconds': 45, 'keys': 2};
        d.keyPress = 'approve';
        d.actions.add({'id': 'act6', 'status': 'pending', 'tool': 'block_device', 'principal': 'p', 'summary': 'x'});
      },
    );
    await tapKey(t, 'approve-act6');
    expect(h.device.relayedApprovals, 0);
    expect(h.device.actions.single['status'], 'executed', reason: 'the device asked its own key');
  });

  testWidgets('MCP: nobody presses the hardware key, the request stays pending', (t) async {
    final h = await onDevice(
      t,
      'MCP',
      prep: (d) {
        d.approver = {'required': true, 'wait_seconds': 30, 'keys': 1};
        d.keyPress = null;
        d.actions.add({'id': 'act3', 'status': 'pending', 'tool': 'block_device', 'principal': 'p', 'summary': 'x'});
      },
    );
    await tapKey(t, 'approve-act3');
    expect(h.device.actions.single['status'], 'pending');
    expect(find.byKey(const Key('approver-wait')), findsNothing);
    expect(find.byKey(const Key('approve-act3')), findsOneWidget, reason: 'can be tried again');
  });

  testWidgets('Settings: ESP32 boards show status and errors, and switch profile signed', (t) async {
    final h = await onDevice(t, 'Settings');
    await tapKey(t, 'open-boards');
    expect(find.byKey(const Key('board-/dev/rp-approver')), findsOneWidget);
    expect(find.byKey(const Key('board-/dev/rp-approver-backup')), findsOneWidget);
    expect(find.byKey(const Key('board-errors-/dev/rp-approver-backup')), findsOneWidget);
    expect(find.textContaining('“main”'), findsOneWidget);
    // Default level: warnings and errors only.
    expect(find.textContaining('SysBrownOut'), findsWidgets);
    expect(find.text('running profile=approver firmware=0.2.0'), findsNothing);
    expect(find.text('I (27) boot: chip revision: v0.2'), findsNothing);
    await t.tap(find.text('All'));
    await settle(t);
    expect(find.text('I (27) boot: chip revision: v0.2'), findsOneWidget);

    await tapKey(t, 'board-switch-/dev/rp-approver');
    await tapKey(t, 'profile-sentry');
    expect(find.byKey(const Key('profile-confirm')), findsOneWidget, reason: 'leaving approver is confirmed');
    await tapKey(t, 'profile-confirm');
    expect(h.device.boards.first['profile'], 'sentry');
    final call = h.device.calls.lastWhere((c) => c.path == '/v1/boards/profile');
    expect(jsonDecode((call.body as Map)['payload'] as String),
        {'op': 'set_board_profile', 'port': '/dev/rp-approver', 'profile': 'sentry'});

    // A profile the board does not support is not offered.
    await tapKey(t, 'board-switch-/dev/rp-approver');
    expect(find.byKey(const Key('profile-oob')), findsNothing);
  });

  testWidgets('Settings: an older device without board support says to update', (t) async {
    await onDevice(t, 'Settings', prep: (d) => d.boardsSupported = false);
    await tapKey(t, 'open-boards');
    expect(find.byKey(const Key('boards-outdated')), findsOneWidget);
    expect(find.textContaining('no such endpoint'), findsNothing);
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

  testWidgets('Settings: check for updates, install a signed release, go back', (t) async {
    final h = await onDevice(t, 'Settings');
    expect(find.text('v0.2.0'), findsOneWidget);
    await tapKey(t, 'upd-check');
    await tapKey(t, 'upd-install');
    expect(find.text('Updated to v0.2.1.'), findsOneWidget);
    expect(h.device.live, 'v0.2.1');
    final call = h.device.calls.lastWhere((c) => c.path == '/v1/update' && c.method == 'POST');
    expect(jsonDecode((call.body as Map)['payload'] as String), {'op': 'install_update', 'tag': 'v0.2.1'});
    await tapKey(t, 'upd-rollback');
    expect(h.device.live, 'v0.2.0');
  });

  testWidgets('Settings: a device without a signing key is explained, no install offered', (t) async {
    await onDevice(t, 'Settings', prep: (d) => d.signingKey = false);
    expect(find.byKey(const Key('upd-nokey')), findsOneWidget);
    await tapKey(t, 'upd-check');
    expect(find.byKey(const Key('upd-install')), findsNothing);
  });

  testWidgets('Settings: removal needs the device name typed, then forgets the device', (t) async {
    final h = await onDevice(t, 'Settings');
    await tapKey(t, 'uninstall');
    expect(t.widget<FilledButton>(find.byKey(const Key('uninstall-go'))).onPressed, isNull);
    await enter(t, 'uninstall-confirm', 'rp-demo');
    await tapKey(t, 'uninstall-go');
    expect(h.device.uninstalled, isTrue);
    expect(await h.services.vault.devices(), isEmpty);
  });
}
