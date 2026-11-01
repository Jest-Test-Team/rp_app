// The real Dart client against the real API: `rp-api --fake` (rp-privd's
// logic on a simulated device) over TLS. Started by
// test/suites/82_app_contract.robot, which passes:
//   RP_FAKE_API=127.0.0.1:PORT  RP_FAKE_PIN=<cert sha256>  RP_FAKE_SECRET=<pairing secret>
// Skipped when those are not set.
@Timeout(Duration(minutes: 3))
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/core/api/client.dart';
import 'package:rp_console/core/api/models.dart';
import 'package:rp_console/core/api/transport.dart';
import 'package:rp_console/core/auth/admin_key.dart';
import 'package:rp_console/core/changes/change_runner.dart';
import 'package:rp_console/core/pairing/pairing.dart';
import 'package:rp_console/features/vpn/vpn_page.dart';

void main() {
  final env = Platform.environment;
  final addr = env['RP_FAKE_API'];
  final pin = env['RP_FAKE_PIN'];
  final secret = env['RP_FAKE_SECRET'];
  final skip = addr == null || pin == null || secret == null
      ? 'RP_FAKE_API / RP_FAKE_PIN / RP_FAKE_SECRET not set'
      : null;
  final host = addr?.split(':').first ?? '';
  final port = int.tryParse(addr?.split(':').last ?? '') ?? 0;

  late RpClient client;
  late AdminKey key;
  PinnedTransport pinned() => PinnedTransport(host: host, port: port, pin: pin);

  Future<Map<String, Object?>> fake(String path, Map<String, Object?> body) async =>
      asMap(await pinned().request('POST', path, body: body));

  group('contract', skip: skip, () {
    test('a wrong pin is refused at the TLS layer', () async {
      final t = PinnedTransport(host: host, port: port, pin: '00' * 32);
      await expectLater(t.request('GET', '/v1/info'), throwsA(anyOf(isA<PinMismatch>(), isA<HandshakeException>())));
      expect(t.seenCert, pin, reason: 'it saw the real certificate and still refused');
    });

    test('pairing proves both sides over the real certificate', () async {
      key = await AdminKey.fromSeed(List.filled(32, 42));
      final t = PinnedTransport(host: host, port: port); // no pin yet: pairing proves it
      final c = RpClient(t);
      final r = await c.pair(PairingCode(host: host, port: port, secret: secret!), key, 'contract-test');
      expect(r.certSha256, pin);
      expect(t.seenCert, pin);
      client = RpClient(pinned(), key: key, deviceId: r.deviceId);
      await expectLater(
        c.pair(PairingCode(host: host, port: port, secret: secret), key, 'again'),
        throwsA(isA<ApiException>().having((e) => e.code, 'code', 'pairing_closed')),
      );
    });

    test('the served OpenAPI document is the committed one', () async {
      final served = (await client.openapi())['paths'] as Map;
      final committed = (jsonDecode(File('api/openapi.json').readAsStringSync()) as Map)['paths'] as Map;
      expect(served.keys.toSet(), committed.keys.toSet());
    });

    test('every read endpoint answers through a signed session', () async {
      expect((await client.me())['name'], 'contract-test');
      final caps = await client.capabilities();
      expect(caps.module('ap').available, isTrue);
      expect(caps.model, contains('simulated'));
      final st = await client.status();
      expect(st.revision, greaterThan(0));
      for (final f in <Future<Object?> Function()>[
        client.modules,
        client.config,
        () => client.moduleConfig('dns'),
        client.changesets,
        client.admins,
        client.pendingActions,
        client.mcpTools,
        client.mcpClients,
        client.health,
        client.inventory,
        client.apClients,
        client.vpnStatus,
        () => client.dnsEvents(limit: 5),
        client.dnsStats,
        client.flows,
        client.firewallRules,
        client.auditEvents,
      ]) {
        expect(await f(), isNotNull);
      }
      expect((await client.apClients())['clients'], hasLength(2));
    });

    test('DNS change: review, apply, verify, confirm', () async {
      final r = ChangeRunner(client, retryDelay: const Duration(milliseconds: 200));
      await r.prepare('dns', {
        'dns.block': ['tracker.example'],
        'dns.block_suspicious': true,
      });
      expect(r.phase, Phase.review, reason: '${r.error} ${r.failedChecks.map((c) => c.name)}');
      expect(r.change!.configDiff, contains('tracker.example'));
      await r.applyAndConfirm();
      expect(r.phase, Phase.confirmed, reason: r.error);
      final dns = asMap(asMap((await client.moduleConfig('dns'))['config'])['dns']);
      expect(dns['block'], ['tracker.example']);
      expect(dns['block_suspicious'], true);
    });

    test('IoT AP: secret first, then the change; the secret never comes back', () async {
      final set = await client.setSecret('ap_passphrase', 'contract horse battery');
      expect(jsonEncode(set), isNot(contains('horse')));
      final r = ChangeRunner(client, retryDelay: const Duration(milliseconds: 200));
      await r.prepare('ap', {'ap.ssid': 'Contract-IoT', 'ap.block_dot': true});
      await r.applyAndConfirm();
      expect(r.phase, Phase.confirmed, reason: '${r.error} ${r.failedChecks.map((c) => c.detail)}');
      expect((await client.status()).secretSet('ap_passphrase'), isTrue);
      final all = jsonEncode([
        await client.config(),
        (await client.changesets()).map((c) => c.raw).toList(),
        await client.auditEvents(),
      ]);
      expect(all, isNot(contains('contract horse')));
    });

    test('firewall rules go through as typed tables', () async {
      final r = ChangeRunner(client, retryDelay: const Duration(milliseconds: 200));
      await r.prepare('firewall', {
        'firewall.rules': [
          {
            'name': 'No IoT to NAS',
            'from': 'iot',
            'to': 'lan',
            'proto': 'tcp',
            'ports': [445],
            'action': 'drop',
            'log': true,
          },
        ],
      });
      expect(r.change!.files.any((f) => '${f['diff']}'.contains('tcp dport { 445 } drop')), isTrue);
      await r.applyAndConfirm();
      expect(r.phase, Phase.confirmed, reason: r.error);
      expect(((await client.firewallRules())['rules'] as List).single['name'], 'No IoT to NAS');
    });

    test('a lockout rule is refused by the device', () async {
      final r = ChangeRunner(client);
      await r.prepare('firewall', {
        'firewall.rules': [
          {
            'name': 'oops',
            'from': 'lan',
            'to': 'device',
            'proto': 'tcp',
            'ports': [8443],
            'action': 'drop',
          },
        ],
      });
      expect(r.phase, Phase.failed);
      expect(r.errorCode, 'invalid');
    });

    test('an unconfirmed change is rolled back by the device', () async {
      final st = await client.status();
      final cs = await client.createChangeset('dns', st.revision, {
        'dns.block': ['will-be-undone.example'],
      });
      await client.preflight(cs.id);
      final applied = await client.apply(cs.id, confirmSecs: 30);
      expect(applied.status, ChangeStatus.awaitingConfirm);
      final clock = await fake('/_fake/clock', {'advance_secs': 31});
      expect(clock['expired'], [cs.id]);
      expect((await client.changeset(cs.id)).status, ChangeStatus.rolledBack);
      await expectLater(client.confirm(cs.id), throwsA(isA<ApiException>().having((e) => e.code, 'code', 'state')));
      final dns = asMap(asMap((await client.moduleConfig('dns'))['config'])['dns']);
      expect(dns['block'], ['tracker.example'], reason: 'back to the confirmed state');
    });

    test('stale revisions conflict', () async {
      await expectLater(
        client.createChangeset('dns', 1, {'dns.block': []}),
        throwsA(isA<ApiException>().having((e) => e.isConflict, 'conflict', isTrue)),
      );
    });

    test('approving an MCP request runs it on the device', () async {
      final a = await fake('/_fake/actions', {
        'tool': 'block_device',
        'args': {'ip': '198.51.100.150', 'ttl_minutes': 30},
      });
      final id = a['id'] as String;
      final pending = asList((await client.pendingActions())['actions']).map(asMap).toList();
      expect(pending.single['status'], 'pending');
      final done = await client.approve(id);
      expect(done['status'], 'executed');
      final cmds = asList(asMap(await pinned().request('GET', '/_fake/commands'))['commands']);
      expect(cmds.any((c) => '$c'.contains('nft add element inet rp ap_quarantine4')), isTrue);
    });

    test('MCP clients: token once, listed by name, removable', () async {
      final r = await client.mcpAddClient('contract', ['read']);
      final token = r['token'] as String;
      final list = await client.mcpClients();
      expect(jsonEncode(list), isNot(contains(token)));
      await expectLater(pinned().request('GET', '/v1/status', token: token), throwsA(isA<ApiException>()));
      await client.mcpRemoveClient('contract');
    });

    test('a replayed or tampered envelope is refused', () async {
      final e = await key.sign(client.deviceId!, {'op': 'session'});
      await pinned().request('POST', '/v1/session', body: e.toJson());
      await expectLater(
        pinned().request('POST', '/v1/session', body: e.toJson()),
        throwsA(isA<ApiException>().having((x) => x.status, 'status', 401)),
      );
      final t = (await key.sign(client.deviceId!, {'op': 'session'})).toJson()..['payload'] = '{"op":"session","x":1}';
      await expectLater(
        pinned().request('POST', '/v1/session', body: t),
        throwsA(isA<ApiException>().having((x) => x.status, 'status', 401)),
      );
    });

    test('WireGuard peers: public key to the device, config built locally', () async {
      final st = await client.status();
      final keys = await WgKeys.generate();
      final cs = await client.createChangeset('vpn', st.revision, {
        'vpn.mode': 'wireguard',
        'vpn.wireguard.peers': [
          {'name': 'phone', 'public_key': keys.publicB64, 'host': 2},
        ],
      });
      expect(jsonEncode(cs.raw), isNot(contains(keys.privateB64)));
      expect(cs.configDiff, contains(keys.publicB64));
    });

    test('a second app pairs; revoking the first locks it out', () async {
      final open = await client.openPairing(validMinutes: 5);
      final second = await AdminKey.fromSeed(List.filled(32, 43));
      final c2 = RpClient(PinnedTransport(host: host, port: port, pin: pin));
      await c2.pair(
        PairingCode(
          host: host,
          port: port,
          secret: open['secret'] as String,
          device: open['device_id'] as String,
          cert: pin,
        ),
        second,
        'second-app',
      );
      expect(await c2.admins(), hasLength(2));
      await c2.revokeAdmin(key.adminId);
      final fresh = RpClient(pinned(), key: key, deviceId: client.deviceId);
      await expectLater(fresh.status(), throwsA(isA<ApiException>().having((e) => e.status, 'status', 401)));
    });
  });
}
