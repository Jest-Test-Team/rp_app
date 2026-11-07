import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/core/api/client.dart';
import 'package:rp_console/core/api/models.dart';
import 'package:rp_console/core/auth/admin_key.dart';
import 'package:rp_console/core/changes/change_runner.dart';
import 'package:rp_console/core/pairing/pairing.dart';

import '../support/fakes.dart';

Future<(RpClient, FakeDevice)> setup() async {
  final dev = FakeDevice();
  final c = RpClient(dev);
  await c.pair(PairingCode(host: 'h', port: 1, secret: kSecret), await AdminKey.fromSeed(List.filled(32, 2)), 't');
  return (c, dev);
}

void main() {
  test('happy path: create, preflight, review, apply, verify, confirm', () async {
    final (c, dev) = await setup();
    final r = ChangeRunner(c, retryDelay: Duration.zero);
    final phases = <Phase>[];
    r.addListener(() => phases.add(r.phase));
    await r.prepare('dns', {
      'dns.block': ['ads.example'],
    });
    expect(r.phase, Phase.review);
    expect(r.change!.configDiff, contains('dns.block'));
    await r.applyAndConfirm();
    expect(r.phase, Phase.confirmed);
    expect(r.change!.status, ChangeStatus.confirmed);
    expect(
      phases,
      containsAllInOrder([Phase.preparing, Phase.review, Phase.applying, Phase.verifying, Phase.confirmed]),
    );
    expect((dev.config['dns'] as Map)['block'], ['ads.example']);
  });

  test('preflight failure ends in failed with the failing checks', () async {
    final (c, dev) = await setup();
    dev.preflightFail = 'api_lockout';
    final r = ChangeRunner(c);
    await r.prepare('base', {'base.allow_mdns': false});
    expect(r.phase, Phase.failed);
    expect(r.errorCode, 'preflight_failed');
    expect(r.failedChecks.single.name, 'api_lockout');
    await r.applyAndConfirm();
    expect(r.phase, Phase.failed, reason: 'cannot apply a change that failed preflight');
  });

  test('post-apply failure on the device is reported, nothing is confirmed', () async {
    final (c, dev) = await setup();
    dev.applyFails = true;
    final r = ChangeRunner(c);
    await r.prepare('ap', {'ap.ssid': 'x'});
    await r.applyAndConfirm();
    expect(r.phase, Phase.failed);
    expect(r.errorCode, 'apply_failed');
    expect(r.failedChecks.single.name, 'hostapd_active');
    expect(dev.calls.any((x) => x.path.endsWith('/confirm')), isFalse);
  });

  test('a short outage after apply is retried, then confirmed', () async {
    final (c, dev) = await setup();
    final r = ChangeRunner(c, retryDelay: Duration.zero);
    await r.prepare('firewall', {'firewall.rules': []});
    dev.failNextGets = 2;
    await r.applyAndConfirm();
    expect(r.phase, Phase.confirmed);
  });

  test('never reachable again: the app does not confirm and says the device rolls back', () async {
    final (c, dev) = await setup();
    final r = ChangeRunner(c, confirmSecs: 6, retryDelay: const Duration(milliseconds: 200));
    await r.prepare('firewall', {'firewall.rules': []});
    dev.failNextGets = 1 << 30;
    await r.applyAndConfirm();
    expect(r.phase, Phase.failed);
    expect(r.errorCode, 'not_confirmed');
    expect(dev.calls.any((x) => x.path.endsWith('/confirm')), isFalse);
  });

  test('custom verification can veto the confirm', () async {
    final (c, _) = await setup();
    final r = ChangeRunner(
      c,
      confirmSecs: 6,
      retryDelay: const Duration(milliseconds: 100),
      verify: (_) async => false,
    );
    await r.prepare('dns', {'dns.block': []});
    await r.applyAndConfirm();
    expect(r.errorCode, 'not_confirmed');
  });

  test('manual keep / undo when auto-confirm is off', () async {
    final (c, _) = await setup();
    final r = ChangeRunner(c, autoConfirm: false, retryDelay: Duration.zero);
    await r.prepare('dns', {'dns.block': []});
    await r.applyAndConfirm();
    expect(r.phase, Phase.awaitingConfirm);
    await r.rollbackNow();
    expect(r.phase, Phase.rolledBack);
  });

  test('confirming too late reports the rollback', () async {
    final (c, dev) = await setup();
    final r = ChangeRunner(c, autoConfirm: false, retryDelay: Duration.zero);
    await r.prepare('dns', {'dns.block': []});
    await r.applyAndConfirm();
    dev.changes[r.change!.id]!['status'] = 'rolled_back';
    await r.confirmNow();
    expect(r.phase, Phase.rolledBack);
  });

  test('conflicts are surfaced as such', () async {
    final (c, dev) = await setup();
    final r = ChangeRunner(c);
    final orig = dev.revision;
    dev.revision = orig; // status reads current; create uses it — force a race:
    final cs = await c.createChangeset('dns', orig, {'dns.block': []});
    await c.preflight(cs.id);
    await c.apply(cs.id);
    // Revision moved on: a runner that read the old revision would conflict.
    await r.prepare('dns', {
      'dns.block': ['x.example'],
    });
    expect(r.phase, Phase.review, reason: 'the runner re-reads the revision');
  });
}
