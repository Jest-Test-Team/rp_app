import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/core/storage/vault.dart';

PairedDevice dev(String id) => PairedDevice(
  deviceId: id,
  name: 'n',
  host: '192.0.2.10',
  port: 8443,
  certSha256: 'ab' * 32,
  adminId: 'a' * 16,
  addedAt: 1,
);

void main() {
  test('one admin key per installation, persisted in the secure store only', () async {
    final store = MemoryStore();
    final a = await Vault(store).adminKey();
    final b = await Vault(store).adminKey();
    expect(b.publicKeyB64, a.publicKeyB64, reason: 'reloaded, not regenerated');
    expect(store.data.keys, ['rp.admin_key.v1']);
    expect(store.data['rp.admin_key.v1'], matches(RegExp(r'^[0-9a-f]{64}$')));
  });

  test('devices are saved, replaced by id, removed, and wiped', () async {
    final v = Vault(MemoryStore());
    await v.saveDevice(dev('1'));
    await v.saveDevice(dev('2'));
    await v.saveDevice(dev('1').copyWith(name: 'renamed'));
    final all = await v.devices();
    expect(all.map((d) => d.deviceId), ['2', '1']);
    expect(all.last.name, 'renamed');
    expect(all.last.certSha256, 'ab' * 32, reason: 'the pin survives a rename');
    await v.removeDevice('2');
    expect((await v.devices()).single.deviceId, '1');
    final k1 = (await v.adminKey()).publicKeyB64;
    await v.wipe();
    expect(await v.devices(), isEmpty);
    expect((await v.adminKey()).publicKeyB64, isNot(k1));
  });
}
