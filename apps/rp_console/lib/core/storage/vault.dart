// Where the app keeps its admin key and the devices it has paired with.
//
// Everything goes into the platform keystore (iOS/macOS Keychain, this device
// only, after unlock; Android Keystore-backed storage; libsecret; Windows
// Credential Manager). Nothing is written to plain files or app backups.

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../auth/admin_key.dart';

abstract class SecureStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

class PlatformSecureStore implements SecureStore {
  PlatformSecureStore()
    : _s = const FlutterSecureStorage(
        iOptions: IOSOptions(accessibility: KeychainAccessibility.unlocked_this_device),
        mOptions: MacOsOptions(accessibility: KeychainAccessibility.unlocked_this_device),
        aOptions: AndroidOptions(migrateWithBackup: false),
      );

  final FlutterSecureStorage _s;

  @override
  Future<String?> read(String key) => _s.read(key: key);
  @override
  Future<void> write(String key, String value) => _s.write(key: key, value: value);
  @override
  Future<void> delete(String key) => _s.delete(key: key);
}

/// For tests and the demo mode.
class MemoryStore implements SecureStore {
  final Map<String, String> data = {};
  @override
  Future<String?> read(String key) async => data[key];
  @override
  Future<void> write(String key, String value) async => data[key] = value;
  @override
  Future<void> delete(String key) async => data.remove(key);
}

class PairedDevice {
  PairedDevice({
    required this.deviceId,
    required this.name,
    required this.host,
    required this.port,
    required this.certSha256,
    required this.adminId,
    required this.addedAt,
  });

  final String deviceId;
  final String name;
  final String host;
  final int port;
  final String certSha256;
  final String adminId;
  final int addedAt;

  Map<String, Object> toJson() => {
    'device_id': deviceId,
    'name': name,
    'host': host,
    'port': port,
    'cert_sha256': certSha256,
    'admin_id': adminId,
    'added_at': addedAt,
  };

  static PairedDevice fromJson(Map<String, Object?> j) => PairedDevice(
    deviceId: j['device_id'] as String,
    name: j['name'] as String,
    host: j['host'] as String,
    port: j['port'] as int,
    certSha256: j['cert_sha256'] as String,
    adminId: j['admin_id'] as String,
    addedAt: j['added_at'] as int,
  );

  PairedDevice copyWith({String? name, String? host, int? port}) => PairedDevice(
    deviceId: deviceId,
    name: name ?? this.name,
    host: host ?? this.host,
    port: port ?? this.port,
    certSha256: certSha256,
    adminId: adminId,
    addedAt: addedAt,
  );
}

class Vault {
  Vault(this.store);

  final SecureStore store;
  static const _keyName = 'rp.admin_key.v1';
  static const _devicesName = 'rp.devices.v1';
  AdminKey? _cached;

  /// The installation's admin key, created on first use.
  Future<AdminKey> adminKey() async {
    final c = _cached;
    if (c != null) return c;
    final stored = await store.read(_keyName);
    if (stored != null) return _cached = await AdminKey.fromSeed(hexDecode(stored));
    final (key, seed) = await AdminKey.generate();
    await store.write(_keyName, hexOf(seed));
    return _cached = key;
  }

  Future<List<PairedDevice>> devices() async {
    final t = await store.read(_devicesName);
    if (t == null) return [];
    final v = jsonDecode(t);
    if (v is! List) return [];
    return [
      for (final d in v)
        if (d is Map) PairedDevice.fromJson(d.cast<String, Object?>()),
    ];
  }

  Future<void> saveDevice(PairedDevice d) async {
    final all = (await devices()).where((x) => x.deviceId != d.deviceId).toList()..add(d);
    await store.write(_devicesName, jsonEncode([for (final x in all) x.toJson()]));
  }

  Future<void> removeDevice(String deviceId) async {
    final all = (await devices()).where((x) => x.deviceId != deviceId).toList();
    await store.write(_devicesName, jsonEncode([for (final x in all) x.toJson()]));
  }

  /// Forget everything (sign-out of the app).
  Future<void> wipe() async {
    _cached = null;
    await store.delete(_keyName);
    await store.delete(_devicesName);
  }
}
