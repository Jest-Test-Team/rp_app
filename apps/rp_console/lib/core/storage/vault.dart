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
    this.vpnHosts = const [],
    this.profile = '',
  });

  final String deviceId;
  final String name;
  final String host;
  final int port;
  final String certSha256;
  final String adminId;
  final int addedAt;

  /// The device's VPN addresses (Tailscale name and IPs, WireGuard address),
  /// learned from the device; used away from home or with an exit node.
  final List<String> vpnHosts;

  /// '' for the device as paired; 'tailscale' / 'wireguard' for a profile of
  /// the same device that always connects through that VPN ([host] is then
  /// the device's VPN address). Same key, same pinned certificate.
  final String profile;

  /// Unique per entry (a device and its VPN profiles share [deviceId]).
  String get key => profile.isEmpty ? deviceId : '$deviceId#$profile';

  Map<String, Object> toJson() => {
    'device_id': deviceId,
    'name': name,
    'host': host,
    'port': port,
    'cert_sha256': certSha256,
    'admin_id': adminId,
    'added_at': addedAt,
    if (vpnHosts.isNotEmpty) 'vpn_hosts': vpnHosts,
    if (profile.isNotEmpty) 'profile': profile,
  };

  static PairedDevice fromJson(Map<String, Object?> j) => PairedDevice(
    deviceId: j['device_id'] as String,
    name: j['name'] as String,
    host: j['host'] as String,
    port: j['port'] as int,
    certSha256: j['cert_sha256'] as String,
    adminId: j['admin_id'] as String,
    addedAt: j['added_at'] as int,
    vpnHosts: j['vpn_hosts'] is List ? (j['vpn_hosts'] as List).whereType<String>().toList() : const [],
    profile: j['profile'] is String ? j['profile'] as String : '',
  );

  PairedDevice copyWith({String? name, String? host, int? port, List<String>? vpnHosts, String? profile}) =>
      PairedDevice(
        deviceId: deviceId,
        name: name ?? this.name,
        host: host ?? this.host,
        port: port ?? this.port,
        certSha256: certSha256,
        adminId: adminId,
        addedAt: addedAt,
        vpnHosts: vpnHosts ?? this.vpnHosts,
        profile: profile ?? this.profile,
      );
}

class Vault {
  Vault(this.store);

  final SecureStore store;
  static const _keyName = 'rp.admin_key.v1';
  static const _devicesName = 'rp.devices.v1';
  static const _prefsName = 'rp.prefs.v1';
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
    final all = (await devices()).where((x) => x.key != d.key).toList()..add(d);
    await store.write(_devicesName, jsonEncode([for (final x in all) x.toJson()]));
  }

  /// Remove one entry by [PairedDevice.key] (a device id removes the device
  /// as paired, not its VPN profiles).
  Future<void> removeDevice(String key) async {
    final all = (await devices()).where((x) => x.key != key).toList();
    await store.write(_devicesName, jsonEncode([for (final x in all) x.toJson()]));
  }

  /// App preferences (language, prompts already shown). Not secret, but kept
  /// with the rest of the app's state.
  Future<Map<String, Object?>> prefs() async {
    final t = await store.read(_prefsName);
    final v = t == null ? null : jsonDecode(t);
    return v is Map ? v.cast<String, Object?>() : {};
  }

  Future<void> setPref(String key, Object? value) async {
    final p = await prefs();
    if (value == null) {
      p.remove(key);
    } else {
      p[key] = value;
    }
    await store.write(_prefsName, jsonEncode(p));
  }

  /// Forget everything (sign-out of the app).
  Future<void> wipe() async {
    _cached = null;
    await store.delete(_keyName);
    await store.delete(_devicesName);
    await store.delete(_prefsName);
  }
}
