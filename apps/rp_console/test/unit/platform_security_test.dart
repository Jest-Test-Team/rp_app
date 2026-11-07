// Static checks on the app's source and platform configuration.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String read(String p) => File(p).readAsStringSync();

Iterable<File> dartFiles() =>
    Directory('lib').listSync(recursive: true).whereType<File>().where((f) => f.path.endsWith('.dart'));

void main() {
  test('TLS: no CA is trusted and the certificate callback enforces the pin', () {
    final t = read('lib/core/api/transport.dart');
    expect(t, contains('SecurityContext(withTrustedRoots: false)'));
    expect(t, contains("findProxy = (_) => 'DIRECT'"));
    for (final f in dartFiles()) {
      final s = f.readAsStringSync();
      expect(RegExp(r'badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true').hasMatch(s), isFalse, reason: f.path);
      if (f.path != 'lib/core/api/transport.dart' && f.path != 'lib/app/release.dart') {
        expect(s.contains('HttpClient('), isFalse, reason: '${f.path}: device traffic must use PinnedTransport');
      }
    }
  });

  test('secrets are never logged or written to plain files', () {
    for (final f in dartFiles()) {
      final s = f.readAsStringSync();
      expect(RegExp(r'\b(print|debugPrint)\(').hasMatch(s), isFalse, reason: '${f.path}: no logging in the app');
      expect(s.contains('SharedPreferences'), isFalse, reason: f.path);
    }
    final vault = read('lib/core/storage/vault.dart');
    expect(vault, contains('unlocked_this_device'));
    expect(vault, contains('migrateWithBackup: false'));
  });

  test('Android: no cleartext, no backups, multicast permission', () {
    final m = read('android/app/src/main/AndroidManifest.xml');
    expect(m, contains('android:usesCleartextTraffic="false"'));
    expect(m, contains('android:allowBackup="false"'));
    expect(m, contains('android.permission.INTERNET'));
    expect(m, contains('CHANGE_WIFI_MULTICAST_STATE'));
    expect(read('android/app/src/main/res/xml/data_extraction_rules.xml'), contains('<cloud-backup>'));
  });

  test('iOS / macOS: local network purpose, Bonjour type, network entitlements', () {
    final p = read('ios/Runner/Info.plist');
    expect(p, contains('NSLocalNetworkUsageDescription'));
    expect(p, contains('<string>_rp-security._tcp</string>'));
    for (final e in ['macos/Runner/DebugProfile.entitlements', 'macos/Runner/Release.entitlements']) {
      final s = read(e);
      expect(s, contains('com.apple.security.network.client'), reason: e);
      expect(s, contains('com.apple.security.app-sandbox'), reason: e);
    }
  });

  test('the mDNS type matches what the device advertises', () {
    final rust = read('../../crates/rp-core/src/api.rs');
    expect(rust, contains('pub const MDNS_TYPE: &str = "_rp-security._tcp";'));
    expect(read('lib/core/discovery/discovery.dart'), contains("'_rp-security._tcp.local'"));
  });
}
