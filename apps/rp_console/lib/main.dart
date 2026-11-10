import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'app/app.dart';
import 'app/app_state.dart';
import 'app/release.dart';
import 'app/services.dart';
import 'core/discovery/discovery.dart';
import 'core/storage/vault.dart';
import 'core/vpn/vpn_platform.dart';
import 'demo/demo_device.dart';
import 'features/onboarding/qr_scanner.dart';

/// Demo mode: a simulated device inside the app, nothing stored, no network.
/// Always on in a browser (which cannot pin certificates, use mDNS or SSH);
/// elsewhere with `--dart-define=RP_DEMO=true`.
const demoFlag = bool.fromEnvironment('RP_DEMO');

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final demo = kIsWeb || demoFlag;
  final Services services;
  if (demo) {
    final device = FakeDevice();
    services = Services(
      vault: Vault(MemoryStore()),
      discoverer: StaticDiscoverer([
        Found(name: 'RP Security on rp-demo (simulated)', host: 'rp-demo.local', port: 8443),
      ]),
      transport: (h, p, pin) => device,
      release: () async => ReleaseInfo('v0.2.0', 'a' * 64),
      latest: () async => 'v0.2.1',
      demoPairingCode: '{"v":1,"host":"rp-demo.local","port":8443,"secret":"$kSecret"}',
    );
  } else {
    services = Services(
      vault: Vault(PlatformSecureStore()),
      discoverer: MdnsDiscoverer(),
      desktop: Platform.isMacOS || Platform.isLinux || Platform.isWindows,
      scanQr: Platform.isAndroid || Platform.isIOS ? scanPairingQr : null,
      vpn: Platform.isAndroid ? AndroidVpnPlatform() : null,
    );
  }
  final state = AppState(services);
  await state.load();
  runApp(RpApp(state: state));
}
