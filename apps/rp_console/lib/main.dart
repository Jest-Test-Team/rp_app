import 'dart:io';

import 'package:flutter/material.dart';

import 'app/app.dart';
import 'app/app_state.dart';
import 'app/services.dart';
import 'core/discovery/discovery.dart';
import 'core/storage/vault.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final services = Services(
    vault: Vault(PlatformSecureStore()),
    discoverer: MdnsDiscoverer(),
    desktop: Platform.isMacOS || Platform.isLinux || Platform.isWindows,
  );
  final state = AppState(services);
  await state.load();
  runApp(RpApp(state: state));
}
