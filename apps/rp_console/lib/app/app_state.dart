import 'package:flutter/foundation.dart';

import '../core/api/client.dart';
import '../core/storage/vault.dart';
import 'services.dart';

class AppState extends ChangeNotifier {
  AppState(this.services);

  final Services services;
  List<PairedDevice> devices = [];
  bool loaded = false;
  final Map<String, RpClient> _clients = {};

  Future<void> load() async {
    devices = await services.vault.devices();
    loaded = true;
    notifyListeners();
  }

  Future<RpClient> client(PairedDevice d) async => _clients[d.deviceId] ??= await services.clientFor(d);

  Future<void> add(PairedDevice d) async {
    await services.vault.saveDevice(d);
    _clients.remove(d.deviceId);
    await load();
  }

  Future<void> forget(PairedDevice d) async {
    await services.vault.removeDevice(d.deviceId);
    _clients.remove(d.deviceId);
    await load();
  }
}
