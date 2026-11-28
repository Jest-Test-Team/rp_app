// KeyRelay over Bluetooth LE (firmware/approver-s3, src/bin/ble.rs): one
// GATT service; the app writes line chunks to rx, the key notifies chunks on
// tx; lines end with "\n".

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:universal_ble/universal_ble.dart';

import 'key_relay.dart';

const _service = '5270b001-7270-4b65-7900-000000000000';
const _rx = '5270b001-7270-4b65-7900-000000000001';
const _tx = '5270b001-7270-4b65-7900-000000000002';
const _chunk = 20;

class BleKeyRelay implements KeyRelay {
  BleKeyRelay({this.scanTime = const Duration(seconds: 8)});
  final Duration scanTime;

  Future<String> _find() async {
    final state = await UniversalBle.getBluetoothAvailabilityState();
    if (state != AvailabilityState.poweredOn) {
      throw KeyRelayException(KeyRelayError.unavailable, '$state');
    }
    await UniversalBle.requestPermissions();
    final found = Completer<String>();
    final sub = UniversalBle.scanStream.listen((d) {
      final name = d.name ?? '';
      if (name.startsWith('rp-key-') && !found.isCompleted) found.complete(d.deviceId);
    });
    try {
      await UniversalBle.startScan();
      return await found.future.timeout(scanTime, onTimeout: () => throw const KeyRelayException(KeyRelayError.noKey));
    } finally {
      await sub.cancel();
      await UniversalBle.stopScan();
    }
  }

  @override
  Future<String> sign(String ask, {Duration timeout = const Duration(minutes: 2)}) async {
    final id = await _find();
    await UniversalBle.connect(id, timeout: const Duration(seconds: 15));
    final lines = StreamController<String>();
    final buf = <int>[];
    StreamSubscription<Uint8List>? sub;
    try {
      await UniversalBle.discoverServices(id);
      sub = UniversalBle.characteristicValueStream(id, _tx, serviceId: _service).listen((data) {
        for (final b in data) {
          if (b == 10) {
            lines.add(utf8.decode(buf, allowMalformed: true).trim());
            buf.clear();
          } else if (buf.length < 300) {
            buf.add(b);
          }
        }
      });
      await UniversalBle.subscribeNotifications(id, _service, _tx);
      final bytes = utf8.encode('$ask\n');
      for (var i = 0; i < bytes.length; i += _chunk) {
        final end = i + _chunk < bytes.length ? i + _chunk : bytes.length;
        await UniversalBle.write(id, _service, _rx, Uint8List.fromList(bytes.sublist(i, end)));
      }
      await for (final l in lines.stream.timeout(timeout)) {
        if (l.startsWith('DECIDE ')) return l;
        if (l.startsWith('TIMEOUT')) throw const KeyRelayException(KeyRelayError.timeout);
        if (l.startsWith('ERR ')) throw KeyRelayException(KeyRelayError.refused, l.substring(4));
      }
      throw const KeyRelayException(KeyRelayError.timeout);
    } on TimeoutException {
      throw const KeyRelayException(KeyRelayError.timeout);
    } finally {
      await sub?.cancel();
      await lines.close();
      try {
        await UniversalBle.disconnect(id);
      } catch (_) {}
    }
  }
}
