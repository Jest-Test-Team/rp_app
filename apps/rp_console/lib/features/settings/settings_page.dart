import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../app/app_state.dart';
import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/storage/vault.dart';
import '../../widgets/common.dart';

class SettingsPage extends StatelessWidget {
  const SettingsPage({super.key, required this.app, required this.device, required this.client});
  final AppState app;
  final PairedDevice device;
  final RpClient client;

  Future<void> _addPhone(BuildContext context) async {
    final r = await client.openPairing(validMinutes: 10);
    final code = jsonEncode({
      'v': 1,
      'host': device.host,
      'port': device.port,
      'device': r['device_id'],
      'secret': r['secret'],
      'cert': r['cert_sha256'],
    });
    if (!context.mounted) return;
    final s = S.of(context);
    await showDialog<void>(
      context: context,
      builder: (c) => AlertDialog(
        title: Text(s('set.addphone')),
        content: SizedBox(
          width: 280,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(s('set.addphone.body')),
              const SizedBox(height: 12),
              QrImageView(key: const Key('pair-qr'), data: code, size: 220, backgroundColor: Colors.white),
              SelectableText(
                code,
                key: const Key('pair-code-text'),
                style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => copyText(c, code), child: Text(s('common.copy'))),
          FilledButton(onPressed: () => Navigator.pop(c), child: Text(s('common.close'))),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Loader<List<Map<String, Object?>>>(
      load: client.admins,
      builder: (context, admins, reload) => ListView(
        children: [
          Section(
            title: s('set.admins'),
            children: [
              for (final a in admins)
                ListTile(
                  key: Key('admin-${a['id']}'),
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(a['id'] == device.adminId ? Icons.smartphone : Icons.devices),
                  title: Text(str(a['name'])),
                  subtitle: Text(str(a['id'])),
                  trailing: a['id'] == device.adminId
                      ? null
                      : TextButton(
                          key: Key('revoke-${a['id']}'),
                          onPressed: () async {
                            await client.revokeAdmin(str(a['id']));
                            reload();
                          },
                          child: Text(s('set.revoke')),
                        ),
                ),
              OutlinedButton.icon(
                key: const Key('add-phone'),
                onPressed: () => _addPhone(context),
                icon: const Icon(Icons.qr_code),
                label: Text(s('set.addphone')),
              ),
            ],
          ),
          Section(
            title: device.name,
            children: [
              ListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Certificate (SHA-256)'),
                subtitle: SelectableText(device.certSha256),
              ),
              ListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Device ID'),
                subtitle: SelectableText(device.deviceId),
              ),
              TextButton.icon(
                key: const Key('forget'),
                onPressed: () async {
                  await app.forget(device);
                  if (context.mounted) Navigator.of(context).popUntil((r) => r.isFirst);
                },
                icon: const Icon(Icons.delete_outline),
                label: Text(s('set.forget')),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
