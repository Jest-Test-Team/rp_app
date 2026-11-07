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
          UpdateSection(app: app, client: client),
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
              TextButton.icon(
                key: const Key('uninstall'),
                style: TextButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error),
                onPressed: () => _uninstall(context),
                icon: const Icon(Icons.warning_amber),
                label: Text(s('rm.title')),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Future<void> _uninstall(BuildContext context) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => ConfirmRemoveDialog(deviceName: device.name),
    );
    if (ok != true) return;
    await client.uninstall();
    await app.forget(device);
    if (context.mounted) Navigator.of(context).popUntil((r) => r.isFirst);
  }
}

/// Typing the device name enables "Remove" (owns its controller).
class ConfirmRemoveDialog extends StatefulWidget {
  const ConfirmRemoveDialog({super.key, required this.deviceName});
  final String deviceName;
  @override
  State<ConfirmRemoveDialog> createState() => _ConfirmRemoveDialogState();
}

class _ConfirmRemoveDialogState extends State<ConfirmRemoveDialog> {
  final typed = TextEditingController();

  @override
  void dispose() {
    typed.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return AlertDialog(
      title: Text(s('rm.title')),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(s('rm.body')),
          TextField(key: const Key('uninstall-confirm'), controller: typed, onChanged: (_) => setState(() {})),
        ],
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: Text(s('common.cancel'))),
        FilledButton(
          key: const Key('uninstall-go'),
          onPressed: typed.text == widget.deviceName ? () => Navigator.pop(context, true) : null,
          child: Text(s('rm.go')),
        ),
      ],
    );
  }
}

class UpdateSection extends StatefulWidget {
  const UpdateSection({super.key, required this.app, required this.client});
  final AppState app;
  final RpClient client;
  @override
  State<UpdateSection> createState() => _UpdateSectionState();
}

class _UpdateSectionState extends State<UpdateSection> {
  Map<String, Object?>? status;
  String? latest;
  String? message;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final st = await widget.client.updateStatus();
      if (mounted) setState(() => status = st);
    } on Exception {
      // Older devices have no update endpoint: the section stays minimal.
    }
  }

  Future<void> _check() async {
    setState(() => busy = true);
    final t = await widget.app.services.latest();
    if (mounted) {
      setState(() {
        latest = t;
        busy = false;
      });
    }
  }

  Future<void> _install(String tag) async {
    final s = S.of(context);
    setState(() {
      busy = true;
      message = s('upd.installing');
    });
    String result;
    try {
      await widget.client.installUpdate(tag);
      result = s('upd.done', {'tag': tag});
    } on Exception catch (e) {
      result = mounted ? describeError(context, e) : '$e';
    }
    if (!mounted) return;
    setState(() {
      busy = false;
      message = result;
    });
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final st = status ?? const <String, Object?>{};
    final live = str(st['live'], 'v${str(st['running_version'], '?')}');
    final prev = st['previous'] as String?;
    final hasKey = st['signing_key'] == true;
    final newer = latest != null && latest != live;
    return Section(
      title: s('upd.title'),
      children: [
        ListTile(
          contentPadding: EdgeInsets.zero,
          title: Text(s('upd.running')),
          trailing: Text(live, key: const Key('upd-live')),
        ),
        if (status != null && !hasKey) Text(s('upd.nokey'), key: const Key('upd-nokey')),
        if (latest != null)
          ListTile(contentPadding: EdgeInsets.zero, title: Text(s('upd.latest')), trailing: Text(latest!)),
        if (latest != null && !newer) Text(s('upd.uptodate')),
        if (message != null)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Text(message!, key: const Key('upd-message')),
          ),
        if (busy) const LinearProgressIndicator(),
        Wrap(
          spacing: 8,
          children: [
            OutlinedButton(key: const Key('upd-check'), onPressed: busy ? null : _check, child: Text(s('upd.check'))),
            if (newer && hasKey)
              FilledButton(
                key: const Key('upd-install'),
                onPressed: busy ? null : () => _install(latest!),
                child: Text(s('upd.install', {'tag': latest!})),
              ),
            if (prev != null)
              TextButton(
                key: const Key('upd-rollback'),
                onPressed: busy
                    ? null
                    : () async {
                        await widget.client.rollbackUpdate();
                        await _load();
                      },
                child: Text(s('upd.rollback', {'tag': prev})),
              ),
          ],
        ),
      ],
    );
  }
}
