// ESP32 boards attached to the device (Settings › ESP32 boards): what each
// one is and runs, its error log as kept by rp-boards on the device, and a
// signed profile switch. Board text comes from hardware we do not control:
// it is displayed, never acted on.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/api/transport.dart';
import '../../widgets/common.dart';

const _levels = ['error', 'warn', 'info', 'debug'];

int _rank(String l) {
  final i = _levels.indexOf(l);
  return i < 0 ? _levels.length : i;
}

class BoardsPage extends StatefulWidget {
  const BoardsPage({super.key, required this.client});
  final RpClient client;
  @override
  State<BoardsPage> createState() => _BoardsPageState();
}

class _BoardsPageState extends State<BoardsPage> {
  String level = 'warn';

  Future<void> _switch(BuildContext context, Map<String, Object?> b, VoidCallback reload) async {
    final s = S.of(context);
    final current = str(b['profile']);
    final options = asList(b['supported']).whereType<String>().toList();
    final picked = await showDialog<String>(
      context: context,
      builder: (c) => SimpleDialog(
        title: Text(s('boards.switch')),
        children: [
          for (final p in options)
            SimpleDialogOption(
              key: Key('profile-$p'),
              onPressed: () => Navigator.pop(c, p),
              child: ListTile(
                leading: Icon(p == current ? Icons.radio_button_checked : Icons.radio_button_off),
                title: Text(s('boards.profile.$p', {}, p)),
                subtitle: Text(s('boards.profile.$p.desc', {}, '')),
              ),
            ),
        ],
      ),
    );
    if (picked == null || picked == current || !context.mounted) return;
    if (current == 'approver') {
      final ok = await showDialog<bool>(
        context: context,
        builder: (c) => AlertDialog(
          title: Text(s('boards.leave.title')),
          content: Text(s('boards.leave.body')),
          actions: [
            TextButton(onPressed: () => Navigator.pop(c, false), child: Text(s('common.cancel'))),
            FilledButton(
              key: const Key('profile-confirm'),
              onPressed: () => Navigator.pop(c, true),
              child: Text(s('boards.switch')),
            ),
          ],
        ),
      );
      if (ok != true || !context.mounted) return;
    }
    final messenger = ScaffoldMessenger.of(context);
    try {
      await widget.client.setBoardProfile(str(b['port']), picked);
      messenger.showSnackBar(SnackBar(content: Text(s('boards.switched', {'p': s('boards.profile.$picked', {}, picked)}))));
    } on ApiException catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    }
    reload();
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(s('boards.title'))),
      body: Loader<(Map<String, Object?>, Map<String, Object?>)>(
        load: () async => (await widget.client.boards(), await widget.client.boardLogs(level: level, limit: 300)),
        builder: (context, d, reload) {
          final boards = asList(d.$1['boards']).map(asMap).toList();
          final entries = asList(d.$2['entries'])
              .map(asMap)
              .where((e) => _rank(str(e['level'])) <= _rank(level))
              .toList();
          return RefreshIndicator(
            onRefresh: () async => reload(),
            child: ListView(
              padding: const EdgeInsets.all(8),
              children: [
                if (d.$1['managed'] != true) Text(s('boards.unmanaged'), key: const Key('boards-unmanaged')),
                for (final b in boards) _BoardCard(board: b, onSwitch: () => _switch(context, b, reload)),
                Section(
                  title: s('boards.logs'),
                  trailing: IconButton(
                    key: const Key('boards-copy'),
                    tooltip: s('common.copy'),
                    icon: const Icon(Icons.copy_all),
                    onPressed: () => Clipboard.setData(ClipboardData(
                      text: entries.map((e) => '${_time(e['ts'])} ${e['port']} ${e['level']} ${e['text']}').join('\n'),
                    )),
                  ),
                  children: [
                    SegmentedButton<String>(
                      key: const Key('boards-level'),
                      segments: [
                        for (final l in _levels)
                          ButtonSegment(value: l, label: Text(s('boards.level.$l')), tooltip: s('boards.level.$l.hint')),
                      ],
                      selected: {level},
                      onSelectionChanged: (v) {
                        setState(() => level = v.first);
                        reload();
                      },
                    ),
                    if (entries.isEmpty) Text(s('boards.nologs'), key: const Key('boards-nologs')),
                    for (final e in entries) _LogTile(entry: e),
                  ],
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}

String _time(Object? ts) {
  if (ts is! num) return '';
  final t = DateTime.fromMillisecondsSinceEpoch(ts.toInt() * 1000).toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${t.month}/${t.day} ${two(t.hour)}:${two(t.minute)}:${two(t.second)}';
}

class _BoardCard extends StatelessWidget {
  const _BoardCard({required this.board, required this.onSwitch});
  final Map<String, Object?> board;
  final VoidCallback onSwitch;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final b = board;
    final up = b['connected'] == true;
    final profile = str(b['profile']);
    final enrolled = b['enrolled_as'];
    final errors = (b['errors'] as num?)?.toInt() ?? 0;
    final theme = Theme.of(context);
    return Card(
      key: Key('board-${b['port']}'),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.developer_board, color: up ? Colors.green : theme.disabledColor),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    up ? str(b['chip'], s('boards.unknownchip')) : s('boards.offline'),
                    style: theme.textTheme.titleMedium,
                  ),
                ),
                if (errors > 0)
                  Chip(
                    key: Key('board-errors-${b['port']}'),
                    avatar: const Icon(Icons.error_outline, size: 18),
                    label: Text(s('boards.errors', {'n': errors})),
                    backgroundColor: theme.colorScheme.errorContainer,
                  ),
              ],
            ),
            Text(str(b['port']), style: theme.textTheme.bodySmall),
            if (up) ...[
              const SizedBox(height: 8),
              Text('${s('boards.profile')}: ${s('boards.profile.$profile', {}, profile)} · ${s('boards.firmware')} ${str(b['firmware'])}'),
              Text(
                enrolled is String ? s('boards.key.enrolled', {'name': enrolled}) : s('boards.key.not'),
                key: Key('board-key-${b['port']}'),
              ),
              if (b['last_boot'] is String) Text('${s('boards.lastboot')}: ${b['last_boot']}'),
              for (final p in asList(b['recent_problems']).map(asMap).take(3))
                Text('⚠ ${str(p['text'])}', style: TextStyle(color: theme.colorScheme.error)),
              Align(
                alignment: Alignment.centerRight,
                child: OutlinedButton.icon(
                  key: Key('board-switch-${b['port']}'),
                  onPressed: onSwitch,
                  icon: const Icon(Icons.swap_horiz),
                  label: Text(s('boards.switch')),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _LogTile extends StatelessWidget {
  const _LogTile({required this.entry});
  final Map<String, Object?> entry;
  @override
  Widget build(BuildContext context) {
    final l = str(entry['level']);
    final scheme = Theme.of(context).colorScheme;
    final (icon, color) = switch (l) {
      'error' => (Icons.error, scheme.error),
      'warn' => (Icons.warning_amber, Colors.orange),
      'info' => (Icons.info_outline, scheme.primary),
      _ => (Icons.notes, scheme.outline),
    };
    return ListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      leading: Icon(icon, color: color),
      title: Text(str(entry['text']), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
      subtitle: Text('${_time(entry['ts'])} · ${str(entry['port'])} · ${str(entry['source'])}'),
    );
  }
}
