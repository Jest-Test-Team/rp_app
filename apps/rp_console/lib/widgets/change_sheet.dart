import 'dart:async';

import 'package:flutter/material.dart';

import '../app/strings.dart';
import '../core/api/client.dart';
import '../core/api/models.dart';
import '../core/changes/change_runner.dart';

/// Review and apply one change. Returns true when it was kept.
Future<bool> showChange(
  BuildContext context,
  RpClient client,
  String module,
  Map<String, Object?> patch, {
  Future<void> Function()? before,
}) async {
  final runner = ChangeRunner(client);
  final kept = await showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    useSafeArea: true,
    builder: (_) => ChangeSheet(runner: runner, module: module, patch: patch, before: before),
  );
  return kept ?? false;
}

class ChangeSheet extends StatefulWidget {
  const ChangeSheet({super.key, required this.runner, required this.module, required this.patch, this.before});
  final ChangeRunner runner;
  final String module;
  final Map<String, Object?> patch;
  final Future<void> Function()? before;

  @override
  State<ChangeSheet> createState() => _ChangeSheetState();
}

class _ChangeSheetState extends State<ChangeSheet> {
  Timer? _tick;

  @override
  void initState() {
    super.initState();
    widget.runner.addListener(_changed);
    _start();
    _tick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted && widget.runner.phase == Phase.awaitingConfirm) setState(() {});
    });
  }

  Future<void> _start() async {
    if (widget.before != null) {
      try {
        await widget.before!();
      } catch (e) {
        if (mounted) setState(() {});
      }
    }
    await widget.runner.prepare(widget.module, widget.patch);
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _tick?.cancel();
    widget.runner.removeListener(_changed);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final r = widget.runner;
    final cs = r.change;
    final busy = {Phase.preparing, Phase.applying, Phase.verifying}.contains(r.phase);
    final done = {Phase.confirmed, Phase.rolledBack, Phase.failed}.contains(r.phase);
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.8,
      builder: (context, scroll) => ListView(
        controller: scroll,
        padding: const EdgeInsets.all(16),
        children: [
          Text('${s('change.title')} · ${s.module(widget.module)}', style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 12),
          if (busy) ...[
            const LinearProgressIndicator(),
            const SizedBox(height: 8),
            Text(switch (r.phase) {
              Phase.applying => s('change.applying'),
              Phase.verifying => s('change.verifying'),
              _ => s('common.loading'),
            }, key: const Key('change-phase')),
          ],
          if (r.phase == Phase.awaitingConfirm && cs?.deadline != null)
            Card(
              color: Theme.of(context).colorScheme.tertiaryContainer,
              child: ListTile(
                key: const Key('change-countdown'),
                leading: const Icon(Icons.timer_outlined),
                title: Text(
                  s('change.countdown', {
                    's': (cs!.deadline! - DateTime.now().millisecondsSinceEpoch ~/ 1000).clamp(0, 9999),
                  }),
                ),
              ),
            ),
          if (r.phase == Phase.confirmed)
            _result(Icons.check_circle, s('change.confirmed'), const Key('change-confirmed')),
          if (r.phase == Phase.rolledBack) _result(Icons.undo, s('change.rolledback'), const Key('change-rolledback')),
          if (r.phase == Phase.failed)
            _result(
              Icons.error_outline,
              r.errorCode == 'conflict' ? s('change.conflict') : s('change.failed', {'why': r.error ?? ''}),
              const Key('change-failed'),
            ),
          for (final c in r.failedChecks)
            ListTile(
              dense: true,
              leading: const Icon(Icons.close, color: Colors.red),
              title: Text(c.name),
              subtitle: Text(c.detail),
            ),
          if (cs != null && cs.configDiff.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(s('change.diff'), style: Theme.of(context).textTheme.titleSmall),
            _Diff(text: cs.configDiff),
          ],
          if (cs != null && cs.files.isNotEmpty)
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              title: Text('${s('change.files')} (${cs.files.length})'),
              children: [for (final f in cs.files) ListTile(dense: true, title: Text(str(f['path'])))],
            ),
          if (cs != null && cs.checks.isNotEmpty && r.phase == Phase.review)
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              title: Text('${s('change.checks')} (${cs.checks.where((c) => !c.failed).length}/${cs.checks.length})'),
              children: [
                for (final c in cs.checks)
                  ListTile(
                    dense: true,
                    leading: Icon(c.failed ? Icons.close : Icons.check, color: c.failed ? Colors.red : Colors.green),
                    title: Text(c.name),
                    subtitle: Text(c.detail),
                  ),
              ],
            ),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              if (r.phase == Phase.awaitingConfirm) ...[
                TextButton(onPressed: r.rollbackNow, child: Text(s('change.undo'))),
                const SizedBox(width: 8),
                FilledButton(onPressed: r.confirmNow, child: Text(s('change.keep'))),
              ] else if (done)
                FilledButton(
                  key: const Key('change-close'),
                  onPressed: () => Navigator.of(context).pop(r.phase == Phase.confirmed),
                  child: Text(s('common.close')),
                )
              else ...[
                TextButton(
                  onPressed: busy ? null : () => Navigator.of(context).pop(false),
                  child: Text(s('common.cancel')),
                ),
                const SizedBox(width: 8),
                FilledButton(
                  key: const Key('change-apply'),
                  onPressed: r.phase == Phase.review ? r.applyAndConfirm : null,
                  child: Text(s('change.apply')),
                ),
              ],
            ],
          ),
        ],
      ),
    );
  }

  Widget _result(IconData i, String text, Key key) => Card(
    child: ListTile(key: key, leading: Icon(i), title: Text(text)),
  );
}

class _Diff extends StatelessWidget {
  const _Diff({required this.text});
  final String text;

  @override
  Widget build(BuildContext context) {
    final lines = text.split('\n').where((l) => !l.startsWith('---') && !l.startsWith('+++')).toList();
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
      ),
      child: SelectableText.rich(
        TextSpan(
          children: [
            for (final l in lines)
              TextSpan(
                text: '$l\n',
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: l.startsWith('+') ? Colors.green.shade700 : (l.startsWith('-') ? Colors.red.shade700 : null),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
