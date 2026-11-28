// MCP management (plan §三.4): tools and their tiers, clients (token shown
// once), the approval queue, the audit trail and a connection guide.
// Approving signs the request with this app's admin key; the device checks it
// again (rp-privd) — MCP clients themselves can never approve.

import 'dart:async';

import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/api/transport.dart';
import '../../core/hwkey/key_relay.dart';
import '../../widgets/common.dart';
import 'tool_runner.dart';

class McpPage extends StatelessWidget {
  const McpPage({super.key, required this.client, this.keyRelay});
  final RpClient client;

  /// Reaches a hardware key next to the user (Bluetooth); null = only the
  /// key plugged into the device.
  final KeyRelay? keyRelay;

  @override
  Widget build(BuildContext context) =>
      Loader<(Map<String, Object?>, Map<String, Object?>, Map<String, Object?>, Map<String, Object?>)>(
        load: () async => (
          await client.mcpTools(),
          await client.mcpClients(),
          await client.pendingActions(),
          await client.auditEvents(),
        ),
        builder: (context, d, reload) => RefreshIndicator(
          onRefresh: () async => reload(),
          child: ListView(
            children: [
              ApprovalQueue(client: client, actions: d.$3, onChanged: reload, keyRelay: keyRelay),
              _Tools(client: client, tools: d.$1, onRequested: reload),
              _Clients(client: client, data: d.$2, onChanged: reload),
              _Audit(audit: d.$4),
              const _Guide(),
            ],
          ),
        ),
      );
}

class ApprovalQueue extends StatelessWidget {
  const ApprovalQueue({super.key, required this.client, required this.actions, required this.onChanged, this.keyRelay});
  final RpClient client;
  final KeyRelay? keyRelay;
  final Map<String, Object?> actions;
  final VoidCallback onChanged;

  Map<String, Object?> get _approver => asMap(actions['approver']);

  /// What happened, in words: executed / failed (with the device's reason) /
  /// denied / approved but still running.
  static String outcome(S s, Map<String, Object?> a) {
    final st = str(a['status']);
    return switch (st) {
      'executed' => s('outcome.executed'),
      'failed' => s('outcome.failed', {'why': str(a['result'], s('outcome.noreason'))}),
      'denied' || 'expired' || 'approved' => s('outcome.$st'),
      _ => s('outcome.done'),
    };
  }

  bool get _keyRequired => _approver['required'] == true && _approver['bypass_until'] == null;

  Future<void> _decide(BuildContext context, String id, bool approve) async {
    final s = S.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final navigator = Navigator.of(context);
    var dialogOpen = false;
    try {
      if (approve && _keyRequired && keyRelay != null) {
        // Default: the key next to the user, over Bluetooth. The app only
        // carries the device's challenge and the key's signed answer.
        dialogOpen = true;
        unawaited(
          showDialog<void>(
            context: context,
            barrierDismissible: false,
            builder: (_) => const _PressKeyDialog(seconds: 120, nearby: true),
          ),
        );
        try {
          final ch = await client.hwkeyChallenge(id);
          final line = await keyRelay!.sign(str(ch['ask']));
          final a = await client.approve(id, hwkeyDecide: line);
          navigator.pop();
          dialogOpen = false;
          messenger.showSnackBar(SnackBar(content: Text(outcome(s, a))));
          onChanged();
          return;
        } on KeyRelayException catch (e) {
          navigator.pop();
          dialogOpen = false;
          if (e.error != KeyRelayError.noKey && e.error != KeyRelayError.unavailable) {
            messenger.showSnackBar(SnackBar(content: Text(s('approver.relay.${e.error.name}'))));
            onChanged();
            return;
          }
          // No key nearby: ask the one plugged into the device instead.
          messenger.showSnackBar(SnackBar(content: Text(s('approver.relay.fallback'))));
        }
      }
      if (approve && _keyRequired) {
        if (!context.mounted) return;
        // The device answers only after someone presses its hardware key.
        final wait = Duration(seconds: (_approver['wait_seconds'] as num?)?.toInt() ?? 60);
        dialogOpen = true;
        unawaited(
          showDialog<void>(
            context: context,
            barrierDismissible: false,
            builder: (_) => _PressKeyDialog(seconds: wait.inSeconds),
          ),
        );
        final a = await client.approve(id, keyWait: wait + const Duration(seconds: 20));
        if (dialogOpen) navigator.pop();
        dialogOpen = false;
        messenger.showSnackBar(SnackBar(content: Text(outcome(s, a))));
      } else {
        final a = approve ? await client.approve(id) : await client.deny(id);
        messenger.showSnackBar(SnackBar(content: Text(outcome(s, a))));
      }
      onChanged();
    } on ApiException catch (e) {
      if (dialogOpen) navigator.pop();
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
      onChanged();
    } on TimeoutException {
      if (dialogOpen) navigator.pop();
      messenger.showSnackBar(SnackBar(content: Text(s('approver.timeout'))));
      onChanged();
    } catch (e) {
      // Anything else (network, Bluetooth plugin): never leave the dialog up.
      if (dialogOpen) navigator.pop();
      messenger.showSnackBar(SnackBar(content: Text(errorText(s, e))));
      onChanged();
    }
  }

  Widget _keyBanner(BuildContext context) {
    final s = S.of(context);
    final bypass = _approver['bypass_until'] != null;
    final keys = _approver['keys'];
    return ListTile(
      key: const Key('approver-banner'),
      contentPadding: EdgeInsets.zero,
      leading: Icon(bypass ? Icons.lock_open_outlined : Icons.key, color: bypass ? Colors.orange : null),
      title: Text(s(bypass ? 'approver.bypass' : 'approver.required')),
      subtitle: keys is num ? Text(s('approver.keys', {'n': keys})) : null,
    );
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final all = asList(actions['actions']).map(asMap).toList();
    final pending = all.where((a) => str(a['status']) == 'pending').toList();
    final recent = all.where((a) => str(a['status']) != 'pending').toList()
      ..sort((a, b) => integer(b['created']).compareTo(integer(a['created'])));
    return Section(
      title: s('mcp.approvals'),
      children: [
        if (_approver['required'] == true) _keyBanner(context),
        if (pending.isEmpty) Text(s('mcp.none'), key: const Key('mcp-none')),
        for (final a in pending)
          Card(
            key: Key('action-${a['id']}'),
            child: Padding(
              padding: const EdgeInsets.all(8),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Text from the network / the model: displayed, never acted on.
                  Text(str(a['summary']), style: Theme.of(context).textTheme.titleSmall),
                  Text('${str(a['tool'])} · ${str(a['principal'])}'),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      TextButton(
                        key: Key('deny-${a['id']}'),
                        onPressed: () => _decide(context, str(a['id']), false),
                        child: Text(s('mcp.deny')),
                      ),
                      FilledButton(
                        key: Key('approve-${a['id']}'),
                        onPressed: () => _decide(context, str(a['id']), true),
                        child: Text(s('mcp.approve')),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        if (recent.isNotEmpty) ...[
          const SizedBox(height: 8),
          Text(s('mcp.recent'), style: Theme.of(context).textTheme.titleSmall),
          for (final a in recent.take(5))
            ListTile(
              key: Key('outcome-${a['id']}'),
              dense: true,
              contentPadding: EdgeInsets.zero,
              leading: OutcomeIcon(str(a['status'])),
              title: Text(str(a['summary'])),
              subtitle: Text(outcome(s, a)),
            ),
        ],
      ],
    );
  }
}

/// ✓ succeeded, ✗ failed, — denied/expired, … still running.
class OutcomeIcon extends StatelessWidget {
  const OutcomeIcon(this.status, {super.key});
  final String status;
  @override
  Widget build(BuildContext context) => switch (status) {
    'executed' || 'ok' || 'allowed' => const Icon(Icons.check_circle, color: Colors.green),
    'failed' || 'error' => Icon(Icons.error, color: Theme.of(context).colorScheme.error),
    'approved' || 'pending' || 'requested' => const Icon(Icons.hourglass_top),
    _ => const Icon(Icons.remove_circle_outline, color: Colors.grey),
  };
}

/// Shown while the device waits for a press on its hardware approval key.
class _PressKeyDialog extends StatefulWidget {
  const _PressKeyDialog({required this.seconds, this.nearby = false});
  final int seconds;

  /// The key next to the user (Bluetooth), not the one at the device.
  final bool nearby;
  @override
  State<_PressKeyDialog> createState() => _PressKeyDialogState();
}

class _PressKeyDialogState extends State<_PressKeyDialog> {
  late int left = widget.seconds;
  Timer? timer;

  @override
  void initState() {
    super.initState();
    timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (left > 0) setState(() => left--);
    });
  }

  @override
  void dispose() {
    timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return AlertDialog(
      key: const Key('approver-wait'),
      icon: const Icon(Icons.key),
      title: Text(s('approver.press.title')),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(s(widget.nearby ? 'approver.press.nearby' : 'approver.press.body')),
          const SizedBox(height: 16),
          const LinearProgressIndicator(),
          const SizedBox(height: 8),
          Text(s('approver.press.left', {'s': left})),
        ],
      ),
    );
  }
}

class _Clients extends StatelessWidget {
  const _Clients({required this.client, required this.data, required this.onChanged});
  final RpClient client;
  final Map<String, Object?> data;
  final VoidCallback onChanged;

  Future<void> _add(BuildContext context) async {
    final r = await showDialog<(String, List<String>)>(context: context, builder: (_) => const _NewClientDialog());
    if (r == null || !context.mounted) return;
    try {
      final res = await client.mcpAddClient(r.$1, r.$2);
      if (!context.mounted) return;
      await showDialog<void>(
        context: context,
        builder: (c) => TokenDialog(token: str(res['token'])),
      );
      onChanged();
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(errorText(S.of(context), e))));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Section(
      title: s('mcp.clients'),
      trailing: IconButton(
        key: const Key('mcp-add'),
        onPressed: () => _add(context),
        icon: const Icon(Icons.add),
        tooltip: s('mcp.addclient'),
      ),
      children: [
        Text(s('mcp.clients.hint'), style: Theme.of(context).textTheme.bodySmall),
        for (final c in asList(data['clients']).map(asMap))
          ListTile(
            key: Key('mcp-client-${c['name']}'),
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.key_outlined),
            title: Text(str(c['name'])),
            subtitle: Text(asList(c['capabilities']).map((t) => s('mcp.tier.$t')).join(', ')),
            trailing: IconButton(
              key: Key('mcp-remove-${c['name']}'),
              icon: const Icon(Icons.delete_outline),
              onPressed: () async {
                final m = ScaffoldMessenger.of(context);
                try {
                  await client.mcpRemoveClient(str(c['name']));
                  m.showSnackBar(SnackBar(content: Text(s('mcp.client.removed'))));
                } catch (e) {
                  m.showSnackBar(SnackBar(content: Text(errorText(s, e))));
                }
                onChanged();
              },
            ),
          ),
      ],
    );
  }
}

class _NewClientDialog extends StatefulWidget {
  const _NewClientDialog();
  @override
  State<_NewClientDialog> createState() => _NewClientDialogState();
}

class _NewClientDialogState extends State<_NewClientDialog> {
  final name = TextEditingController(text: 'claude-code');
  final tiers = <String>{'read'};
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final ok = RegExp(r'^[A-Za-z0-9_-]{1,32}$').hasMatch(name.text) && tiers.isNotEmpty;
    return AlertDialog(
      title: Text(s('mcp.addclient')),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(key: const Key('mcp-name'), controller: name, onChanged: (_) => setState(() {})),
          for (final t in ['read', 'active', 'privileged'])
            CheckboxListTile(
              key: Key('mcp-tier-$t'),
              title: Text(s('mcp.tier.$t')),
              value: tiers.contains(t),
              onChanged: (v) => setState(() => v == true ? tiers.add(t) : tiers.remove(t)),
            ),
        ],
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(s('common.cancel'))),
        FilledButton(
          key: const Key('mcp-create'),
          onPressed: ok ? () => Navigator.pop(context, (name.text, tiers.toList())) : null,
          child: Text(s('common.save')),
        ),
      ],
    );
  }
}

class TokenDialog extends StatelessWidget {
  const TokenDialog({super.key, required this.token});
  final String token;
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return AlertDialog(
      title: Text(s('mcp.token')),
      content: SelectableText(
        token,
        key: const Key('mcp-token'),
        style: const TextStyle(fontFamily: 'monospace'),
      ),
      actions: [
        TextButton(onPressed: () => copyText(context, token), child: Text(s('common.copy'))),
        FilledButton(onPressed: () => Navigator.pop(context), child: Text(s('common.close'))),
      ],
    );
  }
}

class _Tools extends StatelessWidget {
  const _Tools({required this.client, required this.tools, required this.onRequested});
  final RpClient client;
  final Map<String, Object?> tools;
  final VoidCallback onRequested;
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Section(
      title: s('mcp.tools'),
      children: [
        Text(s('mcp.tools.hint'), style: Theme.of(context).textTheme.bodySmall),
        for (final t in asList(tools['tools']).map(asMap))
          ListTile(
            key: Key('tool-${t['name']}'),
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Icon(switch (str(t['tier'])) {
              'privileged' => Icons.gpp_maybe_outlined,
              'active' => Icons.radar,
              _ => Icons.visibility_outlined,
            }),
            title: Text(s('tool.name.${str(t['name'])}', {}, str(t['name']))),
            subtitle: Text(
              '${s('mcp.tier.${str(t['tier'])}')} · ${s('tool.desc.${str(t['name'])}', {}, str(t['description']))}',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute<void>(
                builder: (_) => ToolRunnerPage(client: client, tool: t, onRequested: onRequested),
              ),
            ),
          ),
      ],
    );
  }
}

class _Audit extends StatelessWidget {
  const _Audit({required this.audit});
  final Map<String, Object?> audit;
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final chainOk = asMap(audit['chain'])['ok'] == true;
    return Section(
      title: s('mcp.audit'),
      trailing: Icon(
        chainOk ? Icons.verified_outlined : Icons.report_problem_outlined,
        color: chainOk ? Colors.green : Colors.red,
      ),
      children: [
        for (final e in asList(audit['entries']).map(asMap).take(30))
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: OutcomeIcon(str(e['outcome'])),
            title: Text(s('tool.name.${str(e['tool'])}', {}, str(e['tool']))),
            subtitle: Text('${s('outcome.${str(e['outcome'])}', {}, str(e['outcome']))} · ${str(e['principal'])}'),
          ),
      ],
    );
  }
}

class _Guide extends StatelessWidget {
  const _Guide();
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    const snippet =
        '{\n  "mcpServers": {\n    "rp-gateway": {\n      "command": "ssh",\n'
        '      "args": ["-i", "~/.ssh/rp_mcp", "<user>@<device>", "rp-mcp", "--stdio"]\n    }\n  }\n}';
    return ExpansionTile(
      key: const Key('mcp-guide'),
      title: Text(s('mcp.guide')),
      subtitle: Text(s('mcp.guide.hint')),
      childrenPadding: const EdgeInsets.symmetric(horizontal: 16),
      children: [
        const SelectableText(snippet, style: TextStyle(fontFamily: 'monospace', fontSize: 12)),
        Align(
          alignment: Alignment.centerRight,
          child: TextButton(onPressed: () => copyText(context, snippet), child: Text(s('common.copy'))),
        ),
      ],
    );
  }
}
