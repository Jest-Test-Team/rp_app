// MCP management (plan §三.4): tools and their tiers, clients (token shown
// once), the approval queue, the audit trail and a connection guide.
// Approving signs the request with this app's admin key; the device checks it
// again (rp-privd) — MCP clients themselves can never approve.

import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/api/transport.dart';
import '../../widgets/common.dart';

class McpPage extends StatelessWidget {
  const McpPage({super.key, required this.client});
  final RpClient client;

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
              ApprovalQueue(client: client, actions: d.$3, onChanged: reload),
              _Clients(client: client, data: d.$2, onChanged: reload),
              _Tools(tools: d.$1),
              _Audit(audit: d.$4),
              const _Guide(),
            ],
          ),
        ),
      );
}

class ApprovalQueue extends StatelessWidget {
  const ApprovalQueue({super.key, required this.client, required this.actions, required this.onChanged});
  final RpClient client;
  final Map<String, Object?> actions;
  final VoidCallback onChanged;

  Future<void> _decide(BuildContext context, String id, bool approve) async {
    try {
      if (approve) {
        await client.approve(id);
      } else {
        await client.deny(id);
      }
      onChanged();
    } on ApiException catch (e) {
      if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final pending = asList(actions['actions']).map(asMap).where((a) => str(a['status']) == 'pending').toList();
    return Section(
      title: s('mcp.approvals'),
      children: [
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
      ],
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
    } on ApiException catch (e) {
      if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
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
                await client.mcpRemoveClient(str(c['name']));
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
  const _Tools({required this.tools});
  final Map<String, Object?> tools;
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Section(
      title: s('mcp.tools'),
      children: [
        for (final t in asList(tools['tools']).map(asMap))
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Icon(switch (str(t['tier'])) {
              'privileged' => Icons.gpp_maybe_outlined,
              'active' => Icons.radar,
              _ => Icons.visibility_outlined,
            }),
            title: Text(str(t['name'])),
            subtitle: Text('${s('mcp.tier.${str(t['tier'])}')} · ${str(t['description'])}'),
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
            title: Text('${str(e['tool'])} · ${str(e['outcome'])}'),
            subtitle: Text(str(e['principal'])),
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
    return Section(
      title: s('mcp.guide'),
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
