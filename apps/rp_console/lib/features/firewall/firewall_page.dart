import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../widgets/change_sheet.dart';
import '../../widgets/common.dart';

const zones = ['lan', 'wan', 'iot', 'vpn', 'device'];
const protos = ['any', 'tcp', 'udp', 'icmp'];
const actions = ['drop', 'reject', 'accept'];

/// A rule as the API expects it (rp_schema::FwRule). Returns an error text or null.
String? validateRule(Map<String, Object?> r) {
  final name = str(r['name']);
  if (name.trim().isEmpty || name.length > 40 || !RegExp(r'^[A-Za-z0-9 _-]+$').hasMatch(name)) return 'name';
  if (r['from'] == 'device') return 'from';
  if (r['from'] == r['to'] && r['to'] != 'device') return 'to';
  final ports = asList(r['ports']);
  if (ports.isNotEmpty && !(r['proto'] == 'tcp' || r['proto'] == 'udp')) return 'proto';
  if (ports.any((p) => p is! int || p < 1 || p > 65535)) return 'ports';
  if (r['to'] == 'device' && r['action'] != 'accept' && ports.isEmpty) return 'ports';
  return null;
}

List<int>? parsePorts(String text) {
  if (text.trim().isEmpty) return [];
  final out = <int>[];
  for (final p in text.split(',')) {
    final n = int.tryParse(p.trim());
    if (n == null || n < 1 || n > 65535) return null;
    out.add(n);
  }
  return out;
}

class FirewallPage extends StatelessWidget {
  const FirewallPage({super.key, required this.client});
  final RpClient client;

  @override
  Widget build(BuildContext context) => Loader<Map<String, Object?>>(
    load: client.firewallRules,
    builder: (context, d, reload) =>
        RuleList(client: client, rules: asList(d['rules']).map(asMap).toList(), onSaved: reload),
  );
}

class RuleList extends StatefulWidget {
  const RuleList({super.key, required this.client, required this.rules, required this.onSaved});
  final RpClient client;
  final List<Map<String, Object?>> rules;
  final VoidCallback onSaved;
  @override
  State<RuleList> createState() => _RuleListState();
}

class _RuleListState extends State<RuleList> {
  late List<Map<String, Object?>> rules = [for (final r in widget.rules) Map.of(r)];
  bool dirty = false;

  Future<void> _edit([int? i]) async {
    final r = await showDialog<Map<String, Object?>>(
      context: context,
      builder: (_) => RuleDialog(initial: i == null ? null : rules[i]),
    );
    if (r == null) return;
    setState(() {
      if (i == null) {
        rules.add(r);
      } else {
        rules[i] = r;
      }
      dirty = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return ListView(
      children: [
        Section(
          title: s('fw.rules'),
          trailing: IconButton(
            key: const Key('fw-add'),
            onPressed: () => _edit(),
            icon: const Icon(Icons.add),
            tooltip: s('fw.add'),
          ),
          children: [
            Text(s('fw.mgmt'), style: Theme.of(context).textTheme.bodySmall),
            if (rules.isEmpty) Padding(padding: const EdgeInsets.only(top: 8), child: Text(s('fw.empty'))),
            ReorderableListView(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              buildDefaultDragHandles: true,
              onReorderItem: (a, b) => setState(() {
                rules.insert(b, rules.removeAt(a));
                dirty = true;
              }),
              children: [
                for (final (i, r) in rules.indexed)
                  ListTile(
                    key: Key('fw-rule-$i'),
                    contentPadding: EdgeInsets.zero,
                    leading: Icon(r['action'] == 'accept' ? Icons.check_circle_outline : Icons.block),
                    title: Text(str(r['name'])),
                    subtitle: Text(
                      '${r['from']} → ${r['to']} · ${r['proto'] ?? 'any'}'
                      '${asList(r['ports']).isEmpty ? '' : ' ${asList(r['ports']).join(',')}'} · ${r['action']}',
                    ),
                    onTap: () => _edit(i),
                    trailing: IconButton(
                      key: Key('fw-del-$i'),
                      icon: const Icon(Icons.delete_outline),
                      onPressed: () => setState(() {
                        rules.removeAt(i);
                        dirty = true;
                      }),
                    ),
                  ),
              ],
            ),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton(
                key: const Key('fw-save'),
                onPressed: dirty
                    ? () async {
                        if (await showChange(context, widget.client, 'firewall', {'firewall.rules': rules})) {
                          setState(() => dirty = false);
                          widget.onSaved();
                        }
                      }
                    : null,
                child: Text(s('common.save')),
              ),
            ),
          ],
        ),
      ],
    );
  }
}

class RuleDialog extends StatefulWidget {
  const RuleDialog({super.key, this.initial});
  final Map<String, Object?>? initial;
  @override
  State<RuleDialog> createState() => _RuleDialogState();
}

class _RuleDialogState extends State<RuleDialog> {
  late final name = TextEditingController(text: str(widget.initial?['name']));
  late final ports = TextEditingController(text: asList(widget.initial?['ports']).join(', '));
  late String from = str(widget.initial?['from'], 'iot');
  late String to = str(widget.initial?['to'], 'lan');
  late String proto = str(widget.initial?['proto'], 'tcp');
  late String action = str(widget.initial?['action'], 'drop');
  late bool log = flag(widget.initial?['log']);
  String? error;

  Widget _dd(String label, String value, List<String> items, ValueChanged<String> on, String key) => Padding(
    padding: const EdgeInsets.only(bottom: 12),
    child: DropdownButtonFormField<String>(
      key: Key(key),
      initialValue: value,
      decoration: InputDecoration(labelText: label),
      items: [for (final i in items) DropdownMenuItem(value: i, child: Text(i))],
      onChanged: (v) => setState(() => on(v ?? value)),
    ),
  );

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return AlertDialog(
      title: Text(s('fw.add')),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              key: const Key('fw-name'),
              controller: name,
              decoration: const InputDecoration(labelText: 'Name'),
            ),
            const SizedBox(height: 12),
            _dd(s('fw.from'), from, zones.where((z) => z != 'device').toList(), (v) => from = v, 'fw-from'),
            _dd(s('fw.to'), to, zones, (v) => to = v, 'fw-to'),
            _dd(s('fw.proto'), proto, protos, (v) => proto = v, 'fw-proto'),
            TextField(
              key: const Key('fw-ports'),
              controller: ports,
              decoration: InputDecoration(labelText: s('fw.ports')),
            ),
            const SizedBox(height: 12),
            _dd(s('fw.action'), action, actions, (v) => action = v, 'fw-action'),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(s('fw.log')),
              value: log,
              onChanged: (v) => setState(() => log = v),
            ),
            if (error != null)
              Text(
                error!,
                key: const Key('fw-error'),
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(s('common.cancel'))),
        FilledButton(
          key: const Key('fw-ok'),
          onPressed: () {
            final p = parsePorts(ports.text);
            final r = <String, Object?>{
              'name': name.text.trim(),
              'from': from,
              'to': to,
              'proto': proto,
              'ports': p ?? [-1],
              'action': action,
              'log': log,
            };
            final bad = validateRule(r);
            if (bad != null) {
              setState(() => error = bad);
              return;
            }
            Navigator.pop(context, r);
          },
          child: Text(s('common.save')),
        ),
      ],
    );
  }
}
