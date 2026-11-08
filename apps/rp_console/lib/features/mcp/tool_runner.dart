// Run one MCP tool from the app: a form generated from the tool's input
// schema, then a readable result. Privileged tools only create a request;
// the person approves it in the approval queue (signed with this app's key).

import 'dart:convert';

import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/api/transport.dart';

/// Arguments from form text, typed by the schema. Returns an error message
/// key for the first invalid field, or null.
(Map<String, Object?>, String?) toolArgs(Map<String, Object?> schema, Map<String, String> text) {
  final props = asMap(schema['properties']);
  final required = asList(schema['required']).whereType<String>().toSet();
  final out = <String, Object?>{};
  for (final e in props.entries) {
    final p = asMap(e.value);
    final raw = (text[e.key] ?? '').trim();
    if (raw.isEmpty) {
      if (required.contains(e.key)) return (out, e.key);
      continue;
    }
    if (str(p['type']) == 'integer') {
      final n = int.tryParse(raw);
      final min = p['minimum'], max = p['maximum'];
      if (n == null || (min is int && n < min) || (max is int && n > max)) return (out, e.key);
      out[e.key] = n;
    } else {
      out[e.key] = raw;
    }
  }
  return (out, null);
}

class ToolRunnerPage extends StatefulWidget {
  const ToolRunnerPage({super.key, required this.client, required this.tool, this.onRequested});
  final RpClient client;
  final Map<String, Object?> tool;

  /// Called after a privileged request was queued (to refresh the queue).
  final VoidCallback? onRequested;

  @override
  State<ToolRunnerPage> createState() => _ToolRunnerPageState();
}

class _ToolRunnerPageState extends State<ToolRunnerPage> {
  late final Map<String, Object?> schema = asMap(widget.tool['input_schema']);
  late final Map<String, Object?> props = asMap(schema['properties']);
  late final Map<String, TextEditingController> fields = {
    for (final e in props.entries) e.key: TextEditingController(text: asMap(e.value)['default']?.toString() ?? ''),
  };
  final enums = <String, String?>{};
  bool busy = false;
  String? error;
  Map<String, Object?>? result;

  String get name => str(widget.tool['name']);
  bool get privileged => str(widget.tool['tier']) == 'privileged';

  @override
  void initState() {
    super.initState();
    // Read-only tools without arguments run straight away.
    if (props.isEmpty && !privileged) WidgetsBinding.instance.addPostFrameCallback((_) => _run());
  }

  @override
  void dispose() {
    for (final c in fields.values) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _run() async {
    final s = S.of(context);
    final text = {for (final e in fields.entries) e.key: enums[e.key] ?? e.value.text};
    final (args, bad) = toolArgs(schema, text);
    if (bad != null) {
      setState(() => error = s('tool.badfield', {'field': s('tool.arg.$bad', {}, bad)}));
      return;
    }
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final r = await widget.client.runTool(name, args);
      if (!mounted) return;
      setState(() => result = r);
      if (privileged) widget.onRequested?.call();
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(s('tool.name.$name', {}, name))),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(s('tool.desc.$name', {}, str(widget.tool['description']))),
          if (privileged)
            Card(
              margin: const EdgeInsets.symmetric(vertical: 12),
              child: ListTile(leading: const Icon(Icons.gpp_maybe_outlined), title: Text(s('tool.privileged.hint'))),
            ),
          const SizedBox(height: 8),
          for (final e in props.entries) _field(context, e.key, asMap(e.value)),
          const SizedBox(height: 12),
          FilledButton.icon(
            key: const Key('tool-run'),
            onPressed: busy ? null : _run,
            icon: busy
                ? const SizedBox.square(dimension: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : Icon(privileged ? Icons.send_outlined : Icons.play_arrow),
            label: Text(privileged ? s('tool.request') : s('tool.run')),
          ),
          if (error != null)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(
                error!,
                key: const Key('tool-error'),
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ),
          if (result != null) ...[
            const Divider(height: 32),
            ToolResult(name: name, result: asMap(result!['result']), privileged: privileged),
          ],
        ],
      ),
    );
  }

  Widget _field(BuildContext context, String key, Map<String, Object?> p) {
    final s = S.of(context);
    final label = s('tool.arg.$key', {}, key);
    final options = asList(p['enum']).whereType<String>().toList();
    if (options.isNotEmpty) {
      return Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: DropdownButtonFormField<String?>(
          key: Key('arg-$key'),
          initialValue: enums[key],
          decoration: InputDecoration(labelText: label),
          items: [
            DropdownMenuItem(value: null, child: Text(s('tool.any'))),
            for (final o in options) DropdownMenuItem(value: o, child: Text(s('tool.enum.$o', {}, o))),
          ],
          onChanged: (v) => setState(() => enums[key] = v),
        ),
      );
    }
    final isInt = str(p['type']) == 'integer';
    final hint = isInt && p['minimum'] != null ? '${p['minimum']}–${p['maximum']}' : str(p['description']);
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        key: Key('arg-$key'),
        controller: fields[key],
        keyboardType: isInt ? TextInputType.number : TextInputType.text,
        decoration: InputDecoration(labelText: label, helperText: hint.isEmpty ? null : hint),
      ),
    );
  }
}

/// A tool result in plain words where the shape is known, else formatted JSON.
class ToolResult extends StatelessWidget {
  const ToolResult({super.key, required this.name, required this.result, this.privileged = false});
  final String name;
  final Map<String, Object?> result;
  final bool privileged;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final t = Theme.of(context).textTheme;
    Widget rows(List<Widget> children) =>
        Column(key: const Key('tool-result'), crossAxisAlignment: CrossAxisAlignment.start, children: children);
    ListTile row(IconData i, String title, [String? sub]) => ListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      leading: Icon(i),
      title: Text(title),
      subtitle: sub == null || sub.isEmpty ? null : Text(sub),
    );

    if (privileged) {
      return rows([
        row(Icons.hourglass_top, s('tool.requested'), s('tool.requested.body', {'id': str(result['id'])})),
      ]);
    }
    if (result['devices'] is List) {
      final devices = asList(result['devices']).map(asMap).toList();
      return rows([
        Text(s('tool.devices.count', {'n': devices.length}), style: t.titleSmall),
        for (final d in devices)
          row(
            flag(d['new']) ? Icons.fiber_new_outlined : Icons.devices_other,
            str(d['hostname'], str(d['ip'])),
            [str(d['ip']), str(d['mac']), str(d['iface'])].where((x) => x.isNotEmpty).join(' · '),
          ),
      ]);
    }
    if (result['events'] is List) {
      final ev = asList(result['events']).map(asMap).toList();
      return rows([
        Text(s('tool.events.count', {'n': ev.length}), style: t.titleSmall),
        for (final e in ev)
          row(
            str(e['action']) == 'blocked' ? Icons.block : Icons.help_outline,
            str(e['qname']),
            '${str(e['client'])} · ${s('tool.enum.${str(e['action'])}', {}, str(e['action']))} · ${str(e['reason'])}',
          ),
      ]);
    }
    if (result['actions'] is List) {
      final a = asList(result['actions']).map(asMap).toList();
      return rows([
        if (a.isEmpty) Text(s('mcp.none')),
        for (final x in a)
          row(Icons.gpp_maybe_outlined, str(x['summary']), '${str(x['status'])} · ${str(x['principal'])}'),
      ]);
    }
    if (result.containsKey('mem_total_kb') || result.containsKey('load')) {
      String mb(Object? kb) => kb is num ? '${(kb / 1024).round()} MB' : '-';
      final load = asList(result['load']).whereType<num>().map((n) => n.toStringAsFixed(2)).join(' · ');
      return rows([
        row(Icons.speed, s('health.cpu'), load.isEmpty ? '-' : load),
        row(Icons.memory, s('health.mem'), '${mb(result['mem_available_kb'])} / ${mb(result['mem_total_kb'])}'),
        row(
          Icons.thermostat,
          s('health.temp'),
          result['temperature_c'] == null ? '-' : '${result['temperature_c']} °C',
        ),
        row(
          Icons.storage,
          s('health.disk'),
          result['disk_used_percent'] == null ? '-' : '${result['disk_used_percent']} %',
        ),
        for (final a in asList(result['alerts']).map(asMap))
          row(Icons.warning_amber, s('health.alert.${str(a['kind'])}', {}, str(a['kind'])), str(a['detail'])),
      ]);
    }
    return SelectableText(
      const JsonEncoder.withIndent('  ').convert(result),
      key: const Key('tool-result'),
      style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
    );
  }
}
