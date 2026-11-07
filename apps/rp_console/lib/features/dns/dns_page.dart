import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../widgets/change_sheet.dart';
import '../../widgets/common.dart';

final _domain = RegExp(r'^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$');

/// Lower-case, trimmed, without a trailing dot; null if not a domain.
String? normalizeDomain(String input) {
  final d = input.trim().toLowerCase().replaceAll(RegExp(r'\.$'), '');
  return _domain.hasMatch(d) ? d : null;
}

class DnsPage extends StatelessWidget {
  const DnsPage({super.key, required this.client});
  final RpClient client;

  @override
  Widget build(BuildContext context) => Loader<(Map<String, Object?>, Map<String, Object?>, Map<String, Object?>)>(
    load: () async => (await client.moduleConfig('dns'), await client.dnsStats(), await client.dnsEvents(limit: 30)),
    builder: (context, d, reload) {
      final cfg = asMap(asMap(d.$1['config'])['dns']);
      return RefreshIndicator(
        onRefresh: () async => reload(),
        child: ListView(
          children: [
            if (cfg.isEmpty)
              _EnableDns(client: client, onDone: reload)
            else ...[
              _Stats(stats: d.$2),
              _Rules(client: client, cfg: cfg, onSaved: reload),
              _Events(events: d.$3),
            ],
          ],
        ),
      );
    },
  );
}

class _EnableDns extends StatefulWidget {
  const _EnableDns({required this.client, required this.onDone});
  final RpClient client;
  final VoidCallback onDone;
  @override
  State<_EnableDns> createState() => _EnableDnsState();
}

class _EnableDnsState extends State<_EnableDns> {
  final up = TextEditingController(text: '1.1.1.1:53, 9.9.9.9:53');
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Section(
      title: s('module.dns'),
      children: [
        TextField(
          key: const Key('dns-upstreams'),
          controller: up,
          decoration: const InputDecoration(labelText: 'Upstream DNS'),
        ),
        const SizedBox(height: 12),
        FilledButton(
          key: const Key('dns-enable'),
          onPressed: () async {
            final ups = up.text.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty).toList();
            if (await showChange(context, widget.client, 'dns', {'dns.upstreams': ups})) widget.onDone();
          },
          child: Text(s('change.apply')),
        ),
      ],
    );
  }
}

class _Stats extends StatelessWidget {
  const _Stats({required this.stats});
  final Map<String, Object?> stats;
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final rate = (stats['block_rate'] is num) ? (stats['block_rate'] as num) * 100 : 0;
    return Section(
      title: s('dns.stats'),
      children: [
        StatGrid(
          tiles: [
            StatTile(key: const Key('dns-total'), label: s('dns.total'), value: '${integer(stats['total'])}'),
            StatTile(label: s('dns.blocked'), value: '${integer(stats['blocked'])}'),
            StatTile(label: s('dns.rate'), value: '${rate.toStringAsFixed(1)} %'),
          ],
        ),
        const SizedBox(height: 8),
        Text(s('dns.top'), style: Theme.of(context).textTheme.titleSmall),
        for (final t in asList(stats['top_blocked']).take(5))
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            title: Text(str(asMap(t)['domain'])),
            trailing: Text('${asMap(t)['count']}'),
          ),
      ],
    );
  }
}

class _Rules extends StatefulWidget {
  const _Rules({required this.client, required this.cfg, required this.onSaved});
  final RpClient client;
  final Map<String, Object?> cfg;
  final VoidCallback onSaved;
  @override
  State<_Rules> createState() => _RulesState();
}

class _RulesState extends State<_Rules> {
  late List<String> block = asList(widget.cfg['block']).whereType<String>().toList();
  late List<String> allow = asList(widget.cfg['allow']).whereType<String>().toList();
  late bool suspicious = flag(widget.cfg['block_suspicious']);
  late double threshold = integer(widget.cfg['suspicious_threshold'], 60).toDouble();
  final add = TextEditingController();
  String? addError;

  bool get dirty =>
      !_same(block, asList(widget.cfg['block'])) ||
      !_same(allow, asList(widget.cfg['allow'])) ||
      suspicious != flag(widget.cfg['block_suspicious']) ||
      threshold.round() != integer(widget.cfg['suspicious_threshold'], 60);

  static bool _same(List<String> a, List<Object?> b) => a.length == b.length && a.every(b.contains);

  void _add(List<String> to) {
    final d = normalizeDomain(add.text);
    setState(() {
      if (d == null) {
        addError = S.of(context)('dns.add');
        return;
      }
      addError = null;
      if (!to.contains(d)) to.add(d);
      add.clear();
    });
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Section(
      title: s('fw.rules'),
      children: [
        TextField(
          key: const Key('dns-add-field'),
          controller: add,
          autocorrect: false,
          decoration: InputDecoration(labelText: s('dns.add'), errorText: addError),
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          children: [
            OutlinedButton.icon(
              key: const Key('dns-add-block'),
              onPressed: () => _add(block),
              icon: const Icon(Icons.block),
              label: Text(s('dns.block')),
            ),
            OutlinedButton.icon(
              key: const Key('dns-add-allow'),
              onPressed: () => _add(allow),
              icon: const Icon(Icons.check),
              label: Text(s('dns.allow')),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Text(s('dns.block'), style: Theme.of(context).textTheme.titleSmall),
        Wrap(
          spacing: 6,
          children: [
            for (final d in block)
              InputChip(key: Key('block-$d'), label: Text(d), onDeleted: () => setState(() => block.remove(d))),
          ],
        ),
        const SizedBox(height: 8),
        Text(s('dns.allow'), style: Theme.of(context).textTheme.titleSmall),
        Wrap(
          spacing: 6,
          children: [
            for (final d in allow)
              InputChip(key: Key('allow-$d'), label: Text(d), onDeleted: () => setState(() => allow.remove(d))),
          ],
        ),
        SwitchListTile(
          key: const Key('dns-suspicious'),
          contentPadding: EdgeInsets.zero,
          title: Text(s('dns.suspicious')),
          value: suspicious,
          onChanged: (v) => setState(() => suspicious = v),
        ),
        Row(
          children: [
            Text(s('dns.threshold')),
            Expanded(
              child: Slider(
                value: threshold,
                min: 30,
                max: 100,
                divisions: 14,
                label: '${threshold.round()}',
                onChanged: (v) => setState(() => threshold = v),
              ),
            ),
            Text('${threshold.round()}'),
          ],
        ),
        Align(
          alignment: Alignment.centerRight,
          child: FilledButton(
            key: const Key('dns-save'),
            onPressed: dirty
                ? () async {
                    final ok = await showChange(context, widget.client, 'dns', {
                      'dns.block': block,
                      'dns.allow': allow,
                      'dns.block_suspicious': suspicious,
                      'dns.suspicious_threshold': threshold.round(),
                    });
                    if (ok) widget.onSaved();
                  }
                : null,
            child: Text(s('common.save')),
          ),
        ),
      ],
    );
  }
}

class _Events extends StatelessWidget {
  const _Events({required this.events});
  final Map<String, Object?> events;
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Section(
      title: s('dns.events'),
      children: [
        for (final e in asList(events['events']).map(asMap))
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Icon(str(e['action']) == 'blocked' ? Icons.block : Icons.help_outline),
            // Names come from the network: shown as plain text, never interpreted.
            title: Text(str(e['qname']), maxLines: 1, overflow: TextOverflow.ellipsis),
            subtitle: Text('${str(e['client'])} · ${str(e['action'])} · ${str(e['reason'])}'),
          ),
      ],
    );
  }
}
