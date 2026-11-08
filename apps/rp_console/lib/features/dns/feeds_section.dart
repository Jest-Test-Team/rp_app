// Public threat-intelligence feeds for the DNS firewall: which are on, how
// many domains each blocks, when they were last updated (daily on the
// device), and "Update now".

import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/api/transport.dart';
import '../../widgets/change_sheet.dart';
import '../../widgets/common.dart';

/// The recommended set, from the device's catalogue.
List<String> balancedFeeds(List<Map<String, Object?>> catalog) => [
  for (final f in catalog)
    if (f['balanced'] == true) str(f['id']),
];

/// "3 h ago" style age of a unix time.
String ago(S s, int? at, {int? now}) {
  if (at == null) return s('feeds.never');
  final secs = (now ?? DateTime.now().millisecondsSinceEpoch ~/ 1000) - at;
  if (secs < 120) return s('feeds.ago.now');
  if (secs < 7200) return s('feeds.ago.min', {'n': secs ~/ 60});
  if (secs < 172800) return s('feeds.ago.h', {'n': secs ~/ 3600});
  return s('feeds.ago.d', {'n': secs ~/ 86400});
}

class FeedsSection extends StatefulWidget {
  const FeedsSection({super.key, required this.client, required this.feeds, required this.onSaved});
  final RpClient client;

  /// `feeds` from `/v1/dns/stats`: enabled, catalog, status, updated_at.
  final Map<String, Object?> feeds;
  final VoidCallback onSaved;

  @override
  State<FeedsSection> createState() => _FeedsSectionState();
}

class _FeedsSectionState extends State<FeedsSection> {
  late final List<Map<String, Object?>> catalog = asList(widget.feeds['catalog']).map(asMap).toList();
  late final Set<String> saved = asList(widget.feeds['enabled']).whereType<String>().toSet();
  late Set<String> on = {...saved};
  bool updating = false;

  bool get dirty => on.length != saved.length || !on.containsAll(saved);

  Map<String, Object?> _status(String id) =>
      asList(widget.feeds['status']).map(asMap).firstWhere((x) => x['id'] == id, orElse: () => const {});

  Future<void> _save() async {
    final ordered = [
      for (final f in catalog)
        if (on.contains(str(f['id']))) str(f['id']),
    ];
    if (await showChange(context, widget.client, 'dns', {'dns.feeds': ordered})) widget.onSaved();
  }

  Future<void> _updateNow() async {
    final s = S.of(context);
    setState(() => updating = true);
    try {
      await widget.client.updateDnsFeeds();
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(s('feeds.updating'))));
    } on ApiException catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    } finally {
      if (mounted) setState(() => updating = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final t = Theme.of(context).textTheme;
    final balanced = balancedFeeds(catalog);
    final total = [for (final id in saved) integer(_status(id)['entries'])].fold(0, (a, b) => a + b);
    return Section(
      title: s('feeds.title'),
      trailing: IconButton(
        key: const Key('feeds-update'),
        tooltip: s('feeds.update'),
        onPressed: saved.isEmpty || updating ? null : _updateNow,
        icon: const Icon(Icons.sync),
      ),
      children: [
        Text(s('feeds.body'), style: t.bodySmall),
        const SizedBox(height: 4),
        if (saved.isNotEmpty)
          Text(
            s('feeds.summary', {
              'n': total,
              'ago': ago(s, widget.feeds['updated_at'] is int ? widget.feeds['updated_at']! as int : null),
            }),
            key: const Key('feeds-summary'),
            style: t.titleSmall,
          ),
        for (final f in catalog) _feedTile(context, f),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          alignment: WrapAlignment.end,
          children: [
            if (!(on.length == balanced.length && on.containsAll(balanced)))
              OutlinedButton(
                key: const Key('feeds-balanced'),
                onPressed: () => setState(() => on = balanced.toSet()),
                child: Text(s('feeds.balanced')),
              ),
            FilledButton(key: const Key('feeds-save'), onPressed: dirty ? _save : null, child: Text(s('common.save'))),
          ],
        ),
      ],
    );
  }

  Widget _feedTile(BuildContext context, Map<String, Object?> f) {
    final s = S.of(context);
    final id = str(f['id']);
    final st = _status(id);
    final err = st['error'];
    String? state;
    if (saved.contains(id)) {
      state = err is String
          ? s('feeds.error', {'why': err})
          : st.isEmpty
          ? s('feeds.pending')
          : s('feeds.entries', {'n': integer(st['entries'])});
    }
    final desc = s('feed.$id', {}, str(f['blocks']));
    return SwitchListTile(
      key: Key('feed-$id'),
      contentPadding: EdgeInsets.zero,
      value: on.contains(id),
      onChanged: (v) => setState(() => v ? on.add(id) : on.remove(id)),
      title: Row(
        children: [
          Flexible(child: Text(str(f['name']))),
          if (f['balanced'] == true) ...[
            const SizedBox(width: 6),
            Chip(label: Text(s('feeds.recommended')), visualDensity: VisualDensity.compact),
          ],
        ],
      ),
      subtitle: Text(
        [desc, '${s('feeds.license')}: ${str(f['license'])}', ?state].join('\n'),
        style: err is String ? TextStyle(color: Theme.of(context).colorScheme.error) : null,
      ),
      isThreeLine: true,
    );
  }
}
