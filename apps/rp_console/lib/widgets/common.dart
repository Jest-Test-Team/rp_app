import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app/strings.dart';
import '../core/api/models.dart';
import '../core/api/transport.dart';

/// Load once, show a spinner, an error with retry, or the data.
class Loader<T> extends StatefulWidget {
  const Loader({super.key, required this.load, required this.builder});
  final Future<T> Function() load;
  final Widget Function(BuildContext, T, VoidCallback reload) builder;

  @override
  State<Loader<T>> createState() => _LoaderState<T>();
}

class _LoaderState<T> extends State<Loader<T>> {
  late Future<T> _f = widget.load();

  void _reload() {
    // Not an arrow body: setState's callback must not return the Future.
    setState(() {
      _f = widget.load();
    });
  }

  @override
  Widget build(BuildContext context) => FutureBuilder<T>(
    future: _f,
    builder: (context, snap) {
      if (snap.hasError) return ErrorView(error: snap.error!, onRetry: _reload);
      if (!snap.hasData) {
        return const Center(
          child: Padding(padding: EdgeInsets.all(32), child: CircularProgressIndicator()),
        );
      }
      return widget.builder(context, snap.data as T, _reload);
    },
  );
}

String describeError(BuildContext context, Object e) {
  final s = S.of(context);
  if (e is PinMismatch) return s('pair.pin');
  if (e is ApiException) {
    if (e.code == 'conflict') return s('change.conflict');
    return e.message;
  }
  return s('common.unreachable');
}

class ErrorView extends StatelessWidget {
  const ErrorView({super.key, required this.error, this.onRetry});
  final Object error;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final pin = error is PinMismatch;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              pin ? Icons.gpp_bad_outlined : Icons.cloud_off_outlined,
              size: 40,
              color: Theme.of(context).colorScheme.error,
            ),
            const SizedBox(height: 12),
            Text(describeError(context, error), key: const Key('error-text'), textAlign: TextAlign.center),
            if (onRetry != null && !pin) ...[
              const SizedBox(height: 12),
              OutlinedButton(onPressed: onRetry, child: Text(s('common.retry'))),
            ],
          ],
        ),
      ),
    );
  }
}

class Section extends StatelessWidget {
  const Section({super.key, required this.title, required this.children, this.trailing});
  final String title;
  final List<Widget> children;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) => Card(
    margin: const EdgeInsets.fromLTRB(16, 8, 16, 8),
    child: Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Expanded(child: Text(title, style: Theme.of(context).textTheme.titleMedium)),
              ?trailing,
            ],
          ),
          const SizedBox(height: 8),
          ...children,
        ],
      ),
    ),
  );
}

class StatTile extends StatelessWidget {
  const StatTile({super.key, required this.label, required this.value, this.warn = false});
  final String label;
  final String value;
  final bool warn;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: warn ? cs.errorContainer : cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: Theme.of(context).textTheme.labelMedium),
          const SizedBox(height: 4),
          Text(value, style: Theme.of(context).textTheme.titleLarge),
        ],
      ),
    );
  }
}

class StatGrid extends StatelessWidget {
  const StatGrid({super.key, required this.tiles});
  final List<Widget> tiles;
  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, c) {
      final cols = c.maxWidth > 700 ? 4 : 2;
      final w = (c.maxWidth - (cols - 1) * 8) / cols;
      return Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [for (final t in tiles) SizedBox(width: w, child: t)],
      );
    },
  );
}

/// Why a module is unavailable on this hardware.
class UnavailableBanner extends StatelessWidget {
  const UnavailableBanner({super.key, required this.cap});
  final ModuleCapability cap;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Section(
      title: s('common.unavailable'),
      children: [
        for (final r in cap.reasons)
          ListTile(
            key: Key('reason-$r'),
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.info_outline),
            title: Text(s.reason(r)),
          ),
      ],
    );
  }
}

Future<void> copyText(BuildContext context, String text) async {
  await Clipboard.setData(ClipboardData(text: text));
  if (context.mounted) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(S.of(context)('common.copied'))));
  }
}
