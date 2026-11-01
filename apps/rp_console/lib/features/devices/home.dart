import 'package:flutter/material.dart';

import '../../app/app_state.dart';
import '../../app/strings.dart';
import '../../core/storage/vault.dart';
import '../onboarding/onboarding.dart';
import 'device_screen.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key, required this.app});
  final AppState app;

  Future<void> _add(BuildContext context) async {
    final d = await Navigator.of(context)
        .push<PairedDevice>(MaterialPageRoute(builder: (_) => OnboardingScreen(app: app)));
    if (d != null && context.mounted) _open(context, d);
  }

  void _open(BuildContext context, PairedDevice d) => Navigator.of(context).push(
    MaterialPageRoute(
      builder: (_) => DeviceScreen(app: app, device: d),
    ),
  );

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) => Scaffold(
        appBar: AppBar(title: Text(s('app.title'))),
        floatingActionButton: app.devices.isEmpty
            ? null
            : FloatingActionButton.extended(
                key: const Key('home-add'),
                onPressed: () => _add(context),
                icon: const Icon(Icons.add),
                label: Text(s('home.add')),
              ),
        body: !app.loaded
            ? const Center(child: CircularProgressIndicator())
            : app.devices.isEmpty
            ? Center(
                child: Padding(
                  padding: const EdgeInsets.all(32),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.shield_outlined, size: 64),
                      const SizedBox(height: 16),
                      Text(s('home.empty.title'), style: Theme.of(context).textTheme.headlineSmall),
                      const SizedBox(height: 8),
                      Text(s('home.empty.body'), textAlign: TextAlign.center),
                      const SizedBox(height: 24),
                      FilledButton.icon(
                        key: const Key('home-add-first'),
                        onPressed: () => _add(context),
                        icon: const Icon(Icons.add),
                        label: Text(s('home.add')),
                      ),
                    ],
                  ),
                ),
              )
            : ListView(
                children: [
                  for (final d in app.devices)
                    Card(
                      margin: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                      child: ListTile(
                        key: Key('device-${d.deviceId}'),
                        leading: const Icon(Icons.router_outlined),
                        title: Text(d.name),
                        subtitle: Text('${d.host}:${d.port}'),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => _open(context, d),
                      ),
                    ),
                ],
              ),
      ),
    );
  }
}
