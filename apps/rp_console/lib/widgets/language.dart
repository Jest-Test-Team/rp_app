// Language choice: follow the phone, English, or Traditional Chinese.

import 'package:flutter/material.dart';

import '../app/app_state.dart';
import '../app/strings.dart';

String languageLabel(S s, String l) => switch (l) {
  'en' => 'English',
  'zh' => '繁體中文',
  _ => s('lang.system'),
};

/// App-bar button opening the language menu.
class LanguageButton extends StatelessWidget {
  const LanguageButton({super.key, required this.app});
  final AppState app;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return PopupMenuButton<String>(
      key: const Key('lang-menu'),
      icon: const Icon(Icons.translate),
      tooltip: s('lang.title'),
      initialValue: app.language,
      onSelected: app.setLanguage,
      itemBuilder: (_) => [
        for (final l in AppState.languages)
          CheckedPopupMenuItem(
            key: Key('lang-$l'),
            value: l,
            checked: app.language == l,
            child: Text(languageLabel(s, l)),
          ),
      ],
    );
  }
}

/// The same choice as a settings row.
class LanguageSetting extends StatelessWidget {
  const LanguageSetting({super.key, required this.app});
  final AppState app;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) => SegmentedButton<String>(
        key: const Key('lang-setting'),
        segments: [
          for (final l in AppState.languages)
            ButtonSegment(
              value: l,
              label: Text(languageLabel(s, l), key: Key('lang-seg-$l')),
            ),
        ],
        selected: {app.language},
        onSelectionChanged: (v) => app.setLanguage(v.single),
      ),
    );
  }
}
