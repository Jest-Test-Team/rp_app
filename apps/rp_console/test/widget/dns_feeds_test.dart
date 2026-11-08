import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/app/strings.dart';
import 'package:rp_console/features/dns/dns_page.dart';
import 'package:rp_console/features/dns/feeds_section.dart';

import 'modules_test.dart' show applySheet, onDevice;
import 'harness.dart';

void main() {
  test('the app\'s recommended feeds are the device\'s balanced set, and every feed has a description', () {
    final rs = File('../../crates/rp-core/src/dns_feeds.rs').readAsStringSync();
    final ids = RegExp(r'id: "(\w+)"').allMatches(rs).map((m) => m.group(1)!).toList();
    final balanced = RegExp(r'id: "(\w+)",[^}]*?balanced: true', dotAll: true).allMatches(rs).map((m) => m.group(1));
    expect(kBalancedFeeds, balanced.toList());
    for (final id in ids) {
      for (final t in S.tables.values) {
        expect(t['feed.$id'], isNotNull, reason: 'feed.$id');
      }
    }
  });

  test('ages in words', () {
    final s = S(const Locale('en'));
    expect(ago(s, null), 'never');
    expect(ago(s, 1000, now: 1000 + 3 * 3600), '3 h ago');
    expect(ago(s, 1000, now: 1000 + 3 * 86400), '3 days ago');
  });

  testWidgets('turning DNS on enables the recommended threat lists by default', (t) async {
    final h = await onDevice(t, 'DNS firewall', prep: (d) => d.config['dns'] = null);
    expect(find.byKey(const Key('dns-enable-feeds')), findsOneWidget);
    await tapKey(t, 'dns-enable');
    expect(h.device.changes.values.single['patch'], {
      'dns.upstreams': ['1.1.1.1:53', '9.9.9.9:53'],
      'dns.feeds': kBalancedFeeds,
    });
  });

  testWidgets('feeds: status in words, add one, update now; a failure says the old list is kept', (t) async {
    final h = await onDevice(
      t,
      'DNS firewall',
      prep: (d) {
        (d.config['dns']! as Map)['feeds'] = ['stevenblack', 'urlhaus'];
        d.feedFails = {'urlhaus'};
        d.feedsUpdatedAt = DateTime.now().millisecondsSinceEpoch ~/ 1000 - 7200;
      },
    );
    expect(find.text('1000 dangerous domains blocked · updated 2 h ago'), findsOneWidget);
    expect(find.textContaining('the previous list is still used'), findsOneWidget);
    // Phishing Army is recommended but off: offer the recommended set.
    await tapKey(t, 'feeds-balanced');
    await tapKey(t, 'feeds-save');
    await applySheet(t);
    expect((h.device.config['dns']! as Map)['feeds'], kBalancedFeeds);
    await tapKey(t, 'feeds-update');
    expect(h.device.feedUpdates, 1);
    expect(find.textContaining('Updating in the background'), findsOneWidget);
  });
}
