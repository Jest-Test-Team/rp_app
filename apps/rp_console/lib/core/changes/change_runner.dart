// Every configuration change the app makes goes through this flow
// (plan §4.3): create → preflight → the user reviews the diff → apply (the
// device arms its own rollback timer) → the app reconnects and verifies →
// confirm. If the app cannot reach the device afterwards it does nothing:
// the device undoes the change by itself when the timer fires.

import 'dart:async';

import 'package:flutter/foundation.dart';

import '../api/client.dart';
import '../api/models.dart';
import '../api/transport.dart';

enum Phase { idle, preparing, review, applying, verifying, awaitingConfirm, confirmed, rolledBack, failed }

class ChangeRunner extends ChangeNotifier {
  ChangeRunner(this.client, {this.confirmSecs = 120, this.autoConfirm = true, this.verify, Duration? retryDelay})
    : retryDelay = retryDelay ?? const Duration(seconds: 2);

  final RpClient client;
  final int confirmSecs;

  /// Confirm automatically once verification succeeds.
  final bool autoConfirm;

  /// Extra check after apply (default: the device answers status()).
  final Future<bool> Function(RpClient)? verify;
  final Duration retryDelay;

  Phase phase = Phase.idle;
  ChangeSet? change;
  List<Check> failedChecks = const [];
  String? error;
  String? errorCode;

  void _set(Phase p) {
    phase = p;
    notifyListeners();
  }

  void _fail(String code, String message, [List<Check> checks = const []]) {
    errorCode = code;
    error = message;
    failedChecks = checks;
    _set(Phase.failed);
  }

  /// Create and preflight. Ends in [Phase.review] or [Phase.failed].
  Future<void> prepare(String module, Map<String, Object?> patch) async {
    error = null;
    errorCode = null;
    failedChecks = const [];
    _set(Phase.preparing);
    try {
      final rev = (await client.status()).revision;
      final cs = await client.createChangeset(module, rev, patch);
      change = cs;
      change = await client.preflight(cs.id);
      _set(Phase.review);
    } on ApiException catch (e) {
      final details = asMap(e.details);
      final checks = asList(details['checks']).map((c) => Check(asMap(c))).where((c) => c.failed).toList();
      if (details.isNotEmpty && details['id'] != null) change = ChangeSet(details);
      _fail(e.code, e.message, checks);
    } on PinMismatch {
      _fail('pin_mismatch', 'The device presented an unexpected certificate.');
    } catch (e) {
      _fail('unreachable', '$e');
    }
  }

  /// Apply the reviewed change, verify, and (by default) confirm it.
  Future<void> applyAndConfirm() async {
    final cs = change;
    if (cs == null || phase != Phase.review) return;
    _set(Phase.applying);
    try {
      change = await client.apply(cs.id, confirmSecs: confirmSecs);
    } on ApiException catch (e) {
      final details = asMap(e.details);
      if (details['id'] != null) change = ChangeSet(details);
      final checks = (change?.verification ?? const <Check>[]).where((c) => c.failed).toList();
      _fail(e.code, e.message, checks);
      return;
    } catch (e) {
      // The connection dropped mid-apply: the device rolls back unless we
      // reach it again and confirm.
      _set(Phase.awaitingConfirm);
      await _verifyThenConfirm();
      return;
    }
    _set(Phase.verifying);
    await _verifyThenConfirm();
  }

  Future<void> _verifyThenConfirm() async {
    final cs = change;
    if (cs == null) return;
    final deadline = DateTime.now().add(Duration(seconds: confirmSecs - 5));
    while (DateTime.now().isBefore(deadline)) {
      try {
        final ok = verify == null ? (await client.status()).revision > 0 : await verify!(client);
        if (ok) {
          if (!autoConfirm) {
            _set(Phase.awaitingConfirm);
            return;
          }
          await confirmNow();
          return;
        }
      } on PinMismatch {
        _fail('pin_mismatch', 'The device presented an unexpected certificate; not confirming.');
        return;
      } catch (_) {
        // Not reachable yet; keep trying until the deadline.
      }
      await Future<void>.delayed(retryDelay);
    }
    // We never got back in: the device rolls back by itself.
    try {
      change = await client.changeset(cs.id);
    } catch (_) {}
    _fail(
      'not_confirmed',
      'The device could not be reached after the change, so it is being rolled back automatically.',
    );
  }

  Future<void> confirmNow() async {
    final cs = change;
    if (cs == null) return;
    try {
      change = await client.confirm(cs.id);
      _set(Phase.confirmed);
    } on ApiException catch (e) {
      // Too late (the timer already rolled back) or another state.
      try {
        change = await client.changeset(cs.id);
      } catch (_) {}
      if (change?.status == ChangeStatus.rolledBack) {
        _set(Phase.rolledBack);
      } else {
        _fail(e.code, e.message);
      }
    }
  }

  Future<void> rollbackNow() async {
    final cs = change;
    if (cs == null) return;
    try {
      change = await client.rollback(cs.id);
      _set(Phase.rolledBack);
    } on ApiException catch (e) {
      _fail(e.code, e.message);
    }
  }

  void reset() {
    change = null;
    error = null;
    errorCode = null;
    failedChecks = const [];
    _set(Phase.idle);
  }
}
