// A hardware key "next to the user" for the demo and tests: answers the
// simulated device's challenges the way the real key would.

import '../core/hwkey/key_relay.dart';

class FakeKeyRelay implements KeyRelay {
  /// 'approve', 'deny', or a [KeyRelayError] to fail with.
  Object press = 'approve';
  final asked = <String>[];

  @override
  Future<String> sign(String ask, {Duration timeout = const Duration(minutes: 2)}) async {
    asked.add(ask);
    final p = press;
    if (p is KeyRelayError) throw KeyRelayException(p);
    final parts = ask.split(' '); // ASK <id> <nonce>
    return 'DECIDE ${parts[1]} ${p == 'approve' ? 'A' : 'D'} ${parts[2]}';
  }
}
