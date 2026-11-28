// Relays the gateway's challenge to a hardware approval key next to the
// user and brings back the key's signed answer. The app only carries lines:
// it cannot sign, and the gateway checks the signature, its own one-time
// nonce and the request's digest, so a relayed answer cannot be forged or
// reused.

abstract class KeyRelay {
  /// Sends [ask] (an rp-wire `ASK` line from `hwkeyChallenge`) to a nearby
  /// key and returns its `DECIDE` line once someone pressed it.
  Future<String> sign(String ask, {Duration timeout = const Duration(minutes: 2)});
}

/// Why relaying failed.
enum KeyRelayError {
  /// Bluetooth is off, unsupported, or not permitted.
  unavailable,

  /// No rp key advertising nearby.
  noKey,

  /// Nobody pressed the key in time.
  timeout,

  /// The key answered with an error.
  refused,
}

class KeyRelayException implements Exception {
  const KeyRelayException(this.error, [this.detail = '']);
  final KeyRelayError error;
  final String detail;
  @override
  String toString() => 'KeyRelayException($error${detail.isEmpty ? '' : ': $detail'})';
}
