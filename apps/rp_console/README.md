# RP Security console (Flutter)

The app that installs, pairs and manages RP Security devices — Android, iOS,
macOS, Linux and Windows. It talks to a device's `rp-api` over HTTPS with the
certificate pinned at pairing, and signs every change with an Ed25519 key that
never leaves the platform keystore. See `../../docs/threat-model.md`.

```
lib/
  core/api/        pinned HTTPS transport, typed client, models
  core/auth/       the admin key and signed envelopes (same bytes as rp-policy)
  core/pairing/    one-time pairing codes and HMAC proofs
  core/changes/    create → preflight → review → apply → verify → confirm
  core/provision/  SD-card first boot (Dart port of rp_core::provision), SSH bootstrap
  core/storage/    keystore-backed vault (key + paired devices)
  core/discovery/  mDNS `_rp-security._tcp`
  features/        onboarding, devices, health, dns, ap, firewall, vpn, mcp, settings
api/openapi.json   the API contract (kept equal to `rp-api openapi` by a static test)
```

## Develop

```
flutter pub get
flutter test test/unit test/widget          # no device needed
../../target/debug/rp-api --fake --listen 127.0.0.1:8443 \
    --fake-pairing-secret $(openssl rand -hex 32)   # a simulated device for the app
```

All test layers run from the repository root with Robot Framework:

```
test/run.sh app        # static, unit, widget, contract (real rp-api), security
test/run.sh build      # platform builds this machine can do (others are skipped)
```
