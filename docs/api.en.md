# Console API (rp-api)

[繁體中文](api.md) | **English**

The contract is the OpenAPI document `rp-api openapi` prints (also served at `/v1/openapi.json` and committed as [`apps/rp_console/api/openapi.json`](../apps/rp_console/api/openapi.json); a static test keeps them equal).

## Transport

- HTTPS on `api.listen` (default `0.0.0.0:8443`), self-signed P-256 certificate created on first start; clients pin its SHA-256 at pairing.
- The firewall allows the port from `device.lan_cidrs` and (with `api.allow_tailnet`, the default) the tailnet. The WAN is always dropped, and rp-api refuses other sources too.
- Bodies ≤ 256 KiB, header read timeout 10 s, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. Rate limits: 600 requests/min per address, 120 signed/min, 10 pairing attempts/min.
- Errors: `{"error": {"code", "message", "details"?}}`. Codes: `unauthorized` 401, `forbidden` / `pairing_closed` 403, `not_found` 404, `conflict` / `busy` / `state` 409 (`details.current_revision` on conflicts), `invalid` / `bad_request` 400, `preflight_failed` / `apply_failed` / `verification_failed` / `update_failed` 422 (`details` holds the change set or checks), `locked` / `rate_limited` 429.

## Authentication

| Kind | How |
|---|---|
| Public | `GET /v1/info`, `GET /v1/openapi.json`, `POST /v1/pairing` |
| Read | `Authorization: Bearer rps_…` from `POST /v1/session` (signed `session`), valid `api.session_minutes` (15) |
| Change | The body is a signed envelope, verified by rp-privd |

Signed envelope:

```json
{"admin_id": "22a94de7fafab8d3", "nonce": "<16-64 hex, never reused>", "expires_at": 1800000060,
 "payload": "{\"op\":\"confirm\",\"id\":\"0123456789abcdef\"}", "signature": "<base64 Ed25519>"}
```

The signature covers `rp-admin-v1\n<device_id>\n<admin_id>\n<nonce>\n<expires_at>\n<payload>`. `admin_id` is the first 8 bytes (hex) of SHA-256 over the base64 public key. `expires_at` ≤ now + 300 s. The `op` (and the ids in it) must match the URL. Golden values for implementers: [`test/fixtures/console/crypto.json`](../test/fixtures/console/crypto.json).

Operations: `session`, `create_changeset {module, expected_revision, patch}`, `preflight {id}`, `apply {id, confirm_secs?}` (30–600), `confirm {id}`, `rollback {id}`, `set_secret {name, value}` (`ap_passphrase`, `tailscale_auth_key`), `approve` / `deny {action_id}`, `revoke_admin {admin_id}`, `open_pairing {valid_minutes}`, `mcp_add_client {name, capabilities}`, `mcp_remove_client {name}`, `install_update {tag}`, `rollback_update {}`, `uninstall {confirm_device_id}`.

## Pairing

```
client_proof = HMAC-SHA256(secret, "rp-pair-v1|client|<device_id>|<public_key>|<client_nonce>")
server_proof = HMAC-SHA256(secret, "rp-pair-v1|server|<device_id>|<public_key>|<client_nonce>|<cert_sha256>|<admin_id>")
```

`POST /v1/pairing {name, public_key, client_nonce, proof}` → `{admin_id, device_id, cert_sha256, server_proof}`. The client must check `server_proof` and that `cert_sha256` is the certificate of this very connection, then pin it. A secret works once; five wrong proofs lock pairing for ten minutes.

## Change set patches

Dotted keys per module; only these can be changed (no device facts, no paths):

| Module | Keys |
|---|---|
| base | `base.allow_mdns`, `base.unattended_upgrades`, `base.journal_max_mb`, `base.confirm_timeout_secs`, `ssh.password_auth`, `ssh.allow_from` |
| dns | `dns.upstreams`, `dns.block`, `dns.allow`, `dns.block_response`, `dns.block_suspicious`, `dns.suspicious_threshold`, `dns.events_retention_days`, `dns.rate_limit_qps`, `dns.upstream_timeout_ms` |
| ap | `ap.interface`, `ap.ssid`, `ap.country`, `ap.channel`, `ap.subnet`, `ap.lease_time`, `ap.dns_servers`, `ap.lan_can_reach_clients`, `ap.allow_lan`, `ap.block_dot` |
| vpn | `vpn.mode`, `vpn.allow_lan`, `vpn.tailscale.hostname`, `vpn.tailscale.auth_key_file` (only `/etc/rp/tailscale.key`), `vpn.wireguard.{endpoint, listen_port, subnet, client_dns, peers}` |
| agent | `agent.scan_allow`, `agent.scan_max_hosts`, `agent.pending_minutes`, `agent.max_ttl_minutes`, `mcp.rate_limit_per_minute`, `mcp.stdio_capabilities` |
| firewall | `firewall.rules` (array of `{name, from, to, dest?, proto?, ports?, action, log?}`) |
| api | `api.allow_tailnet`, `api.session_minutes` |

`null` removes a key (back to its default). The result is validated as a whole.
