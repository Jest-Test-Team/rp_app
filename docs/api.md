# 管理 API（rp-api）

**繁體中文** | [English](api.en.md)

API 契約是 `rp-api openapi` 輸出的 OpenAPI 文件（也在 `/v1/openapi.json` 提供，並提交為 [`apps/rp_console/api/openapi.json`](../apps/rp_console/api/openapi.json)；static 測試確保兩者一致）。

## 傳輸

- HTTPS，位址為 `api.listen`（預設 `0.0.0.0:8443`），首次啟動時產生自簽 P-256 憑證；用戶端在配對時釘選其 SHA-256。
- 防火牆只允許 `device.lan_cidrs` 與（`api.allow_tailnet`，預設開啟）tailnet 連到此埠，WAN 一律丟棄；rp-api 本身也會拒絕其他來源。
- body ≤ 256 KiB、標頭讀取逾時 10 秒、`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`。速率限制：每位址每分鐘 600 次請求、120 次簽章請求、10 次配對嘗試。
- 錯誤：`{"error": {"code", "message", "details"?}}`。代碼：`unauthorized` 401、`forbidden`／`pairing_closed` 403、`not_found` 404、`conflict`／`busy`／`state` 409（衝突時含 `details.current_revision`）、`invalid`／`bad_request` 400、`preflight_failed`／`apply_failed`／`verification_failed`／`update_failed` 422（`details` 為 change set 或檢查結果）、`locked`／`rate_limited` 429。

## 驗證

| 類型 | 方式 |
|---|---|
| 公開 | `GET /v1/info`、`GET /v1/openapi.json`、`POST /v1/pairing` |
| 讀取 | `Authorization: Bearer rps_…`，由 `POST /v1/session`（簽章的 `session`）取得，有效 `api.session_minutes`（15）分鐘 |
| 變更 | body 為簽章信封，由 rp-privd 驗證 |

簽章信封：

```json
{"admin_id": "22a94de7fafab8d3", "nonce": "<16-64 個 hex，不可重複>", "expires_at": 1800000060,
 "payload": "{\"op\":\"confirm\",\"id\":\"0123456789abcdef\"}", "signature": "<base64 Ed25519>"}
```

簽章涵蓋 `rp-admin-v1\n<device_id>\n<admin_id>\n<nonce>\n<expires_at>\n<payload>`。`admin_id` 為 base64 公鑰之 SHA-256 的前 8 bytes（hex）。`expires_at` ≤ 現在 + 300 秒。`op`（及其中的 id）必須與 URL 相符。實作用的 golden 值：[`test/fixtures/console/crypto.json`](../test/fixtures/console/crypto.json)。

操作：`session`、`create_changeset {module, expected_revision, patch}`、`preflight {id}`、`apply {id, confirm_secs?}`（30–600）、`confirm {id}`、`rollback {id}`、`set_secret {name, value}`（`ap_passphrase`、`tailscale_auth_key`）、`approve`／`deny {action_id}`、`revoke_admin {admin_id}`、`open_pairing {valid_minutes}`、`mcp_add_client {name, capabilities}`、`mcp_remove_client {name}`、`install_update {tag}`、`rollback_update {}`、`uninstall {confirm_device_id}`。

## 配對

```
client_proof = HMAC-SHA256(secret, "rp-pair-v1|client|<device_id>|<public_key>|<client_nonce>")
server_proof = HMAC-SHA256(secret, "rp-pair-v1|server|<device_id>|<public_key>|<client_nonce>|<cert_sha256>|<admin_id>")
```

`POST /v1/pairing {name, public_key, client_nonce, proof}` → `{admin_id, device_id, cert_sha256, server_proof}`。用戶端必須檢查 `server_proof`，並確認 `cert_sha256` 就是這條連線的憑證，然後釘選它。秘密只能使用一次；五次錯誤的證明會鎖定配對十分鐘。

## Change set patch

各模組以點號鍵值表示；只有下列鍵可以變更（不含裝置事實、不含路徑）：

| 模組 | 鍵 |
|---|---|
| base | `base.allow_mdns`、`base.unattended_upgrades`、`base.journal_max_mb`、`base.confirm_timeout_secs`、`ssh.password_auth`、`ssh.allow_from` |
| dns | `dns.upstreams`、`dns.block`、`dns.allow`、`dns.block_response`、`dns.block_suspicious`、`dns.suspicious_threshold`、`dns.events_retention_days`、`dns.rate_limit_qps`、`dns.upstream_timeout_ms` |
| ap | `ap.interface`、`ap.ssid`、`ap.country`、`ap.channel`、`ap.subnet`、`ap.lease_time`、`ap.dns_servers`、`ap.lan_can_reach_clients`、`ap.allow_lan`、`ap.block_dot` |
| vpn | `vpn.mode`、`vpn.allow_lan`、`vpn.tailscale.hostname`、`vpn.tailscale.auth_key_file`（只能是 `/etc/rp/tailscale.key`）、`vpn.wireguard.{endpoint, listen_port, subnet, client_dns, peers}` |
| agent | `agent.scan_allow`、`agent.scan_max_hosts`、`agent.pending_minutes`、`agent.max_ttl_minutes`、`mcp.rate_limit_per_minute`、`mcp.stdio_capabilities` |
| firewall | `firewall.rules`（`{name, from, to, dest?, proto?, ports?, action, log?}` 陣列） |
| api | `api.allow_tailnet`、`api.session_minutes` |

`null` 會移除鍵（回到預設值）。結果會以整份設定驗證。
