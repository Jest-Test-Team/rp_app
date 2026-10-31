# 架構

## 元件

| Binary | 執行位置 | 角色 | 權限 |
|---|---|---|---|
| `rpctl` | 裝置（root） | 設定、preflight、apply / confirm / rollback、核准特權動作、MCP client 管理、稽核驗證 | 由管理者以 sudo 執行 |
| `rp-dns` | 裝置（systemd） | 過濾、記錄的 DNS 轉發器 | DynamicUser，只有 `CAP_NET_BIND_SERVICE` |
| `rp-agent` | 裝置（systemd） | 唯讀觀測 API、掃描、特權動作**請求** | root 但僅 `CAP_DAC_READ_SEARCH` + `CAP_NET_ADMIN`，`ProtectSystem=strict` |
| `rp-mcp` | 裝置或 Homelab | MCP server（stdio / Streamable HTTP），所有呼叫經 rp-policy | DynamicUser，無任何 capability，秘密以 `LoadCredential` 取得 |
| `rp-probe` | 測試／稽核 | 秘密掃描、DNS／MCP／吞吐量測試工具 | — |

函式庫：`rp-schema`（設定型別）、`rp-core`（驗證、渲染、apply 引擎、各模組）、`rp-policy`（授權、驗證、核准、稽核）、`rp-http`（精簡 HTTP/1.1）。

## 資料平面 vs 控制平面

```
                    ┌──────────── 控制平面（可停機） ────────────┐
 AI client ──MCP──▶ │ rp-mcp ──token──▶ rp-agent ──(唯讀)──▶ /proc /sys DB │
                    │    │ 只能「請求」特權動作                              │
                    └────┼──────────────────────────────────────────────────┘
                         ▼
               pending 請求（檔案）── 人在裝置上執行 `rpctl approve <id>`
                                                     │
 ┌──────────── 資料平面（不依賴控制平面） ───────────▼──────────┐
 │ nftables（table inet rp）· WireGuard／Tailscale · rp-dns · hostapd／dnsmasq │
 └────────────────────────────────────────────────────────────────┘
```

- VPN、DNS、AP、防火牆在 MCP／agent 停止時照常運作。
- 模型永遠無法直接取得 root，也沒有任何 MCP 方法能核准動作。

## 模組（`rpctl apply <module>`）

| 模組 | 管理的檔案 | 依賴 | Dead-man 計時器 |
|---|---|---|---|
| `base` | nftables 基線、`rp-firewall.service`、sysctl 強化、sshd drop-in、unattended-upgrades | — | 有 |
| `vpn` | `nft.d/50-vpn.nft`、forwarding sysctl、WireGuard 設定或 Tailscale apt 來源 | base | 有 |
| `dns` | `rp-dns.service`、`nft.d/40-dns.nft` | base | 有 |
| `ap` | hostapd／dnsmasq 設定與 unit、NetworkManager 交接、`nft.d/60-ap.nft` | base | 有 |
| `agent` | `rp-agent.service`、`rp-mcp.service` | base | 無 |

## 可組合的防火牆

`base` 擁有 `/etc/rp/nftables.nft`：

- 宣告 `table inet rp`、集合與鏈，以及三個擴充鏈：
  - `mod_prefilter`：在 input／forward 的**第一條**就 jump，早於 conntrack 接受既有連線（用於 quarantine）
  - `mod_input`、`mod_forward`：在基本規則之後、記錄與預設 drop 之前
- 最後 `include "/etc/rp/nft.d/*.nft"`

各模組只擁有自己的片段，可獨立 apply／rollback。整份規則仍由一次 `nft -f` 原子載入。模組驗證時會產生「base + 自身片段」的 check-only 合併檔，用 `nft -c` 檢查。

## Apply 流程

1. render → diff（無差異即結束，冪等）
2. preflight：root、OS、必要工具、管理介面 carrier、**目前 SSH 來源在允許清單內**、key-only SSH 需已有金鑰、AP 不得在管理介面上
3. 暫存所有檔案、**備份**所有將被取代的檔案（manifest）
4. 套件前步驟、early 檔案（例如 apt 來源）、`apt-get install`
5. 對暫存檔驗證（`nft -c`、`dnsmasq --test`、`rp-dns check` …）——此時線上系統尚未改變
6. 原子安裝檔案（tmp + rename、明確權限）
7. 啟用步驟；任何失敗自動還原備份
8. 防火牆類模組啟動 dead-man 計時器：未在時限內 `rpctl confirm` 就自動 rollback

## 特權動作流程

```
model ─ tools/call block_device {ip, ttl} ─▶ rp-mcp：能力檢查 → 限速 → 嚴格參數 → 稽核
       ─▶ rp-agent：再次驗證（只限 AP client、非 gateway、TTL 上限）→ 存成 pending → 稽核
人 ─ sudo rpctl approve <id> ─▶ 重新驗證儲存的請求 → nft add element … timeout Nm → 稽核
                                 （逾時由 kernel 自動移除；防火牆重載後由 quarantine-restore 補回剩餘時間）
```

## 秘密的存放

| 秘密 | 位置 | 權限 | 是否寫入渲染檔／備份 |
|---|---|---|---|
| WireGuard server 私鑰 | 裝置上產生於 `/etc/rp/wireguard/private.key` | 0600 | 否（以 `PostUp` 載入） |
| WireGuard client 私鑰 | 只在 `rpctl vpn add-peer` 輸出一次 | — | 否 |
| Tailscale auth key | `vpn.tailscale.auth_key_file` 指向的檔案 | 由管理者設定 | 否 |
| AP 密碼 | `rpctl ap set-passphrase` 寫入 `/etc/rp/ap.psk` | 0600（建立即是） | 否（hostapd 用 `wpa_psk_file`） |
| agent token | 裝置上產生於 `/etc/rp/agent.token` | 0600 | 否（rp-mcp 以 credential 取得） |
| MCP client token | 只輸出一次；儲存 SHA-256 | 0600 | 否 |
