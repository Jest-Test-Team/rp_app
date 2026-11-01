# 部署狀態與待辦

> 這份文件記錄**這台裝置**目前套用了什麼、還差什麼。網路值一律以佔位符表示。

## 裝置現況

| 項目 | 狀態 |
|---|---|
| 硬體 | Raspberry Pi 2 Model B Rev 1.1、Edimax EW-7811Un（2.4 GHz） |
| 系統 | Raspberry Pi OS Lite 32-bit（trixie），以 SD 卡腳本燒錄、cloud-init 首次開機 |
| 對外連線 | **只有 Wi-Fi（wlan0）**：同時是管理介面與 uplink；尚未接 Ethernet |
| 已安裝 | `rpctl`、`rp-dns`、`rp-agent`、`rp-mcp`（以 `deploy/install.sh --from-source --host` 部署） |
| 設定 | `/etc/rp/rp.toml`：`device.wan_if = "wlan0"`、`lan_cidrs = ["<LAN_CIDR>"]` |

## 模組

| 模組 | 狀態 | 備註 |
|---|---|---|
| `base` | ✅ 已套用並確認 | 預設丟棄 inbound；SSH 只限 LAN；mDNS 保留；journal 上限 64 MB／保留 2 週；密碼登入**仍開啟** |
| `dns` | ✅ 已套用並確認 | 上游 1.1.1.1／9.9.9.9／8.8.8.8；封鎖清單匯入 StevenBlack（76,744 網域，RSS 8.5 MB） |
| `agent` | ✅ 已套用 | rp-agent、rp-mcp 只聽 127.0.0.1；agent token `0640 root:rp-mcp-clients` |
| `vpn` | ⏸ 未套用 | 需要 Tailscale auth key，或 WireGuard 的公開 endpoint 與路由器轉 UDP |
| `ap` | ⏸ 不可用 | wlan0 正被當 uplink；需要 Ethernet 或第二張支援 AP 的 USB 網卡 |

## 裝置健康（`get_system_health`）

| 項目 | 最近一次讀數 |
|---|---|
| 狀態 | **critical** |
| 警報 | **電壓不足**（firmware `rpi_volt` 警報）：電源太弱 |
| 溫度 | 約 42 °C |
| 時鐘 | NTP 已同步 |
| 磁碟 | 20% |

> ⚠️ 目前由 Mac 的 USB-C 孔供電。Pi 2 加 USB Wi-Fi 需要穩定的 **5 V／2.5 A** 電源；電壓不足可能造成 SD 卡損毀與 USB 網卡斷線。

## MCP 連線

- Claude Code 已加入 `rp-gateway`（user scope），經 SSH stdio 連線
- 使用專用金鑰 `~/.ssh/rp_mcp_ed25519`；在裝置上限制為 `restrict,command="/usr/local/bin/rp-mcp --stdio"`（無 shell、無 pty、無 forwarding）
- 目前只有唯讀工具（`stdio_capabilities = ["read"]`）

## 實機驗證紀錄

| 驗證 | 結果 |
|---|---|
| base 套用後新開 SSH、mDNS | ✅ |
| DNS：正常解析（UDP／TCP）、封鎖回 NXDOMAIN、事件寫入 | ✅ |
| `rpctl dns block/unblock` 即時生效 | ✅ |
| MCP stdio：initialize、12 工具、health／inventory／flows（conntrack）、scan 被拒 | ✅ |
| 受限金鑰：不能執行其他指令、無 pty、forwarding 被拒 | ✅ |
| network namespace 整合測試（Pi kernel） | 16／16 |
| e2e（非破壞性） | 6／6 |

## 待辦（需要使用者）

1. **換成 5 V／2.5 A 的電源**（目前電壓不足警報持續中）
2. **路由器 DHCP 的 DNS 改成這台裝置**，並保留一組公共 DNS 作為第二順位（fail-open）
3. **SSH 改用金鑰登入**：建立一般用途金鑰並加入 `authorized_keys`，確認能登入後設 `ssh.password_auth = false` 再 `apply base`
4. **接上 Ethernet**（或加第二張 USB Wi-Fi）→ 才能 `apply ap`、跑 `RP_E2E_APPLY=1` 破壞性 e2e
5. **VPN**：提供 Tailscale auth key（或決定用 WireGuard）
6. **push `pi-wifi-flash`** → 讓 CI（Linux、Windows、hwsim、root netns、cross build）實跑
7. **推 tag `v0.1.0`** → 正式 GitHub Release（之後 `install.sh` 預設的 release 下載才可用）
