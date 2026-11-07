# 部署狀態與待辦

**繁體中文** | [English](status.en.md)

> 這份文件記錄**這台裝置**目前套用了什麼、還差什麼。網路值一律以佔位符表示。

## 裝置現況

| 項目 | 狀態 |
|---|---|
| 硬體 | Raspberry Pi 2 Model B Rev 1.1、Edimax EW-7811Un（2.4 GHz） |
| 系統 | Raspberry Pi OS Lite 32-bit（trixie），以 SD 卡腳本燒錄、cloud-init 首次開機 |
| 對外連線 | **eth0（100 Mbps）**：uplink 與管理介面；wlan0 是 IoT AP |
| 已安裝 | `rpctl`、`rp-dns`、`rp-agent`、`rp-mcp`（以 `deploy/install.sh --from-source --host` 部署） |
| 設定 | `/etc/rp/rp.toml`：`device.wan_if = "eth0"`、`lan_cidrs = ["<LAN_CIDR>"]` |

## 模組

| 模組 | 狀態 | 備註 |
|---|---|---|
| `base` | ✅ 已套用並確認 | 預設丟棄 inbound；SSH 只限 LAN；mDNS 保留；journal 上限 64 MB／保留 2 週；**SSH 只接受金鑰**（密碼與 keyboard-interactive 皆關閉） |
| `dns` | ✅ 已套用並確認 | 上游 1.1.1.1／9.9.9.9／8.8.8.8；封鎖清單匯入 StevenBlack（76,744 網域，RSS 8.5 MB） |
| `agent` | ✅ 已套用 | rp-agent、rp-mcp 只聽 127.0.0.1；agent token `0640 root:rp-mcp-clients` |
| `vpn` | ✅ 已套用並確認（Tailscale） | exit node 已宣告（`0.0.0.0/0`、`::/0`），`--accept-dns=false`；**待使用者在管理後台核准**；VPN client 不能進入 LAN（`allow_lan = []`） |
| `ap` | ✅ 已套用並確認 | wlan0 為 AP（2.4 GHz、channel 6、WPA2）；IoT 網段 10.77.0.0/24；`block_dot = true`（拒絕 DoT／DoQ）；密碼 `/etc/rp/ap.psk`（0600） |

## 裝置健康（`get_system_health`）

| 項目 | 最近一次讀數 |
|---|---|
| 狀態 | **ok**（之前為 critical：電壓不足） |
| 警報 | 無；接上 Ethernet 後的兩次開機都沒有 Undervoltage 紀錄，soak 每 5 分鐘也記錄電壓警報（目前皆 0） |
| 溫度 | 約 50 °C（AP + VPN 運作中） |
| 時鐘 | NTP 已同步 |
| 磁碟 | 20% |

> ⚠️ 裝置由電源供應器直接供電，但 kernel 記錄到間歇性的「Undervoltage detected」（負載時電壓低於約 4.63 V）。常見原因：micro-USB 線太細／太長造成壓降，或供應器實際電流不足。建議改用官方 5.1 V／2.5 A 供應器與短而粗的線。電壓不足可能造成降頻、SD 卡損毀與 USB 網卡斷線。
>
> 重開機驗證（五個模組都套用後，2026-11-01）：約 36 秒恢復 SSH；rp-firewall、rp-dns、rp-agent、rp-mcp、AP（hostapd／dnsmasq）、tailscaled 全部自動啟動；forwarding、DoT reject、VPN／AP 到 LAN 的阻擋、input `policy drop` 都還在；Tailscale exit node 仍為已核准。

## SSH 管理存取

- 管理金鑰 `~/.ssh/rp_admin_ed25519`（有 passphrase；passphrase 存在 macOS 鑰匙圈），`~/.ssh/config` 的 `Host <PI_HOST>` 區塊指定 `IdentityFile` 與 `IdentitiesOnly yes`
- 裝置只接受金鑰登入；sudo 仍需帳號密碼
- 換電腦或遺失金鑰：接螢幕與鍵盤在本機登入，把 `/etc/rp/rp.toml` 的 `ssh.password_auth` 改回 `true` 後 `sudo rpctl apply base && sudo rpctl confirm`（macOS 無法直接寫入 SD 卡的 ext4 根分割區）

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
| e2e（已上線裝置，`RP_E2E_ALLOW_IN_USE=1`，五個模組都已套用） | 8 過、3 個破壞性案例依設計跳過（實機 apply／re-apply／rollback 已另以 ap 驗證） |
| 所有 daemon 與設定版本一致（`rp-dns check`、`rp-agent snapshot`、`rpctl check`） | ✅ 重新部署全部 binary 後通過；舊版 rp-dns 會拒絕 `block_dot`（已由 e2e 案例攔截） |
| `ssh.password_auth = false`：新金鑰連線成功、純密碼連線被拒（`Permission denied (publickey)`）、`sshd -T` 確認 | ✅ |
| mac80211_hwsim AP 測試（Pi kernel） | 5／5 |
| CI（Linux、Windows ps1、hwsim、root netns、armv7／aarch64 cross build） | ✅ 全綠 |
| GHA release dry-run（3 個 target、SHA256SUMS、SBOM） | ✅ 全綠 |
| 切換到 eth0：`mgmt_if` carrier、base／dns／agent 無變更 | ✅ |
| 經 sudo 的 SSH 防鎖死檢查（`ssh_lockout`）：允許清單內 PASS、清單外 FAIL | ✅ |
| `apply ap`：新開 eth0 SSH、wlan0 為 AP、hostapd／dnsmasq active、裝置仍可上網、`rpctl confirm` | ✅ |
| IoT client 實際連線 | ✅ 取得 10.77.0.x、訊號約 -53 dBm |
| IoT client 上網 | ❌→修正：ap 模組原本沒開 `ip_forward`；新增 `/etc/sysctl.d/91-rp-ap.conf` 後重新套用並 confirm，`ip_forward=1` |
| 修正後 netns 整合測試（Pi kernel） | 16／16（舊版 rpctl：AP 測試 4／8 失敗，證明測試能抓到此問題） |
| IoT client 上網（修正後） | ✅ 網站可開；conntrack：51 條連線到公網、3 條到 gateway |
| IoT client 隔離：連路由器管理頁 | ✅ 失敗（被丟棄）；conntrack 中 0 條連到私有／LAN 位址 |
| IoT client 的 DoT（853） | ✅ `block_dot = true`：TCP／UDP 853 被 reject（netns 測試：預設可連、開啟後拒絕、網頁不受影響） |
| `rpctl rollback ap`（套用 → 修改後重新套用 → rollback） | ✅ 所有 AP 檔案、防火牆規則、forwarding 都移除；wlan0 自動重新連回原本的 Wi-Fi（必要時自動重載驅動） |
| 24 小時 AP 穩定性 | 🔄 記錄中：每 5 分鐘一筆，寫到 `/var/lib/rp/ap/soak.log`（自動在 288 筆後停止；重開機會中止） |
| AP 吞吐（iPhone，-41 dBm，link 65 Mbit/s） | 下載峰值 12.6 Mbit/s（5 秒視窗）；上傳未量到；CPU load ≤ 0.34 |

## 待辦（需要使用者）

1. **改善供電**：換官方 5.1 V／2.5 A 供應器或更短更粗的 micro-USB 線（目前間歇性電壓不足）
2. **路由器 DHCP 的 DNS 改成這台裝置**，並保留一組公共 DNS 作為第二順位（fail-open）
3. **IoT AP**：讓至少 3 台裝置連上（24 小時穩定性測試）、用其中一台跑測速（吞吐量測）；並在路由器為 eth0 設 DHCP 保留位址
4. **VPN**：在 Tailscale 管理後台核准 exit node；各裝置安裝 Tailscale 並選擇 exit node（見 [gateway.md](gateway.md#4-vpn-exit-node)）；**撤銷已用過的 auth key**
5. ~~推 tag `v0.1.0`~~ ✅ 已發佈：https://github.com/Jest-Test-Team/rp_app/releases/tag/v0.1.0（已在 Pi 上核對 checksum 並執行 `rpctl`）
