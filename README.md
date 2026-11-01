# rp_app — Raspberry Pi Edge Security Gateway

兩部分：

1. **無線開機設定**（本頁）：用腳本把 SD 卡重灌成 Raspberry Pi OS Lite (32-bit, Trixie)，第一次開機就透過 USB Wi-Fi 連上網、開好 SSH。
2. **Edge Security Gateway**（Rust）：VPN exit node（Tailscale／WireGuard，親友無法進入 LAN）、DNS 防火牆、隔離的 IoT AP、唯讀觀測 agent，以及受 policy 管控、特權動作需人工核准的 MCP server。→ [docs/gateway.md](docs/gateway.md)

### 目前狀態

這台 Pi 2B 已套用 `base`（防火牆基線、SSH 只接受金鑰）、`dns`（DNS 防火牆，含 StevenBlack 清單）、`agent`（agent + MCP），Claude Code 可經 SSH 以唯讀工具查詢。VPN 與 IoT AP 尚待使用者條件（Tailscale key／Ethernet）。詳見 [docs/status.md](docs/status.md)。

### Gateway 快速開始

```bash
# 從 Mac／Linux 部署到 Pi（GitHub Release 發佈前請用 --from-source，需要 zig + cargo-zigbuild）
deploy/install.sh --host <USER>@<PI_HOST> --from-source

# 在 Pi 上：每個模組都先 preflight、dry-run，再 apply；防火牆類變更要在時限內 confirm
sudo rpctl preflight base && sudo rpctl apply base --dry-run
sudo rpctl apply base && sudo rpctl confirm
```

常用操作：

| 做什麼 | 指令 |
|---|---|
| 封鎖／解除網域 | `sudo rpctl dns block <domain>`／`sudo rpctl dns unblock <domain>` |
| 匯入公開封鎖清單 | `sudo rpctl dns import --url https://<LIST_URL>` |
| 查看封鎖事件 | `rp-dns events --action blocked` |
| 模組狀態／復原 | `sudo rpctl status`／`sudo rpctl rollback <module>` |
| 接到 Claude Code | 見 [docs/gateway.md](docs/gateway.md#接到-claude-code建議受限制的專用金鑰) |
| 核准特權請求 | `sudo rpctl actions`、`sudo rpctl approve <id>` |
| 驗證稽核紀錄 | `sudo rpctl audit verify` |

### 開發與測試

```bash
cargo test --workspace            # Rust 單元測試
test/run.sh                       # Robot：static unit cli installer security
test/run.sh integration           # DNS／MCP 整合（Linux root 下另含 network namespace）
```

文件：[docs/](docs/README.md)　狀態：[status](docs/status.md)　架構：[architecture](docs/architecture.md)　威脅模型：[threat-model](docs/threat-model.md)　實測：[benchmarks](docs/benchmarks.md)　疑難排解：[troubleshooting](docs/troubleshooting.md)

---

## 無線開機設定

> ⚠️ 燒錄會**清空整張 SD 卡**。

## 0. 準備 `local.env`

```bash
cp local.env.example local.env   # 已在 .gitignore，不會被 commit
```

| 變數 | 說明 |
|---|---|
| `PI_HOSTNAME` | 主機名稱，SSH 用 `<名稱>.local`，預設 `raspberrypi` |
| `PI_USER` / `PI_PASSWORD` | 登入帳密（新系統沒有 `pi / raspberry` 預設帳號） |
| `WIFI_SSID` / `WIFI_PASSWORD` | **2.4 GHz** 的 Wi-Fi，WPA2 |
| `WIFI_COUNTRY` | `TW` |
| `SD_DISK` | SD 卡的磁碟代號，例如 `disk5`（見步驟 1） |

`WIFI_SSID` 可以從這台 Mac 已儲存的 Wi-Fi 裡挑，密碼自己填：

```bash
./scripts/wifi-ssid.sh          # 列出已儲存的網路，輸入編號
./scripts/wifi-ssid.sh --list   # 只列出
```

## 1. 找出 SD 卡

```bash
./scripts/00-preflight.sh
```

會列出所有外接磁碟。**注意大小一樣的不一定是 SD 卡**：這台 Mac 上 `HYPERDISPLY`（USB 螢幕轉接器）也是 15.7 GB，腳本會標示並拒絕它。把 SD 卡的代號填進 `SD_DISK`。

## 2. 下載映像檔

```bash
./scripts/01-download-image.sh
```

下載最新的 Pi OS Lite armhf 到 `.cache/`，並核對 SHA-256。已下載過就會跳過。

## 3. 燒錄

```bash
./scripts/02-flash-sd.sh disk5 --dry-run   # 先看會做什麼
./scripts/02-flash-sd.sh disk5             # 真的寫入，需要 sudo，要再輸入一次 disk5 確認
```

安全檢查：必須等於 `SD_DISK`、是外接且可移除的整顆磁碟、不是 Mac 開機碟、小於 64 GB、不是 HYPERDISPLY。

## 4. 寫入首次開機設定

```bash
./scripts/03-configure-boot.sh
```

在 `/Volumes/bootfs` 寫入 cloud-init 的 `user-data`（帳號、密碼雜湊、SSH）、`network-config`（Wi-Fi、國家 TW）和 `ssh` 檔，印出遮罩過的內容後自動退出 SD 卡。

- 登入密碼只以 SHA-512 雜湊寫入卡片。
- **Wi-Fi 密碼會以明文存在 SD 卡的 boot 分割區**（cloud-init 的限制），卡片別借人。

## 5. 開機並連線

1. SD 卡插回 Pi，**Edimax 網卡保持插著**，接上電源。
2. Pi 2 第一次開機很慢（擴充分割區、cloud-init），等 3～5 分鐘。

```bash
./scripts/04-find-pi.sh      # 最多等 8 分鐘，找到後印出 IP
./scripts/ssh-pi.sh          # = ssh $PI_USER@$PI_HOSTNAME.local（會清掉舊系統的 host key）
```

連上後確認：

```bash
hostname; nmcli -f IN-USE,SSID,CHAN,SIGNAL dev wifi | grep "^\*"; ip -4 -br addr show wlan0
```

## 連不上時

- Edimax 小網卡**只支援 2.4 GHz**；路由器只開 5 GHz 或只開 WPA3 都會連不上。
- 也可以先用手機熱點（開「最大相容性」/ 2.4 GHz），Mac 連同一個熱點。
- `04-find-pi.sh` 找不到 `.local` 時會掃 ARP 表，列出 Raspberry Pi / Edimax 的 MAC 和 IP。
- 改了 Wi-Fi 設定想重來：SD 卡插回 Mac，只要重跑步驟 4。腳本每次都會換新的 `instance_id`，讓 cloud-init 在下次開機重新套用設定，不用重新燒錄。

## 備案：Raspberry Pi Imager 圖形介面

不想跑腳本也可以用 Imager（`brew install --cask raspberry-pi-imager`）：

1. SD 卡插 Mac，打開 Imager：裝置選 **Raspberry Pi 2**，作業系統選 **Raspberry Pi OS Lite (32-bit)**，儲存裝置選 SD 卡（看清楚，別選到 HYPERDISPLY）。
2. 下一步 →「編輯設定」：主機名稱 `raspberrypi`、自訂帳密、Wi-Fi SSID/密碼、國家 TW；「服務」分頁勾選啟用 SSH（密碼登入）。
3. 寫入後照上面第 5 步開機、`./scripts/04-find-pi.sh`、`./scripts/ssh-pi.sh`。
