# 安裝步驟

> ⚠️ 燒錄會**清空整張 SD 卡**。

所有指令都在 `rp_app/` 目錄下執行。

## 1. 準備設定檔

```bash
cp local.env.example local.env
chmod 600 local.env
```

| 變數 | 說明 |
|---|---|
| `PI_HOSTNAME` | 主機名稱，SSH 時用 `<PI_HOSTNAME>.local`，預設 `raspberrypi` |
| `PI_USER` | 登入帳號（小寫英數，新版系統沒有預設的 `pi` 帳號） |
| `PI_PASSWORD` | 登入密碼 |
| `WIFI_SSID` | **2.4 GHz** 的 Wi-Fi 名稱 |
| `WIFI_PASSWORD` | Wi-Fi 密碼（WPA2，至少 8 字元） |
| `WIFI_COUNTRY` | Wi-Fi 國家代碼，台灣填 `TW` |
| `SD_DISK` | SD 卡的磁碟代號（步驟 2 查） |
| `IMAGE_URL` | 映像檔來源，預設為最新的 Pi OS Lite armhf |

`WIFI_SSID` 可以從 Mac 已儲存的網路中挑選：

```bash
./scripts/wifi-ssid.sh          # 列出並輸入編號
./scripts/wifi-ssid.sh --list   # 只列出
```

名稱帶 `5G` 的網路會被標示；Edimax 網卡無法使用 5 GHz。

## 2. 找出 SD 卡

```bash
./scripts/00-preflight.sh
```

會列出所有外接磁碟與分割區。**大小相同不代表就是 SD 卡**：USB 螢幕轉接器等裝置也可能以外接磁碟出現，腳本會標示並拒絕它們。確認後把代號（如 `diskN`）填入 `SD_DISK`。

## 3. 下載映像檔

```bash
./scripts/01-download-image.sh
```

下載到 `.cache/`（gitignored）並核對官方 SHA-256；已下載且驗證過會直接跳過。

## 4. 燒錄

```bash
./scripts/02-flash-sd.sh <SD_DISK> --dry-run   # 只做檢查並列出將執行的指令
./scripts/02-flash-sd.sh <SD_DISK>             # 實際寫入
```

實際寫入時需要再輸入一次磁碟代號確認，並輸入 Mac 的 sudo 密碼。因為需要互動輸入，請在 **Terminal.app** 執行。

## 5. 寫入首次開機設定

```bash
./scripts/03-configure-boot.sh
```

寫入 `user-data`、`network-config`、`ssh` 標記檔，並更新 `meta-data` 的 `instance_id`，印出遮罩後的內容，最後自動退出 SD 卡。

## 6. 開機

1. SD 卡插回 Pi，**USB Wi-Fi 網卡保持插著**，接上電源。
2. 第一次開機需要擴充分割區並執行 cloud-init，Pi 2 約需 3～5 分鐘。

```bash
./scripts/04-find-pi.sh      # 預設最多等 8 分鐘，找到後印出 IP
./scripts/ssh-pi.sh          # ssh <PI_USER>@<PI_HOSTNAME>.local
```

`ssh-pi.sh` 會先清掉該主機名稱的舊 host key（重灌後 key 會改變），再以 `accept-new` 登入。

## 7. 驗證

登入後執行：

```bash
hostname
cat /proc/device-tree/model
nmcli -f IN-USE,SSID,CHAN,SIGNAL dev wifi | grep '^\*'
ip -4 -br addr show wlan0
systemctl is-active ssh NetworkManager
cloud-init status
```

預期結果：

- `wlan0` 為 `UP` 並取得區網 IP
- 目前連線的頻道在 1–13（2.4 GHz）
- `ssh`、`NetworkManager` 皆為 `active`
- `cloud-init status` 為 `done`

> Pi OS Lite 沒有內建 `iw`，請用 `nmcli` 查詢 Wi-Fi 狀態。

## 更改 Wi-Fi 或帳號

不需要重新燒錄：

1. Pi 關機，SD 卡插回 Mac。
2. 修改 `local.env`。
3. 重跑 `./scripts/03-configure-boot.sh`。

腳本每次都會寫入新的 `instance_id`，cloud-init 會把卡片視為新機器，在下次開機時重新套用所有設定。

## 備案：Raspberry Pi Imager

不想用腳本時，可用官方 Imager（`brew install --cask raspberry-pi-imager`）：

1. 裝置選 **Raspberry Pi 2**，作業系統選 **Raspberry Pi OS Lite (32-bit)**，儲存裝置選 SD 卡。
2. 「編輯設定」：主機名稱、帳號密碼、Wi-Fi SSID／密碼、國家 `TW`；「服務」分頁勾選啟用 SSH（密碼登入）。
3. 寫入後依步驟 6、7 開機與驗證。
