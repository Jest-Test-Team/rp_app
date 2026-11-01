# 腳本說明

所有腳本位於 `rp_app/scripts/`，以 bash 撰寫（`pi-diag.sh` 為 POSIX sh，在 Pi 上執行），並通過 `shellcheck`。

這些是**燒錄與首次開機**用的腳本。Gateway 的工具以 Rust 撰寫（`rpctl`、`rp-dns`、`rp-agent`、`rp-mcp`），安裝程式是 `deploy/install.sh`／`deploy/install.ps1`，說明見 [gateway.md](gateway.md)。

## lib.sh

共用函式，由其他腳本 `source`，不可直接執行。

| 函式 | 用途 |
|---|---|
| `load_env KEY...` | 載入 `local.env`，並要求列出的變數存在且不是 `CHANGE_ME` |
| `yaml_str VALUE` | 輸出 JSON 雙引號字串（也是合法 YAML），避免特殊字元破壞設定檔 |
| `cached_image` | 回傳 `.cache/` 中最新的 `.img.xz` |
| `die` / `warn` / `info` / `ok` | 彩色訊息輸出 |
| `confirm` | 要求使用者輸入指定文字才繼續 |

環境變數 `RP_ENV_FILE` 可指定其他設定檔（測試用）。

## 00-preflight.sh

檢查必要工具，列出所有外接實體磁碟的名稱、大小與分割區。符合 Pi 特徵（`boot`、`bootfs`、`Linux` 分割區）的磁碟會標示為可能的 SD 卡；已知的 USB 螢幕轉接器會標示警告。**不會寫入任何東西。**

## 01-download-image.sh

1. 追蹤 `IMAGE_URL` 的轉址，取得實際檔名。
2. 下載官方 `.sha256`。
3. 快取檔若已存在且雜湊正確就跳過下載；否則下載後驗證，不符即中止。

## 02-flash-sd.sh

```
02-flash-sd.sh DISK [--dry-run]
```

寫入前必須全部通過的安全檢查：

| 檢查 | 目的 |
|---|---|
| 格式為 `diskN` | 只接受整顆磁碟 |
| 等於 `local.env` 的 `SD_DISK` | 指令參數與設定檔要一致，避免打錯 |
| `Device Location` 為 External | 排除內建磁碟 |
| `Removable Media` 為 Removable | 排除外接硬碟 |
| 不是 Mac 開機碟 | 最後一道防線 |
| 小於 64 GB | 排除一般非 SD 卡的大容量裝置 |
| 名稱不是已知的 USB 螢幕轉接器 | 這類裝置也會顯示為可移除磁碟 |
| 輸入磁碟代號確認 | 人工確認 |

通過後執行 `diskutil unmountDisk`、`xz -dc | sudo dd of=/dev/rdiskN bs=4m`、`sync`，並等待 `bootfs` 掛載。`--dry-run` 只做檢查並列出指令。

## 03-configure-boot.sh

```
03-configure-boot.sh [BOOT_DIR] [--no-eject] [--diag]
```

在 boot 分割區（預設 `/Volumes/bootfs`）寫入：

| 檔案 | 內容 |
|---|---|
| `user-data` | 主機名稱、時區、使用者（`openssl passwd -6` 雜湊）、`ssh_pwauth: true`、`runcmd`（解除 rfkill、設定 Wi-Fi 國家、啟用 ssh） |
| `network-config` | netplan v2：`renderer: NetworkManager`、`wlan0` DHCP、regulatory domain、SSID 與密碼 |
| `meta-data` | 更新 `instance_id` 為時間戳，讓 cloud-init 重新套用 |
| `ssh` | 空檔，觸發 `sshswitch.service` 啟用 SSH |

所有使用者提供的字串都經 `yaml_str` 加引號。輸出時會遮罩密碼雜湊與 Wi-Fi 密碼。

| 參數 | 作用 |
|---|---|
| `BOOT_DIR` | 指定其他目錄（測試用） |
| `--no-eject` | 寫完不退出 |
| `--diag` | 加入開機診斷，見 [troubleshooting.md](troubleshooting.md#開機診斷---diag) |

## 04-find-pi.sh

```
04-find-pi.sh [TIMEOUT_SECONDS]   # 預設 480
```

每 5 秒 ping `<PI_HOSTNAME>.local` 並檢查 port 22。逾時後對所在 /24 網段做 ping sweep，再從 ARP 表中找出 Raspberry Pi 與 Edimax 的 MAC 前綴，列出候選 IP 與 SSH 狀態。

## ssh-pi.sh

```
ssh-pi.sh [HOST_OR_IP] [ssh 參數...]
```

`ssh-keygen -R` 清掉舊 host key 後，以 `StrictHostKeyChecking=accept-new` 登入 `<PI_USER>@<host>`。

## wifi-ssid.sh

```
wifi-ssid.sh [SSID | --list]
```

從 `networksetup -listpreferredwirelessnetworks` 取得 Mac 已儲存的 Wi-Fi，讓使用者選擇後以 shell 安全引號寫入 `local.env` 的 `WIFI_SSID`，並重新載入驗證。**只寫 SSID，不讀取也不寫入任何密碼。**

## pi-diag.sh

在 Pi 上執行，由 `03-configure-boot.sh --diag` 複製到 boot 分割區。結果寫到 boot 分割區的 `rp-diag.txt`，Mac 不需 sudo 即可讀取。Wi-Fi 密碼相關字串會被遮罩。

| 模式 | 觸發時機 | 內容 |
|---|---|---|
| `early` | cloud-init `bootcmd`（開機早期，每次開機） | 型號、kernel、`lsusb`、`ip link`、Wi-Fi 驅動 dmesg |
| `full` | cloud-init `runcmd`（開機後期，每個 instance 一次） | 等 60 秒後輸出 cloud-init 狀態、rfkill、IP、NetworkManager 裝置與連線、掃描到的 Wi-Fi、驅動 dmesg、NetworkManager 日誌、cloud-init 錯誤 |


sudo rpctl dns block ads.example tracker.example   # 加入，子網域一起封鎖
sudo rpctl dns unblock tracker.example             # 移除
sudo rpctl dns list                                # 列出
sudo rpctl dns import ./hosts.txt                  # 合併 hosts 格式或一行一個網域的清單
sudo rpctl dns import --url https://<清單網址>      # 只接受 https，有大小上限