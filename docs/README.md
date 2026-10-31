# rp-app 文件

讓 Raspberry Pi 2 Model B 不接網路線、不接螢幕，第一次開機就透過 USB Wi-Fi 網卡連上網路並開啟 SSH，全程用 Mac 上的腳本完成。

| 文件 | 內容 |
|---|---|
| [setup.md](setup.md) | 從燒錄到 SSH 登入的完整步驟 |
| [scripts.md](scripts.md) | 每支腳本的用途、參數與安全檢查 |
| [troubleshooting.md](troubleshooting.md) | 已知問題、根本原因與診斷方法 |

## 環境

| 項目 | 說明 |
|---|---|
| 主機 | Raspberry Pi 2 Model B（BCM2836，只能跑 32-bit） |
| 無線網卡 | Edimax EW-7811Un（Realtek RTL8188CUS，驅動 `rtl8192cu`，**只支援 2.4 GHz**） |
| 系統 | Raspberry Pi OS Lite (32-bit, armhf)，Debian 13 trixie |
| 首次開機設定 | cloud-init（NoCloud，讀 boot 分割區的 `user-data`、`network-config`、`meta-data`） |
| 網路管理 | NetworkManager（netplan 產生設定） |
| 操作端 | macOS，需要 `curl`、`xz`、`shasum`、`openssl`、`python3`、`diskutil` |

## 為什麼不用舊系統或 USB 直連

- Pi 2 的 USB 控制器只能當 host，**不支援 USB gadget 模式**，所以無法用一條 USB 線同時供電又連線。
- 原本 SD 卡上的 2015 年 Raspbian 不支援從 boot 分割區讀 Wi-Fi 設定；要改 Wi-Fi 就得寫 ext4 的 rootfs，macOS 預設無法寫入。
- 因此改為重灌新版 Pi OS，並在 boot 分割區（FAT，Mac 可直接寫）放 cloud-init 設定。

## Repo 結構

程式碼在 `rp_app/`（git repo）：

```
rp_app/
├── local.env.example     # 設定範本（可 commit）
├── local.env             # 實際值（gitignored，權限 600）
├── README.md             # 快速上手
└── scripts/
    ├── lib.sh                 # 共用函式
    ├── 00-preflight.sh        # 列出外接磁碟
    ├── 01-download-image.sh   # 下載並驗證映像檔
    ├── 02-flash-sd.sh         # 燒錄（有安全檢查）
    ├── 03-configure-boot.sh   # 寫入 cloud-init 設定
    ├── 04-find-pi.sh          # 等待 Pi 上線
    ├── ssh-pi.sh              # SSH 登入
    ├── wifi-ssid.sh           # 從 Mac 已存的 Wi-Fi 挑 SSID
    └── pi-diag.sh             # 在 Pi 上執行的診斷腳本
```

## 機密資料原則

- 所有實際值（帳號、密碼、Wi-Fi SSID 與密碼、磁碟代號）只存在 `rp_app/local.env`，已列入 `.gitignore`。
- 文件與 commit 中只使用佔位符，例如 `<PI_USER>`、`<WIFI_SSID>`。
- 登入密碼只以 SHA-512 雜湊寫入 SD 卡；**Wi-Fi 密碼會以明文存在 SD 卡的 boot 分割區**（cloud-init 的限制），卡片請妥善保管。
