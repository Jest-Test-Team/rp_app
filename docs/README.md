# rp-app 文件

**繁體中文** | [English](README.en.md)

兩部分：

1. **無線開機**：讓 Raspberry Pi 2 Model B 不接網路線、不接螢幕，第一次開機就透過 USB Wi-Fi 網卡連上網路並開啟 SSH，全程用 Mac 上的腳本完成。
2. **Edge Security Gateway**（Rust）：防火牆基線、VPN exit node、DNS 防火牆、IoT AP、觀測 agent 與受 policy 管控的 MCP server。

目前這台裝置的部署狀態與待辦：[status.md](status.md)。

| 文件 | 內容 |
|---|---|
| [status.md](status.md) | **這台裝置目前套用了什麼、還差什麼** |
| [setup.md](setup.md) | 燒錄 SD 卡、Wi-Fi／SSH 首次開機設定、登入 |
| [scripts.md](scripts.md) | 燒錄相關腳本的用途與安全檢查 |
| [troubleshooting.md](troubleshooting.md) | 已知問題、根本原因與診斷方法 |
| [gateway.md](gateway.md) | Edge Security Gateway：安裝、各模組、MCP、測試 |
| [architecture.md](architecture.md) | 元件、資料平面／控制平面、可組合防火牆、apply 與核准流程 |
| [threat-model.md](threat-model.md) | 攻擊者、對策與對應測試、已知限制 |
| [benchmarks.md](benchmarks.md) | 實測：加密、轉發、DNS 延遲、偵測率、binary 大小 |
| [hardware-matrix.md](hardware-matrix.md) | 各代 Pi 的功能對照與這台裝置的實測 |

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

```
rp_app/
├── Cargo.toml / rust-toolchain.toml   # Rust workspace
├── crates/
│   ├── rp-schema/    # 設定型別（rp.toml）
│   ├── rp-core/      # 驗證、渲染、apply/rollback 引擎、模組 base/vpn/dns/ap/agent
│   ├── rpctl/        # 管理 CLI
│   ├── rp-dns/       # DNS 防火牆
│   ├── rp-policy/    # 授權、參數驗證、核准、稽核
│   ├── rp-http/      # 精簡 HTTP/1.1
│   ├── rp-agent/     # 觀測 API
│   ├── rp-mcp/       # MCP server
│   └── rp-probe/     # 測試／稽核工具
├── deploy/           # install.sh、install.ps1
├── configs/          # rp.example.toml
├── test/             # Robot Framework（suites、resources、fixtures）
├── scripts/          # SD 卡燒錄與首次開機腳本
├── docs/             # 本文件
├── .github/workflows # ci.yml、release.yml
├── local.env.example
└── local.env         # 實際值（gitignored）
```

## 機密資料原則

- 所有實際值（帳號、密碼、Wi-Fi SSID 與密碼、磁碟代號）只存在 `rp_app/local.env`，已列入 `.gitignore`。
- 文件與 commit 中只使用佔位符，例如 `<PI_USER>`、`<WIFI_SSID>`。
- 登入密碼只以 SHA-512 雜湊寫入 SD 卡；**Wi-Fi 密碼會以明文存在 SD 卡的 boot 分割區**（cloud-init 的限制），卡片請妥善保管。
