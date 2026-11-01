# Edge Security Gateway：安裝與操作

**繁體中文** | [English](gateway.en.md)

> 本文所有網路值都是佔位符或文件專用網段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24），請換成自己的值。

## 1. 安裝

> GitHub Release 發佈（推 tag）之前，預設的 release 下載會 404；請先用 `--from-source`。

### 在 Pi 上直接安裝

```bash
curl -fsSLO https://github.com/<OWNER>/<REPO>/releases/latest/download/install.sh
bash install.sh                    # 下載 release、核對 SHA256SUMS、安裝
bash install.sh --release v0.1.0   # 指定版本
bash install.sh --from-source      # 在 Pi 上用 cargo 編譯（慢）
```

### 從 macOS／Linux 部署到 Pi

```bash
deploy/install.sh --host <USER>@<PI_HOST>                 # release
deploy/install.sh --host <USER>@<PI_HOST> --from-source   # 本機 cargo-zigbuild 交叉編譯
```

### 從 Windows 部署到 Pi

```powershell
./deploy/install.ps1 -Target <USER>@<PI_HOST>
./deploy/install.ps1 -Target <USER>@<PI_HOST> -FromSource   # 需要 cargo-zigbuild + zig
```

安裝程式只放 binary（`rpctl`、`rp-dns`、`rp-agent`、`rp-mcp`）與 `/etc/rp/rp.toml` 範例；不會改動網路。解除安裝：`--uninstall`（保留設定）或 `--uninstall --purge`。

- `--host` 部署時，若在終端機執行，遠端 sudo 會用 `ssh -t` 詢問密碼
- Mac 上直接執行（沒有 `--host`）會被拒絕：本機安裝只支援 Linux

## 2. 設定與套用

編輯 `/etc/rp/rp.toml`（範例：`configs/rp.example.toml`）。每個模組都照同樣流程：

```bash
sudo rpctl check                      # 驗證設定
sudo rpctl preflight <module>         # 安全檢查
sudo rpctl apply <module> --dry-run   # 顯示 diff 與將執行的指令
sudo rpctl apply <module>
sudo rpctl confirm                    # 防火牆類變更：在時限內確認，否則自動 rollback
sudo rpctl status
sudo rpctl rollback <module>          # 移除模組：還原到第一次套用前（dead-man 計時器只撤銷最後一次套用）
```

建議順序：`base` → `dns` → `vpn` → （接好 Ethernet 後）`ap` → `agent`。

只有 Wi-Fi、尚未接 Ethernet 時：設 `device.wan_if = "wlan0"`，`base`、`dns`、`agent` 都能用；`vpn` 可用但頻寬有限（同一個 2.4 GHz 無線電收送）；`ap` 會被拒絕。

套件安裝會等待 dpkg 鎖最多 120 秒（例如 apt 每日更新正在跑）。

## 3. base

- 預設丟棄所有 inbound；SSH 只允許 `ssh.allow_from`（預設為 `device.lan_cidrs`）；允許 mDNS 以保留 `<hostname>.local`
- sysctl 強化、sshd 強化（drop-in 名為 `10-rp.conf`，優先於 cloud-init 的設定）、unattended-upgrades
- 確認可用金鑰登入後，再設 `ssh.password_auth = false`；沒有 `authorized_keys` 時 preflight 會拒絕
- journald 上限（降低 SD 卡磨損）：`base.journal_max_mb`（預設 64；設 0 不管理）

### 裝置健康

`rp-agent snapshot health`（或 MCP `get_system_health`）回報溫度、電壓不足、CPU 頻率、NTP、磁碟與記憶體，並給出 `status`（ok／warning／critical）與 `alerts`：

| 警報 | 門檻 |
|---|---|
| under_voltage | firmware 警報為 1（critical） |
| temperature | ≥ 70 °C warning、≥ 80 °C critical |
| disk | ≥ 90% warning、≥ 95% critical |
| memory | 可用 < 10% warning |
| clock | NTP 未同步 warning |

## 4. VPN exit node

```toml
[vpn]
mode = "tailscale"          # 或 "wireguard"
allow_lan = []              # 預設親友完全不能碰 LAN

[vpn.tailscale]
auth_key_file = "/etc/rp/tailscale.key"   # 只放檔案路徑；不要把 key 寫進 rp.toml
```

- **Tailscale**：apply 後到管理後台核准 exit node，再用「Allow use as an exit node」把這台機器分享給親友的 tailnet。
- **WireGuard**：在路由器轉發 UDP `listen_port`；新增 client：

```bash
sudo rpctl vpn add-peer <NAME> --write   # 印出 client 設定與 QR（只顯示一次），並寫入 rp.toml
sudo rpctl apply vpn
sudo rpctl vpn remove-peer <NAME> && sudo rpctl apply vpn   # 撤銷
```

### 在手機與電腦上使用

**Tailscale**（不需路由器設定，CGNAT 也可用）

| 裝置 | 步驟 |
|---|---|
| iPhone／iPad | App Store 安裝 Tailscale → 登入同一帳號 → 「Exit Node」選這台裝置 |
| Android | Play 商店安裝 Tailscale → 登入 → 右上選單「Exit node」→ 選這台裝置 |
| Windows | tailscale.com/download 安裝 → 系統匣圖示 → Exit nodes → 選這台裝置 |
| macOS | App Store 或 tailscale.com/download 安裝 → 選單列圖示 → Exit Node → 選這台裝置 |

- 第一次需在管理後台（Machines → 這台 → Edit route settings）核准「Use as exit node」
- 親友：Share 這台機器並勾選「Allow use as an exit node」，對方用自己的帳號登入
- 驗證：開啟 exit node 後查詢公網 IP，應顯示家裡的 ISP

**WireGuard**（需要公網 IPv4 與路由器轉發 UDP `listen_port`）

| 裝置 | 步驟 |
|---|---|
| iPhone／Android | 安裝 WireGuard App →「新增通道 → 掃描 QR code」（`rpctl vpn add-peer` 輸出）→ 開啟 |
| Windows／macOS | wireguard.com/install 安裝 →「Import tunnel(s) from file」匯入 `.conf` → Activate |

每台裝置各用一個 peer（`rpctl vpn add-peer <NAME> --write`）；QR 與私鑰只顯示一次。

## 5. DNS 防火牆

```toml
[dns]
upstreams = ["1.1.1.1:53", "9.9.9.9:53"]
blocklists = ["/etc/rp/dns/blocklist.txt"]
block = ["ads.example"]
allow = ["cdn.ads.example"]
block_suspicious = false     # 可疑名稱先只記錄
```

- 在路由器的 DHCP 把 DNS 設成這台裝置，**並保留一組公共 DNS 作為第二順位**（fail-open）
- 查看事件：`rp-dns events --action blocked`；測試評分：`rp-dns score <name>`
- 管理封鎖清單（`dns.blocklists` 的第一個檔案；會驗證、去重、保留註解，改完自動 reload）：

```bash
sudo rpctl dns block ads.example tracker.example   # 加入（含子網域）
sudo rpctl dns unblock tracker.example             # 移除
sudo rpctl dns list                                # 列出
sudo rpctl dns import ./hosts.txt                  # 合併 hosts 或一行一個網域的清單
sudo rpctl dns import --url https://<LIST_URL>     # 只接受 https
```

## 6. IoT／訪客 AP

前提：eth0 已接線並設為管理介面。

```toml
[ap]
interface = "wlan0"
ssid = "<IOT_SSID>"
country = "TW"
subnet = "10.77.0.0/24"
block_dot = false            # true：拒絕 IoT client 的 DNS-over-TLS／QUIC（853），讓它們回到 DNS 防火牆
```

- 853 埠連線一律記錄（`rp-ap-dot`／`rp-ap-doq`）；`block_dot = true` 時改為 reject，手機「私人 DNS」設為自動的會立刻改用一般 DNS；若設成**指定主機名稱**的嚴格模式，該裝置會無法解析 DNS

```bash
sudo rpctl ap set-passphrase     # 不回顯；存成 0600，從不出現在設定或備份中
sudo rpctl apply ap
sudo rpctl rollback ap           # 移除 AP（還原到第一次套用前），交還 wlan0 給 NetworkManager 並重新連回原本的 Wi-Fi
```

## 7. Agent 與 MCP

```toml
[agent]
[mcp]
listen = "127.0.0.1:9851"        # 遠端使用請改成 Tailscale 位址
```

```bash
sudo rpctl apply agent
sudo rpctl mcp add-client <NAME> --cap read          # token 只顯示一次
sudo rpctl mcp add-client <NAME> --cap read,active,privileged
sudo systemctl restart rp-mcp
```

連線方式：

- Streamable HTTP：`http://<MCP_LISTEN>/mcp`，Header `Authorization: Bearer <TOKEN>`（預設只聽 127.0.0.1；base 防火牆也不會對外開放 9851）
- stdio：先 `sudo usermod -aG rp-mcp-clients <USER>` 並重新登入，再用 `ssh <USER>@<PI_HOST> rp-mcp --stdio`（預設只有 read 能力；稽核寫到 `~/.local/state/rp-mcp/`）

### 接到 Claude Code（建議：受限制的專用金鑰）

MCP client 在背景啟動、無法輸入密碼，所以用一把沒有 passphrase、但**只能執行 rp-mcp** 的專用金鑰：

```bash
ssh-keygen -t ed25519 -N '' -f ~/.ssh/rp_mcp_ed25519 -C 'rp-mcp'
# 在裝置的 ~/.ssh/authorized_keys 加一行（restrict = 無 shell、無 pty、無 forwarding）：
#   restrict,command="/usr/local/bin/rp-mcp --stdio" ssh-ed25519 AAAA... rp-mcp
claude mcp add --scope user rp-gateway -- \
  ssh -i ~/.ssh/rp_mcp_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes <USER>@<PI_HOST> rp-mcp --stdio
claude mcp list        # rp-gateway: ✔ Connected
```

金鑰外洩時，對方也只能用 MCP 的唯讀工具；撤銷就是刪掉 authorized_keys 裡那一行。

特權動作：

```bash
sudo rpctl actions           # 列出請求
sudo rpctl approve <ID>      # 人工核准；在期限後自動失效
sudo rpctl deny <ID>
sudo rpctl audit verify      # 驗證稽核 hash chain
```

## 8. 測試

```bash
test/run.sh                                     # static unit cli installer security
test/run.sh integration                         # DNS／MCP（不需 root）；netns 案例需 root
RP_ALLOW_ROOT=1 sudo -E test/run.sh integration # Linux：含 network namespace 拓撲
RP_E2E_HOST=<USER>@<PI_HOST> test/run.sh e2e    # 真實裝置（非破壞性）
RP_E2E_APPLY=1 RP_E2E_HOST=… test/run.sh e2e    # 含實際 apply／rollback（需有線管理連線）
```

已上線的裝置（`/etc/rp/rp.toml` 已存在）上 e2e 預設跳過；`RP_E2E_ALLOW_IN_USE=1` 只跑唯讀檢查。

SSH 金鑰：`RP_E2E_KEY=<私鑰檔>`（預設 `~/.ssh/id_ed25519`）；有 passphrase 的金鑰請先 `ssh-add`，再設 `RP_E2E_KEY=agent`。sudo 密碼用 `RP_E2E_SUDO_PASSWORD`。

測試層級與 tag：`static`、`unit`、`cli`、`integration`、`security`、`installer`、`e2e`、`perf`、`hwsim`、`requires-root`、`requires-pi`。
