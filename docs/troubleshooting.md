# 疑難排解

**繁體中文** | [English](troubleshooting.en.md)

## 快速檢查

| 症狀 | 先檢查 |
|---|---|
| Pi 一直沒出現在網路上 | Wi-Fi 是否有 2.4 GHz、是否為 WPA2、Mac 與 Pi 是否在同一網路 |
| `.local` 找不到但懷疑已上線 | `04-find-pi.sh` 逾時後的 ARP 掃描結果 |
| 不確定有沒有開機 | 把 SD 卡插回 Mac，看下面「判斷 Pi 是否開機成功」 |
| SSH 出現 host key 警告 | 重灌後 key 會改變，用 `ssh-pi.sh`（會先清掉舊 key） |
| `sudo` 要求密碼 | 輸入 `PI_PASSWORD` 即可 |

## 已知問題與根本原因

### 1. Wi-Fi 沒連上：netplan 預設交給 systemd-networkd

**症狀**：Pi 開機成功、cloud-init 也執行了，但從未出現在網路上。

**原因**：Pi OS trixie 的 cloud-init 設定為 `renderers: ['netplan', 'network-manager']`，netplan 未指定 renderer 時預設產生 systemd-networkd 設定；但系統只啟用了 NetworkManager，networkd 沒有啟用，所以 `wlan0` 從未被設定。

**查證方式**：用 `e2fsprogs` 的 `debugfs` 直接讀映像檔的 ext4 分割區，確認 `/etc/cloud/cloud.cfg` 的 renderers、`multi-user.target.wants` 中只有 `NetworkManager.service`、`/etc/netplan` 為空。

**修正**：`network-config` 加上 `renderer: NetworkManager`（與官方 Imager 產生的設定一致）。

### 2. 開機卡住：在 bootcmd 呼叫 systemd

**症狀**：加上診斷後，綠燈閃約 5 秒後熄滅再恆亮；`rp-diag.txt` 只有早期標記，`ssh` 標記檔沒有被處理掉。

**原因**：cloud-init 的 `bootcmd` 在 `sysinit.target` 之前執行，當時 D-Bus 尚未啟動。

- `systemd-run --on-active=…` 會等待 timer 啟動，timer 又依賴 sysinit，sysinit 在等 cloud-init，形成死結。
- 改成 `--no-block` 仍然卡住，因為連線 D-Bus 本身就會等待。

**修正**：`bootcmd` 只做不需 systemd 的快照；完整診斷改放在 `runcmd`（開機後期，D-Bus 與 NetworkManager 都已就緒）。

**原則**：`bootcmd` 中不要呼叫 `systemctl`、`systemd-run`、`nmcli` 或任何需要 D-Bus 的指令。

### 3. 5 GHz 網路

Edimax EW-7811Un 只支援 2.4 GHz。Mac 連在 5 GHz 不代表路由器沒有 2.4 GHz；雙頻同名的路由器可以直接使用，否則需填入 2.4 GHz 的 SSID，或改用手機熱點（開啟「最大相容性」）。

### 4. macOS 隱藏 SSID

沒有定位權限時，`ipconfig getsummary`、`system_profiler` 會把 SSID 顯示為 `<redacted>`。`networksetup -listpreferredwirelessnetworks` 仍可列出已儲存的網路，`wifi-ssid.sh` 即使用此方式。

## 判斷 Pi 是否開機成功

不需網路，把 SD 卡插回 Mac 檢查：

| 跡象 | 代表 |
|---|---|
| Linux 分割區從約 2 GB 擴大到接近整張卡 | 第一次開機的分割區擴充已完成 |
| `cmdline.txt` 中的 `resize` 消失 | 同上 |
| `cmdline.txt` 多了 `cfg80211.ieee80211_regdom=<COUNTRY>` | `runcmd` 已執行 `raspi-config do_wifi_country` |
| `ssh` 標記檔消失 | `sshswitch.service` 已執行，開機已進入後期 |
| `ssh` 標記檔還在 | 開機沒有走到 multi-user 階段 |

## LED 燈號（Pi 2）

| 燈號 | 意義 |
|---|---|
| 紅燈恆亮 | 有電 |
| 綠燈開機時不規則閃爍 | 正在讀取 SD 卡 |
| 綠燈從通電起就恆亮、從未閃爍 | 通常是沒有讀到可開機的映像 |
| 綠燈固定次數重複閃爍 | 開機錯誤碼 |

綠燈的行為會被 kernel 接管，開機後的燈號不足以判斷 Wi-Fi 狀態，請以診斷檔為準。

## 開機診斷（--diag）

```bash
./scripts/03-configure-boot.sh --diag
```

1. SD 卡插回 Pi 開機，等約 6 分鐘（包含 `full` 模式等待的 60 秒）。
2. 拔電，SD 卡插回 Mac。
3. 讀取結果：

```bash
cat /Volumes/bootfs/rp-diag.txt
```

判讀重點：

| 區段 | 看什麼 |
|---|---|
| `lsusb` | 是否有 Edimax `7392:7811` |
| dmesg | `rtl8192cu` 是否載入、韌體 `rtl8192cufw_TMSC.bin` 是否成功 |
| `rfkill list` | wlan 是否被 soft/hard block |
| `nmcli … device` | `wlan0` 狀態（connected / disconnected / unavailable） |
| `nmcli … wifi list` | 是否掃描到目標 SSID、在哪個頻道 |
| NetworkManager 日誌 | 認證失敗、找不到網路等原因 |

只有早期標記、沒有 `full dump` 時，代表開機沒走到 `runcmd`，請參考上面的「開機卡住」。

診斷完成後，不加 `--diag` 再跑一次 `03-configure-boot.sh` 即可移除診斷腳本。

## 讀取 SD 卡的 ext4 分割區（進階）

macOS 無法直接讀 ext4。需要查映像檔內容時：

```bash
brew install e2fsprogs
xz -dkc .cache/<image>.img.xz > .cache/image.img
# 依分割表取出第二分割區後：
$(brew --prefix e2fsprogs)/sbin/debugfs -R "cat /etc/cloud/cloud.cfg" .cache/root.ext4
```

直接讀實體 SD 卡（`/dev/diskNs2`）需要 sudo。用完記得刪除解壓縮的映像檔（數 GB）。

## Gateway 已知問題（開發與實測中發現並已處理）

| 現象 | 原因 | 處理 |
|---|---|---|
| 改了 `ssh.password_auth` 卻沒生效 | sshd 取**第一個**讀到的值；cloud-init 的 `50-cloud-init.conf` 先被讀到 | rpctl 的 drop-in 命名為 `10-rp.conf`，排在前面 |
| 開啟 IPv6 forwarding 後 uplink 失去 IPv6 位址 | forwarding=1 時 kernel 預設忽略 RA | vpn 模組同時設定 `accept_ra = 2` |
| rollback VPN 後仍在轉發 | 刪掉 sysctl 檔不會改變目前的值 | rollback 明確執行 `sysctl -w net.ipv4.ip_forward=0` |
| 裝 `dnsmasq` 後 DNS 埠衝突 | 完整 `dnsmasq` 套件會自動啟動並綁 53 埠 | 只裝 `dnsmasq-base`，以 DHCP-only（`port=0`）執行 |
| AP 套用後失去管理連線 | wlan0 同時是管理介面 | config 與 preflight 都拒絕在管理介面上啟用 AP；先接 eth0 |
| DNS 查詢每次都慢 400 ms | 第一個 upstream 掛掉，每次都等逾時 | upstream 失敗後 30 秒內先跳過（hold-down） |
| 被隔離的 IoT 裝置仍能用舊連線 | 規則在 conntrack 接受 established 之後才檢查 | quarantine 規則放在最先執行的 `mod_prefilter` |
| 稽核 `audit verify` 顯示 chain 斷掉 | rp-agent 與 `rpctl approve` 兩個 process 寫同一個檔，agent 快取了舊的鏈頭 | 每次寫入都加檔案鎖並重新讀取鏈頭 |
| `get_flows` 永遠是空的 | 新版 kernel 沒有 `/proc/net/nf_conntrack` | agent 改用 `conntrack -L -o extended`（agent 模組會安裝 `conntrack`） |
| 防火牆重載後 quarantine 消失 | 重載會重建 table，timeout 元素跟著消失 | `rp-firewall` 啟動／重載後執行 `rpctl quarantine-restore` 補回剩餘時間 |
| `get_system_health` 回報 critical：under_voltage | 供電不足：micro-USB 線太細／太長的壓降，或供應器電流不夠（負載時低於約 4.63 V） | 換 5 V／2.5 A 電源；agent 讀 firmware 的 `rpi_volt` 警報（沙箱看不到 `vcgencmd`） |
| `apply` 在 `apt-get install` 失敗 | apt 每日更新／unattended-upgrades 正持有 dpkg 鎖 | apt 以 `-o DPkg::Lock::Timeout=120` 執行；失敗時尚未安裝任何檔案 |
| `rp-mcp.service` 啟動失敗（`217/USER`） | 另建的 `rp-mcp` 群組與 `DynamicUser=` 自動配置的同名使用者衝突 | token 群組改名為 `rp-mcp-clients`；舊的 `rp-mcp` 群組需 `groupdel` |
| `ssh <host> rp-mcp --stdio` 讀不到 agent token | token 原本只有 root 可讀 | token 改為 `0640 root:rp-mcp-clients`；`usermod -aG rp-mcp-clients <user>` 後重新登入 |
| 接上 Ethernet 後 `ssh <PI_HOST>.local` 偶爾逾時 | mDNS 同時回報 eth0 與 wlan0 兩個位址，連往 wlan0 位址的回應從 eth0 送出 | 改連 eth0 位址；wlan0 改成 AP 後就只剩 eth0 |
| SSH 顯示 `Permission denied (publickey)` | 已設 `ssh.password_auth = false`，這台電腦沒有被授權的金鑰 | 用有授權的金鑰（`ssh -i <KEY>`）；或接螢幕鍵盤在本機把 `password_auth` 改回 `true` 後 `rpctl apply base` |
| preflight 顯示 `ssh_lockout … not running over SSH`，但其實在 SSH 上 | sudo 重設環境變數，`SSH_CONNECTION` 不見了 | rpctl 改從上層 process 讀取 `SSH_CONNECTION` |
| `apply ap` 驗證失敗：`dnsmasq: cannot read {staged:…}` | 只有「整個參數」是 `{staged:…}` 才會被替換，`--conf-file={staged:…}` 沒被替換 | 參數中的 token 一律替換（已修正；失敗時沒有任何變更） |
| IoT client 拿得到位址與 DNS，但完全上不了網 | ap 模組沒有開啟 IPv4 forwarding（netns 測試自己開了，所以沒抓到） | ap 會寫入 `/etc/sysctl.d/91-rp-ap.conf`；檢查 `cat /proc/sys/net/ipv4/ip_forward` 為 1 |
| `install.sh --host` 卡在 sudo | 遠端沒有 TTY，sudo 無法詢問密碼 | 互動執行時改用 `ssh -t` |
| 純文字清單的 `not valid!` 被當成網域 `not` | 一行多個字時只取第一個字 | 非 hosts 格式且有多個字的行視為無效（rp-dns 與 `rpctl dns import` 都已修正） |

## MCP（Claude Code）連不上

```bash
claude mcp list                                    # rp-gateway 是否 ✔ Connected
ssh -i ~/.ssh/rp_mcp_ed25519 -o BatchMode=yes <USER>@<PI_HOST> </dev/null; echo $?   # 金鑰能否登入
sudo systemctl status rp-agent                     # 裝置上 agent 是否在跑
id <USER> | grep rp-mcp-clients                    # 一般 SSH stdio 需要這個群組
```

## Gateway 快速診斷

```bash
sudo rpctl status                 # 各模組是否套用、是否已確認、是否有未套用的變更
sudo rpctl preflight <module>     # 套用前的安全檢查
sudo nft list table inet rp       # 目前生效的規則
sudo journalctl -u rp-firewall -u rp-dns -u rp-agent -u rp-mcp -u rp-ap-hostapd -n 100
sudo rpctl audit verify           # 稽核 chain 是否完整
```
