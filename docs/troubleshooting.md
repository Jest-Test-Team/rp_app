# 疑難排解

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
