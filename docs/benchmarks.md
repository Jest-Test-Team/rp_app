# 效能與偵測量測

所有數據都在 **Raspberry Pi 2 Model B Rev 1.1**（4× Cortex-A7、armhf、Raspberry Pi OS trixie、kernel 6.18）上量測，除非另外註明。

## 加密（openssl speed，單核）

| 演算法 | 吞吐量 |
|---|---|
| ChaCha20-Poly1305（WireGuard 使用） | 約 53 MB/s（約 420 Mbit/s） |
| AES-128-GCM | 約 13 MB/s |

結論：WireGuard 的加密不是瓶頸；AES 系的 OpenVPN 不適合這塊板子。

## 防火牆轉發（`70_performance`，network namespace 內的 veth）

| 情境 | 吞吐量 |
|---|---|
| 無規則 | 約 2578 Mbit/s |
| VPN filter + NAT 規則 | 約 2239 Mbit/s（約 13% 開銷） |

veth 是記憶體內的複製，代表 CPU 處理規則的成本，不代表實際網路吞吐。實際上限是 eth0 的 100 Mbps（經 USB 2.0）與上傳頻寬；規則集遠低於這個上限。

**尚未量測**：經 WireGuard／Tailscale 隧道的實際吞吐（需要實機 VPN 與遠端 client）。

## DNS（rp-dns）

| 項目 | 結果 |
|---|---|
| 常駐記憶體（RSS） | 4.8 MB |
| binary 大小（armv7） | 2.9 MB |
| 被封鎖的名稱（本機直接回應） | p95 0.57 ms |
| 轉發到公共 DNS | p50 7.9 ms／p95 20.7 ms |
| 直接查詢公共 DNS（對照） | p50 7.3 ms／p95 20.5 ms |
| 額外延遲 | p50 約 +0.6 ms、p95 約 +0.1 ms |

### 大型封鎖清單

| 項目 | 結果 |
|---|---|
| 匯入 StevenBlack hosts | 76,744 個網域（6 行無效被略過） |
| 匯入後 RSS | 8.5 MB（服務上限 96 MB） |
| SIGHUP 重新載入 | 即時生效，不中斷監聽 |

## DNS 可疑名稱偵測（`32_dns_detection`，預設門檻 60）

| 樣本 | 數量 | 結果 |
|---|---|---|
| 正常名稱（含 CDN／影音／雲端的特殊主機名） | 159 | 誤報 **0%** |
| DNS tunnel 型（hex／base32 payload） | 150 | 偵測 **99.3%** |
| DGA 型（固定種子產生） | 150 | 偵測 **83.3%** |

調整前（門檻 70、沒有新訊號）：DGA 0%、tunnel 55%。評分規則是針對這些樣本調整的，以上數據是可重現的估計，不是對所有網路的保證。

## Binary 大小（armv7，release）

| Binary | 大小 |
|---|---|
| rpctl | 1.8 MB |
| rp-dns | 2.9 MB |
| rp-agent | 2.7 MB |
| rp-mcp | 1.5 MB |
| 發佈壓縮檔 | 約 4.4 MB／target |

## 重現

```bash
# 在 Pi 上（root，隔離的 namespace）
RP_ALLOW_ROOT=1 sudo -E test/run.sh perf
# 任何機器（不需 root）
test/run.sh dns            # 含 32_dns_detection
test/.venv/bin/robot test/suites/71_dns_performance.robot
```

結果寫在 `test/results/perf.json` 與 `test/results/detection.json`。
