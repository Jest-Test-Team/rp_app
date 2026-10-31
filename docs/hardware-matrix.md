# 硬體對照

| 功能 | Pi 1 / Zero（ARMv6） | **Pi 2B（已驗證）** | Pi 3B | Pi 4B / 5 |
|---|---|---|---|---|
| 支援 | ❌ 安裝程式會拒絕 | ✅ armv7 | ✅ armv7／aarch64 | ✅ aarch64 |
| 有線上限 | 100 Mbps | 100 Mbps（USB 2.0） | 約 300 Mbps（USB 2.0） | 1 Gbps |
| 內建 Wi-Fi | 無 | 無（需 USB 網卡） | 2.4 GHz | 2.4／5 GHz |
| base 防火牆 | — | ✅ | ✅ | ✅ |
| VPN exit node | — | ✅ 少數人、上限約 100 Mbps | ✅ | ✅ 建議 |
| DNS 防火牆 | — | ✅（RSS 4.8 MB） | ✅ | ✅ |
| IoT AP | — | ✅ 需要獨立的 WAN（eth0）+ 支援 AP 的網卡 | ✅ | ✅ |
| Agent／MCP | — | ✅ | ✅ | ✅ |

## 這台裝置的實測（Pi 2B Rev 1.1）

- 4× Cortex-A7、armv7l、NEON，無 ARMv8 crypto；RAM 920 MB
- eth0 100 Mbps（LAN9514 USB hub）
- Wi-Fi：Edimax EW-7811Un（RTL8188CUS、驅動 `rtl8192cu`）——**只支援 2.4 GHz**、NetworkManager 回報支援 AP 模式
- 無藍牙；GPIO 可用；I²C／SPI 預設未啟用
- kernel 已內建：wireguard、nf_tables、nft_masq、nft_chain_nat、tun、bridge、8021q、mac80211_hwsim
- 新版 kernel 沒有 `/proc/net/nf_conntrack`；agent 改用 `conntrack -L -o extended`

## 重要前提

- 要把 wlan0 改成 AP，必須先有**另一條管理連線**（eth0）。preflight 會拒絕在管理介面上啟用 AP。
- 2.4 GHz 1T1R 網卡的 AP 吞吐約十幾到 30 Mbps，所有 client 共享——適合 IoT，不適合取代主 Wi-Fi。
