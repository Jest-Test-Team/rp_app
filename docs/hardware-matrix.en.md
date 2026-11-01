# Hardware matrix

[繁體中文](hardware-matrix.md) | **English**

| Feature | Pi 1 / Zero (ARMv6) | **Pi 2B (verified)** | Pi 3B | Pi 4B / 5 |
|---|---|---|---|---|
| Supported | ❌ refused by the installer | ✅ armv7 | ✅ armv7 / aarch64 | ✅ aarch64 |
| Wired ceiling | 100 Mbps | 100 Mbps (USB 2.0) | about 300 Mbps (USB 2.0) | 1 Gbps |
| Built-in Wi-Fi | none | none (needs a USB adapter) | 2.4 GHz | 2.4 / 5 GHz |
| base firewall | — | ✅ | ✅ | ✅ |
| VPN exit node | — | ✅ a few users, about 100 Mbps max | ✅ | ✅ recommended |
| DNS firewall | — | ✅ (RSS 4.8 MB) | ✅ | ✅ |
| IoT AP | — | ✅ needs a separate WAN (eth0) + an AP-capable adapter | ✅ | ✅ |
| Agent / MCP | — | ✅ | ✅ | ✅ |

## This device (Pi 2B Rev 1.1)

- 4× Cortex-A7, armv7l, NEON, no ARMv8 crypto; 920 MB RAM
- eth0 100 Mbps (LAN9514 USB hub)
- Wi-Fi: Edimax EW-7811Un (RTL8188CUS, driver `rtl8192cu`) — **2.4 GHz only**; NetworkManager reports AP mode support
- No Bluetooth; GPIO available; I²C / SPI disabled by default
- Kernel includes: wireguard, nf_tables, nft_masq, nft_chain_nat, tun, bridge, 8021q, mac80211_hwsim
- Recent kernels have no `/proc/net/nf_conntrack`; the agent uses `conntrack -L -o extended` instead

## Power

- A Pi 2 with a USB Wi-Fi adapter needs **5 V / 2.5 A**. This device runs from a dedicated power supply yet still reports intermittent **under-voltage** under load (`under_voltage` in `get_system_health`; "Undervoltage detected" in the kernel log), usually from voltage drop on the micro-USB cable or a supply short on current.
- Under-voltage causes throttling, SD card corruption and USB adapter drop-outs; use a proper supply before running 24/7.

## Key prerequisites

- Turning wlan0 into an AP requires **another management link** (eth0) first. preflight refuses an AP on the management interface.
- A 2.4 GHz 1T1R adapter gives roughly 10–30 Mbps of AP throughput shared by all clients — fine for IoT, not a replacement for the main Wi-Fi.
