# 實體核准鑰匙（ESP32-S3）

**繁體中文** | [English](approver.en.md)

在設定檔加上 `[approver]` 之後，**核准**任何特權動作（`block_device`、`isolate_client`……）除了原本的 `rpctl approve` 或 App 的管理員簽章，還必須有人在裝置旁的 ESP32-S3 上**長按按鍵**。就算 Claude、MCP client 或手機 App 被騙、被盜，沒有人按鍵，防火牆就不會被動到。**拒絕**動作不需要按鍵。

## 運作方式

```
rpctl approve <id> ／ App 核准（rp-privd）
        │  admin_ops::decide → approver::confirm
        ▼
  ASK <action id> <摘要> <nonce>   ──USB 序列──►  ESP32-S3（燈閃琥珀色）
                                                      │ 長按 BOOT 3 秒＝核准
                                                      │ 短按＝拒絕；超過 wait_seconds＝逾時
  DECIDE <id> A|D <Ed25519 簽章>   ◄──────────────────┘
        │  hwkey::verify：已登記的金鑰、同一個動作、同一個 nonce
        ▼
  執行並寫入稽核紀錄（decided_by = admin:<人>+key:<鑰匙名稱>）
```

- 協定：`crates/rp-wire`（no_std，Pi 與韌體共用同一份原始碼），一行一則訊息、十六進位欄位。
- 簽章內容綁定：網域標籤、動作 id、**動作摘要**（principal、tool、args、summary、ttl、建立／到期時間的 SHA-256）、Pi 產生的一次性 nonce、核准或拒絕。拿舊的簽章、別的動作的簽章、或「拒絕」的簽章，都無法核准。
- 私鑰在第一次開機時用硬體 TRNG 產生，存在 S3 的 flash（`nvs` 分割區，0x9000），只有公鑰會離開板子。
- 鑰匙上按「拒絕」會把請求**直接拒絕**；逾時、拔掉、簽章不符則維持 `pending`，可以再試。

## 安裝

### 1. 燒錄韌體（在 Mac 上）

```bash
cargo install espup espflash --locked && espup install
. ~/export-esp.sh
cd firmware/approver-s3
cargo build --release
espflash flash --chip esp32s3 target/xtensa-esp32s3-none-elf/release/approver-s3
```

USB 線接 S3 標示 **USB** 的那個孔（原生 USB Serial/JTAG，`303a:1001`）。用 `espflash flash` 更新韌體**不會**改變金鑰；`espflash erase-flash` 會清掉金鑰，之後得重新登記。

### 2. 接到 Pi

> ⚠️ Pi 2B 有電壓不足的紀錄。S3 請接在**有獨立供電的 USB hub** 上，不要直接吃 Pi 的 USB 電。

```bash
sudo cp firmware/approver-s3/99-rp-approver.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger
ls -l /dev/rp-approver
```

### 3. 登記金鑰、啟用

```bash
sudo rpctl approver enroll --name main      # 讀取公鑰並信任
sudo rpctl approver enroll --name backup    # 換上第二塊備用鑰匙再登記一次（建議）
sudo rpctl approver list
```

在 `/etc/rp/rp.toml` 加上：

```toml
[approver]
# port = "/dev/rp-approver"
# keys_file = "/etc/rp/approver-keys.toml"
# wait_seconds = 60        # 10-300
```

## 備用鑰匙（ESP32-WROOM）與 profile

`firmware/board-esp32` 是經典 ESP32 的韌體，和 S3 共用 `crates/rp-board`（協定、按鍵規則、profile）。WROOM 經由板上的 USB-UART 晶片連線（CH9102，`1a86:55d4`，Pi 上是 `/dev/ttyUSB*`）；按鍵是 BOOT，指示燈是 GPIO2 的藍燈（請求等待中快閃、按夠久恆亮）。

```bash
cd firmware/board-esp32 && cargo build --release
espflash flash --chip esp32 target/xtensa-esp32-none-elf/release/board-esp32
sudo rpctl approver info --port /dev/ttyUSB0                 # 晶片、韌體、profile、金鑰 id
sudo rpctl approver enroll --name backup --port /dev/ttyUSB0
sudo rpctl approver profile sentry --port /dev/ttyUSB0       # 切換 profile（板子會重開機）
```

- 設定檔的 `backup_port`（預設 `/dev/rp-approver-backup`）在 `port` 沒插東西時使用；udev 規則請用板子的序號綁定（見 `99-rp-approver.rules`）。
- 每塊板子一次跑一個 profile：`approver`、`oob`、`honeypot`、`sentry`、`csi`（S3 不支援 `oob`）。**只有 `approver` 會回應核准請求**；切到其他 profile 時核准會失敗（維持 pending），不會變寬鬆。目前除了 `approver` 以外的 profile 只有切換與狀態回報，功能尚未實作。
- 開啟 USB-UART 時 Pi 會同時放掉 DTR/RTS，避免經典 ESP32 被自動下載電路卡在重置；核准前會先等板子回應 `INFO`，並確認它是已登記的鑰匙且在 `approver` profile。

## 鑰匙遺失或損壞

兩種方式並存：

| 方式 | 做法 |
|---|---|
| 備用鑰匙 | 平常就登記兩把（`main`、`backup`），任一把簽章都有效。遺失的那把用 `sudo rpctl approver revoke <id>` 撤銷。 |
| 本機 bypass | 在裝置上以 root 執行 `sudo rpctl approver bypass --minutes 15`（1–60 分鐘），期間核准不需要鑰匙；`--close` 提前結束。開啟、關閉、每一次靠 bypass 的核准都會寫進稽核紀錄（`hwkey=bypass`）。手動改檔案拉長時間會被忽略。 |

## 限制

- **目前用的是板上的 BOOT 鍵（GPIO0），這是暫時方案**：S3 原生 USB 的 DTR/RTS 控制線也會驅動 GPIO0（用於自動進入燒錄模式），所以主機端可以**假造一次按鍵**；實測燒錄後 GPIO0 會一直讀成「按下」。韌體已加上 arming（請求送到後必須先看到按鈕放開才接受按壓），但正式使用前請在 GPIO4 與 GND 之間接一顆按鈕，並把 `main.rs` 的 `p.GPIO0` 改成 `p.GPIO4`。
- 板子沒有螢幕，按鍵前看不到「要核准的是什麼」；請先用 `rpctl actions` 或 App 確認內容，同一時間只會有一個請求在等待。加一塊 OLED 可以補上這點。
- 沒有啟用 secure boot／flash 加密：拿到板子的人可以讀出 flash 裡的私鑰。鑰匙遺失就立刻撤銷。
- 能以 root 登入裝置的人本來就能修改設定、關掉 `[approver]`；這把鑰匙防的是**遠端**的核准（MCP、App、被盜的管理員金鑰）。
