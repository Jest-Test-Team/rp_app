# RP Security 管理 App（v0.2）

**繁體中文** | [English](console.en.md)

管理 App 以 Flutter 撰寫（Android、iOS、macOS、Linux、Windows），負責安裝、配對與管理裝置。使用者不需要懂 SSH、Rust、nftables 或 MCP；App 也從不取得 root，它只簽署型別化的操作，由裝置自行驗證。

```
App（Flutter）──HTTPS，釘選憑證──▶ rp-api（無特權，只開放 LAN / tailnet）
                                      │ unix socket，只有 rp-api 使用者可連
                                      ▼
                                   rp-privd（root，socket 啟動）
                                      │ 驗證管理員簽章、nonce、期限
                                      ▼
                      rp-core changeset · rpctl · 各模組 · rp-agent
```

## 加入裝置

精靈共六步。先選一條路徑：

| 路徑 | 適用 | 過程 |
|---|---|---|
| 新的 SD 卡（桌面版 App） | 剛用 Raspberry Pi Imager 燒錄 Raspberry Pi OS Lite、**沒有**使用 OS 自訂設定的 SD 卡 | App 把 `user-data`／`network-config`（cloud-init）與獨立的一次性 `rp-pairing.toml` 寫入開機分割區。首次開機時，裝置把秘密移到 `/etc/rp`、在卡上 shred、下載（SHA-256 已釘選的）release 安裝程式並執行 `rpctl setup`。 |
| 已經在執行（SSH） | 已在你的網路上、你能登入的 Pi | 一次 SSH 連線：先顯示主機金鑰；密碼只用一次且只寫給 `sudo -S`，不會儲存；安裝程式檢查 SHA-256；`rpctl setup --json` 透過同一條連線回傳配對碼。 |
| 配對碼 | 裝置上的 `sudo rpctl pairing new`，或另一支手機（設定 › 加入手機） | 貼上 QR 內容，或輸入 64 字元配對碼與位址。 |

接著：尋找裝置（mDNS `_rp-security._tcp`）→ 配對（雙方以 HMAC 證明配對碼，裝置的證明涵蓋其 TLS 憑證，App 將其釘選）→ 這台硬體能做什麼（以文字說明原因，例如「你目前是透過 Wi-Fi 連到這台裝置」）→ 驗證。

不用 App 的同等流程：在裝置上執行 `sudo rpctl setup`（或以 `rpctl bootfs write --dir /Volumes/bootfs --tag v0.2.0 --install-sha256 …` 準備 SD 卡）。

## 變更設定

App 中的每個變更都是一個 **change set**：

1. App 送出經簽章、只含允許鍵值的 patch（沒有檔案路徑、沒有原始 nftables）。
2. 裝置比對目前 revision（他處有修改 → 衝突），驗證整份設定並執行 preflight。preflight 會檢查硬體支援、必要模組，以及 App 本身的位址仍然被允許。
3. 你檢視 `rp.toml` 與系統檔案的 diff。
4. 套用：裝置備份、套用、自我檢查（管理連線、防火牆已載入、服務正常），並啟動回復計時器。
5. App 重新連線後確認。如果 App 連不到裝置，就不會有人確認，**裝置會自行復原**。

| 畫面 | 可以做什麼 |
|---|---|
| 總覽 | 健康狀態（CPU、記憶體、溫度、電壓不足）、模組與無法使用的原因 |
| DNS 防火牆 | 統計、封鎖／允許清單、可疑網域封鎖、最近事件 |
| IoT Wi-Fi | SSID、密碼（以秘密存在裝置上，不會出現在變更內容）、國家、頻道、網段、DoT 封鎖、已連線裝置 |
| 防火牆 | zone 規則 `lan / wan / iot / vpn → … / device`；優先於模組規則生效；任何會切斷管理連線的規則都無法儲存 |
| VPN | Tailscale（auth key 以秘密儲存）或 WireGuard；WireGuard 金鑰在 App 內產生，用戶端設定只以 QR 顯示一次 |
| MCP | 核准或拒絕特權請求（由你簽章）、用戶端（token 只顯示一次）、依等級列出工具、稽核鏈 |
| 設定 | 已配對的 App（撤銷遺失的手機）、加入另一支手機、軟體更新、從裝置移除 RP Security |

## 軟體更新

release 以 minisign 簽章。裝置只會安裝 `SHA256SUMS` 簽章能以 `/etc/rp/minisign.pub`（隨第一次安裝的 release 一起安裝）驗證、且封存檔雜湊相符的 release。新的 `rpctl` 必須先接受目前的設定（`rpctl check`）才會切換。接著所有 binary 一次切換、重啟執行中的服務；只要有一個服務沒有恢復，裝置會自動切回。shell 中可用 `rpctl update install --tag vX`、`rpctl update rollback`、`rpctl update status` 做同樣的事。

維護者：以 `rp-probe release keygen --out-dir keys --password-env MINISIGN_PASSWORD` 建立一次金鑰，將 `keys/minisign.pub` 提交為 `deploy/minisign.pub`，並把 `minisign.key` 與密碼存成 GitHub secrets `MINISIGN_SECRET_KEY`／`MINISIGN_PASSWORD`。release workflow 在沒有簽章時拒絕發佈。

## 開發與測試

```
cd apps/rp_console && flutter test test/unit test/widget
target/debug/rp-api --fake --listen 127.0.0.1:8443 --fake-pairing-secret $(openssl rand -hex 32)
test/run.sh app        # static、unit、widget、對真實 rp-api 的 contract、security
test/run.sh build      # 本機能建置的平台
```

`rp-api --fake` 不是 mock：請求會經過真正的 rp-privd 邏輯（配對、簽章、nonce、change set、秘密、稽核），在模擬裝置上執行，系統指令只記錄不執行。
