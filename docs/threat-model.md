# 威脅模型

## 資產

- 家用 LAN 與 Homelab 的機密性（VPN 使用者、IoT 裝置不應觸及）
- 裝置本身的控制權（root、防火牆）
- 管理者能持續連線到裝置（不被自己的變更鎖在外面）
- 秘密：VPN 金鑰、AP 密碼、各種 token
- 稽核紀錄的完整性

## 攻擊者與對策

| 攻擊者 | 目標 | 對策 | 測試 |
|---|---|---|---|
| 被 prompt injection 操控的 AI 模型 | 任意掃描、改防火牆、執行指令 | 能力分級；參數嚴格驗證（拒絕未知鍵、控制字元與 shell 字元、超出 allowlist 的 CIDR、IPv6、/0、過大範圍）；從不經過 shell；特權動作只能「請求」 | `40_security` |
| 同上 | 自己核准自己的請求 | 沒有任何 MCP 方法或工具能核准；只有裝置上的 `rpctl approve` | `40_security`「A Model Cannot Approve Its Own Request」 |
| 同上 | 修改已儲存的請求 | 核准時重新驗證儲存內容（視為資料而非可信輸入） | `40_security`「Tampered Stored Request」 |
| 惡意 IoT 裝置 | 透過 DHCP 主機名稱或 USB 描述字串注入指令 | agent 拒絕格式錯誤的名稱、只保留可列印 ASCII；MCP 移除控制字元、限制長度；工具說明標示結果為不可信資料 | `34_mcp_integration`「Sanitises Device-Supplied Names」 |
| 惡意 IoT 裝置 | 進入 LAN、攻擊其他 IoT 裝置、管理介面 | AP 隔離：hostapd `ap_isolate`、hairpin drop、LAN 與私有網段 drop、無 IPv6、不得連裝置的 SSH | `30_integration` IoT 案例 |
| 惡意 IoT 裝置 | 被隔離後換 IP 或沿用既有連線 | quarantine 依 IP 與 MAC；在 conntrack 接受既有連線之前（`mod_prefilter`）就丟棄 | `30_integration` quarantine 案例 |
| 惡意 IoT 裝置 | 用 DoH／DoT 繞過 DNS 防火牆 | 記錄 853 埠連線（DoT／DoQ）；DoH 無法只靠 DNS 防護完全阻擋（已知限制） | `23_ap_cli` |
| VPN 使用者（親友） | 進入家用 LAN／Homelab | forward 鏈阻擋 LAN、RFC1918、CGNAT、link-local、ULA、多播；僅 `allow_lan` 明確例外 | `30_integration` VPN 案例 |
| 偷到 MCP 專用 SSH 金鑰的人 | 取得 shell、隧道進內網 | 金鑰在 `authorized_keys` 以 `restrict,command="rp-mcp --stdio"` 限制：其他指令不執行、無 pty、forwarding 被拒；stdio 預設只有 read | 實機驗證（[status.md](status.md)） |
| 區網上的其他程式或瀏覽器 | 呼叫本機 MCP | 每個 client 一組 bearer token；拒絕任何帶 `Origin` 的請求（DNS rebinding） | `40_security` |
| 區網上的其他程式 | 直接呼叫 agent | agent token 與 MCP token 是不同的；agent 只信任 rp-mcp | `40_security` |
| 網路上的攻擊者 | HTTP 請求走私、超大請求 | 拒絕 chunked、限制 header 與 body 大小、逾時、限制連線數 | `40_security`、`rp-http` 單元測試 |
| DNS 濫用者 | 洪泛、畸形封包 | 每個 client 的 token bucket 限速；畸形封包直接丟棄 | `31_dns_integration` |
| 竄改者 | 修改或刪除稽核紀錄 | hash-chain JSONL；`rpctl audit verify` 可指出被修改或刪除的那一行；多個寫入者使用檔案鎖 | `40_security`、`rp-policy` 單元測試 |
| 管理者自己 | 套用錯誤規則而被鎖在外面 | preflight 檢查目前 SSH 來源；`nft -c` 先驗證；dead-man 計時器自動 rollback | `20_cli`、`60_e2e`（destructive） |

## 已知限制

- DNS 防火牆只對使用本裝置作為 DNS 的用戶端有效。DoH 可以繞過；DoT／DoQ 只做記錄。
- 主 LAN 上的裝置無法被封鎖：本裝置不是它們的 gateway。特權工具只對 AP client 有效。
- 評分規則是確定性的啟發式，量測值以固定樣本為準（見 [benchmarks.md](benchmarks.md)），不保證適用於所有網路。
- Wi-Fi 密碼的保護依賴檔案權限；拿到 SD 卡的人可以讀取。
- 不做 TLS 解密（刻意排除）。
