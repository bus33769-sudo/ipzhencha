# IP侦查 · IPZhencha（ipzhencha.com）

IP 质量检测站：查任意 IP 的国家、类型（家宽/机房）、原生/租赁标记、黑名单与滥用历史，每项结论摆出多家来源原始判定，分歧与数据缺失如实标明。中英双语。方案原件：`~/workspace/your_files/ip-zhiliang-jiance-zhan-fangan-20261112.md`；立项表：`qidong-moban-yitian.md`。

当前状态：**免 Key 在线判定 + 4 个带 Key 适配器均已真实实现，部署包已备好（dist/deploy/），未部署**。前端五块渲染、Worker 路由与缓存、评分引擎已就位并通过 mock 测试；PTR 反查、租赁判定、RPKI 已用免 Key 公开接口实接并通过真实在线测试；DNSBL 已全量接入 13 个现役名单并逐项列出（2026-11-12 核对+实测，见下「DNSBL 全量 13 名单」）；AbuseIPDB / proxycheck / ipapi.is / IP2Location 适配器已于 2026-11-13 改为真实实现并通过 mock-fetch 单元测试（`test/adapters.mjs`，48 条断言），账号已由 lucky 本人注册完毕，Key 只待部署时由本人填入 Worker Secrets——无 Key 或调用失败时一律如实标 `returned:false` 并带原因码，不假装有数据。MaxMind GeoLite 为**后置源**（见下），自建风险库待 V1.5。

## 目录说明

```
ipzhencha/
├─ qidong-moban-yitian.md   四合一立项表（已填版）
├─ web/                     静态前端（Cloudflare Pages），原生 JS，无构建步骤
│  ├─ index.html            检测页：自己 IP 占位、输入框、五块报告渲染
│  ├─ app.js                双语 i18n + 取 /api/check 渲染
│  ├─ style.css
│  └─ about.html            评分公式摘要、数据源署名（占位）、隐私说明
├─ worker/
│  ├─ wrangler.toml         name=ipzhencha-api（占位配置，无任何真实 Key）
│  └─ src/
│     ├─ index.js           Worker 入口：/api/check、/json、curl 纯文本简报；Cache API 缓存 15 分钟；数据源适配器
│     ├─ scoring.js         纯函数评分引擎（方案第 8 节公式 + 完整度闸门）
│     ├─ livecheck.mjs      免 Key 在线判定纯函数：PTR 反查 / 租赁判定 / RPKI（只用 fetch，Node 与 Worker 通用）
│     └─ dnsbl.mjs          DNSBL 全量查询纯函数：13 个现役名单逐家返回码语义 + 8 个已移除名单及原因（只用 fetch，Node 与 Worker 通用）
└─ test/
   ├─ fixtures.mjs          5 个已知 IP 的固化 mock 判定（2026-11-12 实测结论）
   ├─ run.mjs               评分断言测试（mock，含养号适合度断言），node 直接跑
   ├─ live.mjs              在线判定真实调用测试（打 dns.google / rdap.org / RIPEstat，9 条断言），node 直接跑
   ├─ dnsbl.mjs             DNSBL 真实在线验证（RFC 5782 正负对照 + 台湾家宽 + 美国机房参考跑），node 直接跑
   └─ adapters.mjs          带 Key 适配器单元测试（mock fetch + 文档化响应 fixture，48 条断言），node 直接跑
```

## 在线判定已接入 / 待接入清单

已接入（免 Key，2026-11-12 真实在线测试全过，`node test/live.mjs`）：

| 判定项 | 实现 | 数据来源 |
|---|---|---|
| PTR 反查 | `livecheck.fetchPtr`：DoH 查 PTR，返回域名；含 dynamic/dyn/dsl/cable/residential 等模式或以 `.hinet.net` 等已知家宽后缀结尾 → 家宽格式硬证据（模式/后缀为可扩展常量，在 `livecheck.mjs` 里注明依据） | dns.google DoH |
| 租赁判定 | `livecheck.checkLeased`：RDAP 登记方（registrant 实体名/网络名）vs RIPEstat 宣告 ASN 的 holder 名，品牌词元归一化比对；明显不一致 → `leased=true` 并输出含双方名称的证据字符串；同体系 → `false`；只有一方数据 → `null`（未知，不许猜） | rdap.org（跳转权威 RIR）+ RIPEstat network-info / as-overview |
| 宣告 ASN / 前缀 | `livecheck.fetchNetworkInfo`，租赁与 RPKI 共用 | RIPEstat network-info |
| RPKI | `livecheck.fetchRpki`：状态 valid/invalid/unknown 原样映射到 scoring 的 `rpki` 字段 | RIPEstat rpki-validation |
| DNSBL 黑名单逐项 | `dnsbl.checkDnsbl`：13 个现役名单全量查询，逐名单按各自公开文档解释返回码（见下节），报告逐项列出 status 与原始码；受限/无回答/文档外码一律 `listed:null` | dns.google DoH |
| 养号适合度标记（2026-11-12 用户批准） | `scoring.scoreIP` 输出 `suitability{tier, reasons[]}`：unknown（源 <4）→ avoid（Tor/恶意名单/置信度 ≥50/近 180 天举报 ≥20 次/分数 <50 任一）→ suitable（家宽或移动 + 分数 ≥70 + 零滥用记录含旧举报 + 代理标记 <2 源 + 源 ≥7）→ 其余 daily；理由为稳定英文 key，引擎内置中文说明（`SUITABILITY_REASON_ZH`）供 curl 简报，结论卡徽章四色 + 双语理由 + 固定免责小字 | 本地判定（基于各源归一化结果） |

接入路径：`index.js` 的 `srcLive` 适配器 → `normalize` 把 `rdns` / `leased` / `rpki` 喂给评分引擎，PTR 家宽格式另在 sources 里单列一条 `ptr` 硬证据票；证据原文随报告 `sources.livecheck` 一起返回，前端可直接展示。实测注意：rdap.org 对 fetch 默认 UA 返回 403，`livecheck.mjs` 里统一带 `user-agent: ipzhencha/0.1` 自报家门后正常。

带 Key 适配器（2026-11-13 已真实实现，`index.js` 内 `srcAbuseIPDB/srcProxycheck/srcIpapiIs/srcIp2Location`）：

| 源 | 实现要点 |
|---|---|
| AbuseIPDB | `GET /api/v2/check?maxAgeInDays=365&verbose`，请求头带 Key；映射置信度、总举报数、举报人数（numDistinctUsers）、最近举报时间，并用 verbose 的 reports 数组精确数出近 180 天内举报条数（reportsWithin180Days）；评分三种情形（置信度 ≥50 / 180 天内举报 ≥20 次 / 仅历史旧记录）所需字段齐备 |
| proxycheck | `GET /v2/<ip>?vpn=1&asn=1&risk=1&port=1&seen=1&days=30`；映射 proxy yes/no、type（Residential/Business/Wireless/Hosting 等）、risk、asn、provider、port、seen；devices/operator 等套餐字段若有则带回 |
| ipapi.is | `GET api.ipapi.is?q=<ip>&key=`；映射 company.type / asn.type（类型投票）、is_datacenter/is_proxy/is_vpn/is_tor/is_abuser/is_mobile、location 国家城市、ASN |
| IP2Location.io | `GET api.ip2location.io/?package=WS25`；免费套餐若不支持 WS25（返回 error 对象）自动退回默认字段集，报告里 `package` 字段如实标注实际用包；映射 country/region/city、isp、usage_type、is_proxy 及 proxy.type/provider；字段名兼容现行文档名与 WS 式旧名 |

统一纪律：每家超时 6 秒（AbortController）；HTTP 错误、超时、JSON 解析失败、API 业务错误都只返回 `returned:false` + 原因码（`no_key` / `http_<状态码>` / `timeout` / `bad_json` / `network_error` / `api_error` / `bad_shape`），永不抛异常中断整份报告。Key 只从 env（Worker Secrets）读。

**类型投票与完整度口径（2026-11-13 对齐）：** 类型投票源 = proxycheck、ipapi.is、IP2Location 三家（各自归一化映射见 `normalize`）+ PTR 家宽硬证据票 + scoring 内部 rdns 正则票，胜出类型仍需 ≥3 票。完整度计数 = 参与源逐条（rdap、dnsbl、tor、livecheck[PTR/租赁/RPKI 汇总一条]、abuseipdb、proxycheck、ipapiis、ip2location，外加 PTR 票单列一条），分母与之一致；TEST_ONLY 的 ip-api 适配器未启用时不进结果列表、不占分母。

**后置源（不进结果、不进完整度分母、不算失败源）：**

| 项 | 状态 |
|---|---|
| MaxMind GeoLite2 | **后置**：下载型离线数据库，无法塞进「Cloudflare 后台粘贴代码」的部署方式；待后续用 GitHub Actions 定时构建离线库（City/ASN）后启用。代码里以 `DEFERRED_SOURCES` 常量标注并随报告 `deferredSources` 字段如实输出，完整度计数不把它算作失败源。MaxMind 账号与 License Key 已由 lucky 注册自存（见注册清单第 6 行），启用时再用 |
| IPinfo Lite 离线库 | 同为离线库路线，随 MaxMind 一并后置评估 |
| 自建风险库（方案 V1.5） | 未开始：GitHub Actions 每 6 小时聚合公开名单、C 段画像、`segmentRiskCount` 仍为占位 0 |

## DNSBL 全量 13 名单（2026-11-12 逐家核对文档 + RFC 5782 测试点实测，`node test/dnsbl.mjs` 全过）

实现：`worker/src/dnsbl.mjs`。每个名单单独定义返回码语义，不再是「有 A 记录就算命中」：

| 名单 | 命中语义（按其公开文档） |
|---|---|
| zen.spamhaus.org | 码 127.0.0.2–.11 为命中（逐码含义随报告给出，.10/.11 为 PBL 策略列入）；127.255.255.x 为查询错误码记**受限**；经公共解析器时官方明示 NXDOMAIN 不证明未命中，故空回答也记**受限**，永不冒充未命中 |
| bl.spamcop.net | 仅 127.0.0.2 |
| b.barracudacentral.org | 仅 127.0.0.2；注：官方免费使用要求登记查询方解析器 IP，未登记者可能被限速/切断，经本站 DoH 通道 2026-11-12 实测可用 |
| psbl.surriel.com | 仅 127.0.0.2 |
| dnsbl.dronebl.org | 任意 127.0.0.x（末位为 drone 类别码；其测试条目码就是 127.0.0.1，与多数名单不同） |
| dnsbl-1.uceprotect.net | 仅 127.0.0.2；补入。只用 Level 1，Level 2/3 按网段连坐易误伤，不用 |
| bl.mailspike.net | 补入；命中码 127.0.0.2 与 127.0.0.10–.14；**127.0.1.x 是其白名单/好声誉回答，明确不算命中** |
| all.s5h.net | 补入；仅 127.0.0.2（2026-11-12 下午人工核对 37.123.193.82 命中的即此名单，与自动实测互证） |
| bl.blocklist.de | 补入；仅 127.0.0.2（Rspamd 默认名单） |
| ips.backscatterer.org | 补入；仅 127.0.0.2 |
| truncate.gbudb.net | 补入；仅 127.0.0.2 |
| bl.0spam.org | 补入；仅 127.0.0.2 |
| rbl.interserver.net | 补入；仅 127.0.0.2 |

通用规则：SERVFAIL/REFUSED/超时先自动重试 1 次，仍无回答记 `no_answer`；返回文档外码记 `unknown_code`；两者都 `listed:null`，不计命中也不计未命中。

**已移除的 8 个（原常量名单里有，2026-11-12 核对后移除，代码 `DNSBL_REMOVED` 有逐条证据原文）：**

- `dnsbl.sorbs.net` — 已停服：Proofpoint 2024-06-05 关停 SORBS 并清空 zones；实测测试点 NXDOMAIN
- `cbl.abuseat.org` — 已退役：Spamhaus 官方公告 CBL 2021 年退役、数据并入 XBL（已在 ZEN 内），继续查是重复计数
- `ix.dnsbl.manitu.net` — 已停服：NiX Spam 2025-01-16 宣布终止，2025-03 还曾对所有查询返回命中码；实测全量 REFUSED
- `db.wpbl.info` — 实测全部查询 REFUSED，近期维护证据未找到，存续记「未核实」，不假装在查
- `noptr.spamrats.com` — SpamRATS 拒绝公共解析器查询（多家核对站有载），实测 SERVFAIL 与 NXDOMAIN 不一致，不可信
- `combined.abuse.ch` — 实测全部 NOERROR 空回答、无测试条目；abuse.ch 数据服务已转 API Key 制，该 zone 是否仍维护未核实
- `wormrbl.imp.ch` — 实测测试点 NXDOMAIN（无 RFC 5782 测试条目），近期维护证据未找到
- `access.redhawk.org` — 实测全部 SERVFAIL，zone 已损坏

验证结果（2026-11-12）：正对照 127.0.0.2 在 12 个支持测试点的名单上全部判命中（DroneBL 回其自家测试码 127.0.0.1、Mailspike 回声誉码组），ZEN 记受限；负对照 127.0.0.1 与台湾家宽 1.168.162.221 均 0 命中（台湾家宽 12 个明确未命中 + ZEN 受限）；37.123.193.82 命中 all.s5h.net（另一轮还查到 ZEN 返回 SBL+PBL 真实码，ZEN 经公共解析器的回答本身不稳定，故 ZEN 在本站恒按「有真实码才算数、空回答记受限」处理）。

## 本地预览

```bash
# 1) 评分引擎测试（不需要任何账号和网络）
cd ~/workspace/ipzhencha
node test/run.mjs

# 1b) 在线判定测试（需要网络，打真实公开接口，无需任何账号/Key）
node test/live.mjs

# 1c) DNSBL 全量测试（需要网络，RFC 5782 正负对照 + 两个已知 IP）
node test/dnsbl.mjs

# 1d) 带 Key 适配器单元测试（不需要网络、不需要真 Key，mock fetch + 文档化 fixture，48 条断言）
node test/adapters.mjs

# 2) 前端页面（纯静态；接口未部署时页面会提示接口不可用，属骨架预期）
cd ~/workspace/ipzhencha/web
python3 -m http.server 8080
# 浏览器打开 http://localhost:8080

# 3) Worker 本地调试（装有 wrangler 时；无 Key 时带 Key 的源自动 returned:false）
cd ~/workspace/ipzhencha/worker
npx wrangler dev
# curl "http://localhost:8787/api/check?ip=1.1.1.1"
# curl http://localhost:8787/        → 纯文本简报
```

## 部署步骤（验证通过、lucky 点头后才执行；现在不要部署）

部署包已备好：`dist/deploy/`（`worker.txt` = 打包后的单文件 Worker 代码、`web/` = 前端全部文件、`DEPLOY.md` = 给 lucky 的大白话后台点选步骤）。走 Cloudflare 后台粘贴部署，不用命令行：

1. 接口：Cloudflare 后台新建 Worker `ipzhencha-api`，把 `worker.txt` 全部内容粘进编辑器替换示例代码并 Deploy，得到 workers.dev 免费地址。
2. Secrets：在该 Worker 的 Settings → Variables and Secrets 里按下方清单逐个添加，**值只由 lucky 本人从自己备忘录粘贴，不经聊天、不进仓库**；MaxMind 后置，不在此列。
3. 前端：Cloudflare Pages 新建项目（Upload assets），项目名 `ipzhencha`，上传 `web/` 内全部文件，得到 `ipzhencha.pages.dev` 免费地址。
4. 前端指向 Worker：Pages 与 Worker 分开部署（不同域名）时，把 `web/app.js` 顶部 `CONFIG.API_BASE` 改成 Worker 地址后重新上传 `app.js`（同域/路由转发部署时留空即可）。细节见 `dist/deploy/DEPLOY.md`。
5. 域名 ipzhencha.com：V1 不买、不绑定；验证出需求后再议。

（命令行路线仍保留：`worker/` 下 `npx wrangler deploy` + `wrangler secret put`，与后台粘贴二选一。）

## 数据源账号注册清单（lucky 本人注册，Key 归属本人）

| # | 服务 | 用途 | 免费额度（2026-11-12 口径，上线前复核） | Secret 变量名 |
|---|---|---|---|---|
| 1 | Cloudflare | Pages + Workers 托管 | 免费版（Workers 10 万请求/天） | —（平台账号本身） |
| 2 | AbuseIPDB | 滥用置信度、举报数/时间/类别 | 1,000 次检查/天、100 次网段检查/天 | `ABUSEIPDB_API_KEY` |
| 3 | proxycheck.io | 代理/VPN、风险值、运营商类型 | 注册免费 1,000 次/天（每人限一个免费账号） | `PROXYCHECK_API_KEY` |
| 4 | ipapi.is | 机房/代理/VPN 标记、公司类型 | 免费约 1,000 次/天 | `IPAPIIS_API_KEY` |
| 5 | IP2Location.io | 国家、城市、ASN | 免费 5 万次/月（须署名链接） | `IP2LOCATION_API_KEY` |
| 6 | MaxMind | GeoLite2 City/ASN 离线库下载 | 免费下载（账号 + 许可密钥） | **后置源，不配 Secrets**：账号与 License Key 已注册自存；待 GitHub Actions 构建离线库时再启用（构建侧凭据届时另定，不经聊天） |

补充：IPinfo Lite（CC BY-SA，须署名）与 Scamalytics（约 5,000 次/月，只作复核票）如启用，变量名拟为 `IPINFO_TOKEN`、`SCAMALYTICS_API_KEY`，启用时再定。ip-api.com 免费版**仅限非商业**，代码里以 `IPAPI_TEST_ONLY` 开关隔离（默认关），公开推广前必须移除该适配器。

## 纪律

- 所有 Key 只存 Worker Secrets；仓库、前端代码、聊天里都不出现真实值。
- 改评分公式每次只改一项，改完必跑 `node test/run.mjs` 并对比结果。
- 不记录访客 IP、不存完整被查 IP；缓存只按 IP 做 15 分钟结果缓存。
- 止损：上线两周内真实用户（非自己）查询 <200 次且无判错反馈，暂停新功能，只保留运行。
