// dnsbl.mjs — DNSBL 全量查询：13 个现役公开名单，逐名单按各自公开文档解释返回码。
// 只用 fetch（dns.google DoH），Node 与 Cloudflare Worker 通用。
//
// 为什么不能「有 A 记录 = 命中」：
//  - Spamhaus 等名单用 127.255.255.x 表示「查询被拒」（经公共解析器/超量），与被查 IP 的声誉无关；
//  - Mailspike 用 127.0.1.x 表示白名单/好声誉，不是命中；
//  - DroneBL 的 127.0.0.1 是它自家的测试条目码，是真回答；
//  - 已停服的名单可能返回通配/异常答案。凡是文档外的码，一律记 unknown（listed:null），
//    既不算命中也不算未命中——这是本站「分歧与缺失如实标」的纪律。
//
// 名单核对日期：2026-11-12（逐家查公开文档 + 用 RFC 5782 测试点 127.0.0.2 / 127.0.0.1 实测）。
// 状态取值：listed（命中）/ not_listed（未命中）/ restricted（查询受限，未返回可用结论）/
//          no_answer（无可用回答：SERVFAIL/REFUSED/超时等）/ unknown_code（返回了文档外的码）。

// ---------- 已移除名单（2026-11-12 核对，证据写明，不再查询） ----------
export const DNSBL_REMOVED = [
  { zone: 'dnsbl.sorbs.net', reason: '已停服：运营方 Proofpoint 于 2024-06-05 正式关停 SORBS 并清空其 zones，不再含声誉数据（Proofpoint 经 The Register 等多家确认）；2026-11-12 实测测试点 127.0.0.2 返回 NXDOMAIN，zone 已空', removedAt: '2026-11-12' },
  { zone: 'cbl.abuseat.org', reason: '已退役且与 ZEN 重复：Spamhaus 官方 2020-12-18 公告 CBL 于 2021 年第一周退役，数据并入 XBL（已包含在 zen.spamhaus.org 内）；cbl zone 仅为遗留服务，继续查等于对同一数据重复计数', removedAt: '2026-11-12' },
  { zone: 'ix.dnsbl.manitu.net', reason: '已停服：维护方 2025-01-16 宣布终止 NiX Spam 项目（nixspam.net 公告，dnsbl.com 标 DEAD）；2025-03 曾一度对所有查询返回 127.0.0.2「列遍全网」；2026-11-12 实测全部查询 REFUSED', removedAt: '2026-11-12' },
  { zone: 'db.wpbl.info', reason: '无法核实仍在提供服务：2026-11-12 实测测试点与全部对照查询均返回 REFUSED（Status 5），无可用回答；未找到近期维护证据。状态记「未核实存续」，按纪律移除而非假装在查', removedAt: '2026-11-12' },
  { zone: 'noptr.spamrats.com', reason: '经公共解析器不可用：多家核对站（如 ZeroBounce 2026-10）指出 SpamRATS 拒绝公共解析器查询；2026-11-12 实测同批查询在 SERVFAIL 与 NXDOMAIN 间不一致（测试点 SERVFAIL），无法取得可信结论', removedAt: '2026-11-12' },
  { zone: 'combined.abuse.ch', reason: '无有效数据：2026-11-12 实测测试点与全部对照均为 NOERROR 空回答（zone 存在但不返回任何 A 记录，无 RFC 5782 测试条目）；abuse.ch 已将数据服务转 API Key 制，该公开 DNSBL 是否仍维护未核实', removedAt: '2026-11-12' },
  { zone: 'wormrbl.imp.ch', reason: '疑似已停服：2026-11-12 实测测试点 127.0.0.2 返回 NXDOMAIN（无 RFC 5782 测试条目），未找到近期维护证据', removedAt: '2026-11-12' },
  { zone: 'access.redhawk.org', reason: 'zone 已损坏：2026-11-12 实测测试点与全部对照查询均 SERVFAIL（Status 2），无可用回答，未找到近期维护证据', removedAt: '2026-11-12' },
];

// ---------- 现役 13 名单 ----------
// hitKind 语义（逐家按公开文档）：
//  'zen'       listed 码为 127.0.0.2–.11（含义见 ZEN_CODE_MEANING）；127.255.255.x 为查询错误码；
//              且经公共解析器时 Spamhaus 官方说明可能直接返回 NXDOMAIN「什么都证明不了」，
//              故本名单 emptyIs='restricted'：空回答记受限，绝不记未命中。
//  'code2'     仅 127.0.0.2 表示命中；出现其他 127.0.0.x 码记 unknown_code。
//  'any_code'  任意 127.0.0.x 均为命中码（DroneBL 用末位表示 drone 类别，其测试条目码为 127.0.0.1）。
//  'mailspike' 命中码 127.0.0.2 与 127.0.0.10–.14（声誉等级）；127.0.1.x 为白名单/好声誉，明确不是命中。
export const DNSBL_ZONES = [
  { zone: 'zen.spamhaus.org', label: 'Spamhaus ZEN', hitKind: 'zen', emptyIs: 'restricted', testPoint: 'restricted',
    basis: '业界第一大名单（SBL/CSS/XBL/PBL 合并 zone）；Spamhaus 官方文档：127.255.255.252/254/255 为查询错误码（zone 名写错/经公共或开放解析器/超量），且经公共解析器的 NXDOMAIN 不证明未命中——故经本站 DoH 通道恒记受限，除非返回真实 listed 码' },
  { zone: 'bl.spamcop.net', label: 'SpamCop', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: 'SpamCop 官方：命中返回 127.0.0.2；SpamAssassin 默认规则集查询名单之一' },
  { zone: 'b.barracudacentral.org', label: 'Barracuda BRBL', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: 'Barracuda 官方：命中返回 127.0.0.2。注意其免费使用要求登记查询方解析器 IP，未登记者可能被限速/切断——经公共 DoH 通道 2026-11-12 实测可用（测试点命中、干净 IP 为 NXDOMAIN）；若日后出现文档外码或全量无回答，按 unknown/no_answer 如实呈现' },
  { zone: 'psbl.surriel.com', label: 'PSBL', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: 'PSBL 官方文档：命中返回 127.0.0.2，未命中 NXDOMAIN，超时/SERVFAIL 为查询失败；SpamAssassin 内置规则 RCVD_IN_PSBL' },
  { zone: 'dnsbl.dronebl.org', label: 'DroneBL', hitKind: 'any_code', emptyIs: 'not_listed', testPoint: 'listed',
    basis: 'DroneBL 官方：返回 127.0.0.x，末位为 drone 类别码，其 RFC 5782 测试条目返回 127.0.0.1（在该名单上 127.0.0.1 是真命中码，与多数名单不同）；多家现役核对站（ZeroBounce、Unspam，2026-10）仍在查询' },
  { zone: 'dnsbl-1.uceprotect.net', label: 'UCEPROTECT Level 1', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: '补入（2026-11-12）：UCEPROTECT 官方 Level 1 为单 IP 名单，命中 127.0.0.2；只取 Level 1——Level 2/3 按网段连坐聚合，业界普遍认为易误伤，不采用。依据：MxToolbox/ZeroBounce 等现役监控均含此名单' },
  { zone: 'bl.mailspike.net', label: 'Mailspike', hitKind: 'mailspike', emptyIs: 'not_listed', testPoint: 'listed',
    basis: '补入（2026-11-12）：Mailspike 官方返回码——命中为 127.0.0.10–.14（声誉由差到好）及测试条目 127.0.0.2；127.0.1.x 为其白名单/好声誉回答，明确不是命中。依据：SpamAssassin 默认规则集（RCVD_IN_MAILSPIKE_BL 等）查询名单' },
  { zone: 'all.s5h.net', label: 'S5H', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: '补入（2026-11-12）：s5h 公开名单，命中 127.0.0.2；pydnsbl 等开源核对工具的默认名单之一；2026-11-12 下午人工核对 37.123.193.82 时命中的即此类邮件名单，与实测互证' },
  { zone: 'bl.blocklist.de', label: 'blocklist.de', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: '补入（2026-11-12）：blocklist.de 官方公开 DNSBL，命中 127.0.0.2；依据：Rspamd 默认 rbl 配置查询名单之一' },
  { zone: 'ips.backscatterer.org', label: 'Backscatterer', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: '补入（2026-11-12）：Backscatterer 官方：专列退信/回弹滥发源，命中 127.0.0.2，长期运营；pydnsbl 默认名单之一' },
  { zone: 'truncate.gbudb.net', label: 'GBUdb Truncate', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: '补入（2026-11-12）：GBUdb Truncate 官方公开名单，命中 127.0.0.2；依据：Unspam 等现役核对站（2026-10）仍在查询名单' },
  { zone: 'bl.0spam.org', label: '0Spam', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: '补入（2026-11-12）：0Spam 官方公开名单，命中 127.0.0.2；依据：Unspam 现役核对站仍在查询名单（2026-10）' },
  { zone: 'rbl.interserver.net', label: 'InterServer RBL', hitKind: 'code2', emptyIs: 'not_listed', testPoint: 'listed',
    basis: '补入（2026-11-12）：InterServer（美国主机商）维护的公开 RBL，命中 127.0.0.2；pydnsbl 默认名单之一，2026-11-12 实测测试点/对照行为标准' },
];

export const ZEN_CODE_MEANING = {
  '127.0.0.2': 'SBL 已知垃圾邮件源', '127.0.0.3': 'CSS 低声誉自动列入',
  '127.0.0.4': 'XBL 被控/被利用主机', '127.0.0.5': 'XBL 被控/被利用主机',
  '127.0.0.6': 'XBL 被控/被利用主机', '127.0.0.7': 'XBL 被控/被利用主机',
  '127.0.0.9': 'DROP 被劫持/恶意网段',
  '127.0.0.10': 'PBL 策略列入（该段不应直投邮件，非垃圾指控）',
  '127.0.0.11': 'PBL 策略列入（该段不应直投邮件，非垃圾指控）',
};

const RESTRICTED_PREFIX = '127.255.255.'; // Spamhaus 系查询错误码段（官方文档）

// 把一家名单的一组 A 记录按该名单语义分类。codes 为空数组表示「无 A 回答」，由调用方按 dnsStatus 处理。
export function classifyCodes(def, codes) {
  if (!codes.length) return { listed: null, status: 'no_answer', codes };
  if (codes.some((c) => c.startsWith(RESTRICTED_PREFIX))) {
    return { listed: null, status: 'restricted', codes, note: '名单返回查询错误码（经公共解析器/超量等），不代表被查 IP 的声誉' };
  }
  if (codes.some((c) => !c.startsWith('127.'))) {
    return { listed: null, status: 'unknown_code', codes, note: '返回非 127.0.0.0/8 地址，疑似 zone 异常，不作结论' };
  }
  switch (def.hitKind) {
    case 'zen': {
      const hit = codes.filter((c) => ZEN_CODE_MEANING[c]);
      if (hit.length) return { listed: true, status: 'listed', codes, meaning: hit.map((c) => ZEN_CODE_MEANING[c]) };
      return { listed: null, status: 'unknown_code', codes, note: 'ZEN 返回文档外返回码，不作结论' };
    }
    case 'any_code': {
      if (codes.every((c) => c.startsWith('127.0.0.'))) return { listed: true, status: 'listed', codes };
      return { listed: null, status: 'unknown_code', codes, note: '返回 127.0.0.0/8 之外的 127 段码，不作结论' };
    }
    case 'mailspike': {
      const wl = codes.filter((c) => c.startsWith('127.0.1.'));
      const bl = codes.filter((c) => c === '127.0.0.2' || /^127\.0\.0\.(1[0-4])$/.test(c));
      const other = codes.filter((c) => !wl.includes(c) && !bl.includes(c));
      if (other.length) return { listed: null, status: 'unknown_code', codes, note: 'Mailspike 返回文档外返回码，不作结论' };
      if (bl.length) return { listed: true, status: 'listed', codes };
      return { listed: false, status: 'not_listed', codes, note: 'Mailspike 白名单/好声誉回答（127.0.1.x），不是命中' };
    }
    case 'code2':
    default: {
      if (codes.includes('127.0.0.2')) return { listed: true, status: 'listed', codes };
      return { listed: null, status: 'unknown_code', codes, note: '返回文档外返回码（该名单命中码仅 127.0.0.2），不作结论' };
    }
  }
}

async function dohQuery(name, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(`https://dns.google/resolve?name=${name}&type=A`, { headers: { accept: 'application/dns-json' }, signal: ctrl.signal });
    if (!r.ok) return { dnsStatus: -1, codes: [] };
    const j = await r.json();
    const codes = (j.Answer || []).filter((a) => a.type === 1).map((a) => String(a.data).replace(/\.$/, ''));
    return { dnsStatus: j.Status, codes };
  } catch { return { dnsStatus: -1, codes: [] }; } finally { clearTimeout(t); }
}

export async function dnsblLookup(ip, def, timeoutMs = 4000) {
  const rev = ip.split('.').reverse().join('.');
  const { dnsStatus, codes } = await dohQuery(`${rev}.${def.zone}`, timeoutMs);
  const base = { zone: def.zone, label: def.label };
  if (codes.length) return { ...base, ...classifyCodes(def, codes), dnsStatus };
  if (dnsStatus === 3) { // NXDOMAIN
    if (def.emptyIs === 'restricted') {
      return { ...base, listed: null, status: 'restricted', codes: [], dnsStatus, note: '经公共解析器查询，该名单的空回答不证明未命中（官方说明），记为查询受限' };
    }
    return { ...base, listed: false, status: 'not_listed', codes: [], dnsStatus };
  }
  if (dnsStatus === 0) { // NOERROR 但无 A 回答（NODATA）：zone 行为不标准，不作结论
    return { ...base, listed: null, status: 'no_answer', codes: [], dnsStatus, note: 'NOERROR 空回答，无法区分未命中与 zone 无数据' };
  }
  // SERVFAIL(2)/REFUSED(5)/超时(-1) 等
  return { ...base, listed: null, status: 'no_answer', codes: [], dnsStatus };
}

// 全量查询：返回逐项结果与命中名单。returned = 至少一家给出了确定结论（命中或未命中）。
// no_answer（SERVFAIL/超时等瞬时故障）的名单自动重试 1 次；重试后仍无回答就如实保留 no_answer。
export async function checkDnsbl(ip, { timeoutMs = 4000 } = {}) {
  if (ip.includes(':')) return { returned: false, note: 'ipv6_dnsbl_todo', hits: [], results: [] };
  const results = await Promise.all(DNSBL_ZONES.map((d) => dnsblLookup(ip, d, timeoutMs)));
  for (let i = 0; i < results.length; i++) {
    if (results[i].status === 'no_answer') {
      const retry = await dnsblLookup(ip, DNSBL_ZONES[i], timeoutMs);
      if (retry.status !== 'no_answer') results[i] = retry;
    }
  }
  const answered = results.filter((x) => x.listed !== null);
  return {
    returned: answered.length > 0,
    answered: answered.length,
    total: results.length,
    hits: results.filter((x) => x.listed === true).map((x) => x.zone),
    results,
  };
}
