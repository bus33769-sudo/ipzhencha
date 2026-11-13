// index.js — IP侦查 Cloudflare Worker 入口
// 路由：
//   GET /api/check?ip=1.2.3.4   → JSON 报告（无 ip 参数时用 CF-Connecting-IP，即访客自己的出口 IP）
//   GET /json?ip=1.2.3.4        → 同上 JSON（终端彩蛋）
//   GET /txt?ip=1.2.3.4 或 curl 访问 / → 纯文本简报
// 缓存：Cache API 按 IP 缓存 15 分钟（方案第 5 节：不用 KV 存报告）。
// 纪律：免 Key 源单源超时 2.5 秒、带 Key 源 6 秒；任一源失败只标 returned:false 并带原因码
// （no_key / http_<状态码> / timeout / bad_json / network_error / api_error），绝不抛异常中断整份报告；
// Key 只从 env（Secrets）读，仓库与代码里不出现真实值。
// 后置源：MaxMind GeoLite2 是下载型离线库，无法塞进「Cloudflare 后台粘贴代码」的部署方式，
// 见下方 DEFERRED_SOURCES——不进结果列表、不进完整度分母、不算失败源，待 GitHub Actions
// 构建离线库后再启用。
import { scoreIP, SUITABILITY_TIER_ZH, SUITABILITY_REASON_ZH } from './scoring.js';
import { liveFacts } from './livecheck.mjs';
import { checkDnsbl, DNSBL_ZONES } from './dnsbl.mjs';

const TIMEOUT_MS = 2500;
const KEYED_TIMEOUT_MS = 6000; // 带 Key 商业 API 给宽到 6 秒（任务口径），仍带 AbortController 兜底
const CACHE_TTL = 900; // 15 分钟

async function fetchTimeout(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

// 带 Key 源统一取数：成功返回 { ok:true, json }，失败返回 { ok:false, note:<原因码> }，永不抛异常。
async function fetchKeyedJson(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), KEYED_TIMEOUT_MS);
  let resp;
  try {
    resp = await fetch(url, { ...opts, signal: ctrl.signal });
  } catch (e) {
    return { ok: false, note: e && e.name === 'AbortError' ? 'timeout' : 'network_error' };
  } finally {
    clearTimeout(t);
  }
  if (!resp.ok) return { ok: false, note: `http_${resp.status}` };
  try {
    return { ok: true, json: await resp.json() };
  } catch {
    return { ok: false, note: 'bad_json' };
  }
}

// 后置数据源清单（只用于报告里如实标注，不参与查询与完整度计数）
export const DEFERRED_SOURCES = [
  {
    name: 'maxmind_geolite',
    status: 'deferred',
    reason: 'MaxMind GeoLite2 为下载型离线数据库，无法塞进 Cloudflare 后台粘贴部署的 Worker；待后续用 GitHub Actions 定时构建离线库（City/ASN）后启用。缺席期间不计入完整度分母、不算失败源。',
  },
];

function isIP(s) {
  return /^[0-9a-fA-F.:]+$/.test(s || '') && !!s;
}

// ---------- 免 Key 适配器 ----------

// RDAP：登记方/注册国/网段信息，原生与租赁判定的依据
async function srcRdap(ip) {
  try {
    const r = await fetchTimeout(`https://rdap.db.ripe.net/ip/${encodeURIComponent(ip)}`, { headers: { accept: 'application/json' } });
    if (!r.ok) return { name: 'rdap', returned: false };
    const j = await r.json();
    return {
      name: 'rdap', returned: true,
      country: j.country || null,
      handle: j.handle || null,
      networkName: j.name || null,
      entities: (j.entities || []).map((e) => e.handle).filter(Boolean),
      raw: { startAddress: j.startAddress, endAddress: j.endAddress },
    };
  } catch { return { name: 'rdap', returned: false }; }
}

// DNSBL 全量 13 个：实现与逐名单返回码语义在 dnsbl.mjs（2026-11-12 逐家核对文档+实测）。
// 报告逐项列出每个名单的 listed（true/false/null）、status 与原始返回码 codes；
// 受限/无回答/文档外码一律 listed:null，绝不算命中或未命中。被移除的 8 个停服/失效名单见
// dnsbl.mjs 的 DNSBL_REMOVED（含原因与日期）。
export const DNSBL_ZONES_ALL = DNSBL_ZONES.map((d) => d.zone);

async function srcDnsbl(ip) {
  const r = await checkDnsbl(ip, { timeoutMs: TIMEOUT_MS });
  if (!r.returned) return { name: 'dnsbl', returned: false, note: r.note || 'no_dnsbl_answers', detail: r.results || [] };
  return { name: 'dnsbl', returned: true, hits: r.hits, answered: r.answered, total: r.total, detail: r.results };
}

// Tor 出口名单：官方公开列表，进程内缓存 30 分钟
let torCache = { at: 0, set: null };
async function srcTor(ip) {
  try {
    if (!torCache.set || Date.now() - torCache.at > 30 * 60 * 1000) {
      const r = await fetchTimeout('https://check.torproject.org/torbulkexitlist');
      if (!r.ok) return { name: 'tor', returned: false };
      torCache = { at: Date.now(), set: new Set((await r.text()).split('\n').map((s) => s.trim())) };
    }
    return { name: 'tor', returned: true, isTor: torCache.set.has(ip) };
  } catch { return { name: 'tor', returned: false }; }
}

// 免 Key 在线判定（livecheck.mjs）：PTR 反查 + 租赁判定（RDAP vs RIPEstat）+ RPKI
async function srcLive(ip) {
  try {
    const f = await liveFacts(ip, { timeoutMs: TIMEOUT_MS });
    return {
      name: 'livecheck',
      returned: !!(f.ptr.returned || f.lease.returned || f.rpki.returned),
      ptr: f.ptr, lease: f.lease, rpki: f.rpki, asn: f.asn, prefix: f.prefix,
    };
  } catch { return { name: 'livecheck', returned: false }; }
}

// ---------- 带 Key 适配器（真实实现；Key 缺失 → returned:false + note:'no_key'，不报错） ----------
// 统一约定：超时 6 秒（fetchKeyedJson）；HTTP 错误/超时/JSON 解析失败/API 业务错误都只返回
// returned:false 并在 note 里带简短原因码，永不抛异常。归一化字段名与骨架阶段保持一致，
// normalize() 与 scoring.js 的输入约定不变。

// AbuseIPDB：滥用置信度 + 举报历史是本站压 ipx.al 的核心差异点。
// maxAgeInDays=365 + verbose：拿近 365 天窗口的汇总与逐条 reports。
// 评分引擎的 abuse 口径（见 scoring.js）：confidence ≥50 扣分；totalReports ≥20 且最近一次
// 在 180 天内扣分；只有 180 天前旧举报小扣并标 abuse_history_old。这里除汇总字段外，
// 再用 verbose 的 reports 数组精确数出近 180 天内的条数（reportsWithin180Days）供报告展示与复核。
export async function srcAbuseIPDB(ip, env) {
  const name = 'abuseipdb';
  const key = env && env.ABUSEIPDB_API_KEY;
  if (!key) return { name, returned: false, note: 'no_key' };
  const r = await fetchKeyedJson(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=365&verbose`,
    { headers: { Key: key, Accept: 'application/json' } },
  );
  if (!r.ok) return { name, returned: false, note: r.note };
  const d = r.json && r.json.data;
  if (!d || typeof d !== 'object') return { name, returned: false, note: 'bad_shape' };
  const lastMs = d.lastReportedAt ? Date.parse(d.lastReportedAt) : NaN;
  const lastReportDaysAgo = Number.isFinite(lastMs)
    ? Math.max(0, Math.floor((Date.now() - lastMs) / 86400000))
    : null;
  let reportsWithin180Days = null;
  if (Array.isArray(d.reports)) {
    const now = Date.now();
    reportsWithin180Days = d.reports.filter((x) => {
      const t = x && Date.parse(x.reportedAt);
      return Number.isFinite(t) && now - t <= 180 * 86400000 && now - t >= 0;
    }).length;
  }
  return {
    name, returned: true,
    country: d.countryCode || null,
    usageType: d.usageType || null,
    isp: d.isp || null,
    isTor: !!d.isTor,
    abuse: {
      confidence: d.abuseConfidenceScore ?? 0,
      totalReports: d.totalReports ?? 0,
      distinctUsers: d.numDistinctUsers ?? null,
      lastReportedAt: d.lastReportedAt || null,
      lastReportDaysAgo,
      reportsWithin180Days,
    },
  };
}

// proxycheck.io v2：proxy yes/no、网络 type（Residential/Business/Wireless/Hosting 等）、
// risk 0–100、ASN/provider/organisation、port、seen（最近一次被见作代理的时间）。
// v2 为扁平字段；个别套餐会把 network/location 嵌套返回，这里两种形状都兼容。
// devices/operator 为部分套餐才有的设备/运营商字段，若有则原样带回，无则 null。
export async function srcProxycheck(ip, env) {
  const name = 'proxycheck';
  const key = env && env.PROXYCHECK_API_KEY;
  if (!key) return { name, returned: false, note: 'no_key' };
  const r = await fetchKeyedJson(
    `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}&vpn=1&asn=1&risk=1&port=1&seen=1&days=30`,
  );
  if (!r.ok) return { name, returned: false, note: r.note };
  const j = r.json;
  if (!j || j.status !== 'ok' || !j[ip] || typeof j[ip] !== 'object') {
    return { name, returned: false, note: 'api_error' };
  }
  const d = j[ip];
  const net = d.network && typeof d.network === 'object' ? d.network : {};
  const loc = d.location && typeof d.location === 'object' ? d.location : {};
  const riskNum = d.risk === null || d.risk === undefined || d.risk === '' ? null : Number(d.risk);
  return {
    name, returned: true,
    country: d.isocode || loc.isocode || d.country || null,
    city: d.city || loc.city_name || null,
    region: d.region || loc.region_name || null,
    asn: d.asn || net.asn || null,
    provider: d.provider || net.provider || null,
    organisation: d.organisation || net.organisation || null,
    hostname: d.hostname || net.hostname || null,
    range: d.range || net.range || null,
    type: d.type || net.type || null,
    isProxy: d.proxy === 'yes',
    risk: Number.isFinite(riskNum) ? riskNum : null,
    port: d.port ?? null,
    lastSeen: d.seen || d['last seen'] || null,
    devices: d.devices ?? null,
    operator: d.operator ?? null,
  };
}

// ipapi.is：company.type / asn.type 给类型投票（hosting/isp/business/education 等），
// is_datacenter/is_proxy/is_vpn/is_tor/is_abuser/is_mobile 为官方标记，location 给国家城市。
export async function srcIpapiIs(ip, env) {
  const name = 'ipapiis';
  const key = env && env.IPAPIIS_API_KEY;
  if (!key) return { name, returned: false, note: 'no_key' };
  const r = await fetchKeyedJson(`https://api.ipapi.is?q=${encodeURIComponent(ip)}&key=${encodeURIComponent(key)}`);
  if (!r.ok) return { name, returned: false, note: r.note };
  const j = r.json;
  if (!j || typeof j !== 'object' || j.error || (!j.location && !j.asn && !j.company)) {
    return { name, returned: false, note: 'api_error' };
  }
  const loc = j.location || {};
  const comp = j.company || {};
  const asn = j.asn || {};
  const asnRaw = asn.asn === null || asn.asn === undefined ? null : String(asn.asn);
  return {
    name, returned: true,
    country: loc.country_code || null,
    countryName: loc.country || null,
    city: loc.city || null,
    region: loc.state || null,
    asn: asnRaw ? (asnRaw.toUpperCase().startsWith('AS') ? asnRaw.toUpperCase() : `AS${asnRaw}`) : null,
    asnOrg: asn.org || null,
    asnType: asn.type || null,
    companyName: comp.name || null,
    companyType: comp.type || null,
    isDatacenter: !!j.is_datacenter,
    isProxy: !!j.is_proxy,
    isVpn: !!j.is_vpn,
    isTor: !!j.is_tor,
    isAbuser: !!j.is_abuser,
    isMobile: !!j.is_mobile,
  };
}

// IP2Location.io：先按 package=WS25 请求全字段（usage_type / is_proxy / proxy 详情都在内）。
// 注意：免费套餐（5 万次/月）若不支持 WS25 或返回 error 对象，自动退回不带 package 的
// 默认字段集再查一次（本函数的 package 字段会如实标明实际用到的包）。字段名两种代际都兼容：
// 现行 .io 文档名 country_code/country_name/region_name/city_name 与 WS 式 country_short/
// country_long/region/city。usage_type 为代码（ISP/MOB/DCH/CDN/COM/EDU 等），投票映射在 normalize。
export async function srcIp2Location(ip, env) {
  const name = 'ip2location';
  const key = env && env.IP2LOCATION_API_KEY;
  if (!key) return { name, returned: false, note: 'no_key' };
  const base = `https://api.ip2location.io/?key=${encodeURIComponent(key)}&ip=${encodeURIComponent(ip)}`;
  let r = await fetchKeyedJson(`${base}&package=WS25`);
  let pkg = 'WS25';
  if (r.ok && r.json && r.json.error) {
    r = await fetchKeyedJson(base);
    pkg = 'default';
  }
  if (!r.ok) return { name, returned: false, note: r.note };
  const j = r.json;
  if (!j || typeof j !== 'object' || j.error) return { name, returned: false, note: 'api_error' };
  const proxy = j.proxy && typeof j.proxy === 'object' ? j.proxy : null;
  const asnRaw = j.asn === null || j.asn === undefined || j.asn === '' ? null : String(j.asn);
  return {
    name, returned: true, package: pkg,
    country: j.country_code || j.country_short || null,
    countryName: j.country_name || j.country_long || null,
    region: j.region_name || j.region || null,
    city: j.city_name || j.city || null,
    isp: j.isp || null,
    asn: asnRaw ? (asnRaw.toUpperCase().startsWith('AS') ? asnRaw.toUpperCase() : `AS${asnRaw}`) : null,
    asName: j.as || j.as_name || null,
    usageType: j.usage_type || null,
    isProxy: j.is_proxy === true || j.is_proxy === 'true',
    proxyType: proxy ? (proxy.proxy_type || null) : null,
    proxyProvider: proxy ? (proxy.provider || null) : null,
    fraudScore: typeof j.fraud_score === 'number' ? j.fraud_score : null,
  };
}

// TEST_ONLY — ip-api.com 免费版仅限非商业使用（方案第 6 节写死）：
// 只允许纯个人测试期启用（env.IPAPI_TEST_ONLY === '1'），公开推广前必须移除本适配器。
async function srcIpApiTestOnly(ip, env) {
  if (!env || env.IPAPI_TEST_ONLY !== '1') return { name: 'ipapi', returned: false, note: 'test_only_disabled' };
  try {
    const r = await fetchTimeout(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,city,as,proxy,hosting,mobile`);
    if (!r.ok) return { name: 'ipapi', returned: false };
    const j = await r.json();
    if (j.status !== 'success') return { name: 'ipapi', returned: false };
    return { name: 'ipapi', returned: true, country: j.countryCode || null, city: j.city || null, hosting: !!j.hosting, proxy: !!j.proxy, mobile: !!j.mobile };
  } catch { return { name: 'ipapi', returned: false }; }
}

// ---------- 汇总 ----------

// 把各源原始结果归一化成评分引擎的输入。
// 类型投票源（scoring.decideType 需胜出类型 ≥3 票才定型）：
//   proxycheck（type 字串）、ipapi.is（is_datacenter/is_mobile/company.type/asn.type）、
//   IP2Location（usage_type 代码）三家带 Key 源 + PTR 家宽硬证据票（livecheck 单列 'ptr' 源）
//   + scoring 内部对 rdns 的家宽格式正则票。
// 完整度计数（sourcesReturned 与分母）：上面全部参与源逐条计数，免 Key 源含 rdap、dnsbl、
//   tor、livecheck（PTR/租赁/RPKI 汇总一条）、外加单列的 ptr 票；后置的 MaxMind 不在此列
//   （见 DEFERRED_SOURCES），缺席不算失败、不占分母。
export function normalize(ip, results) {
  const byName = Object.fromEntries(results.map((r) => [r.name, r]));
  const sources = results.map((r) => {
    const s = { name: r.name, returned: !!r.returned };
    if (r.name === 'proxycheck' && r.returned && r.type) {
      const t = String(r.type).toLowerCase();
      if (t.includes('residential')) s.type = 'residential';
      else if (t.includes('wireless')) s.type = 'mobile';
      else if (t.includes('hosting') || t.includes('datacenter') || t.includes('data center')) s.type = 'datacenter';
      else if (t.includes('business')) s.type = 'business';
    }
    if (r.name === 'ipapiis' && r.returned) {
      if (r.isDatacenter) s.type = 'datacenter';
      else if (r.isMobile) s.type = 'mobile';
      else {
        const ct = String(r.companyType || r.asnType || '').toLowerCase();
        if (ct === 'hosting') s.type = 'datacenter';
        else if (ct === 'isp') s.type = 'residential';
        else if (ct === 'business') s.type = 'business';
        else if (ct === 'education') s.type = 'education';
      }
    }
    if (r.name === 'ip2location' && r.returned && r.usageType) {
      // IP2Location usage_type 代码：ISP 固定线路家宽 / MOB 移动 / DCH 机房托管 / CDN /
      // COM 商业 / EDU 教育；个别套餐可能返回描述字串，一并兜底匹配 hosting/datacenter。
      const u = String(r.usageType).trim().toUpperCase();
      if (u === 'ISP') s.type = 'residential';
      else if (u === 'MOB') s.type = 'mobile';
      else if (u === 'DCH' || u === 'CDN') s.type = 'datacenter';
      else if (u === 'COM') s.type = 'business';
      else if (u === 'EDU') s.type = 'education';
      else if (/HOSTING|DATA ?CENTER|DATACENTER/.test(u)) s.type = 'datacenter';
    }
    return s;
  });
  const abuseSrc = byName.abuseipdb;
  const dnsblSrc = byName.dnsbl;
  const torSrc = byName.tor;
  const live = byName.livecheck;
  // 在线判定接入（livecheck.mjs）：PTR 给家宽硬证据票（单列 'ptr' 源），租赁/RPKI 直接喂评分
  if (live && live.returned && live.ptr && live.ptr.returned) {
    const p = { name: 'ptr', returned: true };
    if (live.ptr.residentialFormat) p.type = 'residential';
    sources.push(p);
  }
  const proxyFlags = results.filter((r) => r.returned && (r.isProxy === true)).length;
  const vpnFlags = results.filter((r) => r.returned && (r.isVpn === true)).length;
  return {
    sources,
    rdns: live && live.ptr ? (live.ptr.hostname || null) : null,
    // leased=null 表示未知：scoring 字段是布尔，未知按「未证实租赁」处理，证据原文在报告 sources.livecheck.lease 里如实展示
    leased: !!(live && live.lease && live.lease.leased === true),
    tor: !!(torSrc && torSrc.returned && torSrc.isTor),
    abuse: abuseSrc && abuseSrc.returned ? abuseSrc.abuse : null,
    riskMalicious: false, // V1.5 自建风险库接入后填充
    riskSpamOnly: false,
    dnsblHits: dnsblSrc && dnsblSrc.returned ? dnsblSrc.hits.length : 0,
    proxyFlagSources: proxyFlags,
    vpnFlagSources: vpnFlags,
    segmentRiskCount: 0, // V1.5 C 段画像接入后填充
    rpki: live && live.rpki && ['valid', 'invalid', 'unknown'].includes(live.rpki.rpki) ? live.rpki.rpki : 'unknown',
  };
}

async function buildReport(ip, env) {
  const jobs = [
    srcRdap(ip),
    srcDnsbl(ip),
    srcTor(ip),
    srcLive(ip),
    srcAbuseIPDB(ip, env),
    srcProxycheck(ip, env),
    srcIpapiIs(ip, env),
    srcIp2Location(ip, env),
  ];
  // TEST_ONLY 适配器默认不启用：未启用时不进结果列表——免得一个长期关闭的源
  // 永久占据完整度分母、长期在对照表里挂一行「未返回」。
  if (env && env.IPAPI_TEST_ONLY === '1') jobs.push(srcIpApiTestOnly(ip, env));
  const results = await Promise.all(jobs);
  const norm = normalize(ip, results);
  const scoring = scoreIP(norm);
  return {
    ip,
    generatedAt: new Date().toISOString(),
    sourcesReturned: scoring.sourcesReturned,
    // 分母与评分引擎的 sources 口径一致（结果源逐条 + PTR 硬证据票单列一条）；
    // 后置的 MaxMind 不在分母内（见 deferredSources）。
    sourcesTotal: norm.sources.length,
    conclusion: { type: scoring.type, score: scoring.score, grade: scoring.grade, flags: scoring.flags, suitability: scoring.suitability },
    deductions: scoring.deductions,
    dnsbl: (results.find((r) => r.name === 'dnsbl') || {}).detail || [],
    abuse: (results.find((r) => r.name === 'abuseipdb') || {}).abuse || null,
    sources: results,
    deferredSources: DEFERRED_SOURCES,
    note: 'PTR/租赁/RPKI 已接入免 Key 在线判定（见 sources 里的 livecheck，含证据原文）；DNSBL 已全量接入 13 个现役名单并逐项列出（见 dnsbl，受限/无回答如实标 listed:null）；AbuseIPDB / proxycheck / ipapi.is / IP2Location 已真实接入，无 Key 或调用失败时如实标 returned:false 并带原因码；MaxMind GeoLite 为后置源（见 deferredSources），不计入完整度；自建风险库待 V1.5。',
  };
}

function textBrief(rep) {
  const c = rep.conclusion;
  const scoreTxt = c.score === null ? '数据不足，未给分' : `${c.score} 分（${c.grade}）`;
  const lines = [
    `IP侦查 ipzhencha — ${rep.ip}`,
    `类型：${c.type}　健康分：${scoreTxt}`,
    `完整度：${rep.sourcesReturned}/${rep.sourcesTotal} 个源已返回`,
  ];
  if (c.flags.length) lines.push(`标记：${c.flags.join(', ')}`);
  if (c.suitability) {
    const rs = (c.suitability.reasons || []).map((k) => SUITABILITY_REASON_ZH[k] || k).join('；');
    lines.push(`养号适合度：${SUITABILITY_TIER_ZH[c.suitability.tier] || c.suitability.tier}${rs ? `（${rs}）` : ''}——参考判断，平台还看设备、行为与支付地区，高分不等于一定通过风控`);
  }
  for (const d of rep.deductions) lines.push(`扣分：-${d.points} ${d.item}（${d.source}）${d.note ? ' ' + d.note : ''}`);
  if (rep.abuse) lines.push(`滥用历史：举报 ${rep.abuse.totalReports} 次，置信度 ${rep.abuse.confidence}`);
  lines.push('说明：分数为本站公式推算，仅供参考，不承诺过任何平台风控。');
  return lines.join('\n') + '\n';
}

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, OPTIONS',
  'access-control-allow-headers': 'content-type',
  'access-control-max-age': '86400',
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const isCheck = path === '/api/check' || path === '/json';
    const ua = request.headers.get('user-agent') || '';
    const wantsText = path === '/txt' || (path === '/' && /curl/i.test(ua));
    if (!isCheck && !wantsText && path !== '/') {
      return new Response('Not Found', { status: 404, headers: CORS_HEADERS });
    }
    if (path === '/' && !wantsText) {
      return new Response('IP侦查 API 已启动。用 /api/check?ip= 查询，或 curl 本地址看简报。', { headers: { 'content-type': 'text/plain; charset=utf-8', ...CORS_HEADERS } });
    }
    const selfDetect = !url.searchParams.get('ip');
    let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP') || '';
    if (!isIP(ip)) {
      return new Response(JSON.stringify({ error: 'missing_or_invalid_ip' }), { status: 400, headers: { 'content-type': 'application/json', ...CORS_HEADERS } });
    }
    // Cache API：按 IP 缓存 15 分钟
    const cache = caches.default;
    const cacheKey = new Request(`https://cache.ipzhencha.internal/report/${encodeURIComponent(ip)}`);
    const hit = await cache.match(cacheKey);
    if (hit) return hit;
    const rep = await buildReport(ip, env || {});
    const body = wantsText ? textBrief(rep) : JSON.stringify(rep, null, 2);
    const resp = new Response(body, {
      headers: {
        'content-type': wantsText ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
        'cache-control': selfDetect ? 'no-store' : `public, max-age=${CACHE_TTL}`,
        ...CORS_HEADERS,
      },
    });
    ctx.waitUntil(cache.put(cacheKey, resp.clone()));
    return resp;
  },
};
