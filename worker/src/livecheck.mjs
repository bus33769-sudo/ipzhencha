// livecheck.mjs — 免 Key 在线判定（纯函数模块，Node 与 Cloudflare Worker 通用）
// 只依赖全局 fetch（+ AbortController / setTimeout），不用任何 Node 专有 API。
// 三项判定：
//   1) PTR 反查（dns.google DoH）→ 反向域名 + 是否家宽格式（给 scoring 的硬证据票）
//   2) 租赁判定：RDAP 登记方 vs RIPEstat 宣告 ASN holder，名称归一化后对不上 → leased=true
//   3) RPKI：RIPEstat rpki-validation → 'valid' | 'invalid' | 'unknown'（scoring 已支持的字段）
// 纪律：任一接口失败/超时只把对应项标 returned:false 或 leased:null（未知），绝不猜。

const DEFAULT_TIMEOUT_MS = 6000;

// 带一次重试的 JSON 拉取：只对网络错误/超时重试一次（接口偶发抖动），HTTP 错误不重试。
// 注意（2026-11-12 实测）：rdap.org 对 fetch 默认 UA（undici）返回 403，必须带自报家门的
// user-agent 才放行并跳转到权威 RIR；UA 写明项目名即可，不需要伪装浏览器。
const UA = 'ipzhencha/0.1';
async function fetchJson(url, opts = {}) {
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  let lastErr = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetch(url, { headers: { accept: 'application/json', 'user-agent': UA }, signal: ctrl.signal });
      if (!r.ok) throw new Error(`http_${r.status}`);
      return await r.json();
    } catch (e) {
      lastErr = e;
      if (e && /^http_4/.test(e.message)) break; // 4xx 是确定性错误，重试无意义
    } finally {
      clearTimeout(t);
    }
  }
  throw lastErr || new Error('fetch_failed');
}

// ---------------- 1) PTR 反查 ----------------

// 家宽 PTR 格式模式（可扩展常量）。依据：各国 ISP 给动态家宽分配的 PTR 普遍带
// dynamic/dyn/dial/adsl/pool/dhcp/cable/fttx 等字样，与 scoring.js 的 RESIDENTIAL_RDNS
// 保持同源并略作扩充；命中即视为「家宽格式」硬证据一票。
export const RESIDENTIAL_RDNS_PATTERNS = [
  /dynamic/i, /dyn/i, /dial/i, /adsl/i, /dsl/i, /pool/i, /dhcp/i,
  /home/i, /residential/i, /broadband/i, /cable/i, /fiber/i, /fibre/i,
  /fttb/i, /ftth/i, /fttx/i, /cust/i,
];

// 已知家宽 PTR 后缀（可扩展常量）。依据（实测 2026-11-12）：
// - .hinet.net：台湾中华电信 HiNet 家宽，PTR 形如 1-168-162-221.dynamic-ip.hinet.net
//   —— 即使域名里没有 dynamic 等字样，仅后缀也可认定为该 ISP 的家宽段。
export const RESIDENTIAL_RDNS_SUFFIXES = [
  '.hinet.net',
];

export function isResidentialRdns(hostname) {
  if (!hostname) return false;
  const h = String(hostname).toLowerCase().replace(/\.$/, '');
  if (RESIDENTIAL_RDNS_SUFFIXES.some((s) => h.endsWith(s))) return true;
  return RESIDENTIAL_RDNS_PATTERNS.some((re) => re.test(h));
}

function ptrQueryName(ip) {
  if (ip.includes(':')) {
    // IPv6：展开成 32 个 nibble 反写 .ip6.arpa（处理 :: 压缩）
    let [head, tail] = ip.split('::');
    let headParts = head ? head.split(':') : [];
    let tailParts = tail ? tail.split(':') : [];
    if (ip.includes('::')) {
      const missing = 8 - headParts.length - tailParts.length;
      headParts = headParts.concat(Array(Math.max(missing, 0)).fill('0'));
    }
    const full = headParts.concat(tailParts).map((p) => p.padStart(4, '0')).join('');
    return full.split('').reverse().join('.') + '.ip6.arpa';
  }
  return ip.split('.').reverse().join('.') + '.in-addr.arpa';
}

// 返回 { returned, hostname, residentialFormat, status }
// returned=true 只代表查询执行成功；hostname=null 表示该 IP 没有可用 PTR（无记录/解析失败）。
export async function fetchPtr(ip, opts = {}) {
  const name = ptrQueryName(ip);
  try {
    const j = await fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=PTR`, opts);
    const ans = (j.Answer || []).find((a) => a.type === 12);
    const hostname = ans ? String(ans.data).replace(/\.$/, '').toLowerCase() : null;
    return { returned: true, hostname, residentialFormat: isResidentialRdns(hostname), status: j.Status };
  } catch {
    return { returned: false, hostname: null, residentialFormat: false, status: null };
  }
}

// ---------------- 2) 租赁判定 ----------------

// 名称归一化：小写、去标点、拆词，丢弃法律后缀/角色词/纯数字等无区分度词元，
// 只留有区分度的品牌词元做交集比对（如 kirino / cedoc / hinet）。
const NAME_STOPWORDS = new Set([
  'llc', 'inc', 'ltd', 'limited', 'corp', 'corporation', 'co', 'company', 'gmbh', 'sa', 'bv', 'nv', 'plc',
  'as', 'mnt', 'org', 'ripe', 'apnic', 'arin', 'lacnic', 'afrinic',
  'net', 'network', 'networks', 'adm', 'admin', 'noc', 'abuse', 'role', 'tech', 'technical', 'the', 'and', 'of',
]);

export function nameTokens(str) {
  if (!str) return new Set();
  const toks = String(str).toLowerCase().replace(/[^a-z0-9]+/g, ' ').split(/\s+/).filter(Boolean);
  return new Set(toks.filter((t) => !NAME_STOPWORDS.has(t) && !/^\d+$/.test(t)));
}

// RIPEstat network-info：IP 当前由哪个 ASN 宣告、前缀是什么
export async function fetchNetworkInfo(ip, opts = {}) {
  try {
    const j = await fetchJson(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`, opts);
    const d = j.data || {};
    return { returned: true, asns: (d.asns || []).map(String), prefix: d.prefix || null };
  } catch {
    return { returned: false, asns: [], prefix: null };
  }
}

// RIPEstat as-overview：ASN 的 holder（持有者名，如 "CEDOC-AS HK CEDOC LIMITED"）
export async function fetchAsHolder(asn, opts = {}) {
  try {
    const j = await fetchJson(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${asn}`, opts);
    const d = j.data || {};
    return { returned: true, holder: d.holder || null, announced: !!d.announced };
  } catch {
    return { returned: false, holder: null, announced: false };
  }
}

function vcardFn(entity) {
  const arr = entity && entity.vcardArray && entity.vcardArray[1];
  if (!Array.isArray(arr)) return null;
  const fn = arr.find((x) => Array.isArray(x) && x[0] === 'fn');
  return fn ? String(fn[3]) : null;
}
function vcardKind(entity) {
  const arr = entity && entity.vcardArray && entity.vcardArray[1];
  if (!Array.isArray(arr)) return null;
  const k = arr.find((x) => Array.isArray(x) && x[0] === 'kind');
  return k ? String(k[3]) : null;
}

// RDAP（rdap.org 跳转到权威 RIR）：取网段登记方候选名 + 网络名 + 登记国
export async function fetchRegistration(ip, opts = {}) {
  try {
    const j = await fetchJson(`https://rdap.org/ip/${encodeURIComponent(ip)}`, opts);
    const entities = [];
    const collect = (list) => {
      for (const e of list || []) {
        entities.push(e);
        if (Array.isArray(e.entities)) collect(e.entities);
      }
    };
    collect(j.entities);
    const registrants = entities.filter((e) => (e.roles || []).includes('registrant'));
    const orgRegistrant = registrants.find((e) => vcardKind(e) === 'org');
    const names = [];
    for (const e of entities) { const fn = vcardFn(e); if (fn) names.push(fn); }
    // 展示用登记方：优先 registrant 角色的 org 实体，其次网络名，再其次任意实体名
    const registrant = (orgRegistrant && vcardFn(orgRegistrant))
      || (registrants[0] && vcardFn(registrants[0]))
      || j.name || names[0] || null;
    return { returned: true, networkName: j.name || null, country: j.country || null, registrant, names };
  } catch {
    return { returned: false, networkName: null, country: null, registrant: null, names: [] };
  }
}

// 租赁判定主函数。返回：
// { returned, leased: true|false|null, evidence, registrant, networkName, asn, announcer, prefix }
// leased=null = 只有一方数据（或两方都无区分度词元），未知，不许当结论用。
export async function checkLeased(ip, opts = {}, netInfo = null) {
  const [reg, net] = await Promise.all([
    fetchRegistration(ip, opts),
    netInfo ? Promise.resolve(netInfo) : fetchNetworkInfo(ip, opts),
  ]);
  const asn = net.asns && net.asns.length ? net.asns[0] : null;
  const holderRes = asn ? await fetchAsHolder(asn, opts) : { returned: false, holder: null };
  const announcer = holderRes.holder;
  const base = {
    registrant: reg.registrant, networkName: reg.networkName,
    asn: asn ? `AS${asn}` : null, announcer, prefix: net.prefix || null,
  };
  if (!reg.returned || !holderRes.returned || !reg.registrant || !announcer) {
    return { returned: reg.returned || holderRes.returned, leased: null, evidence: '登记方或宣告方数据缺失，租赁状态未知', ...base };
  }
  // 登记方词元取全部候选名（实体 fn 们 + 网络名）的并集，与宣告 holder 词元求交集
  const regTokens = new Set();
  for (const n of [...reg.names, reg.networkName]) for (const t of nameTokens(n)) regTokens.add(t);
  const annTokens = nameTokens(announcer);
  const shared = [...regTokens].filter((t) => annTokens.has(t));
  if (!regTokens.size || !annTokens.size) {
    return { returned: true, leased: null, evidence: '名称无可比对的品牌词元，租赁状态未知', ...base };
  }
  if (shared.length) {
    return {
      returned: true, leased: false, ...base,
      evidence: `登记方 ${reg.registrant}（网络名 ${reg.networkName}）与宣告方 ${base.asn} ${announcer} 名称同体系（共同词元：${shared.join(', ')}），判非租赁`,
    };
  }
  return {
    returned: true, leased: true, ...base,
    evidence: `登记方 ${reg.registrant}（网络名 ${reg.networkName}）≠ 宣告方 ${base.asn} ${announcer}，名称明显不一致，判租赁/转手运营`,
  };
}

// ---------------- 3) RPKI ----------------

// RIPEstat rpki-validation：需要 宣告 ASN + 前缀。状态原样映射到 scoring 的 rpki 字段。
export async function fetchRpki(ip, opts = {}, netInfo = null) {
  const net = netInfo || (await fetchNetworkInfo(ip, opts));
  const asn = net.asns && net.asns.length ? net.asns[0] : null;
  if (!net.returned || !asn || !net.prefix) {
    return { returned: false, rpki: 'unknown', status: null, asn: asn ? `AS${asn}` : null, prefix: net.prefix || null };
  }
  try {
    const j = await fetchJson(
      `https://stat.ripe.net/data/rpki-validation/data.json?resource=AS${asn}&prefix=${encodeURIComponent(net.prefix)}`, opts);
    const st = (j.data && j.data.status) || 'unknown';
    const rpki = st === 'valid' ? 'valid' : st === 'invalid' ? 'invalid' : 'unknown';
    return { returned: true, rpki, status: st, asn: `AS${asn}`, prefix: net.prefix };
  } catch {
    return { returned: false, rpki: 'unknown', status: null, asn: `AS${asn}`, prefix: net.prefix };
  }
}

// ---------------- 汇总 ----------------

// 一次跑完三项（network-info 只取一次，租赁与 RPKI 共用）。
export async function liveFacts(ip, opts = {}) {
  const net = await fetchNetworkInfo(ip, opts);
  const [ptr, lease, rpki] = await Promise.all([
    fetchPtr(ip, opts),
    checkLeased(ip, opts, net.returned ? net : null),
    fetchRpki(ip, opts, net.returned ? net : null),
  ]);
  return { ptr, lease, rpki, asn: net.asns && net.asns.length ? `AS${net.asns[0]}` : null, prefix: net.prefix || null };
}
