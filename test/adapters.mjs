// adapters.mjs — 带 Key 适配器单元测试：node test/adapters.mjs
// 用 mock fetch 喂各家「文档化响应形状」的 fixture，断言归一化映射、投票映射与异常兜底。
// 全程不打真实接口、不需要任何真实 Key；ENV 里的值是假测试串，不是真 Key。
import {
  srcAbuseIPDB, srcProxycheck, srcIpapiIs, srcIp2Location, normalize, DEFERRED_SOURCES,
} from '../worker/src/index.js';

let failures = 0;
let total = 0;
function assert(cond, label) {
  total++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) failures++;
}

const ENV = {
  ABUSEIPDB_API_KEY: 'test-abuse-key',
  PROXYCHECK_API_KEY: 'test-pc-key',
  IPAPIIS_API_KEY: 'test-ipapi-key',
  IP2LOCATION_API_KEY: 'test-ip2l-key',
};

const realFetch = globalThis.fetch;
function stubFetch(handler) { globalThis.fetch = handler; }
function restoreFetch() { globalThis.fetch = realFetch; }
const jsonResp = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { 'content-type': 'application/json' },
});
const daysAgoIso = (d) => new Date(Date.now() - d * 86400000).toISOString();

// ---------- 无 Key：4 家一律 returned:false + no_key，不得抛错 ----------
for (const [fn, label] of [
  [srcAbuseIPDB, 'abuseipdb'], [srcProxycheck, 'proxycheck'],
  [srcIpapiIs, 'ipapiis'], [srcIp2Location, 'ip2location'],
]) {
  const r = await fn('1.2.3.4', {});
  assert(r.returned === false && r.note === 'no_key', `${label} 无 Key → returned:false + no_key`);
}

// ---------- AbuseIPDB ----------
// 近期举报型：置信度 30、共 30 次、25 次在 180 天内、最近一次 10 天前
{
  const reports = [
    ...Array.from({ length: 25 }, () => ({ reportedAt: daysAgoIso(10.5), categories: [18], reporterCountryCode: 'US' })),
    ...Array.from({ length: 5 }, () => ({ reportedAt: daysAgoIso(200.5), categories: [18], reporterCountryCode: 'DE' })),
  ];
  stubFetch(async () => jsonResp({
    data: {
      ipAddress: '37.123.193.82', isPublic: true, abuseConfidenceScore: 30,
      countryCode: 'US', usageType: 'Data Center/Web Hosting/Transit',
      isp: 'Kirino LLC', isTor: false, totalReports: 30, numDistinctUsers: 12,
      lastReportedAt: daysAgoIso(10.5), reports,
    },
  }));
  const r = await srcAbuseIPDB('37.123.193.82', ENV);
  assert(r.returned === true, 'abuseipdb 近期型 returned');
  assert(r.abuse.confidence === 30 && r.abuse.totalReports === 30, 'abuseipdb 置信度/总举报数映射');
  assert(r.abuse.distinctUsers === 12, 'abuseipdb 举报人数 numDistinctUsers 映射');
  assert(r.abuse.lastReportDaysAgo === 10, `abuseipdb 最近举报距今天数 = 10，实际 ${r.abuse.lastReportDaysAgo}`);
  assert(r.abuse.reportsWithin180Days === 25, `abuseipdb 近 180 天举报数 = 25，实际 ${r.abuse.reportsWithin180Days}`);
  assert(r.usageType === 'Data Center/Web Hosting/Transit' && r.isp === 'Kirino LLC', 'abuseipdb usageType/isp 映射');
}
// 仅历史旧记录型：8 次举报全在 250 天前
{
  stubFetch(async () => jsonResp({
    data: {
      ipAddress: '1.2.3.4', abuseConfidenceScore: 0, countryCode: 'NL',
      usageType: 'Fixed Line ISP', isp: 'Example ISP', isTor: false,
      totalReports: 8, numDistinctUsers: 6, lastReportedAt: daysAgoIso(250.5),
      reports: Array.from({ length: 8 }, () => ({ reportedAt: daysAgoIso(250.5), categories: [18] })),
    },
  }));
  const r = await srcAbuseIPDB('1.2.3.4', ENV);
  assert(r.returned === true && r.abuse.reportsWithin180Days === 0, 'abuseipdb 旧记录型 → 近 180 天举报 = 0');
  assert(r.abuse.lastReportDaysAgo === 250, `abuseipdb 旧记录型最近距今 = 250 天，实际 ${r.abuse.lastReportDaysAgo}`);
}
// 异常兜底：HTTP 403 / 超时 / 坏 JSON / 网络错误
{
  stubFetch(async () => jsonResp({ errors: [{ detail: 'denied' }] }, 403));
  const r1 = await srcAbuseIPDB('1.2.3.4', ENV);
  assert(r1.returned === false && r1.note === 'http_403', `abuseipdb HTTP 403 → http_403，实际 ${r1.note}`);

  stubFetch(async () => { const e = new Error('aborted'); e.name = 'AbortError'; throw e; });
  const r2 = await srcAbuseIPDB('1.2.3.4', ENV);
  assert(r2.returned === false && r2.note === 'timeout', `abuseipdb 超时 → timeout，实际 ${r2.note}`);

  stubFetch(async () => new Response('this is not json', { status: 200 }));
  const r3 = await srcAbuseIPDB('1.2.3.4', ENV);
  assert(r3.returned === false && r3.note === 'bad_json', `abuseipdb 坏 JSON → bad_json，实际 ${r3.note}`);

  stubFetch(async () => { throw new TypeError('fetch failed'); });
  const r4 = await srcAbuseIPDB('1.2.3.4', ENV);
  assert(r4.returned === false && r4.note === 'network_error', `abuseipdb 网络错误 → network_error，实际 ${r4.note}`);
}

// ---------- proxycheck ----------
// 家宽型（形状按 proxycheck.io v2 文档：扁平字段）
{
  stubFetch(async () => jsonResp({
    status: 'ok',
    '1.168.162.221': {
      asn: 'AS3462', range: '1.168.162.0/24', hostname: '1-168-162-221.dynamic-ip.hinet.net',
      provider: 'Chunghwa Telecom Co., Ltd.', organisation: 'Chunghwa Telecom Co., Ltd.',
      country: 'Taiwan', isocode: 'TW', region: 'Changhua', city: 'Changhua',
      proxy: 'no', type: 'Residential', risk: 0,
    },
  }));
  const r = await srcProxycheck('1.168.162.221', ENV);
  assert(r.returned === true && r.isProxy === false && r.risk === 0, 'proxycheck 家宽型 isProxy/risk 映射');
  assert(r.asn === 'AS3462' && r.country === 'TW' && r.type === 'Residential', 'proxycheck 家宽型 asn/country/type 映射');
  const norm = normalize('1.168.162.221', [r]);
  assert(norm.sources[0].type === 'residential', 'proxycheck Residential → 投票 residential');
}
// 机房代理型：proxy yes、Hosting、risk 66、port/seen
{
  stubFetch(async () => jsonResp({
    status: 'ok',
    '37.123.193.82': {
      asn: 'AS60024', provider: 'CEDOC', organisation: 'CEDOC', country: 'United States',
      isocode: 'US', proxy: 'yes', type: 'Hosting', risk: 66, port: '3128', seen: '2026-11-01 12:00:00',
    },
  }));
  const r = await srcProxycheck('37.123.193.82', ENV);
  assert(r.returned === true && r.isProxy === true && r.risk === 66, 'proxycheck 机房型 isProxy/risk 映射');
  assert(r.port === '3128' && r.lastSeen === '2026-11-01 12:00:00', 'proxycheck port/seen 映射');
  const norm = normalize('37.123.193.82', [r]);
  assert(norm.sources[0].type === 'datacenter', 'proxycheck Hosting → 投票 datacenter');
  assert(norm.proxyFlagSources === 1, 'proxycheck isProxy 计入 proxyFlagSources');
}
// Wireless → mobile；业务错误状态 → api_error
{
  stubFetch(async () => jsonResp({ status: 'ok', '1.2.3.4': { proxy: 'no', type: 'Wireless', risk: 5 } }));
  const r = await srcProxycheck('1.2.3.4', ENV);
  const norm = normalize('1.2.3.4', [r]);
  assert(norm.sources[0].type === 'mobile', 'proxycheck Wireless → 投票 mobile');

  stubFetch(async () => jsonResp({ status: 'denied', message: 'Invalid API key' }));
  const r2 = await srcProxycheck('1.2.3.4', ENV);
  assert(r2.returned === false && r2.note === 'api_error', `proxycheck status:denied → api_error，实际 ${r2.note}`);
}

// ---------- ipapi.is ----------
// 机房型（形状按 ipapi.is 文档：company/asn/location + is_* 标记）
{
  stubFetch(async () => jsonResp({
    ip: '37.123.193.82', is_bogon: false, is_mobile: false, is_datacenter: true,
    is_proxy: false, is_vpn: true, is_tor: false, is_abuser: true,
    company: { name: 'Example Hosting Inc.', type: 'hosting', abuser_score: '0.50' },
    asn: { asn: 'AS60024', type: 'hosting', org: 'CEDOC', abuser_score: '0.40' },
    location: { country: 'United States', country_code: 'US', state: 'California', city: 'San Jose' },
  }));
  const r = await srcIpapiIs('37.123.193.82', ENV);
  assert(r.returned === true && r.isDatacenter === true && r.isVpn === true && r.isTor === false, 'ipapi.is 机房型 is_* 标记映射');
  assert(r.companyType === 'hosting' && r.asnType === 'hosting' && r.asn === 'AS60024', 'ipapi.is company/asn 类型与 ASN 映射');
  assert(r.country === 'US' && r.city === 'San Jose', 'ipapi.is location 映射');
  const norm = normalize('37.123.193.82', [r]);
  assert(norm.sources[0].type === 'datacenter', 'ipapi.is is_datacenter → 投票 datacenter');
  assert(norm.vpnFlagSources === 1, 'ipapi.is is_vpn 计入 vpnFlagSources');
}
// ISP 家宽型 与 移动型
{
  stubFetch(async () => jsonResp({
    ip: '1.168.162.221', is_datacenter: false, is_proxy: false, is_vpn: false, is_tor: false,
    is_abuser: false, is_mobile: false,
    company: { name: 'Chunghwa Telecom', type: 'isp' },
    asn: { asn: 'AS3462', type: 'isp', org: 'Chunghwa Telecom' },
    location: { country: 'Taiwan', country_code: 'TW', state: 'Changhua', city: 'Changhua' },
  }));
  const r = await srcIpapiIs('1.168.162.221', ENV);
  const norm = normalize('1.168.162.221', [r]);
  assert(norm.sources[0].type === 'residential', 'ipapi.is company.type=isp → 投票 residential');

  stubFetch(async () => jsonResp({
    ip: '1.2.3.4', is_datacenter: false, is_mobile: true,
    company: { type: 'isp' }, asn: { asn: 'AS10000', type: 'isp' },
    location: { country_code: 'TW', country: 'Taiwan', city: 'Taipei', state: 'Taipei' },
  }));
  const r2 = await srcIpapiIs('1.2.3.4', ENV);
  const norm2 = normalize('1.2.3.4', [r2]);
  assert(norm2.sources[0].type === 'mobile', 'ipapi.is is_mobile → 投票 mobile（优先于 company.type）');
}

// ---------- IP2Location ----------
// WS25 成功（字段名按 ip2location.io 现行文档：country_code / usage_type 代码 / is_proxy / proxy 对象）
{
  stubFetch(async (url) => {
    assert(String(url).includes('package=WS25'), 'ip2location 首次请求带 package=WS25');
    return jsonResp({
      ip: '1.168.162.221', country_code: 'TW', country_name: 'Taiwan',
      region_name: 'Changhua', city_name: 'Changhua', isp: 'Chunghwa Telecom Co., Ltd.',
      asn: 'AS3462', as: 'Chunghwa Telecom Co., Ltd.', usage_type: 'ISP', is_proxy: false,
    });
  });
  const r = await srcIp2Location('1.168.162.221', ENV);
  assert(r.returned === true && r.package === 'WS25', 'ip2location WS25 成功 → package 标 WS25');
  assert(r.country === 'TW' && r.city === 'Changhua' && r.asn === 'AS3462', 'ip2location 国家/城市/ASN 映射');
  assert(r.usageType === 'ISP' && r.isProxy === false, 'ip2location usage_type/is_proxy 映射');
  const norm = normalize('1.168.162.221', [r]);
  assert(norm.sources[0].type === 'residential', 'ip2location usage_type=ISP → 投票 residential');
}
// WS25 被拒 → 退回默认包；DCH + 代理详情
{
  let calls = 0;
  stubFetch(async (url) => {
    calls++;
    if (String(url).includes('package=WS25')) {
      return jsonResp({ error: { error_code: 10006, error_message: 'Package not supported on this plan.' } });
    }
    return jsonResp({
      ip: '37.123.193.82', country_code: 'US', country_name: 'United States of America',
      region_name: 'California', city_name: 'San Jose', isp: 'Example Host',
      asn: 'AS60024', as: 'CEDOC', usage_type: 'DCH', is_proxy: true,
      proxy: { last_seen: 3, proxy_type: 'VPN', threat: '-', provider: 'ExampleVPN' },
    });
  });
  const r = await srcIp2Location('37.123.193.82', ENV);
  assert(calls === 2 && r.returned === true && r.package === 'default', 'ip2location WS25 被拒 → 自动退回默认包');
  assert(r.isProxy === true && r.proxyType === 'VPN' && r.proxyProvider === 'ExampleVPN', 'ip2location proxy 详情映射');
  const norm = normalize('37.123.193.82', [r]);
  assert(norm.sources[0].type === 'datacenter', 'ip2location usage_type=DCH → 投票 datacenter');
  assert(norm.proxyFlagSources === 1, 'ip2location is_proxy 计入 proxyFlagSources');
}
// WS 式旧字段名兼容（country_short 等）+ 两次都 error → api_error
{
  stubFetch(async () => jsonResp({
    country_short: 'TW', country_long: 'Taiwan (Province of China)', region: 'Taipei',
    city: 'Taipei', usage_type: 'ISP', is_proxy: false, asn: '3462',
  }));
  const r = await srcIp2Location('1.168.162.221', ENV);
  assert(r.returned === true && r.country === 'TW' && r.asn === 'AS3462', 'ip2location WS 式字段名兼容 + ASN 补 AS 前缀');

  stubFetch(async () => jsonResp({ error: { error_code: 10002, error_message: 'Invalid API key.' } }));
  const r2 = await srcIp2Location('1.168.162.221', ENV);
  assert(r2.returned === false && r2.note === 'api_error', `ip2location 两次都 error → api_error，实际 ${r2.note}`);
}

// ---------- normalize 综合口径 ----------
// 三家带 Key 源同票 + PTR 硬证据：sources 逐条计数；后置的 MaxMind 不出现在 sources 里
{
  const results = [
    { name: 'rdap', returned: true },
    { name: 'dnsbl', returned: true, hits: [], answered: 12, total: 13, detail: [] },
    { name: 'tor', returned: true, isTor: false },
    {
      name: 'livecheck', returned: true,
      ptr: { returned: true, hostname: '1-168-162-221.dynamic-ip.hinet.net', residentialFormat: true },
      lease: { returned: true, leased: false }, rpki: { returned: true, rpki: 'valid' },
    },
    { name: 'abuseipdb', returned: true, abuse: { confidence: 0, totalReports: 0, lastReportDaysAgo: null } },
    { name: 'proxycheck', returned: true, type: 'Residential', isProxy: false },
    { name: 'ipapiis', returned: true, isDatacenter: false, companyType: 'isp', isProxy: false, isVpn: false },
    { name: 'ip2location', returned: true, usageType: 'ISP', isProxy: false },
  ];
  const norm = normalize('1.168.162.221', results);
  const votes = norm.sources.filter((s) => s.type === 'residential').map((s) => s.name);
  assert(votes.includes('proxycheck') && votes.includes('ipapiis') && votes.includes('ip2location') && votes.includes('ptr'),
    `类型投票含 proxycheck/ipapiis/ip2location/ptr 四票，实际 ${votes.join(',')}`);
  assert(norm.sources.length === 9, `完整度分母 = 9（8 源 + ptr 票），实际 ${norm.sources.length}`);
  assert(!norm.sources.some((s) => s.name === 'maxmind_geolite'), 'MaxMind 后置源不进 sources、不占分母');
  assert(norm.rdns === '1-168-162-221.dynamic-ip.hinet.net' && norm.rpki === 'valid' && norm.leased === false,
    'normalize 透传 rdns/rpki/leased');
  assert(Array.isArray(DEFERRED_SOURCES) && DEFERRED_SOURCES[0].name === 'maxmind_geolite'
    && DEFERRED_SOURCES[0].status === 'deferred', 'DEFERRED_SOURCES 含 MaxMind 后置条目');
}

restoreFetch();
console.log(`\n共 ${total} 条断言，${failures} 条失败`);
console.log(failures ? '结果：有断言失败' : '结果：全部断言通过');
process.exit(failures ? 1 : 0);
