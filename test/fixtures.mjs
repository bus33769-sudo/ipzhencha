// fixtures.mjs — 固化（mock）的各源归一化判定，模拟方案第 9 节测试集的 5 个已知 IP。
// 数据来源：2026-11-12 对 ipx.al 的实测 + 四源交叉核对结论（见方案第 2 节），非实时抓取。
// 字段与 worker/src/scoring.js 的输入约定一致。

const S = (name, returned, type) => (type ? { name, returned, type } : { name, returned });
const ALL8 = (types = {}) => [
  S('rdap', true),
  S('dnsbl', true),
  S('tor', true),
  S('abuseipdb', true),
  S('proxycheck', true, types.proxycheck),
  S('ipapiis', true, types.ipapiis),
  S('ip2location', true),
  S('ipinfo', true, types.ipinfo),
];
const BASE = {
  rdns: null, leased: false, tor: false,
  abuse: { confidence: 0, totalReports: 0, lastReportDaysAgo: null },
  riskMalicious: false, riskSpamOnly: false,
  dnsblHits: 0, proxyFlagSources: 0, vpnFlagSources: 0,
  segmentRiskCount: 0, rpki: 'valid',
};

export const FIXTURES = {
  // Cloudflare 公共 DNS（Anycast）：机房判定，骨架类型表无 anycast，按机房计
  '1.1.1.1': {
    ...BASE,
    sources: ALL8({ proxycheck: 'datacenter', ipapiis: 'datacenter', ipinfo: 'datacenter' }),
  },
  // Google 公共 DNS（Anycast）：机房判定
  '8.8.8.8': {
    ...BASE,
    sources: ALL8({ proxycheck: 'datacenter', ipapiis: 'datacenter', ipinfo: 'datacenter' }),
  },
  // 阿里公共 DNS：机房；实测时 ipx.al 缺 2 家源，这里也模拟 6/8 返回（完整度应下降）
  '223.5.5.5': {
    ...BASE,
    sources: [
      S('rdap', true), S('dnsbl', true), S('tor', true), S('abuseipdb', false),
      S('proxycheck', true, 'datacenter'), S('ipapiis', true, 'datacenter'),
      S('ip2location', false), S('ipinfo', true, 'datacenter'),
    ],
  },
  // 及格线样本：圣何塞机房 + 号段登记方 Kirino LLC、运营方香港 CEDOC（租赁/转手）
  // + AbuseIPDB 62 条举报（2026-07-06 至 08-15，最近一次距 2026-11-12 约 89 天，在 180 天内）
  // + DNSBL 命中 1 个（s5h 邮件黑名单）+ 1 个源标代理（只提示不扣）
  '37.123.193.82': {
    ...BASE,
    sources: ALL8({ proxycheck: 'datacenter', ipapiis: 'datacenter', ipinfo: 'datacenter' }),
    leased: true,
    abuse: { confidence: 0, totalReports: 62, lastReportDaysAgo: 89 },
    dnsblHits: 1,
    proxyFlagSources: 1,
  },
  // 台湾中华电信 HiNet 真家宽：PTR 为 dynamic-ip.hinet.net，零举报，全源干净
  '1.168.162.221': {
    ...BASE,
    sources: ALL8({ proxycheck: 'residential', ipapiis: 'residential', ipinfo: 'residential' }),
    rdns: '1-168-162-221.dynamic-ip.hinet.net',
  },
};

// 源数不足场景：只 3 个源返回 → 不给总分
export const SPARSE_INPUT = {
  ...BASE,
  sources: [
    S('rdap', true), S('dnsbl', true), S('proxycheck', true, 'datacenter'),
    S('tor', false), S('abuseipdb', false), S('ipapiis', false), S('ip2location', false), S('ipinfo', false),
  ],
};
