// scoring.js — IP侦查自研评分引擎（纯函数，无平台依赖，Node 与 Worker 通用）
// 公式依据：方案第 8 节「自研评分公式 v1」。改公式纪律：每次只改一项，改完跑 test/run.mjs。
//
// 输入（各源归一化后的判定对象）：
// {
//   sources: [ { name, returned, type? } ],      // 每家源一条；type 为该源给出的类型（可缺）
//   rdns: string | null,                          // 反向解析，如 "1-168-162-221.dynamic-ip.hinet.net"
//   leased: boolean,                              // 登记方/宣告 ASN/运营方对不上 → 租赁/转手
//   tor: boolean,                                 // 是否 Tor 出口
//   abuse: { confidence, totalReports, lastReportDaysAgo } | null,  // AbuseIPDB 摘要；无记录给 totalReports:0
//   riskMalicious: boolean,                       // 风险库命中恶意/失陷名单
//   riskSpamOnly: boolean,                        // 风险库仅命中垃圾注册名单
//   dnsblHits: number,                            // DNSBL 命中个数
//   proxyFlagSources: number,                     // 标代理的源个数
//   vpnFlagSources: number,                       // 标 VPN 的源个数
//   segmentRiskCount: number,                     // 同 /24 在风险库的 IP 个数
//   rpki: 'valid' | 'invalid' | 'unknown'
// }
//
// 输出：{ score, grade, type, flags, deductions: [{item, points, source, note}], sourcesReturned,
//         suitability: { tier, reasons: [key] } }
// score 为 null 表示源太少（<4），不给总分。
// suitability 为养号适合度（2026-11-12 用户批准加，规则见 decideSuitability，写死不许放宽）：
// tier 四值 suitable / daily / avoid / unknown；reasons 为稳定英文 key，前端翻双语，
// 引擎同时给每个 key 配中文默认说明（SUITABILITY_REASON_ZH），供 curl 纯文本简报直接引用。

export const TYPE_CAPS = {
  residential: 100,
  mobile: 95,
  education: 90,
  business: 85,
  datacenter: 55,
  unknown: 70,
};

const LEASED_CAP = 65;
const MIN_SOURCES_FOR_SCORE = 4;
const MIN_SOURCES_FOR_APLUS = 7;
const RESIDENTIAL_RDNS = /(dynamic|dyn|dial|adsl|pool|home|residential|broadband|fiber|fttb|ftth|cable)/i;
const DYNAMIC_RDNS = /(dynamic|dyn|dial|dhcp)/i; // PTR 为动态格式（动态家宽）

export const SUITABILITY_TIER_ZH = {
  suitable: '适合养号',
  daily: '日常够用',
  avoid: '别碰重要的号',
  unknown: '数据不足，暂不判断',
};

// 每个 reasons key 的中文默认说明（前端另有 zh/en 双语文案，key 必须与此表保持一致）
export const SUITABILITY_REASON_ZH = {
  insufficient_data: '返回源不足 4 个，数据不够，暂不判断',
  tor_exit: 'Tor 出口节点，平台普遍直接拦截',
  risk_malicious: '命中恶意/失陷风险名单',
  abuse_confidence: 'AbuseIPDB 滥用置信度 ≥50',
  abuse_recent: '近 180 天内滥用举报 ≥20 次',
  score_low: '健康分低于 50',
  residential_clean: '真实家宽/移动网络，无滥用记录',
  dynamic_ip: '动态 IP，地址可能会变，偶尔触发验证属正常',
  datacenter: '机房 IP，不是家庭宽带',
  non_residential_type: '非家宽/移动类型（企业/教育/未明）',
  leased: '租赁/转手段，登记与运营方不一致',
  abuse_history_old: '历史上有滥用记录（180 天前的旧举报）',
  abuse_record: '有少量滥用举报记录',
  risk_spam_only: '仅命中垃圾注册名单',
  dnsbl_hits: '命中 DNSBL 黑名单',
  proxy_flagged: '2 个以上来源标记为代理',
  score_below_70: '健康分未达 70',
  incomplete_data: '数据不全（返回源少于 7 个）',
  daily_general: '无硬伤，但不满足养号的严苛条件',
};

// 养号适合度判定（2026-11-12 定版，顺序写死：先命中先算，不许放宽；改规则同改公式纪律）
function decideSuitability(input, { score, type, flags, sourcesReturned }) {
  // 1. 无总分（源 <4）→ 不判断
  if (score === null) return { tier: 'unknown', reasons: ['insufficient_data'] };

  // 2. 硬伤任一成立 → avoid，理由逐项列
  const abuse = input.abuse || null;
  const avoidReasons = [];
  if (input.tor) avoidReasons.push('tor_exit');
  if (input.riskMalicious) avoidReasons.push('risk_malicious');
  if (abuse && abuse.confidence >= 50) avoidReasons.push('abuse_confidence');
  if (abuse && abuse.totalReports >= 20 && abuse.lastReportDaysAgo !== null && abuse.lastReportDaysAgo <= 180) {
    avoidReasons.push('abuse_recent');
  }
  if (score < 50) avoidReasons.push('score_low');
  if (avoidReasons.length) return { tier: 'avoid', reasons: avoidReasons };

  // 3. 严苛条件同时满足 → suitable（有 abuse_history 标记一律不行，含旧举报）
  const isResOrMobile = type === 'residential' || type === 'mobile';
  if (
    isResOrMobile && score >= 70 && !flags.includes('abuse_history')
    && (input.proxyFlagSources || 0) < 2 && !input.tor && sourcesReturned >= MIN_SOURCES_FOR_APLUS
  ) {
    const reasons = ['residential_clean'];
    if (input.rdns && DYNAMIC_RDNS.test(input.rdns)) reasons.push('dynamic_ip'); // 只提示，不降档
    return { tier: 'suitable', reasons };
  }

  // 4. 其余 → daily，理由取实际成立的主要降档原因
  const reasons = [];
  if (type === 'datacenter') reasons.push('datacenter');
  else if (!isResOrMobile) reasons.push('non_residential_type');
  if (input.leased) reasons.push('leased');
  if (flags.includes('abuse_history_old')) reasons.push('abuse_history_old');
  else if (flags.includes('abuse_history')) reasons.push('abuse_record');
  if (input.riskSpamOnly) reasons.push('risk_spam_only');
  if ((input.dnsblHits || 0) > 0) reasons.push('dnsbl_hits');
  if ((input.proxyFlagSources || 0) >= 2) reasons.push('proxy_flagged');
  if (isResOrMobile && score < 70) reasons.push('score_below_70');
  if (sourcesReturned < MIN_SOURCES_FOR_APLUS) reasons.push('incomplete_data');
  if (!reasons.length) reasons.push('daily_general');
  return { tier: 'daily', reasons };
}

export function gradeFor(score) {
  if (score === null || score === undefined) return null;
  if (score >= 85) return 'A+';
  if (score >= 70) return 'A';
  if (score >= 50) return 'B';
  if (score >= 30) return 'C';
  return 'D';
}

// 类型投票：至少 3 票（含 PTR 硬证据 1 票）才定类型，否则 unknown
export function decideType(input) {
  const votes = {};
  for (const s of input.sources || []) {
    if (s.returned && s.type && TYPE_CAPS[s.type] !== undefined) {
      votes[s.type] = (votes[s.type] || 0) + 1;
    }
  }
  if (input.rdns && RESIDENTIAL_RDNS.test(input.rdns)) {
    votes.residential = (votes.residential || 0) + 1; // 家宽域名格式 PTR = 硬证据一票
  }
  let best = null;
  let bestCount = 0;
  for (const [t, c] of Object.entries(votes)) {
    if (c > bestCount) { best = t; bestCount = c; }
  }
  if (!best || bestCount < 3) return { type: 'unknown', votes };
  return { type: best, votes };
}

export function scoreIP(input) {
  const sourcesReturned = (input.sources || []).filter((s) => s.returned).length;
  const { type } = decideType(input);
  const flags = [];
  const deductions = [];
  const ded = (item, points, source, note) => deductions.push({ item, points, source, note: note || '' });

  if (input.leased) flags.push('leased');
  if (input.tor) flags.push('tor_exit');

  // 扣分项（方案第 8 节，逐项写明来源）
  if (input.tor) ded('tor_exit', 40, 'tor_exit_list', 'Tor 出口节点');

  const abuse = input.abuse;
  if (abuse && (abuse.totalReports > 0 || abuse.confidence > 0)) {
    flags.push('abuse_history');
    if (abuse.confidence >= 50) ded('abuse_confidence', 10, 'abuseipdb', `滥用置信度 ${abuse.confidence}`);
    if (abuse.totalReports >= 20 && abuse.lastReportDaysAgo !== null && abuse.lastReportDaysAgo <= 180) {
      ded('abuse_recent_reports', 6, 'abuseipdb', `举报 ${abuse.totalReports} 次，最近一次在 180 天内`);
    } else if (abuse.totalReports > 0 && (abuse.lastReportDaysAgo === null || abuse.lastReportDaysAgo > 180)) {
      ded('abuse_old_reports', 2, 'abuseipdb', '只有 180 天前的旧举报');
      flags.push('abuse_history_old');
    }
  }

  if (input.riskMalicious) ded('risk_malicious', 12, 'risk_db', '命中恶意/失陷名单');
  else if (input.riskSpamOnly) ded('risk_spam_only', 3, 'risk_db', '仅命中垃圾注册名单');

  if (input.dnsblHits > 0) {
    ded('dnsbl', Math.min(input.dnsblHits * 4, 16), 'dnsbl', `DNSBL 命中 ${input.dnsblHits} 个（每命中 -4，上限 -16）`);
  }

  if (input.proxyFlagSources >= 2) ded('proxy_multi_source', 8, 'multi', `${input.proxyFlagSources} 个源标记为代理`);
  else if (input.proxyFlagSources === 1) flags.push('proxy_single_source'); // 仅 1 源只提示不扣
  if (input.vpnFlagSources >= 2) ded('vpn_multi_source', 5, 'multi', `${input.vpnFlagSources} 个源标记为 VPN`);

  if (input.segmentRiskCount >= 8) ded('segment_risk', 5, 'risk_db', `同 /24 有 ${input.segmentRiskCount} 个 IP 在风险库`);
  else if (input.segmentRiskCount >= 3) ded('segment_risk', 2, 'risk_db', `同 /24 有 ${input.segmentRiskCount} 个 IP 在风险库`);

  if (input.rpki === 'invalid') ded('rpki_invalid', 8, 'rpki', 'RPKI 校验无效');

  // 完整度闸门：<4 源不给总分
  if (sourcesReturned < MIN_SOURCES_FOR_SCORE) {
    flags.push('insufficient_data');
    const suitability = decideSuitability(input, { score: null, type, flags, sourcesReturned });
    return { score: null, grade: null, type, flags, deductions, sourcesReturned, suitability };
  }

  let cap = TYPE_CAPS[type];
  if (input.leased) cap = Math.min(cap, LEASED_CAP);
  const totalDed = deductions.reduce((a, d) => a + d.points, 0);
  let score = Math.max(0, cap - totalDed);

  // 完整度闸门：<7 源不出 A+（分数上限 84），并标数据不全
  if (sourcesReturned < MIN_SOURCES_FOR_APLUS) {
    flags.push('incomplete_data');
    if (score > 84) score = 84;
  }

  const suitability = decideSuitability(input, { score, type, flags, sourcesReturned });
  return { score, grade: gradeFor(score), type, flags, deductions, sourcesReturned, suitability };
}
