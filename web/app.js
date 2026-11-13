// app.js — IP侦查前端（原生 JS，无构建步骤）
// 从 /api/check 取 JSON 渲染五块报告；双语 zh/en，默认按浏览器语言，可手动切换并记住选择。

// ===== 部署配置（整个前端唯一需要改的地方）=====
// API_BASE：Worker 接口的地址。
//   留空 '' = 同源：页面和 Worker 在同一域名下（或 Pages 用路由把 /api 转发给 Worker）时用它，
//              请求会打到当前域名的 /api/check。
//   Pages 与 Worker 分开部署（两个不同域名）时，把它改成 Worker 的完整地址，例如：
//              const CONFIG = { API_BASE: 'https://ipzhencha-api.<你的子域>.workers.dev' };
// 改完重新上传 app.js 到 Pages 即可。具体步骤见部署包里的 DEPLOY.md 第 4 步。
const CONFIG = { API_BASE: 'https://ipzhencha-api.bus33769.workers.dev' };

const I18N = {
  zh: {
    nav_about: '公式与说明',
    hero_title: '这个 IP 干不干净，一页看清',
    hero_sub: '多家来源并排摆出，分歧和缺失如实标明；分数每一分都写清扣在哪。',
    own_ip_label: '你的出口 IP：',
    btn_check: '检测',
    f_type: '类型', f_score: '健康分', f_location: '国家/城市', f_asn: 'ASN / 运营商', f_flags: '标记', f_suitability: '养号适合度',
    suit_disclaimer: '参考判断：平台还看设备、行为与支付地区，高分不等于一定通过风控',
    suit_tier_suitable: '适合养号', suit_tier_daily: '日常够用', suit_tier_avoid: '别碰重要的号', suit_tier_unknown: '数据不足，暂不判断',
    suit_reason_insufficient_data: '返回源不足 4 个，暂不判断',
    suit_reason_tor_exit: 'Tor 出口节点',
    suit_reason_risk_malicious: '命中恶意/失陷风险名单',
    suit_reason_abuse_confidence: '滥用置信度 ≥50',
    suit_reason_abuse_recent: '近 180 天内举报 ≥20 次',
    suit_reason_score_low: '健康分低于 50',
    suit_reason_residential_clean: '真实家宽/移动网络，无滥用记录',
    suit_reason_dynamic_ip: '动态 IP，地址可能会变，偶尔触发验证属正常',
    suit_reason_datacenter: '机房 IP，非家庭宽带',
    suit_reason_non_residential_type: '非家宽/移动类型',
    suit_reason_leased: '租赁/转手段',
    suit_reason_abuse_history_old: '历史有记录：180 天前有过滥用举报',
    suit_reason_abuse_record: '有少量滥用举报记录',
    suit_reason_risk_spam_only: '仅命中垃圾注册名单',
    suit_reason_dnsbl_hits: '命中 DNSBL 黑名单',
    suit_reason_proxy_flagged: '≥2 个源标记为代理',
    suit_reason_score_below_70: '健康分未达 70',
    suit_reason_incomplete_data: '数据不全（返回源 <7 个）',
    suit_reason_daily_general: '无硬伤，但不满足养号的严苛条件',
    block_sources: '多源对照', block_deductions: '扣分明细', block_dnsbl: '黑名单逐项（DNSBL）', block_abuse: '滥用历史（AbuseIPDB）',
    col_source: '来源', col_returned: '已返回', col_country: '国家', col_type: '类型判定', col_note: '备注',
    disclaimer: '分数为本站公式推算，仅供参考，不承诺能通过任何平台的风控。',
    footer_privacy: '本站不记录访客 IP。详见',
    badge: (a, b) => `完整度 ${a}/${b} 个源已返回`,
    badge_incomplete: '数据不全，仅供参考',
    badge_insufficient: '源太少，未给总分',
    yes: '是', no: '否', none: '无', no_deductions: '没有扣分项。',
    no_data: '暂无数据',
    score_none: '未给分（源不足）',
    loading: '检测中…',
    load_failed: '接口暂时不可用（骨架阶段属正常：Worker 未部署时无法取数）。',
    abuse_none: '该源未返回滥用数据。',
    abuse_clean: '无举报记录。',
    abuse_summary: (n, c, d) => `共 ${n} 次举报，置信度 ${c}，最近一次约 ${d} 天前。`,
    placeholder_input: '输入任意 IPv4 / IPv6，如 1.1.1.1',
  },
  en: {
    nav_about: 'Formula & About',
    hero_title: 'How clean is this IP? One page, all sources.',
    hero_sub: 'Every source shown side by side; disagreements and missing data are labelled, and every deducted point says why.',
    own_ip_label: 'Your exit IP:',
    btn_check: 'Check',
    f_type: 'Type', f_score: 'Health score', f_location: 'Country / City', f_asn: 'ASN / Operator', f_flags: 'Flags', f_suitability: 'Suitability for Accounts',
    suit_disclaimer: 'Reference only: platforms also weigh device, behaviour and payment region — a high score does not guarantee passing risk checks.',
    suit_tier_suitable: 'Good for account warming', suit_tier_daily: 'Fine for everyday use', suit_tier_avoid: 'Keep away from important accounts', suit_tier_unknown: 'Not enough data to judge',
    suit_reason_insufficient_data: 'Fewer than 4 sources returned — no verdict yet',
    suit_reason_tor_exit: 'Tor exit node',
    suit_reason_risk_malicious: 'Listed on a malicious/compromised blocklist',
    suit_reason_abuse_confidence: 'Abuse confidence score ≥ 50',
    suit_reason_abuse_recent: '20+ abuse reports within the last 180 days',
    suit_reason_score_low: 'Health score below 50',
    suit_reason_residential_clean: 'Real residential/mobile network, no abuse record',
    suit_reason_dynamic_ip: 'Dynamic IP — the address may change; occasional re-verification is normal',
    suit_reason_datacenter: 'Datacenter IP, not a home connection',
    suit_reason_non_residential_type: 'Not a residential/mobile type',
    suit_reason_leased: 'Leased / resold segment',
    suit_reason_abuse_history_old: 'History on record: abuse reports older than 180 days',
    suit_reason_abuse_record: 'A small number of abuse reports on record',
    suit_reason_risk_spam_only: 'Only on a spam-registration list',
    suit_reason_dnsbl_hits: 'Listed on DNSBL blocklist(s)',
    suit_reason_proxy_flagged: 'Flagged as proxy by 2+ sources',
    suit_reason_score_below_70: 'Health score below 70',
    suit_reason_incomplete_data: 'Incomplete data (fewer than 7 sources)',
    suit_reason_daily_general: 'No hard red flags, but does not meet the stricter account-warming bar',
    block_sources: 'Source comparison', block_deductions: 'Deductions', block_dnsbl: 'Blocklists (DNSBL, item by item)', block_abuse: 'Abuse history (AbuseIPDB)',
    col_source: 'Source', col_returned: 'Returned', col_country: 'Country', col_type: 'Type verdict', col_note: 'Note',
    disclaimer: 'Scores are computed by our published formula for reference only; we do not guarantee passing any platform risk check.',
    footer_privacy: 'We do not log visitor IPs. See',
    badge: (a, b) => `Completeness: ${a}/${b} sources returned`,
    badge_incomplete: 'Incomplete data — reference only',
    badge_insufficient: 'Too few sources — no score given',
    yes: 'yes', no: 'no', none: 'none', no_deductions: 'No deductions.',
    no_data: 'No data',
    score_none: 'No score (too few sources)',
    loading: 'Checking…',
    load_failed: 'API unavailable for now (expected in the skeleton stage before the Worker is deployed).',
    abuse_none: 'No abuse data returned by the source.',
    abuse_clean: 'No reports on record.',
    abuse_summary: (n, c, d) => `${n} reports in total, confidence ${c}, most recent about ${d} days ago.`,
    placeholder_input: 'Enter any IPv4 / IPv6, e.g. 1.1.1.1',
  },
};

let lang = localStorage.getItem('ipzhencha-lang')
  || ((navigator.language || 'zh').toLowerCase().startsWith('en') ? 'en' : 'zh');
const t = () => I18N[lang];

function applyI18n() {
  document.documentElement.lang = lang === 'en' ? 'en' : 'zh-CN';
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const v = t()[el.dataset.i18n];
    if (typeof v === 'string') el.textContent = v;
  });
  document.getElementById('ip-input').placeholder = t().placeholder_input;
  document.getElementById('lang-zh').classList.toggle('active', lang === 'zh');
  document.getElementById('lang-en').classList.toggle('active', lang === 'en');
}

let lastReport = null; // 切换语言时用当前语言重渲染动态内容（含适合度理由）
function setLang(next) {
  lang = next;
  localStorage.setItem('ipzhencha-lang', next);
  applyI18n();
  if (lastReport) render(lastReport);
}
document.getElementById('lang-zh').addEventListener('click', () => setLang('zh'));
document.getElementById('lang-en').addEventListener('click', () => setLang('en'));

function setStatus(msg) { document.getElementById('status').textContent = msg || ''; }

async function fetchReport(ip) {
  const url = ip ? `${CONFIG.API_BASE}/api/check?ip=${encodeURIComponent(ip)}` : `${CONFIG.API_BASE}/api/check`;
  const r = await fetch(url);
  if (!r.ok) throw new Error('http_' + r.status);
  return r.json();
}

function render(rep) {
  const tt = t();
  document.getElementById('report').hidden = false;
  document.getElementById('r-ip').textContent = rep.ip;
  const badge = document.getElementById('r-badge');
  let badgeTxt = tt.badge(rep.sourcesReturned, rep.sourcesTotal);
  if (rep.conclusion.flags.includes('insufficient_data')) badgeTxt += ' · ' + tt.badge_insufficient;
  else if (rep.conclusion.flags.includes('incomplete_data')) badgeTxt += ' · ' + tt.badge_incomplete;
  badge.textContent = badgeTxt;
  document.getElementById('r-type').textContent = rep.conclusion.type;
  document.getElementById('r-score').textContent =
    rep.conclusion.score === null ? tt.score_none : `${rep.conclusion.score} (${rep.conclusion.grade})`;
  document.getElementById('r-flags').textContent = rep.conclusion.flags.length ? rep.conclusion.flags.join(', ') : tt.none;
  // 养号适合度徽章 + 理由（旧报告无此字段时按 unknown 兜底）
  const suit = rep.conclusion.suitability || { tier: 'unknown', reasons: ['insufficient_data'] };
  const sb = document.getElementById('r-suitability');
  sb.textContent = tt['suit_tier_' + suit.tier] || suit.tier;
  sb.className = 'suit-badge suit-' + suit.tier;
  const sr = document.getElementById('r-suitability-reasons');
  sr.innerHTML = '';
  for (const k of suit.reasons || []) {
    const li = document.createElement('li');
    li.textContent = tt['suit_reason_' + k] || k;
    sr.appendChild(li);
  }
  // 骨架版：国家/城市、ASN 从已返回源里取第一个有值的（正式版第 3–4 天做投票汇总）
  const loc = rep.sources.find((s) => s.returned && (s.country || s.city));
  document.getElementById('r-location').textContent = loc ? [loc.country, loc.city].filter(Boolean).join(' / ') : tt.no_data;
  const asnSrc = rep.sources.find((s) => s.returned && s.asn);
  document.getElementById('r-asn').textContent = asnSrc ? asnSrc.asn : tt.no_data;

  const tbody = document.querySelector('#sources-table tbody');
  tbody.innerHTML = '';
  for (const s of rep.sources) {
    const tr = document.createElement('tr');
    if (!s.returned) tr.className = 'missing';
    const cells = [s.name, s.returned ? tt.yes : tt.no, s.country || '—', s.type || '—', s.note || ''];
    for (const c of cells) { const td = document.createElement('td'); td.textContent = c; tr.appendChild(td); }
    tbody.appendChild(tr);
  }

  const ded = document.getElementById('deductions-list');
  ded.innerHTML = '';
  if (!rep.deductions.length) {
    const li = document.createElement('li'); li.textContent = tt.no_deductions; ded.appendChild(li);
  }
  for (const d of rep.deductions) {
    const li = document.createElement('li');
    li.textContent = `-${d.points}  ${d.item}（${d.source}）${d.note ? ' — ' + d.note : ''}`;
    ded.appendChild(li);
  }

  const dbl = document.getElementById('dnsbl-list');
  dbl.innerHTML = '';
  if (!rep.dnsbl || !rep.dnsbl.length) {
    const li = document.createElement('li'); li.textContent = tt.no_data; dbl.appendChild(li);
  }
  for (const z of rep.dnsbl || []) {
    const li = document.createElement('li');
    li.textContent = `${z.zone}: ${z.listed === null ? tt.no_data : z.listed ? 'HIT' : '—'}`;
    if (z.listed) li.className = 'hit';
    dbl.appendChild(li);
  }

  const ab = document.getElementById('abuse-body');
  if (!rep.abuse) ab.textContent = tt.abuse_none;
  else if (!rep.abuse.totalReports) ab.textContent = tt.abuse_clean;
  else ab.textContent = tt.abuse_summary(rep.abuse.totalReports, rep.abuse.confidence, rep.abuse.lastReportDaysAgo ?? '—');
}

async function runCheck(ip) {
  setStatus(t().loading);
  try {
    const rep = await fetchReport(ip);
    lastReport = rep;
    render(rep);
    setStatus('');
    return rep;
  } catch (e) {
    setStatus(t().load_failed);
    return null;
  }
}

document.getElementById('query-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const ip = document.getElementById('ip-input').value.trim();
  if (ip) runCheck(ip);
});

// 打开页面自动检测自己的出口 IP（占位：Worker 未部署时静默失败，只显示 …）
(async () => {
  applyI18n();
  const rep = await runCheck('');
  if (rep) document.getElementById('own-ip-value').textContent = rep.ip;
})();
