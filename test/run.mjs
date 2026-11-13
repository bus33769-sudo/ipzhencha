// run.mjs — 评分引擎测试：node test/run.mjs
import { scoreIP } from '../worker/src/scoring.js';
import { FIXTURES, SPARSE_INPUT } from './fixtures.mjs';

let failures = 0;
function assert(cond, label) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) failures++;
}

for (const [ip, input] of Object.entries(FIXTURES)) {
  const r = scoreIP(input);
  console.log(`\n=== ${ip} ===`);
  console.log(JSON.stringify(r, null, 2));
}

const us = scoreIP(FIXTURES['37.123.193.82']);
assert(us.type === 'datacenter', '37.123.193.82 类型 = datacenter');
assert(us.score !== null && us.score <= 65, `37.123.193.82 得分 ≤65（租赁上限），实际 ${us.score}`);
assert(us.flags.includes('leased'), '37.123.193.82 flags 含 leased');
assert(us.flags.includes('abuse_history'), '37.123.193.82 flags 含 abuse_history');

const tw = scoreIP(FIXTURES['1.168.162.221']);
assert(tw.type === 'residential', '1.168.162.221 类型 = residential');
assert(tw.score !== null && tw.score >= 85, `1.168.162.221 得分 ≥85，实际 ${tw.score}`);
assert(!tw.flags.includes('abuse_history'), '1.168.162.221 无滥用误报');

for (const ip of ['1.1.1.1', '8.8.8.8', '223.5.5.5']) {
  const r = scoreIP(FIXTURES[ip]);
  assert(r.type === 'datacenter', `${ip} 类型 = datacenter`);
}
const ali = scoreIP(FIXTURES['223.5.5.5']);
assert(ali.flags.includes('incomplete_data'), '223.5.5.5 只有 6 源返回 → 标 incomplete_data（不出 A+）');

const sparse = scoreIP(SPARSE_INPUT);
console.log('\n=== 源数不足场景（3/8 返回）===');
console.log(JSON.stringify(sparse, null, 2));
assert(sparse.score === null, '源数 <4 时 score = null');
assert(sparse.grade === null, '源数 <4 时 grade = null');

// 养号适合度（2026-11-12 用户批准，规则写死在 scoring.decideSuitability）
assert(tw.suitability && tw.suitability.tier === 'suitable', `1.168.162.221 养号适合度 = suitable，实际 ${tw.suitability && tw.suitability.tier}`);
assert(tw.suitability.reasons.includes('dynamic_ip'), '1.168.162.221 动态家宽 → 理由含 dynamic_ip 提示（不降档）');
assert(us.suitability && us.suitability.tier === 'avoid', `37.123.193.82 养号适合度 = avoid，实际 ${us.suitability && us.suitability.tier}`);
assert(us.suitability.reasons.includes('abuse_recent'), '37.123.193.82 近期 62 条举报 → 理由含 abuse_recent');
for (const ip of ['1.1.1.1', '8.8.8.8']) {
  const r = scoreIP(FIXTURES[ip]);
  assert(r.suitability && r.suitability.tier === 'daily', `${ip} 干净机房 → 养号适合度 = daily，实际 ${r.suitability && r.suitability.tier}`);
  assert(r.suitability.reasons.includes('datacenter'), `${ip} daily 理由含 datacenter`);
}
assert(sparse.suitability && sparse.suitability.tier === 'unknown', `源 <4 → 养号适合度 = unknown，实际 ${sparse.suitability && sparse.suitability.tier}`);
assert(sparse.suitability.reasons.includes('insufficient_data'), 'unknown 理由含 insufficient_data');

console.log(failures ? `\n结果：${failures} 条断言失败` : '\n结果：全部断言通过');
process.exit(failures ? 1 : 0);
