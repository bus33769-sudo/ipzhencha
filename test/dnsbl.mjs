// dnsbl.mjs — DNSBL 全量 13 名单真实在线验证：node test/dnsbl.mjs
// 正对照：127.0.0.2（RFC 5782 测试点）——支持测试点的名单必须判命中；
//         zen.spamhaus.org 经公共解析器按官方规则记受限（restricted），如实标注，不算失败。
// 负对照：127.0.0.1（RFC 5782 规定永不列入）与 1.168.162.221（已知干净台湾家宽）——
//         13 个名单一个都不许判命中；受限/无回答按语义如实呈现，不算失败但会打印。
// 参考跑：37.123.193.82 只记录真实命中数，不断言（DNSBL 数据会变；2026-11-12 下午人工核对时它命中过 s5h 一类邮件名单）。
// 这是联网测试：接口不可达时对应断言会 FAIL 并打印原始输出，不要改松断言蒙混。
import { checkDnsbl, DNSBL_ZONES, DNSBL_REMOVED } from '../worker/src/dnsbl.mjs';

let failures = 0;
function assert(cond, label) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) failures++;
}
function show(title, r) {
  console.log(`\n=== ${title} ===`);
  for (const x of r.results) {
    console.log(`  ${x.zone.padEnd(28)} status=${x.status.padEnd(12)} listed=${String(x.listed).padEnd(5)} codes=[${(x.codes || []).join(', ')}]${x.meaning ? ' ' + x.meaning.join('；') : ''}${x.note ? ' — ' + x.note : ''}`);
  }
  console.log(`  命中 ${r.hits.length} 个：${r.hits.join(', ') || '（无）'}；给出确定结论 ${r.answered}/${r.total}`);
}

console.log(`现役名单 ${DNSBL_ZONES.length} 个；已移除 ${DNSBL_REMOVED.length} 个（${DNSBL_REMOVED.map((d) => d.zone).join(', ')}）`);
assert(DNSBL_ZONES.length === 13, '现役名单恰为 13 个');

console.log('\n--- 正对照 127.0.0.2（RFC 5782 测试点）---');
const pos = await checkDnsbl('127.0.0.2');
show('127.0.0.2', pos);
for (const def of DNSBL_ZONES) {
  const r = pos.results.find((x) => x.zone === def.zone);
  if (def.testPoint === 'listed') {
    assert(r.listed === true, `${def.zone} 测试点判命中（实际 status=${r.status}, codes=[${r.codes}]）`);
  } else {
    assert(r.listed === null && r.status === 'restricted',
      `${def.zone} 经公共解析器记受限、不冒充结论（实际 status=${r.status}, listed=${r.listed}）`);
  }
}

console.log('\n--- 负对照 127.0.0.1（RFC 5782 永不列入）---');
const neg1 = await checkDnsbl('127.0.0.1');
show('127.0.0.1', neg1);
assert(neg1.hits.length === 0, `127.0.0.1 无任何名单判命中（实际命中 ${neg1.hits.length}）`);

console.log('\n--- 负对照 1.168.162.221（台湾 HiNet 干净家宽）---');
const tw = await checkDnsbl('1.168.162.221');
show('1.168.162.221', tw);
assert(tw.hits.length === 0, `台湾家宽 13 名单全部未命中（实际命中：${tw.hits.join(', ') || '无'}）`);
const twDefinitive = tw.results.filter((x) => x.listed === false).length;
console.log(`  其中明确未命中 ${twDefinitive} 个，受限/无回答 ${tw.results.length - twDefinitive - tw.hits.length} 个（逐项见上）`);

console.log('\n--- 参考跑 37.123.193.82（美国机房，只记录不断言）---');
const us = await checkDnsbl('37.123.193.82');
show('37.123.193.82', us);
console.log(`INFO  37.123.193.82 本次真实命中 ${us.hits.length} 个：${us.hits.join(', ') || '（无）'}（DNSBL 数据会变，此项不断言）`);

console.log(failures ? `\n结果：${failures} 条断言失败` : '\n结果：全部断言通过');
process.exit(failures ? 1 : 0);
