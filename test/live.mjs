// live.mjs — 免 Key 在线判定真实调用测试：node test/live.mjs
// 对两个已知答案的 IP 直接打真实接口（dns.google / rdap.org / RIPEstat），断言判定结果。
// 注意：这是联网测试，接口不可达时对应断言会 FAIL 并打印原始输出，不要改松断言蒙混。
import { liveFacts } from '../worker/src/livecheck.mjs';

let failures = 0;
function assert(cond, label) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) failures++;
}

console.log('=== 1.168.162.221（台湾中华电信 HiNet 真家宽）在线判定 ===');
const tw = await liveFacts('1.168.162.221');
console.log(JSON.stringify(tw, null, 2));
assert(tw.ptr.returned === true, 'TW PTR 查询成功返回');
assert(typeof tw.ptr.hostname === 'string' && tw.ptr.hostname.endsWith('.dynamic-ip.hinet.net'),
  `TW PTR 为 *.dynamic-ip.hinet.net 家宽格式，实际 ${tw.ptr.hostname}`);
assert(tw.ptr.residentialFormat === true, 'TW PTR 判为家宽格式（硬证据）');
assert(tw.lease.leased === false, `TW leased = false（登记/宣告同为 HiNet/AS3462 体系），实际 ${tw.lease.leased}`);
assert(tw.rpki.returned === true && ['valid', 'invalid', 'unknown'].includes(tw.rpki.rpki),
  `TW RPKI 有明确返回且为三态之一，实际 returned=${tw.rpki.returned} rpki=${tw.rpki.rpki}`);

console.log('\n=== 37.123.193.82（美国机房，登记 Kirino LLC / 宣告 AS60024 CEDOC，租赁转手）在线判定 ===');
const us = await liveFacts('37.123.193.82');
console.log(JSON.stringify(us, null, 2));
assert(us.lease.leased === true, `US leased = true，实际 ${us.lease.leased}`);
assert(typeof us.lease.evidence === 'string'
  && /kirino/i.test(us.lease.evidence) && /cedoc/i.test(us.lease.evidence),
  'US 租赁证据字符串同时含登记方（Kirino）与宣告方（CEDOC）名称');
assert(us.asn === 'AS60024', `US 宣告 ASN 原始字段 = AS60024，实际 ${us.asn}`);
assert(us.lease.asn === 'AS60024', `US lease.asn = AS60024，实际 ${us.lease.asn}`);

console.log(failures ? `\n结果：${failures} 条断言失败` : '\n结果：全部断言通过');
process.exit(failures ? 1 : 0);
