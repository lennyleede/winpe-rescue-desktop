// 精确统计某个 VEN&DEV 在 INF 里出现的完整硬件 ID 形态(有没有裸 ID / 有哪些 REV)
// 用法: node test/inf_rev.js <inf路径...>   环境变量 ID 默认 PCI\VEN_10EC&DEV_8136
const fs = require('fs');
function decode(p) {
  const b = fs.readFileSync(p);
  if (b[0] === 0xFF && b[1] === 0xFE) return b.toString('utf16le');
  return b.toString('latin1');
}
const target = process.env.ID || 'PCI\\VEN_10EC&DEV_8136';
const forms = new Map();
for (const p of process.argv.slice(2)) {
  const t = decode(p);
  const re = new RegExp(target.replace(/[\\]/g, '\\\\') + '(?:&SUBSYS_[0-9A-Fa-f]{4})?(?:&REV_[0-9A-Fa-f]{2})?', 'gi');
  for (const m of t.matchAll(re)) {
    const id = m[0].toUpperCase();
    forms.set(id, (forms.get(id) || 0) + 1);
  }
}
const revs = new Map();
for (const k of forms.keys()) {
  const r = (k.match(/&REV_(..)$/) || [, '无REV'])[1];
  revs.set(r, (revs.get(r) || 0) + forms.get(k));
}
console.log('目标 ' + target + '  —— 形态 ' + forms.size + ' 种');
console.log('REV 分布: ' + [...revs.entries()].sort().map(([a, b]) => a + ' x' + b).join('  '));
console.log('有没有"裸 ID"(能匹配任意 REV): ' + ([...forms.keys()].some(k => k === target.toUpperCase()) ? '有 -> 任意 REV 都能装' : '没有 -> 只认下面列出的 REV'));
for (const k of [...forms.keys()].sort()) {
  if (!/&SUBSYS_/.test(k)) console.log('   ' + k + '  x' + forms.get(k));
}
