// 用法: node test/inf_ids.js <inf路径...>   打印每个 INF 覆盖的 PCI VEN/DEV(兼容 UTF-16LE INF)
const fs = require('fs');
function txt(p) {
  const b = fs.readFileSync(p);
  if (b[0] === 0xFF && b[1] === 0xFE) return b.toString('utf16le');
  if (b[0] === 0xFE && b[1] === 0xFF) { const o = Buffer.alloc(b.length - 2); for (let i = 2; i < b.length; i += 2) o[i / 2 - 1] = b[i + 1] < b[i] ? b[i + 1] : b[i]; return o.toString('latin1'); }
  return b.toString('latin1');
}
for (const p of process.argv.slice(2)) {
  const t = txt(p);
  const ids = [...t.matchAll(/PCI\\(VEN_[0-9A-Fa-f]{4})&(DEV_([0-9A-Fa-f]{4}))/g)].map(m => m[1] + '&' + m[2]);
  console.log(p.split(/[\\/]/).slice(-2).join('/') + '  =>  ' + [...new Set(ids)].sort().join(' '));
}
