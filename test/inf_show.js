// 用法: node test/inf_show.js <inf路径> <关键字>   —— 打印 INF 里含关键字的行 + 它所属的 [section]
const fs = require('fs');
function txt(p) {
  const b = fs.readFileSync(p);
  if (b[0] === 0xFF && b[1] === 0xFE) return b.toString('utf16le');
  return b.toString('latin1');
}
const [,, p, kw] = process.argv;
const lines = txt(p).split(/\r?\n/);
let sec = '(top)';
for (const L of lines) {
  const t = L.trim();
  if (t.startsWith('[') && t.endsWith(']')) { sec = t; continue; }
  if (kw && !t.toUpperCase().includes(kw.toUpperCase())) continue;
  if (t) console.log(sec.padEnd(34) + ' | ' + t);
}
