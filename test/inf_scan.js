// 扫描一个目录下的所有 INF(兼容 UTF-16LE), 找出覆盖指定 PCI 硬件 ID 的驱动包
// 用法: node test/inf_scan.js <根目录> <匹配串> [--show-lines]
//   node test/inf_scan.js "D:/winpe_build/hotpe_net/Lan" "DEV_8136"
const fs = require('fs');
const path = require('path');
const [,, root, pat, ...rest] = process.argv;
const re = new RegExp(pat, 'i');

function decode(p) {
  const b = fs.readFileSync(p);
  if (b[0] === 0xFF && b[1] === 0xFE) return b.toString('utf16le');
  if (b[0] === 0xFE && b[1] === 0xFF) { const o = []; for (let i = 2; i + 1 < b.length; i += 2) o.push(b[i + 1], b[i]); return Buffer.from(o).toString('latin1'); }
  return b.toString('latin1');
}
function walk(d, out) {
  let es; try { es = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return out; }
  for (const e of es) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) walk(f, out);
    else if (/\.inf$/i.test(e.name)) out.push(f);
  }
  return out;
}
const infs = walk(root, []);
console.log('扫描 ' + infs.length + ' 个 INF, 匹配 /' + pat + '/');
let hit = 0;
for (const f of infs) {
  let t; try { t = decode(f); } catch (e) { continue; }
  if (!re.test(t)) continue;
  hit++;
  const ids = new Set();
  for (const m of t.matchAll(new RegExp('PCI\\\\[0-9A-Za-z_&]*' + pat + '[0-9A-Za-z_&]*', 'gi'))) ids.add(m[0].toUpperCase());
  const dv = (t.match(/DriverVer\s*=\s*([0-9\/,\s]+;\s*[\d.]+)/i) || [])[1] || '?';
  const cls = (t.match(/^\s*Class\s*=\s*(\S+)/im) || [])[1] || '?';
  console.log('  ' + path.relative(root, f).replace(/\\/g, '/'));
  console.log('     Class=' + cls + '  DriverVer=' + dv.trim() + '  匹配ID ' + ids.size + ' 种');
  if (rest[0] === '--show-lines') {
    let sec = '';
    for (const L of t.split(/\r?\n/)) {
      const s = L.trim();
      if (s.startsWith('[') && s.endsWith(']')) { sec = s; }
      if (re.test(s) && /pci\\/i.test(s)) console.log('       ' + sec + ' | ' + s.slice(0, 150));
    }
  }
}
console.log('命中 ' + hit + ' 个 INF');
