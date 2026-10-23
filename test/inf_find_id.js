const fs = require('fs'), path = require('path');
function read(f) {
  const b = fs.readFileSync(f);
  if (b[0] === 0xFF && b[1] === 0xFE) return b.toString('utf16le').replace(/^\uFEFF/, '');
  return b.toString('latin1').replace(/\x00/g, '');
}
function walk(d) {
  let r = [];
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) r = r.concat(walk(p));
    else if (/\.inf$/i.test(e.name)) r.push(p);
  }
  return r;
}
const root = process.argv[2] || 'overlay/Drivers/Net';
const want = process.argv[3] || '15F3';
for (const f of walk(root)) {
  const L = read(f).split(/\r?\n/);
  let sec = '';
  const re = new RegExp('DEV_' + want, 'i');
  L.forEach((l, n) => {
    const m = l.match(/^\s*\[([^\]]+)\]/);
    if (m) sec = m[1];
    if (re.test(l)) console.log(path.basename(f) + ' [' + sec + '] ' + (n + 1) + ': ' + l.trim().slice(0, 110));
  });
}
