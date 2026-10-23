const fs = require('fs'), path = require('path');
function read(f) {
  const b = fs.readFileSync(f);
  if (b[0] === 0xFF && b[1] === 0xFE) return b.toString('utf16le').replace(/^\uFEFF/, '');
  return b.toString('latin1').replace(/\x00/g, '');
}
for (const f of process.argv.slice(2)) {
  const L = read(f).split(/\r?\n/);
  console.log('===== ' + path.basename(f));
  let inM = false;
  L.forEach(l => {
    const m = l.match(/^\s*\[([^\]]+)\]/);
    if (m) { inM = /^Manufacturer$/i.test(m[1]); return; }
    if (inM && l.trim() && !l.trim().startsWith(';')) console.log('  MFG: ' + l.trim());
  });
  L.forEach(l => {
    const m = l.match(/^\s*\[(Intel[^\]]*)\]/);
    if (m) console.log('  SEC: ' + m[1]);
  });
}
