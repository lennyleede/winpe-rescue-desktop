// 提取 HTA 里的 <script> 块做纯语法检查(不执行, ActiveX 在 node 里跑不了)
const fs = require('fs'), vm = require('vm');
const file = process.argv[2] || 'overlay/Desktop/Desktop.hta';
const src = fs.readFileSync(file, 'utf8').replace(/^/, '');
const blocks = [...src.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
if (!blocks.length) { console.log('NO-SCRIPT'); process.exit(1); }
let bad = 0;
blocks.forEach((m, i) => {
  try { new vm.Script(m[1], { filename: file + '#script' + i }); }
  catch (e) { bad++; console.log('SYNTAX-FAIL block' + i + ': ' + e.message); }
});
console.log((bad ? 'JS-BAD ' : 'JS-OK ') + 'blocks=' + blocks.length + ' bytes=' + Buffer.byteLength(src));
process.exit(bad ? 1 : 0);
