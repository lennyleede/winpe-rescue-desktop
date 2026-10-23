// HTA 桌面出盘前的视觉自检: 把 Desktop.hta 转成浏览器可渲染的预览页(ActiveX 打桩),
// 再用 Edge 无头截图。普通权限即可, 不碰镜像不写 C 盘。
//   node test\hta_preview.js            -> build\hta_preview.png (整屏桌面)
//   node test\hta_preview.js frp        -> 顺带打开 frp 面板
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const outDir = path.join(root, 'build');
const hta = path.join(root, 'overlay', 'Desktop', 'Desktop.hta');
const wp = path.join(root, 'overlay', 'Desktop', 'wallpaper.jpg');
const html = path.join(outDir, 'hta_preview.html');
const shot = path.join(outDir, 'hta_preview.png');
const openFrp = process.argv[2] === 'frp';

let h = fs.readFileSync(hta, 'utf8').replace(/^/, '');
h = h.replace(/<HTA:APPLICATION[\s\S]*?\/>/, '');
h = h.replace('var shell = new ActiveXObject("WScript.Shell");',
  'var shell = { Run: function(c){ if(window.console) console.log("RUN: " + c); } };');
h = h.replace('var fso   = new ActiveXObject("Scripting.FileSystemObject");',
  'var fso = { FileExists: function(){ return true; }, OpenTextFile: function(){ ' +
  'return { ReadAll: function(){ return ""; }, Write: function(){}, Close: function(){} }; } };');
if (openFrp) h = h.replace('</body>', '<script>openFrp();</scr' + 'ipt></body>');
fs.writeFileSync(html, h, 'utf8');
if (fs.existsSync(wp)) fs.copyFileSync(wp, path.join(outDir, 'wallpaper.jpg'));

const edges = [
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'];
const bin = edges.find(p => fs.existsSync(p));
if (!bin) { console.error('找不到 Edge/Chrome, 无法截图; 可手动用浏览器打开 ' + html); process.exit(1); }
if (fs.existsSync(shot)) fs.unlinkSync(shot);
execFileSync(bin, ['--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
  '--user-data-dir=' + path.join(outDir, 'edgeprofile'), '--window-size=1280,800',
  '--screenshot=' + shot, 'file:///' + html.replace(/\\/g, '/')], { stdio: 'ignore' });
console.log('截图完成: ' + shot + ' (' + fs.statSync(shot).size + ' bytes), 预览页: ' + html);
