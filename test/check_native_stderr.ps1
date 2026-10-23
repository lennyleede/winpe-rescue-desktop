# 验证 PS5.1 的老坑: $ErrorActionPreference='Stop' 下, 原生 exe 的 stderr 重定向会不会抛终止错误
# 只读/无害: reg query 不存在的键, reg unload 未加载的键
$ErrorActionPreference = 'Stop'
function T([string]$name, [scriptblock]$body) {
  try { & $body | Out-Null; Write-Host ('  OK(没抛)   ' + $name) }
  catch { Write-Host ('  THROW       ' + $name + ' => ' + $_.Exception.GetType().Name + ': ' + ($_.Exception.Message -replace "`r?`n", ' ')) }
}
Write-Host '--- A: 2>$null (build.ps1 v6 用的写法) ---'
T 'reg unload 未加载的键 2>$null' { reg.exe unload 'HKLM\NO_SUCH_HIVE' 2>$null }
T 'reg query 不存在的键 2>$null'  { reg.exe query 'HKLM\NO_SUCH_KEY' 2>$null }
Write-Host '--- B: 2>&1 | Out-Null (我这轮 wifi-inject 改成的写法) ---'
T 'reg unload 未加载的键 2>&1'    { reg.exe unload 'HKLM\NO_SUCH_HIVE' 2>&1 }
T 'reg query 不存在的键 2>&1'     { reg.exe query 'HKLM\NO_SUCH_KEY' 2>&1 }
Write-Host '--- C: 成功命令的 stdout 走 2>&1 ---'
T 'reg query HKCU\Environment 2>&1' { reg.exe query 'HKCU\Environment' 2>&1 }
