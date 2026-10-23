# WinPE 第三轮: SSH 账号问题 / 向日葵缺哪个 DLL / wlansvc 为何不被 SCM 识别
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }

# ============ A. SSH: 换账号登录 ============
try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  AL 'A0_identity' ($id.Name + ' SID=' + $id.User.Value + ' IsAdmin=' + ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
} catch { AL 'A0_identity' ('失败: ' + $_.Exception.Message) }

function Test-Ssh($user) {
  try {
  Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep 2
  $null = Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-d','-e' `
        -NoNewWindow -PassThru -RedirectStandardError "X:\sd_$user.txt" -RedirectStandardOutput 'X:\nul.txt'
  Start-Sleep 3
  $r = & X:\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes -o ConnectTimeout=10 `
        -i X:\tk "$user@127.0.0.1" 'echo LOGIN_OK' 2>&1 | Out-String
  Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
  $line = ($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 3) -join ' // '
  AL ("A_ssh_" + $user) $line
  $dbg = (Get-Content "X:\sd_$user.txt" -ErrorAction SilentlyContinue | Select-Object -Last 8) -join ' // '
  AL ("A_dbg_" + $user) $dbg
  } catch { AL ('A_ssh_' + $user) ('异常: ' + $_.Exception.Message) }
}
foreach ($u in 'Administrator','SYSTEM','admin') { Test-Ssh $u }

# 若 Administrator 可用, 起正式 sshd 供后续使用
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-E','X:\sshd_prod.log' -WindowStyle Hidden
Start-Sleep 3
AL 'A_final_sshd' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'RUNNING' } else { 'NOT-RUNNING' })

# ============ B. 向日葵: 解析 PE 导入表找缺失 DLL ============
function Get-Imports($path) {
  $fs = [IO.File]::OpenRead($path); $br = New-Object IO.BinaryReader($fs)
  try {
    $fs.Position = 0x3C; $lfanew = $br.ReadInt32()
    $fs.Position = $lfanew + 6
    $nSec = $br.ReadUInt16(); $null = $br.ReadUInt32(); $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
    $sizeOpt = $br.ReadUInt16(); $null = $br.ReadUInt16()
    $opt = $lfanew + 24
    $fs.Position = $opt; $magic = $br.ReadUInt16()
    $ddOff = if ($magic -eq 0x20B) { 112 } else { 96 }
    $fs.Position = $opt + $ddOff + 4; $impRva = $br.ReadUInt32()
    $fs.Position = $opt + $ddOff + 4 + 4; $impSize = $br.ReadUInt32()
    $secOff = $opt + $sizeOpt
    $secs = @()
    $fs.Position = $secOff
    for ($i = 0; $i -lt $nSec; $i++) {
      $fs.Position = $secOff + $i * 40
      $null = $br.ReadBytes(8)
      $vsize = $br.ReadUInt32(); $va = $br.ReadUInt32(); $raw = $br.ReadUInt32(); $ptr = $br.ReadUInt32()
      $secs += [pscustomobject]@{ VA = $va; VSize = [math]::Max($vsize, $raw); Ptr = $ptr }
    }
    $r2f = {
      param($rva)
      foreach ($s in $secs) { if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VSize)) { return $s.Ptr + ($rva - $s.VA) } }
      return -1
    }
    $impOff = & $r2f $impRva
    if ($impOff -lt 0) { return @() }
    $names = @(); $pos = $impOff
    while ($true) {
      $fs.Position = $pos
      $oft = $br.ReadUInt32(); $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
      $nameRva = $br.ReadUInt32(); $ft = $br.ReadUInt32()
      if ($oft -eq 0 -and $nameRva -eq 0 -and $ft -eq 0) { break }
      $noff = & $r2f $nameRva
      if ($noff -ge 0) {
        $fs.Position = $noff
        $b = @(); while ($true) { $x = $br.ReadByte(); if ($x -eq 0) { break }; $b += $x; if ($b.Count -gt 260) { break } }
        $names += [Text.Encoding]::ASCII.GetString($b)
      }
      $pos += 20
    }
    return $names
  } finally { $br.Close(); $fs.Close() }
}
foreach ($exe in 'X:\Sunlogin\SunloginSOS.exe','X:\OpenSSH\sshd.exe') {
  try {
    $imps = @(Get-Imports $exe | Sort-Object -Unique)
    $miss = @()
    foreach ($d in $imps) {
      if ($d -match '^(api-ms|ext-ms|windows\.|ntdll)') { continue }
      if (-not ((Test-Path "X:\Sunlogin\$d") -or (Test-Path "X:\Windows\System32\$d") -or (Test-Path "X:\Windows\System32\downlevel\$d"))) { $miss += $d }
    }
    AL ('B_imports_' + (Split-Path $exe -Leaf)) ('共 ' + $imps.Count + ' 个 DLL; 缺失: ' + $(if ($miss) { $miss -join ',' } else { '无' }))
    AL ('B_apiset_' + (Split-Path $exe -Leaf)) ((($imps | Where-Object { $_ -match '^(api-ms|ext-ms)' }) | Measure-Object).Count.ToString() + ' 个 api-set(PE 里可能无法解析)')
  } catch { AL ('B_imports_' + (Split-Path $exe -Leaf)) ('解析失败: ' + $_.Exception.Message) }
}
# 主机侧同名 exe 的完整依赖里有没有 PE 里没有的 System32 DLL
$sunFiles = @(Get-ChildItem X:\Sunlogin -File | ForEach-Object { $_.Name })
AL 'B_sunlogin_files' ($sunFiles -join ',')

# ============ C. wlansvc: SCM 到底看没看到 ============
try { Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop } catch { }
try {
  $all = [System.ServiceProcess.ServiceController]::GetServices() | ForEach-Object { $_.Name }
  AL 'C_scm_count' $all.Count.ToString()
  AL 'C_scm_has_wlansvc' $(if ($all -contains 'wlansvc') { 'YES' } else { 'NO' })
  AL 'C_scm_sample' ((@($all | Get-Random -Count ([math]::Min(25, $all.Count)))) -join ',')
  AL 'C_scm_lanlike' (($all | Where-Object { $_ -match 'lan|wlan|dot3|ndis|rpc|gpsvc' }) -join ',')
} catch { AL 'C_scm' ('失败: ' + $_.Exception.Message) }
# 注册表里该键的完整值
try {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
  $props = (Get-Item $k).GetValueNames() | ForEach-Object { $n = $_; $n + '=' + ((Get-ItemProperty $k).$_ -join '|') }
  AL 'C_reg_values' ($props -join ' ; ')
  AL 'C_reg_subkeys' ((Get-ChildItem $k | ForEach-Object { $_.PSChildName }) -join ',')
} catch { AL 'C_reg_values' ('失败: ' + $_.Exception.Message) }
# 直接手动起 svchost 承载 wlansvc.dll, 看报什么错
try {
  $sp = Start-Process -FilePath 'X:\Windows\System32\svchost.exe' -ArgumentList '-k','PEWLan','-d' -PassThru
  Start-Sleep 5
  $alive = Get-Process -Id $sp.Id -ErrorAction SilentlyContinue
  AL 'C_direct_svchost' $(if ($alive) { '进程存活(可能已注册服务入口)' } else { '已退出 exit=' + $sp.ExitCode })
} catch { AL 'C_direct_svchost' ('失败: ' + $_.Exception.Message) }
# 相关支撑服务在不在
foreach ($sv in 'RpcSs','DcomLaunch','NSI','Dhcp','LanmanWorkstation') {
  try { AL ('C_svc_' + $sv) ([System.ServiceProcess.ServiceController]::new($sv).Status.ToString()) }
  catch { AL ('C_svc_' + $sv) 'NOT-IN-SCM' }
}

$text = $out -join "`r`n"
Set-Content -Path X:\verify3.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify3.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 20 | Out-Null
  Write-Host '>>> 已回传'
} catch { Write-Host '>>> 回传失败, 请把 X:\verify3.txt 截图' }
