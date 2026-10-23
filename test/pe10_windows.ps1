# pe10_windows.ps1 —— 在 WinPE 里跑: 证明界面真的画出来了(不只是进程活着)。
# 为什么要它: 这台宿主机的 Hyper-V 没有 Msvm_VideoHeadService 类(截图 API 不存在),
# 所以用 PE 自己的窗口信息代替肉眼截图: MainWindowHandle/标题 非 0 非空 = 有可见窗口。
# EnumWindows 那段是加分项(能看见全部顶层窗口和类名), 失败也不影响主判据。
param([string[]]$Names = 'mshta,SunloginSOS,pe-sshd,frpc,WallpaperHost,winpeshl,explorer')
$ErrorActionPreference = 'Continue'
foreach ($n in ($Names -split ',')) {
  $ps = @(Get-Process -Name $n -EA SilentlyContinue)
  if (-not $ps.Count) { Write-Output ("  {0,-14} 进程不存在" -f $n); continue }
  foreach ($p in $ps) {
    Write-Output ('  {0,-14} pid={1,-6} 主窗口句柄={2} 标题="{3}" 有可见窗口={4} Responding={5}' -f `
      $n, $p.Id, [int64]$p.MainWindowHandle, $p.MainWindowTitle, ($p.MainWindowHandle -ne 0), $p.Responding)
  }
}
try {
  Add-Type -Namespace W -Name Gu -MemberDefinition '[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, System.Text.StringBuilder s, int n);'
  $script:Win = @()
  $cb = [W.Gu+EnumWindowsProc] {
    param($h, $l)
    $sb = New-Object System.Text.StringBuilder 512
    [void][W.Gu]::GetWindowText($h, $sb, $sb.Capacity)
    $cn = New-Object System.Text.StringBuilder 256
    [void][W.Gu]::GetClassNameW($h, $cn, $cn.Capacity)
    $wpid = [uint32]0
    [void][W.Gu]::GetWindowThreadProcessId($h, [ref]$wpid)
    if ([W.Gu]::IsWindowVisible($h)) { $script:Win += ,@([int]$wpid, $sb.ToString(), $cn.ToString()) }
    return $true
  }
  [void][W.Gu]::EnumWindows($cb, [IntPtr]::Zero)
  Write-Output ('  EnumWindows 可见窗口总数 = ' + $script:Win.Count)
  foreach ($w in ($script:Win | Sort-Object { $_[0] })) {
    $pr = ''
    if ($w[0] -gt 0) { $pr = (Get-Process -Id $w[0] -EA SilentlyContinue).ProcessName }
    Write-Output ('    pid=' + $w[0] + ' [' + $pr + '] class=' + $w[2] + ' title=' + $(if ($w[1]) { $w[1] } else { '(无标题)' }))
  }
  $hta = @($script:Win | Where-Object { $_.2 -match 'HTML' }).Count
  $sun = @($script:Win | Where-Object { $_.1 -match '向日葵|Sunlogin|远程' -or $_.2 -match 'Sunlogin' }).Count
  Write-Output ('  判定: HTA/桌面窗口=' + $(if ($hta) { 'YES(' + $hta + ')' } else { 'NO' }) + '  向日葵窗口=' + $(if ($sun) { 'YES(' + $sun + ')' } else { 'NO' }))
} catch {
  Write-Output ('  EnumWindows 段失败(不影响上面的主窗口判据): ' + $_.Exception.Message)
}
