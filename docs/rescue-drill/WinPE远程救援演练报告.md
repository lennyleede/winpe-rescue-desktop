# WinPE 远程救援演练报告

日期：2026-10-14　|　执行：Qoder（远程）+ 用户（VMware 控制台操作）　|　状态：五个场景全部收官（场景 1/2/3/4A/4B；4B 含 4B-min 与 4B-full 两档）；救援修复面板四件套已产品化落地，并于 10-14 17:15 在最终镜像上活体复验全绿（第九节第 1 项）

## 一、演练目的与结论摘要

验证自研 WinPE 救援盘在"人不到场"条件下的完整救援能力：故障机通过 PE 启动后，修复者仅凭网络远程通道（ssh 为主、frp/向日葵为备援）完成诊断与修复，全程不接触键盘鼠标之外的任何物理介质。

| 场景 | 故障 | 结果 | 耗时（注入→修复完成） |
|---|---|---|---|
| 1 引导损坏（BCD 丢失） | 删除 EFI 分区 `\EFI\Microsoft` | ✅ 远程修复成功，Windows 正常进桌面 | 约 14 分钟（含故障取证往返） |
| 2 启动关键驱动被禁用（蓝屏） | 在线禁用 stornvme 服务 | ✅ 离线蜂巢手术 + 清失败计数，正常进桌面 | 约 18 分钟（含 Recovery 拦截二次处置） |
| 3 系统文件损坏（登录链） | 在线 takeown 后整文件覆写 userinit.exe | ✅ 离线 sfc 暴露 nonSxS 硬链接坑→备份还原+sfc 复核，正常进桌面 | 约 20 分钟（含 sfc"修不动"根因分析） |
| 4 分区/盘符异常（4A 丢盘符） | 在线 diskpart 持久摘除 D: 盘符 | ✅ PE 离线蜂巢写回 MountedDevices，盘符与数据完整回归 | 修复脚本一次通过（约 5 分钟） |
| 4B 分区表破坏（GPT 主+备头同毁） | 在线裸写把两份 GPT 头清零（表与数据不动） | ✅ PE 内用盘外字节备份还原两个扇区，逐字节回到基线，正常进桌面 | 修复侧约 1 分钟（PE 上网→RESTORE-OK） |

**总体结论**：五类高频"进不了桌面"故障全部可在纯远程条件下修复闭环，PE 工具链（bcdboot/bcdedit、离线 reg、sfc、diskpart/Storage cmdlets、裸扇区读写）无能力缺口；真正的短板在**产品化**——修复逻辑散落在演练脚本里，且每个场景都各藏着一个"不懂就会误判重装"的深坑（BOOTSTAT 拦截、nonSxS 硬链接、盘符的蜂巢持久化、以及"只坏一份 GPT 会被固件悄悄回救"）。详见第八节改进项与第九节收官计划。

## 二、演练环境

被救机器：VMware Workstation 虚拟机「Windows 10 x64」——VMware20,1，7GB 内存，60GB 虚拟 NVMe（GPT/UEFI），C: 为 Windows 10 系统卷（46GB），D: 为数据卷（15GB），EFI 系统分区 300MB（PE 下默认无盘符）。

救援盘：自研 WinPE（10-12 2145 盘基线 + 10-13 WiFi 修复热换装），PE 内主机名 WINPE，X: 为内存盘。启动后自动拉起 pe-sshd（administrator，密钥登录）、frpc、向日葵，本次实际使用通道为 ssh `administrator@192.168.0.100:22`。

修复端操作机：宿主机（Windows，Git Bash + PowerShell 5.1），通过 `test\host_push_run.ps1`（分块 base64 + certutil -decode）向 PE 投递脚本并以全路径 powershell 执行——PE 无 scp/sftp、命令行约 6KB 上限、PowerShell 不在 PATH，这三个已知约束决定了"脚本推送→执行→结果文件回传"的标准作业形态。场景 2 起被救机自身的 OpenSSH 成为第二通道（在线注入与恢复后回读），走 `test\host_run_stdin.ps1`，细节见附录 A。

现场动作口径：全程不要求现场人员读屏幕或判断，需要人做的只有下表四类，其余（含重启被救机）一律远程完成。

| 现场动作 | 出现时机 |
|---|---|
| VMware 菜单里连接/断开 WinPE ISO | 每次进 PE 前、每次验证恢复前 |
| 电源键开机或重启 | 每个场景 2–3 次 |
| 登录被救机（administrator，密码为空） | 场景 2、3 的故障确认阶段 |
| 控制台拍照回传 | 故障确认与恢复验证各一次 |

## 三、场景 1：引导损坏（BCD 丢失）

### 3.1 侦察与基线（09:38）

只读探针确认目标身份（防误伤实机：同网段的 12 代实机此前也用过 .100，必须先验 `PCSystemType=1|VMware` 再动手）：

```
CS=MININT-SNQLJ6E|VMware, Inc.|VMware20,1|systype=1|totalGB=7
DISK=0 VMware Virtual NVMe Disk style=GPT sizeGB=60
PART=d0p1 type=System gpt={c12a7328-...}（EFI 分区，无盘符）
WINVOL=C exists 09/28/2026
```

挂载 EFI 分区后取 BCD 基线（`bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum all`，151 行）：{bootmgr} 指向 `\EFI\Microsoft\Boot\bootmgfw.efi`，默认加载器 `\Windows\system32\winload.efi`，osdevice=C:，状态健康。随后把整个 `\EFI` 目录备份到数据卷：`D:\rescue_bcd_backup_20261014_093852`（185 个文件）——备份留在被救盘上，PE 内存盘重启即失，不能作为唯一保险。

### 3.2 故障注入（09:39:38）

```
deleted_files=182  after_exists=False  EFI_left=Boot
```

删除 `\EFI\Microsoft` 全目录，仅留无 BCD 的 fallback `\EFI\Boot`。模拟现实中"启动配置数据丢失"。

### 3.3 故障确认（09:46，用户截图）

断开 ISO 从硬盘启动，VMware 控制台出现教科书式报错：

> Windows Boot Manager — File: \EFI\Microsoft\Boot\BCD — Status: 0xc000000f
> Info: The Boot Configuration Data for your PC is missing or contains errors.

证据：`assets/s1-fault-bcd-missing-0xc000000f.png`

### 3.4 远程修复（09:53:05，全程 ssh，零现场操作）

重进 PE 后一条推送执行完成，核心命令即一行：

```
bcdboot C:\Windows /s S: /f UEFI        →  "Boot files successfully created." rc=0
```

脚本自动完成：幂等重挂 EFI（按 GPT 类型找分区而非记盘符）→ 前置断言故障仍在（`pre_state_Microsoft=False`）→ 扫描含 `winload.efi` 的卷定位 Windows → bcdboot 重建 → 回读新 BCD（92 行，Boot Manager / Boot Loader / winload.efi / osdevice=C: 齐全）→ 双份留档（X:\repair.txt + D:\repair_evidence.txt）。

要点：修复走的是真实重建路径（bcdboot），没有走"还原备份"捷径；备份只作为安全网存在。UEFI 场景不需要 bootrec/fixboot，固件 NVRAM 里的 Windows Boot Manager 条目指向的 `\EFI\Microsoft\Boot\bootmgfw.efi` 被 bcdboot 原位重建，因此无需动固件项。

### 3.5 恢复验证（10:00:47，用户截图）

断开 ISO 从硬盘启动，正常进入 Windows 10 桌面，用户数据、桌面项完好。证据：`assets/s1-verified-desktop.png`

### 3.6 场景 1 小结

从故障注入到修复完成，修复者侧全部动作 = 4 条推送执行 + 0 次现场按键；需要现场的只有"看故障/看恢复"两次开机（本可由机房值班人员或 IP-KVM 代劳）。PE 内置 bcdboot/bcdedit/Storage cmdlets 齐备，引导类故障可完全远程闭环。

## 四、场景 2：启动关键驱动被禁用（INACCESSIBLE_BOOT_DEVICE 蓝屏）

### 4.1 与场景 1 的不同：故障注入也全程远程

被救机（VMware Windows 10，VM-RESCUE-01）本身装有 OpenSSH 且互信同一把密钥，注入前照例先验身份（`PCSystemType=1 | VMware20,1`，防误伤同网段实机），再定位启动盘驱动：虚拟 NVMe 盘的 boot-critical 驱动为 `stornvme`（StartType=Boot，Running）。注入即一条命令（10:19:50），随后 `shutdown /r` 远程重启，现场零操作：

```
Set-Service -Name stornvme -StartupType Disabled
shutdown /r /t 8
```

### 4.2 故障确认

蓝屏 `Stop code: INACCESSIBLE_BOOT_DEVICE`（assets/s2-fault-bsod-inaccessible-boot-device.png）。

### 4.3 远程修复：PE 内注册表离线手术（10:33）

进 PE 后离线加载被救系统蜂巢，把 Start 从 4 改回 0：

```
reg load HKLM\OFFSYS C:\Windows\System32\config\SYSTEM
Select\Current = 0x1                                   → 手术对象 ControlSet001
ControlSet001\Services\stornvme Start: 0x4 → 0x0（回读确认）
reg unload HKLM\OFFSYS                                  → 落盘
```

蜂巢动前先整文件备份到 `D:\rescue_hive_backup_20261014_103308`；系统卷定位不认盘符、以 `\Windows\system32\winload.efi` 存在为准。

### 4.4 二次拦截：修好了却被 Recovery 屏挡住（10:34 截图）

重启后未见桌面，而是 "Your PC couldn't start properly, Error code: 0xc0000001"（assets/s2-recovery-intercept-0xc0000001.png）。这不是没修好，而是注入期间多次启动失败被记入 EFI 分区 `BOOTSTAT.DAT` 失败计数，Windows 在进入引导前先弹 Recovery。现实救援中这一步极易被误判为"修复无效"而转向重装。处置（10:37，仍全远程）：

```
离线回读 stornvme Start = 0x0            → 证明根因已修复
删除 S:\EFI\Microsoft\Boot\BOOTSTAT.DAT（备份 D:\BOOTSTAT.DAT.bak，Windows 自行重建）
bcdedit /store ... /set {default} bootstatuspolicy ignoreallfailures   → IgnoreAllFailures
bcdedit /store ... /set {default} recoveryenabled no                   → No
```

### 4.5 恢复验证（10:38+）

断开 ISO 启动，正常进桌面。从修复后的 Windows 内回读终态：`stornvme StartType=Boot, Status=Running`，System 日志无新的启动关键错误。场景 2 注入→修复完成约 18 分钟，现场动作仅两次开关 CD 连接。

### 4.6 演练中的通道坑

同一 IP（.100）在 pe-sshd 与被救机 Windows OpenSSH 之间来回切换，known_hosts 必然冲突，每次进出 PE 需 `ssh-keygen -R <IP>`；建议固化进作业脚本。

## 五、场景 3：系统文件损坏（登录链 userinit.exe 被毁）

### 5.1 侦察与基线（10:53）

被救机在线 ssh 通道（`test\host_run_stdin.ps1`：ASCII 脚本经 stdin 喂给远端 `powershell -Command -`；`-EncodedCommand` 路线在传输中丢字符，弃用）。只读探针先验身份（`IDENTITY=VM-OK`），再锁定注入对象与修复可行性前提：

```
FILE=userinit.exe len=54272 md5=5cdc907c7818fbaa658fc9f2abb238f1   ← 基线
WINLOGON_shell=explorer.exe userinit=C:\Windows\system32\userinit.exe,
WINSXS_userinit_copies=6                                            ← 当时以为"有源可修"
```

选 `userinit.exe` 的理由：登录链关键（winlogon 之后第一棒）、只在登录瞬间执行（活系统里不是已加载镜像，可写）、WRP 保护文件（真实还原"改不动系统文件"的现场约束）。

### 5.2 故障注入（10:55:15，全程远程）

注入脚本自带三道硬闸：身份=VM、当前 md5==基线、备份校验通过后才准动手。WRP 的破法本身就是实战知识：`takeown /F` + `icacls /grant Administrators:F`，然后把 54272 字节整体覆写 0xA5（MZ 头失效）。备份 `D:\rescue_s3_backup_20261014_105515\userinit.exe`（校验 md5 一致），随后 `shutdown /r /t 8` 远程重启。

### 5.3 故障确认（11:00 截图）

开机正常、登录成功、**黑屏无桌面**（assets/s3-fault-black-screen.png）——引导完好、sshd 存活，只有登录链断了。这是"远程救援最能打"的一类故障：机器在线，现场人员看不见任何可操作的界面。

### 5.4 第一次修复撞墙：全场演练最值钱的一课（11:05–11:12）

PE 内跑 `sfc /scannow /offbootdir=C:\ /offwindir=C:\Windows`：rc=0、耗时 255s，但目标文件哈希纹丝不动，只留下一句 "found corrupt files but was unable to fix some of them"。两个坑接连踩出：

1. **离线 sfc 不带 `/offlogfile` 就没有诊断细节**——被救机 CBS.log 是旧在线会话的，PE 里这次运行"说修不动但没写为什么"。
2. 补 `/offlogfile=X:\cbs_off.log` 重跑（61s），CBS 原文定案：**`[SR] Could not reproject corrupted file \??\C:\Windows\System32\\userinit.exe; source file in store is also corrupted`**。`userinit` 是 **nonSxS 组件**——WinSxS 里那份"修复源"与 System32 本体是**同一文件记录的硬链接**，覆写本体等于连修复源一起毁掉。现实中"sfc 也修不动的系统文件损坏"正是这一类，极易被推向重装。

### 5.5 二次修复：备份还原 + sfc 独立复核（11:14）

分层处置（11:14，仍全远程）：

```
备份 md5 校验 == 基线                        → 准动
Copy-Item 覆写本体（截断写，硬链接不断，Store 端同步复原）
post_md5=5cdc907c…  STORE=...4355_... good=True
icacls /setowner *S-1-5-80-9560…(TrustedInstaller) + /reset   → 复位注入时的 ACL 破坏
第二轮离线 sfc（带 /offlogfile）→ "did not find any integrity violations"   → REPAIR-OK
```

判修不用自己的还原动作背书，而是让 sfc 自己复扫出具"无完整性违规"——工具链闭环。

### 5.6 恢复验证（11:22+）

`wpeutil reboot` 从 PE 远程发出（连"重启"这一步都不用现场按键）。系统内回读（`D:\rescue_s3_verify.txt`）：`userinit_md5==基线`、`explorer_procs=1`（桌面真的起来了）、System 日志近 1 小时无启动关键错误。场景 3 注入→修复完成约 20 分钟，其中近半耗在 sfc"修不动"的根因取证上——这部分时间恰恰最值。

至此，驱动类与系统文件类两类故障已证明"修复可零现场"（连重启都是 `wpeutil reboot` 远程发的）；而引导类与分区类故障必须现场挂 ISO——那时 Windows 自身已不可用，不存在任何在线通道。这条能力边界值得写进产品话术与作业手册。

## 六、场景 4A：分区/盘符异常（数据卷盘符丢失；分区表级破坏 4B 见第七节）

### 6.1 为什么选 4A 档

场景 4 原设计分两档：4A 只摘盘符（不碰分区表，注入与修复都能纯远程闭环）；4B 删分区记录（盘符一消失，Windows 侧在线通道随之消失，必须现场挂 ISO，且要先做 GPT 头与备份表的分区级备份）。4A 已把"盘符丢失"这一类完整打穿，4B 的额外知识点（分区表备份与重建）风险收益比不划算，留作后续专项（见第八节）。

### 6.2 侦察与基线（11:05）

在线探针拿到卷全图与关键一点：**盘符只是注册表别名**，卷本身由 GUID 路径标识。

```
VOL=D: fs=NTFS sizeGB=15 path=\\?\Volume{389a76e7-2c78-417c-b4d1-81e26cb2a45e}\
PART=d0p4 type=Basic offsetMB=46398 sizeGB=14.69 letter=D
MD=\DosDevices\D: bytes=24
PROCS_ON_D=0  PAGEFILE=none        ← 无占用，可安全摘盘符
```

`MountedDevices` 原文（含 hex）存档到 `C:\Windows\Temp\rescue_s4_mounteddevices_before.txt`——注意基线证据必须同时留在**不会随故障消失的位置**：D: 上的 `rescue_s4_baseline.txt` 修复前无法读取，C: 上那份才是可用的标准答案。

### 6.3 故障注入（11:08，全程远程）

```
diskpart: select volume D / remove letter=D   → "successfully removed the drive letter"
post_D_exists=False   md_after_has_DosD=False
guid_path_items=13    ← 卷仍在，经 GUID 路径可列出全部演练备份
```

### 6.4 修复：PE 离线蜂巢手术（15:50）

关键判断：PE 里跑 `diskpart assign` 只写 PE 自己的内存注册表，被救机重启后毫无作用——**盘符必须写回被救系统的 SYSTEM 蜂巢**。修复脚本一次通过：

```
从注入前存档提取 \DosDevices\D: 的 hex（48 位）
  = 444D494F3A49443A ("DMIO:ID:") + 16 字节小端 GUID
解码 GUID == 侦察记录的 D 卷 GUID（389A76E7-…）  → 防挂错卷
蜂巢整文件备份 → C:\Windows\Temp\rescue_s4_hiveSYSTEM_before.bin (11.8MB)
reg load HKLM\OFFSYS <winvol>\Windows\System32\config\SYSTEM
  pre_D_absent=True  pre_C_present=True        → 前置断言
reg add ... /v \DosDevices\D: /t REG_BINARY /d <hex> /f   → rc=0
readback == 原 hex                              → 回读比对
reg unload HKLM\OFFSYS                          → rc=0 落盘
RESULT=REPAIR-OK
```

顺带一个观察：本次 PE 里该卷 `PE_temp_letter=(none)`——连 PE 都没自动给它盘符，正好反证"盘符是注册表别名、不是卷的属性"。

### 6.5 恢复验证（15:51:46 起）

`wpeutil reboot` 远程重启进 Windows，回读（`D:\rescue_s4_verify.txt`）：

```
D_exists=True   D_guid=\\?\Volume{389a76e7-...}\      ← 同一个卷，不是新挂载
md_matches_original=True                                ← 字节级一致
BACKUP=rescue_bcd_backup_... files=134 / hive / s3 全在  ← 历史演练证据完好
SYSERR_since_boot=1 (TPM-WMI，VM 常态噪声)
RESULT=VERIFY-OK
```

场景 4 从注入到修复完成，现场动作 = 挂/断 ISO 各一次；其余（含摘盘符、重启、验证）全部远程。

## 七、场景 4B：分区表级破坏（GPT 主+备头同毁，盘外字节备份还原）

### 7.1 为什么要单独做 4B，还要分两档

4A 毁的只是"盘符"这个注册表别名，卷和分区表都还在，被救机的在线通道也不会断。4B 毁的是分区表本身：固件与 Windows 同时失去卷视图，被救机内的 OpenSSH 随之不可达——这是四个场景里唯一**必须现场挂 ISO** 的一档，也是对"备份到底该放在哪里"最严格的一次考试。因此拆两档做：4B-min 只毁主头（练"从盘内完好备份重建主表"，现场动作最少），4B-full 主备同毁（练"盘外字节备份还原"，真实应急里的多数分区表事故属于这一档）。

### 7.2 侦察、基线与工具准备（17:41–19:03）

`build\scratch\t_s4b_recon.ps1`（在 PE 与在线 Windows 两条通道都跑通，`RESULT=GPTRECON-OK`）给出盘几何与两份头的全部字段：VMware Virtual NVMe Disk，size=64424509440，ss=512，lastLba=125829119，DiskGUID=F231B2D6-8516-400E-A3C0-21DF5DB00FF2，主头 entryLba=2、备头 entryLba=125829087，表 128×128=16384B，主头 CRC=1E4D4292、备头 CRC=90B3FAD9、表 CRC=CBB108E8，4 个分区（System/Reserved/Basic C:/Basic D:）。

三条底层能力在这次一次性补齐，全部有独立交叉验证：

1. **纯 PowerShell CRC32**（GPT 头/表校验的唯一手段，PE 里没有现成工具）。两个必踩的坑：PS5.1 把 `0xEDB88320` 这类 >0x7FFFFFFF 的裸十六进制字面量按**负 Int32** 解析；手工把它十进制化又极易写错一位（正确值 3988292384，错过一次连错三轮）。定式：常量一律 `[Convert]::ToUInt32('EDB88320',16)`，每步运算后 `-band 0xFFFFFFFF`，判据用 `('{0:X8}' -f $v) -eq '1E4D4292'` 字符串比较。自校向量 `'123456789'→CBF43926`，并用 node 独立实现复核真实头 CRC 一致后才敢用。
2. **裸扇区读写**：`\\.\PhysicalDriveN` + `[IO.FileStream]`，bufferSize 必须显式给 512——默认 4KB 会在盘尾越界（读备头时报"找不到要求的扇区"）。
3. **盘外字节备份**：`t_s4b_gptdump.ps1`（在线 Windows，19:03）把主头/主表/备头/备表 4 个 blob 以 `B64|name|md5|…` 行回传，宿主机 node 落盘并逐个验 MD5 → `docs\rescue-drill\assets\s4b\`（prim_hdr md5=1f6eba58…、backup_hdr md5=dba7a04e…、两张表同为 1b2ff310…）。这份 dump 后来是 4B-full 唯一的救命绳。

修复侧先做了 `t_s4b_gptfix.ps1`（PE 内，17:45 体检 `VERDICT=GPT-HEALTHY`）：只读体检 + `-Repair` **从盘内完好备份重建主表**——复制备份头 512B，改 MyLba=1 / AltLba=lastLba / EntryLba=2 三个字段、CRC 字段清零重算，表原样搬到 LBA2；写前 Set-Disk 离线、写后回读 Inspect、再上线 Update-Disk。

### 7.3 4B-min 的结果：故障不持久，而且原因不在这台系统里

19:04:30 注入（`RESULT=INJECT-OK`）：LBA1 的 512B 清零，POST 当场读回全零、备份头仍有效、MBR 完好，随后 `shutdown /r /t 15`。**下一次引导直接进了 Windows 桌面。**

19:38 取证（`t_s4b_forensic.ps1`，只读）：主头 sig/CRC 与基线**逐字节一致**（仍是 1E4D4292），guest 侧 volmgr 事件 0 条，Ntfs 挂载时间 19:05:03。也就是说破坏在操作系统加载之前就被撤销了，而且没有任何 Windows 组件参与——判定为 **EFI 固件（EDK2 GptDxe）从完好的备份头自动回救**。

这一档的收获比"修好了"更值钱：在带完好备份 GPT 的系统上，**只坏一份表不是持久故障**，救援者拿它当"分区表灾难"练手会得出完全错误的判据；真正的分区表应急必须两份同坏——而这恰好证明了盘外字节备份不是可选项。

### 7.4 4B-full 注入与故障确认（19:54–20:32）

注入 `t_s4b_inject2.ps1`（19:54:20，全程远程，`RESULT=INJECT2-OK`）。刻意**先毁备份头再毁主头**，不给"主坏备好"留任何可回救的窗口。前置断言：两份头 CRC 均有效、两张表 MD5 与基线一致、MBR 55AA、盘几何 lastLba=125829119 且 disk#=0（防错盘）。后置断言：两处扇区全零、MBR 完好、两张表逐字节未变。被救机自己的日志给出精确时间线：19:54:21 wininit 发起重启、19:54:48 干净停机（EventLog 6006 / Kernel-Power 109 / Kernel-General 13）。

故障确认（用户 20:32:43 截图，已归档 `docs\rescue-drill\assets\s4b\s4b_full_no_media_203243.png`）：

```
Attempting to start up from:
+ Windows Boot Manager... No Media.
+ EFI VMware Virtual NVMe Namespace (NSID 1)... No Media.
+ EFI VMware Virtual SATA CDROM Drive (1.0)... No Media.
+ EFI Network...
```

NVMe 命名空间报 No Media = 固件读不到 GPT 因而没有 ESP；CDROM 未插盘，于是一路掉到 EFI Network。事后回读被救机日志：19:54:49 之后直到 20:52:59（修复完成那次开机）之间没有任何 Windows 会话事件（无 6005/Kernel-General 12），即虚拟机自那次重启后就一直停在 EFI 无介质界面——在线通道彻底消失，与 4B 的预期完全一致。

附带一条被救机取证坑：这台 VM 的"保护性 MBR"只有 55AA 签名，分区项是空的（`part1_type=00` 而非 0xEE），所以 GPT 一坏连 MBR 兜底都不存在。写分区表类工具时**不能把 0xEE 当成前置断言**（本轮第一版就是这么误判成 `ABORT=PRE-MBR` 的）。

### 7.5 远程修复（20:51–20:52，PE 内，一次通过）

现场动作只有一次：VMware 里挂 `dist\WinPE_Desktop_v8.iso` + 开机进 PE。ssh 起来后推 `t_s4b_gptrestore.ps1`（18KB，两段 512B 头以 1024 字符 hex 内联，省掉文件传输）。

只读体检先给出分诊结论：`VERDICT=BOTH-HEADERS-DEAD TABLES-INTACT restorable=host-dump`——两处扇区 md5=bf619eac…（即 512 全零），而两张表 md5 仍=1b2ff310…，与基线一致。

与 gptfix 的分工是刻意分开的：gptfix 靠**盘内**完好备份重建，两份都没了就只能用**盘外** dump，这正是 4B-full 要练的能力。`-Restore` 的门禁链条：

```
前置：两份头都失效 + 两张表与基线逐字节一致 + MBR 签名在   （任一不满足即 ABORT=PRE-*，不写一字节）
源校验：blob MD5==基线、头 CRC 自校验、DiskGUID 两份一致且==F231B2D6-…、
        MyLba/AltLba 与本盘 lastLba 互证                       （防把 A 盘的头写到 B 盘）
动作：Set-Disk -IsOffline → 写 LBA1 与 lastLba → 回读
复核：md5_prim_ok=True md5_backup_ok=True entries_crc_prim=True entries_crc_backup=True
      tables_still_intact=True → 上线 Update-Disk → PART count=4
RESULT=GPTRESTORE-OK   (20:52:24)
```

分区视图当场回来：System 314572800 / Reserved 16777216 / Basic C: 48319430656 / Basic 15772663296。随后**换另一个工具、另一套代码路径**独立复核：`t_s4b_gptfix.ps1` 体检 → `VERDICT=GPT-HEALTHY`、`style=GPT`。

### 7.6 恢复验证（20:52:59 起）

`wpeutil reboot` 远程重启，Windows 正常进桌面。`t_s4b_verify.ps1`（在线只读）：

```
PRIM   md5=1f6eba584a78872f76169d1df09c292a md5_matches_baseline=True  crc_ok=True
BACKUP md5=dba7a04e1bb648a0013f7f713b97dc3e md5_matches_baseline=True  crc_ok=True
TABLES both_match_baseline=True        PART count=4   C:/D: 均在
BACKUP=rescue_bcd_backup_… files=134 / hive 1 / hive 1 / s3 2   ← 场景 1-3 备份完好
rescue_s4_hiveSYSTEM_before.bin exists=True bytes=11796480      ← 场景 4A 备份完好
md_D_hex=444D494F3A49443AE7769A38… md_matches_original=True     ← 4A 修复仍在
SYSERR_since_boot=1 (TPM-WMI，VM 常态噪声)
RESULT=VERIFY4B-OK
```

证据同时落 `D:\rescue_s4b_verify.txt`。从 PE 上网到 `GPTRESTORE-OK` 约 1 分钟，全程现场动作只有挂 ISO 与拍一张控制台照片。

### 7.7 本次做工具链时抓到的三个自伤型坑

这三个都不是被救机的问题，而是我们脚本工程纪律的问题，值得单独留档：

1. **PowerShell 变量名大小写不敏感**：`$BD = [char]92`（反斜杠，用于拼 `\\.\PhysicalDrive0`）被后面的 `$bd = @(Get-Disk …)`（启动盘列表）静默覆盖，设备路径变成垃圾，FileStream 构造函数抛出的是中文包裹异常、经 ASCII guard 后只剩一串 `?`，白查两轮。定式：跨作用域的短名一律避开易撞组合（本次改 `$BSL` / `$bootDisks`），并在脚本开头把设备路径原样打印一次（`DEVP=\\.\PhysicalDrive0`）作为自检行。
2. **返回值函数里不能用 `Write-Output` 打日志**：`$ok = Blob-SelfCheck …` 会把函数内部 `Add()` 的证据行一起吞进返回值，日志静默消失、判据变成数组。`Add()` 定式改为 `[Console]::Out.WriteLine(...)`，让日志走宿主流不进管道。
3. **`-like` 里的方括号是字符类**：`make_dry.ps1` 用 `-like 'param([switch]$DryRun)*'` 匹配注入脚本的 param 行，永远匹配不上，"干跑副本"于是跑成了真注入。所幸注入脚本自身的前置断言完整通过、注入的正是计划中的故障，才没有变成事故；定式：模式匹配一律用 `-match` + 转义，并且**"干跑"开关必须在干跑前先验证它真的会拦住动作**（本次已把该脚本改为 `-match '^param\(\[switch\]\$DryRun\)'`）。

## 八、工具链缺口与改进项（本次演练发现）

1. **一键引导修复未产品化**：本次修复逻辑（挂 EFI→定位系统卷→bcdboot→取证）已验证，但散落在演练脚本里；建议收进 PE 做成桌面面板按钮或 `bootfix.cmd`，与 netdrvfix 同风格输出 `BOOTFIX=ok` 判据行，便于远程确认。
2. **EFI 分区无盘符**是引导类救援的通用前置坑，任何脚本都必须自带挂载步骤，不能假设 S: 存在。
3. **备份落点纪律**：PE 的 X: 是内存盘，一切备份/证据必须写被救机的数据卷（本次 D:），报告类产物再经 ssh 回传宿主机。
4. Git Bash 内联 PowerShell 的 `$_` 会被外层吞掉（老坑复现一次），所有含 `$` 的远程 PS 一律走 `-File` 脚本推送。
5. **Recovery 拦截要纳入 bootfix 产品线**：根因修好后 `BOOTSTAT.DAT` 失败计数仍会弹 Recovery 屏（本次 0xc0000001），极易被误判为"修复无效"进而重装。一键修复工具应内置"离线回读确认根因已修 → 清 BOOTSTAT → 设 ignoreallfailures/recoveryenabled"这一收尾链，并把"Recovery 屏 ≠ 修复失败"写进话术。
6. **离线蜂巢操作的证据通道只能是 reg.exe**：PowerShell 的 `Test-Path 'HKLM\OFFSYS'`（少冒号）会被当成文件系统路径而给出假阴性，场景 2 的 v1 修复脚本因此误报加载失败、实际未做任何改动。挂蜂巢前后的取值与断言一律走 `reg query` 输出解析。
7. **共享 IP 的 known_hosts  churn**：PE↔Windows 在同 IP 间切换必触发 host key 冲突，`ssh-keygen -R <IP>` 应固化进进出 PE 的连接封装，而不是靠人记得。
8. **被救机在线 ssh 是注入/验证的第二通道**：本次场景 2 的注入、重启、修复后台账回读全部走了被救机自身的 OpenSSH——救援工具链应把"故障机可控时先建立在线通道"纳入侦察阶段。
9. **离线 sfc 必须带 `/offlogfile`**：不带时它只给一句"发现损坏但未能全部修复"，细节全丢（被救机 CBS.log 是旧在线会话的，PE 里这次运行不往里写）。作业模板固化为 `sfc /scannow /offbootdir=<V>:\ /offwindir=<V>:\Windows /offlogfile=X:\cbs_off.log`，读日志前先探测编码（该文件常为 UTF-16LE，按 ANSI 读会得到字符间夹空格的乱码）。
10. **"sfc 修不动"是常态而非例外，产品线必须自带第二层**：nonSxS 组件（userinit.exe 等）在 WinSxS 里的修复源与 System32 本体是同一文件记录的硬链接，本体被毁=源被毁，sfc 必然报 `source file in store is also corrupted`。因此"系统文件修复"工具不能只包一层 sfc，要按 **sfc → 基线备份/外部源（install.wim、同版本健康机）还原 → 再跑一次 sfc 复核** 三级阶梯设计，并把判据交给 sfc 而不是交给还原动作本身。
11. **WRP 系统文件的还原要连 ACL 一起收尾**：改过 owner/ACL 的文件即便内容复原，仍可能被后续在线 sfc/WCP 判定异常。还原动作应固定包含 `icacls /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`（TrustedInstaller）+ `/reset`。
12. **用 `Copy-Item` 覆写可保留硬链接**：截断写入不新建文件记录，硬链接的另一端（Store 源）同步复原；若先 `del` 再 copy 就会断开链接，反而留下"Store 仍损坏"的假故障。
13. **盘符修复必须离线写蜂巢，PE 里 diskpart assign 是无效动作**：盘符持久化在被救系统 SYSTEM 蜂巢的 `MountedDevices\DosDevices<X>:`，值格式有两种实测样本——`"DMIO:ID:"(8 字节 ASCII) + 16 字节小端 GUID`（本 VM 的 C:/D:）与 UTF-16 卷路径（`\??\Volume{...}\`）。修复工具要按"存档原值写回 + 解码 GUID 与目标卷比对"来做，绝不能凭空拼格式。
14. **基线证据要放在"故障波及不到"的位置**：场景 4 的基线同时写了 D:（随故障一起"消失"）与 C:\Windows\Temp（修复时的标准答案）。凡以"盘符/卷可见性"为故障对象的场景，证据落点必须避开被操作卷本身。
15. **远端探测命令要匹配默认 shell**：被救机 sshd 默认 shell 是 PowerShell，用 cmd 时代的 `ver` 做存活探测会永远失败（本轮空转了 6 分钟才发现）；探测一律用 `exit 0` 这类 shell 中立命令。
16. **分区表救援的第一动作是"盘外字节备份"，而不是"想怎么修"**：`gptdump` 必须在被救机还能在线时就把主头/主表/备头/备表 4 个 blob 以 MD5 校验的形式拉到救援机上。4B-full 的整个修复能力完全来自这份 19:03 的 dump——盘内没有任何完好副本可推。产品线建议：`gptdump` 做成 PE/在线两用的"分区表体检+留档"按钮，`gptfix`（盘内完好备份→重建）与 `gptrestore`（盘外 dump→还原）作为两条互斥修复路径并在体检态明确分诊（`PRIMARY-GPT-LOST BACKUP-INTACT` vs `BOTH-HEADERS-DEAD TABLES-INTACT`）。
17. **保护性 MBR 不能当兜底，也不能当前置断言**：本 VM 的 MBR 只有 55AA 签名、分区项为空（`part1_type=00`，非 0xEE）。工具上"MBR 完好"只作信息打印；话术上则要提醒现场人员——GPT 两份头一坏，这台机器连 MBR 引导的可能性都没有，症状就是固件的 `No Media`。
18. **"故障是否已生效"只能以固件/PE 读到的字节为准，配合被救机电源事件做时间线**：注入脚本的 POST 读回全零只证明 OS 视图已改，不证明下一次引导一定看到它；4B-min 更是直接被固件回救。定式：注入后 (a) 以控制台截图为唯一故障判据，(b) 用被救机自己的 User32 1074 / EventLog 6005·6006 / Kernel-General 12·13 事件把"谁在什么时候重启了几次"钉死，避免把"根本没重启"误读成"重启后没故障"。
19. **GPT 校验只能自带 CRC32**：PE 里没有现成工具，纯 PowerShell 实现的两个坑（`>0x7FFFFFFF` 十六进制字面量按负 Int32 解析、手工十进制化写错常量）必须靠"标准向量自校 + 另一语言独立实现交叉验证"兜住，任何一处 CRC 结论在没有自校行之前都不可信。

## 九、收官与后续

五个场景（1 引导损坏、2 启动关键驱动禁用、3 系统文件损坏、4A 盘符丢失、4B 分区表破坏〔含 4B-min/4B-full 两档〕）全部按"侦察→基线→注入→故障确认→远程修复→恢复验证"六段式闭环，修复侧现场动作合计仅挂/断 ISO 与两次登录。后续三件事，按优先级：

1. **产品化收编**（缺口 1/5/10/13 的落地）：**已于 10-14 当天交付**。演练脚本提炼成 PE 桌面面板"救援修复"四件套（`overlay\Scripts\`，同名 `.cmd` 启动器，已接进 `build.ps1` 文件清单与 `update_overlay.ps1` 出盘作业，HTA 磁贴默认先进 `-Check` 体检态、体检输出直接打印修复命令行）：
   - `bootfix.ps1`：ESP 按 GPT 类型全盘扫描幂等挂载 + `bcdboot <win>:\Windows /s S: /f UEFI` 重建 + **BOOTSTAT 收尾链缺省开启**（备份删 BOOTSTAT.DAT、bootstatuspolicy=ignoreallfailures、recoveryenabled=no 并回读），对应场景 1+2 的全部教训；
   - `filefix.ps1`：三级阶梯——离线 sfc（强制 `/offlogfile`，UTF-16LE 字节序探测）→ nonSxS"Store 源同坏"文件从 `-RestoreDir` 基线 `Copy-Item` 截断写还原（保硬链接、两端同修）+ `icacls /setowner TrustedInstaller + /reset` → 二次 sfc 独立复核（判据交给 sfc）；
   - `drvfix.ps1`：离线 SYSTEM 蜂巢手术——`Select\Current` 解析活动 ControlSet、`reg query /s` 块解析器列出"Disabled 且 ErrorControl=1"的启动关键服务候选，`-Service <名> -SetStart 0` 修复并回读（蜂巢先备份到 `<win>:\Windows\Temp\rescue\`）；判据一律走 `reg.exe` 输出文本；
   - `letterfix.ps1`：体检态解码 MountedDevices 全部 `\DosDevices<X>:` 项（DMIO:ID:+小端 GUID 与 UTF-16 卷路径两种格式都认）并与活卷 GUID 对照；修复态要求 `-VolumeGuid` 必填做防挂错卷双断言，hex 从注入前 dump 原文提取，reg load→add→回读→unload。
   四件统一：`RESULT=<TOOL>-OK|CHECK|BAD-*` 判据行、证据双写 `X:\tool.txt` + `<winvol>:\Windows\Temp\rescue\`（盘符/分区类故障波及不到的位置）。门禁全绿：parse、BOM/CRLF/ASCII、`-SelfTest` 干跑（letterfix 用演练真实 hex 解码出 recon GUID 逐字节验证；drvfix 解析器过嵌套键用例）、HTA 走 mshta 同引擎语法闸。（10-14 晚又加第五件 `gptfix` 分区表磁贴，详见第 2 条。）
2. **场景 4B 专项**（分区表级破坏与重建）：**已于 10-14 当天完成**（第七节，4B-min + 4B-full 两档，注入→故障确认→PE 盘外还原→在线复验全链闭环）。工具链三件已成型并全部实跑验证：`t_s4b_gptdump.ps1`（在线 Windows，4 blob + MD5 拉回宿主机）、`t_s4b_gptfix.ps1`（PE，体检 + 从盘内完好备份重建主表）、`t_s4b_gptrestore.ps1`（PE，从盘外 dump 还原两份头，SelfTest 用基线 hex 自校 CRC/MD5/字段形状）。**产品化收编已于 10-14 晚完成**（按上述决策落地；当晚烧盘并活体复验通过，见下）：
   - **`gptfix.ps1`＝面板第五磁贴**（`overlay\Scripts\gptfix.ps1` + `gptfix.cmd`，badge "GPT"，救援修复组内，缺省体检态）。一个工具吃下整张分诊矩阵：`Inspect-Disk` 读两份头并各自验 CRC/签名/头长，`Get-Verdict` 输出 `GPT-HEALTHY / PRIMARY-LOST BACKUP-INTACT / BACKUP-LOST PRIMARY-INTACT / MBR-DISK(不是 GPT 修复对象，勿动) / BOTH-HEADERS-DEAD / UNCLASSIFIED`，每态直接打印对应 `FIX_CMD`。修复源两条：**盘内重建**（`-Repair -Disk N`：主表坏→用备头+备表镜像重建 MyLba/AltLba/EntryLba 后回写，备头坏→反向，只比较"存活且合法"的那份，避开演练版 `fb.GuidHex -ne fh.GuidHex` 在主头清零后必然误 ABORT 的坑）；**盘外 dump 还原**（`-Repair -Disk N -DumpDir <目录>`：合并演练版 gptrestore 的能力并改成**按文件读**——`gpt_d<N>_<kind>_<stamp>.hex|.bin` 命名与 gptdump 产物成对，取最新 stamp，四类齐备才动手，还原前跑几何自校（prim.MyLba=1、AltLba=**本盘** lastLba、备头镜像位）+ 头 CRC + 表 CRC + MD5 一致性，任何一条不过 `ABORT=DUMP-SELF-CHECK`）。写盘只在 PE（`ABORT=REPAIR-PE-ONLY`）、Set-Disk offline 下进行，判据一律是写后重读 `AFTER … VERDICT=`（`RESULT=GPTFIX-OK` 只给 GPT-HEALTHY）；`-Reboot` 可选 wpeutil 重启。`-SelfTest` 用演练真实基线字节做往返（重建备头 CRC==90B3FAD9、重建主头 CRC==1E4D4292、entryLba==125829087、dump 取最新/roundtrip），不碰盘。
   - **`gptdump.ps1`＝救援规程第一动作**（`overlay\Scripts\gptdump.ps1` + `.cmd`，PE/在线 Windows 两用、纯只读）：每盘把主头/主表/备头/备表 4 个 blob 同时落 `.hex` 与 `.bin` 并逐块打 MD5，另发 `B64|name|md5|…` 传输行（沿用演练版被 host_run_stdin 拉回的方式），manifest 记 DISK 几何；盘内任一头已坏时 `RESULT=GPTDUMP-DAMAGED-SOURCE (rc=2)` 提醒"这份留档可能是唯一好数据"。已进 `build.ps1` 清单与 `update_overlay.ps1` 出盘作业，供面板/命令行随取随用。
   - **`letterfix.ps1` 体检态加分区表分诊行**：`triage_gpt_raw_disks=<N>` + 每个 RAW 大盘一行 `HINT=partition table unreadable: run gptfix (survey) FIRST, this is not a letter fault`——"分区没了 vs 只是丢盘符"在体检输出里直接分流。

**五件套活体复验（10-14 22:32，VM 挂新 ISO 进 PE，一条命令自动回传）**：先过身份闸（`IDENTITY vendor=VMware model=VMware20,1 pctype=1`——复验脚本本轮已把"哪台机器"打在首行，实机/VM 同 IP 的历史坑就此免疫）。六文件镜像 MD5 与 overlay 逐个 match=True、HTA 五磁贴（含 GPT）全在位；bootfix `-Check`（WINVOL=C、ESP 幂等、pre_bcd=True/BOOTSTAT absent）、drvfix（12 候选、stornvme 不在列）、letterfix（survey_entries=5、D→389A76E7 volume_live=True、**triage_gpt_raw_disks=0 分诊行生效**）、gptfix 体检（`VERDICT=GPT-HEALTHY`，主/备头 CRC 1E4D4292/90B3FAD9、表 MD5 全部回到基线——4B-full 重建经多次起机依然逐字节健康；顺带新观察：修复后 Windows 首次起机把保护性 MBR 改写成了标准形状 `mbr ee=True`，印证第 17 条"MBR 只能信息打印"的设计）、gptdump `-SelfTest`（CRC 向量+夹具）五件全绿（`RESULT=BOOTFIX-CHECK-ONLY / DRVFIX-CHECK / LETTERFIX-CHECK / GPTFIX-CHECK / GPTDUMP-SELFTEST-OK`）。救援修复面板五件套产品化验收收官。

**活体等价复验（10-14 16:48–17:04，新 PE 开机即验）**：镜像内四文件与 overlay 逐字节一致、HTA 四磁贴在位；bootfix 体检（WINVOL=C、ESP 挂载幂等、pre_bcd=True/BOOTSTAT 已 absent——场景 2 处置留痕正确）与 drvfix 体检（Select\Current=0x1、"Disabled 且 ErrorControl=1"候选 12 项、stornvme 不在列=已修复态）一次通过。**复验抓出两个产品化级 bug 并当场热修**：①`letterfix` 体检态按"每值一行 HKEY 路径"解析 `reg query` 输出——单键查询其实只打一次表头、值行是缩进的 `名称 REG_BINARY hex`，静默 0 条目（演练脚本用 `/v` 单值查询躲过了这一层）；②`filefix` 拼装参数用的 `$w`（bootdir=卷根）在死变量清理时被误删，`/offbootdir` 成了单字符 `\`，CBS 1 秒拒绝（`path.cpp(302) STATUS_INVALID_PARAMETER`）——教训：**SelfTest 必须覆盖每一条参与拼装的变量路径**（已补 bootdir_test 用例，且该用例正是模拟"删掉赋值"这一回归形态）。两处修复热推活 PE 复跑：letterfix 解出 `\DosDevices\D:`→`389A76E7-…` volume_live=True（顺带证明 4A 蜂巢修复经重启仍在），filefix 60 秒全量扫描 `verify_complete=True clean=True`（并顺手修正了 clean 判据：控制台那句"did not find any integrity violations"从不进 CBS offlog，须按 `Verify complete`+无损坏标记判）。健康系统离线 sfc 60 秒（损坏态 255 秒），面板提示耗时按此更新。**再烧盘已完成（17:15 最终镜像复验全绿）**：新 PE 开机即验，镜像内四文件 MD5 与 overlay 逐个一致、HTA 四磁贴在位；bootfix `-Check`、drvfix、letterfix 体检与 filefix `-Check`（67 秒全量扫描，verify_complete=True clean=True）四件全部实跑通过（`RESULT=BOOTFIX-CHECK-ONLY / DRVFIX-CHECK / LETTERFIX-CHECK / FILEFIX-CHECK-ONLY`），letterfix 体检态在最终镜像里解码正常（survey_entries=5，`\DosDevices\D:`→`389A76E7-…` volume_live=True）。救援修复面板产品化验收收官。
3. **回归本盘主线**：WiFi 修复版永久盘已于 10-14 16:14 出盘（`dist\WinPE_Desktop_v8.iso`，997MB，含 WiFi 面板与 wifi.exe 修复；17:10 那次再烧已含救援修复四件套）。**实机验收已于 10-14 晚通过：面板扫描→连接→断开→获取 IP 全链路正常**。本轮 4B 用的正是这张盘，PE 侧 ssh/存储 cmdlets/裸扇区读写在实机镜像上全部可用。至此 WiFi 主线与救援演练两条线都收口。4B 工具产品化已于 10-14 晚交付并过全部门禁（gptfix 面板磁贴、gptrestore 并入 gptfix 改读 dump 文件、gptdump 进规程、letterfix 分诊行），**烧盘与五件套活体复验亦于当晚 22:32 通过**（见上）。

**面板 v11-i18n（10-15 晨追加，10-17 本机验证收官）**：桌面面板升级为中英双语——文案全部收进 HTA 内 `I18N` 表（zh/en 各 139 键），开机按 `Nls\Language`（退回 WMI Locale）自动判定、顶栏 English/中文 手动切换（PE 注册表不持久化，重启回自动判定，刻意设计）；救援五件套的输出本就是 ASCII 英文判据行，无需改动。新门禁 `t_hta_i18n_gate.js`（36_RunGates 11c：两表键一一对应 + 每个引用键两表都有）与既有语法/解析闸同绿。**本机 mshta 真渲染双语截图均已通过**（`build\hta_i18n_zh.png` / `build\hta_i18n_en.png`，英文侧标题"WinPE Rescue Desktop"、顶栏"panel v11-i18n"、五磁贴/WiFi/frp 全英文、切换按钮显示"中文"）；10-17 总门禁 `ALL GATES GREEN`（其间修掉一处与 HTA 无关的存量断言：宿主机 servicing 后 Package04 分裂 7663/7807 两条修订线，vWiFi 池 .cat 由 2 根变 3 根属正确状态，7c 闸与 wifi-inject SelfTest 的"恰好 1 根 Package04"断言已改为"≥1/等于 3"）。待 `update_overlay.ps1` 烧盘后 PE 活体复验：面板版本行显示"面板 v11-i18n"即为生效判据。

## 附录 A：标准作业命令模板

```powershell
# 推送并执行（宿主机）
powershell -NoProfile -ExecutionPolicy Bypass -File test\host_push_run.ps1 `
  -Local build\scratch\t_<probe>.ps1 -RemotePath X\<name>.ps1 `
  -Target administrator@<PE-IP> -Port 22 -ChunkSize 2000 -Run
```

PE 侧脚本三原则：UTF-8 BOM + CRLF + 内容纯 ASCII（`test\bom_fix.ps1 -Target <file>` 统一处理）；结果写 `X:\*.txt`（ASCII）并追加一份到被救机数据卷；所有判据用 `KEY=value` 行输出，供 grep 断言。

被救机在线（Windows OpenSSH，默认 shell 即 PowerShell）改用另一条通道：`test\host_run_stdin.ps1 -Local <ascii.ps1>`——脚本经 stdin 喂给远端 `powershell -Command -`，自动前置 progress/编码 guard 行。注意两点：`-EncodedCommand` 路线实测在传输中吞字符（'ASCII'→'ASC?'），已弃用；每次 PE↔Windows 切换后除 `ssh-keygen -R` 外还需 `-o StrictHostKeyChecking=accept-new`（host key 变更非交互直接拒绝）。交付前所有脚本一律过 `build\scratch\check_parse.ps1 -Files <file>` 语法闸。

分区表（4B）标准作业序列（产品化版，工具在 `overlay\Scripts\`，出盘后位于 `X:\Windows\System32\`）：

```powershell
# 0) 被救机还能在线时：规程第一动作——4 blob + MD5 落档（盘外字节备份）
powershell -NoProfile -ExecutionPolicy Bypass -File test\host_run_stdin.ps1 `
  -Local overlay\Scripts\gptdump.ps1
#    stdout 的 B64|name|md5|... 行由救援机落盘；或直接取
#    <winvol>:\Windows\Temp\rescue\gptdump\gpt_d<N>_{prim_hdr,prim_tab,backup_hdr,backup_tab}_<stamp>.{hex,bin}

# 1) 故障后进 PE：面板"GPT 分区表体检/修复"磁贴，或命令行只读体检
powershell -NoProfile -ExecutionPolicy Bypass -File test\host_push_run.ps1 `
  -Local overlay\Scripts\gptfix.ps1 -RemotePath X\gptfix.ps1 `
  -Target administrator@<PE-IP> -Port 22 -ChunkSize 2000 -Run
#    VERDICT + FIX_CMD 直接给出下一步

# 2) 按分诊二选一：
#    盘内还有一份完好头/表 -> X:\Windows\System32\gptfix.ps1 -Repair -Disk <N>
#    两份头都没了         -> gptfix.ps1 -Repair -Disk <N> -DumpDir <第0步 dump 目录>
#    （判据=写后重读 VERDICT；RESULT=GPTFIX-OK 只在 GPT-HEALTHY 时出现）
```
