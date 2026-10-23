# WinPE 远程救援桌面 (WinPE Rescue Desktop)

[English](README.en.md) | **中文**

> 一个可开机即用的 Windows PE 救援盘：图形桌面面板、SSH/向日葵远程通道、原生 WiFi 支持、
> 存储/无线驱动自愈，以及引导·系统文件·驱动·盘符·分区表"救援五件套"。
> 全程由脚本从 ADK 干净构建，任何改动先过门禁（`test\36_RunGates.ps1`）再出盘。

![platform](https://img.shields.io/badge/platform-Windows%20x64-blue)
![build](https://img.shields.io/badge/build-PowerShell%205.1-yellow)
![desktop](https://img.shields.io/badge/desktop-HTA%20(docMode%208)-green)
![lang](https://img.shields.io/badge/UI-中文%20%2F%20English-orange)
![iso](https://img.shields.io/badge/output-WinPE__Desktop__v8.iso-brightgreen)

## 它是什么

从微软 ADK 的 `WinPE` 基础镜像出发，离线注入定制层，产出一张 U 盘/ISO 均可启动的救援盘。
目标场景是**无人值守的远程救援**：机器起不来、进不了系统，救援人员不在现场——
盘启动后自动拉起 SSH 与向日葵，通过网络（含 WiFi）连回来，在图形面板上点磁贴完成修复。

与常见 WinPE 发行版的差异：

- **WiFi 是真能用的**：ADK 原版 WinPE 没有无线栈，本项目把 wlansvc/wcmsvc、vWiFi 过滤栈、
  WDI 框架（wdiwifi/NdisImPlatform）、L2Schemas、覆盖驱动的 `.cat` 全部离线烘进镜像，
  开机后图形面板扫码、输密码即可连接（12 代实机验收通过）。
- **驱动自愈**：有线/存储/无线三套精选驱动池 + 硬件 ID 索引，开机 `netdrvfix` 按表 drvload，
  Intel VMD (iaStorVD) 这类"PE 看不到盘"的场景自动把盘找回来。
- **每一步都有门禁**：40+ 项检查（语法、ASCII/BOM、SelfTest 红绿双分支、逐包 DISM 复核、
  HTA 解析与 i18n 键对齐）串成一条命令，全绿才允许出盘。

## 快速开始

### 环境要求

| 依赖 | 说明 |
| --- | --- |
| Windows 10/11 x64 | 构建机（宿主机 servicing 状态会影响素材池，见"注意事项"） |
| Windows ADK + WinPE 插件 | `C:\Program Files (x86)\Windows Kits\10` |
| PowerShell 5.1 | 构建脚本；需管理员权限（DISM 挂载 + reg load） |
| Go | 编译 `sshserver`（pe-sshd）与 `wifitool`（wifi.exe）两个自带工具 |

### 构建 ISO

```powershell
# 管理员 PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
# 产物: dist\WinPE_Desktop_v8.iso（不触碰其他工作目录）
```

只补 WiFi 层（不重跑 copype/组件）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File patch_wifi.ps1
```

只更新桌面层（overlay 已 commit，重打包 Desktop + 剔私钥 + pack_iso）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File test\update_overlay.ps1
```

### 出盘前：跑门禁（一条命令）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File test\36_RunGates.ps1
# 期望最后一行: ALL GATES GREEN
```

### 写入 U 盘

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File make_usb.ps1
```

## 桌面面板

开机自启的 HTA 全屏面板（固定 `docMode 8`——更高文档模式下 PE 里输入框拿不到焦点，实测定案）。
中英双语（v11-i18n）：按系统安装语言自动判定，顶栏 English/中文 按钮随时切换
（PE 注册表不持久化，重启回自动判定，刻意设计）。四个分组、20 个磁贴：

- **终端与磁盘**：CMD / PowerShell / 记事本 / diskpart / 分区卷管理
- **救援修复**（离线，先体检再动手）：
  | 磁贴 | 工具 | 干什么 |
  | --- | --- | --- |
  | BCD | `bootfix.ps1` | 引导体检 + 修复（含 BOOTSTAT 清理，拦 0xc0000001） |
  | FIL | `filefix.ps1` | 离线 `sfc /scannow /offbootdir /offwindir`（~1-4 min，必带 /offlogfile） |
  | DRV | `drvfix.ps1` | 列出被禁的启动关键服务（stornvme 蓝屏类故障） |
  | LTR | `letterfix.ps1` | 盘符丢失：解码蜂巢 `MountedDevices` 与在活卷对账后还原 |
  | GPT | `gptfix.ps1` | 分区表体检/修复：盘内备份重建，或从盘外字节 dump（`gptdump` 产物）还原 |
- **网络与远程**：网络信息 / 端口 / SSH 日志 / 向日葵 ID / frp 隧道面板 / **WiFi 面板**（扫码连接，底栏绿灯=已连）
- **日志与电源**：自测报告 / 启动日志 / 关机 / 重启

## 远程通道

| 通道 | 状态 | 说明 |
| --- | --- | --- |
| SSH (pe-sshd) | 开机自启 | 自研 Go 实现；无 scp/sftp，命令串 ≈6KB 上限（stdout 不限） |
| 向日葵 | 开机自启 | SOS 窗口显示识别码，图形兜底 |
| frp | 手动启动 | 面板配置并启动，穿透用 |
| 宿主机→PE | `test\host_push_run.ps1` | 分块推送脚本并执行（certutil 解码，RemotePath 必须单引号 Windows 路径） |
| PE→宿主机 | 单向 pull | 大文件用 certutil+type 拉回 |

```powershell
# 向活 PE 推脚本并跑（示例）
powershell -NoProfile -ExecutionPolicy Bypass -File test\host_push_run.ps1 `
  -Local build\scratch\t_panel_verify_pe.ps1 -RemotePath 'X:\panel_verify.ps1' `
  -Target administrator@192.168.1.100 -Port 22 -ChunkSize 2000 -Run
```

## 仓库结构

```
.
├── build.ps1 / build10.ps1     # v8(WinPE 10.0.19041) 与 Win10 分支的总构建脚本
├── patch_wifi.ps1              # 只补 WiFi 层的快速通道
├── wifi-inject.ps1             # WiFi 栈注入核心（被 build/patch 共用，带 -SelfTest）
├── make_usb.ps1                # ISO → U 盘
├── overlay/                    # 定制层（构建时整体注入镜像）
│   ├── Desktop/                #   HTA 面板 + Frp/Wlan 子面板（I18N 双语表）
│   ├── Scripts/                #   救援五件套 / netdrvfix / 索引表 / startnet.cmd
│   ├── Drivers/Wlan/           #   无线驱动精选池（9 目录 / 23 INF / 361MB）
│   ├── VWiFi/ Cats/ L2Schemas/ #   原生 WiFi 栈素材（INF/.sys/.cat/.xsd）
│   ├── SSH/ Sunlogin/ Tools/   #   pe-sshd、向日葵、随身工具
├── sshserver/                  # pe-sshd 源码（Go）
├── wifitool/                   # wifi.exe 源码（Go，PE 内无线命令行工具）
├── test/                       # 门禁总闸 36_RunGates.ps1 + 各探针/注入/验收脚本
├── build/                      # 工作区（挂载点、临时产物、截图证据）
├── dist/                       # 出盘产物 ISO
└── docs/                       # 方案文档 + 远程救援演练报告（docs/rescue-drill/）
```

## 工程约定

- **脚本编码**：`.ps1` 一律 UTF-8 BOM + CRLF + 门禁脚本本体纯 ASCII（cscript 按 ANSI 读源码，
  UTF-8 中文注释尾字节会"吃掉"换行）；`.bat/.cmd` 转 GBK/CRLF 且无 BOM。
- **判据必须会红**：每个 SelfTest 同时跑红灯/绿灯两条分支——只会长绿的判据等于没有判据。
- **需要管理员的构建步骤**在提权会话执行；交付前先本机过语法 + SelfTest 干跑，
  不让使用者当第一个测试者。
- **destructive 注入前先验身份**：`PCSystemType=1` + `IDENTITY host/vendor/model` 行，
  防止实机与 VM 同 IP 认错机器。

## 已知限制与坑

- WiFi 只能实机验证：Hyper-V 无 802.11 设备模型，VMware 无线网卡不能做 external 交换机。
- 无线池唯一记录在案的缺口：`netrtwlane02`（缺 rtlCoInst.dll/.dat，DISM 必拒，7 个 10EC ID 无替补）；
  现场兜底 = `pe_getdriver` 抓厂商包或插 USB 网卡。
- 素材池的 `.cat` 根数随宿主机 servicing 漂移（如 Package04 分裂双修订 ⇒ 3 根），
  门禁报"数量不对"时先跑 `test\20_MakeVWifiPool.ps1` 看 CATSRC 行再下结论。
- PE 里没有 `taskkill`/`tasklist`/`netsh wlan`；进程管理用 PowerShell `Stop-Process`，
  无线操作走 `wifi.exe`。
- HTA 只能用 IE8 认的 CSS 子集：rgba/渐变/圆角需纯色兜底，placeholder 无效。

## 文档

- [WinPE 远程救援演练报告](docs/rescue-drill/WinPE远程救援演练报告.md) —— 引导/系统文件/驱动/盘符/分区表
  五场故障注入 + 修复的完整实录与标准作业命令模板
- [存储驱动与远程救援方案](docs/存储驱动与远程救援方案_20261008.md)

## License

内部救援工具，未选择开源许可证；使用前请自行确认所用 Windows ADK、驱动与第三方工具的分发条款。
