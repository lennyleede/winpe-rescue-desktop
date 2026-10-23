# WinPE Rescue Desktop

**English** | [中文](README.md)

> A ready-to-boot Windows PE rescue disk: graphical desktop panel, SSH/Sunlogin remote
> channels, native WiFi support, storage/wireless driver self-healing, and a five-tool
> rescue kit covering boot records, system files, drivers, drive letters and GPT partitions.
> Everything is built from a clean ADK image by scripts, and no change ships to an ISO
> until the full gate suite (`test\36_RunGates.ps1`) is green.

![platform](https://img.shields.io/badge/platform-Windows%20x64-blue)
![build](https://img.shields.io/badge/build-PowerShell%205.1-yellow)
![desktop](https://img.shields.io/badge/desktop-HTA%20(docMode%208)-green)
![lang](https://img.shields.io/badge/UI-中文%20%2F%20English-orange)
![iso](https://img.shields.io/badge/output-WinPE__Desktop__v8.iso-brightgreen)

## What it is

Starting from Microsoft ADK's stock `WinPE` image, custom layers are injected offline to
produce an ISO (or USB drive) that boots straight into a rescue desktop. The target
scenario is **unattended remote rescue**: a machine won't boot, nobody is on site — the
disk starts, auto-launches SSH and Sunlogin (a remote-desktop service), gets online even
over WiFi, and the operator fixes the machine by clicking tiles in the panel.

What sets it apart from typical WinPE builds:

- **WiFi that actually works**: stock WinPE has no wireless stack. This project bakes
  wlansvc/wcmsvc, the vWiFi filter stack, the WDI framework (wdiwifi/NdisImPlatform),
  L2Schemas and the covering `.cat` catalogs offline into the image. After boot, the
  graphical panel scans networks and connects with a password (verified on real 12th-gen
  hardware).
- **Driver self-healing**: curated wired/storage/wireless driver pools plus hardware-ID
  indexes; `netdrvfix` runs at boot and drvloads by lookup, recovering "PE can't see the
  disk" cases such as Intel VMD (iaStorVD).
- **Every step is gated**: 40+ checks (syntax, ASCII/BOM, SelfTests with both red and
  green branches, per-package DISM verification, HTA parsing and i18n key parity) chained
  into one command — the ISO is only cut when all gates are green.

## Quick start

### Requirements

| Dependency | Notes |
| --- | --- |
| Windows 10/11 x64 | Build host (the host's servicing state affects the material pool — see Caveats) |
| Windows ADK + WinPE add-on | `C:\Program Files (x86)\Windows Kits\10` |
| PowerShell 5.1 | Build scripts; elevation required (DISM mount + reg load) |
| Go | Builds the two in-house tools: `sshserver` (pe-sshd) and `wifitool` (wifi.exe) |

### Build the ISO

```powershell
# elevated PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
# output: dist\WinPE_Desktop_v8.iso (other working directories are never touched)
```

Patch only the WiFi layer (skips copype/components):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File patch_wifi.ps1
```

Update only the desktop layer (overlay already committed; replaces Desktop, strips
private keys, repacks the ISO):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File test\update_overlay.ps1
```

### Before cutting an ISO: run the gates (one command)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File test\36_RunGates.ps1
# expected last line: ALL GATES GREEN
```

### Write to USB

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File make_usb.ps1
```

## Desktop panel

A full-screen HTA panel auto-started at boot (pinned to `docMode 8` — in higher document
modes input boxes can never take focus inside PE, established by controlled experiments).
Bilingual (v11-i18n): language is auto-detected from the installed system language, with an
English/中文 button in the top bar (PE registry is not persisted, so a reboot returns to
auto-detection — by design). Four groups, 20 tiles:

- **Terminal & Disk**: CMD / PowerShell / Notepad / diskpart / partitions & volumes
- **Rescue Repair** (offline; survey first, then act):
  | Tile | Tool | Purpose |
  | --- | --- | --- |
  | BCD | `bootfix.ps1` | Boot survey + repair (incl. BOOTSTAT cleanup, blocks 0xc0000001) |
  | FIL | `filefix.ps1` | Offline `sfc /scannow /offbootdir /offwindir` (~1-4 min; /offlogfile is mandatory) |
  | DRV | `drvfix.ps1` | Lists disabled boot-critical services (stornvme-style BSOD) |
  | LTR | `letterfix.ps1` | Lost drive letters: decodes the hive's `MountedDevices`, reconciles vs live volumes, restores |
  | GPT | `gptfix.ps1` | Partition-table survey/repair: rebuild from the on-disk backup, or restore from an off-disk byte dump (`gptdump` output) |
- **Network & Remote**: network info / ports / SSH log / Sunlogin ID / frp tunnel panel /
  **WiFi panel** (scan & connect; green dot in the footer = linked)
- **Logs & Power**: self-test report / boot log / shut down / reboot

## Remote channels

| Channel | Status | Notes |
| --- | --- | --- |
| SSH (pe-sshd) | Auto-started | In-house Go implementation; no scp/sftp, command string ≈6KB cap (stdout unlimited) |
| Sunlogin | Auto-started | SOS window shows the ID; graphical fallback |
| frp | Manual | Configured and started from its panel; NAT traversal |
| Host → PE | `test\host_push_run.ps1` | Chunked script push + run (certutil decode; RemotePath must be a single-quoted Windows path) |
| PE → Host | One-way pull | Large files come back via certutil + type |

```powershell
# Push a script into a live PE and run it (example)
powershell -NoProfile -ExecutionPolicy Bypass -File test\host_push_run.ps1 `
  -Local build\scratch\t_panel_verify_pe.ps1 -RemotePath 'X:\panel_verify.ps1' `
  -Target administrator@192.168.1.100 -Port 22 -ChunkSize 2000 -Run
```

## Repository layout

```
.
├── build.ps1 / build10.ps1     # master build scripts: v8 (WinPE 10.0.19041) and the Win10 branch
├── patch_wifi.ps1              # fast path: patch only the WiFi layer
├── wifi-inject.ps1             # WiFi stack injection core (shared by build/patch, has -SelfTest)
├── make_usb.ps1                # ISO → USB
├── overlay/                    # the custom layer (injected wholesale at build time)
│   ├── Desktop/                #   HTA panel + Frp/Wlan sub-panels (I18N string tables)
│   ├── Scripts/                #   rescue five-tool kit / netdrvfix / ID indexes / startnet.cmd
│   ├── Drivers/Wlan/           #   curated wireless driver pool (9 dirs / 23 INFs / 361MB)
│   ├── VWiFi/ Cats/ L2Schemas/ #   native WiFi stack material (INF/.sys/.cat/.xsd)
│   ├── SSH/ Sunlogin/ Tools/   #   pe-sshd, Sunlogin, bundled utilities
├── sshserver/                  # pe-sshd source (Go)
├── wifitool/                   # wifi.exe source (Go, in-PE wireless CLI)
├── test/                       # gate runner 36_RunGates.ps1 + probes/injection/acceptance scripts
├── build/                      # scratch space (mount points, temp artifacts, screenshot evidence)
├── dist/                       # produced ISOs
└── docs/                       # design docs + remote rescue drill reports (docs/rescue-drill/)
```

## Engineering conventions

- **Script encoding**: `.ps1` files are UTF-8 BOM + CRLF; gate scripts themselves must be
  pure ASCII (cscript reads sources as ANSI(GBK), where trailing bytes of UTF-8 CJK
  comments can swallow newlines). `.bat/.cmd` are GBK/CRLF without BOM.
- **Judgments must be able to fail red**: every SelfTest exercises both the red and the
  green branch — a check that can only go green is not a check.
- **Elevation-gated steps run in an admin session**; before handing anything to the user,
  it passes local syntax checks + a SelfTest dry run. Users are never the first testers.
- **Identity gate before destructive injection**: `PCSystemType=1` plus an
  `IDENTITY host/vendor/model` line — prevents fixing the wrong machine when a physical
  box and a VM share the same IP.

## Known limitations & gotchas

- WiFi can only be verified on real hardware: Hyper-V has no 802.11 device model, and a
  wireless NIC cannot back a VMware external switch.
- The one documented gap in the wireless pool: `netrtwlane02` (missing
  rtlCoInst.dll/.dat ⇒ DISM always rejects it; 7 10EC IDs with no substitute). Field
  fallback = run `pe_getdriver` on the target to grab the vendor package, or plug in a
  USB WiFi adapter.
- The number of `.cat` files in the material pool drifts with host servicing (e.g.
  Package04 splitting into two revisions ⇒ 3 catalogs). If a gate reports a count
  mismatch, run `test\20_MakeVWifiPool.ps1` and read its CATSRC lines before concluding
  the pool is broken.
- PE has no `taskkill`/`tasklist`/`netsh wlan`; use PowerShell `Stop-Process` for process
  management and `wifi.exe` for wireless operations.
- The HTA may only use the CSS subset IE8 understands: rgba/gradients/border-radius need
  solid-color fallbacks; the placeholder attribute does nothing.

## Documentation

- *WinPE Remote Rescue Drill Report* (`docs/rescue-drill/`) — full six-stage records of
  five fault-injection + repair scenarios (boot, system files, drivers, drive letters,
  GPT) plus the standard operating command templates
- *Storage Drivers & Remote Rescue Plan* (`docs\存储驱动与远程救援方案_20261008.md`)

## License

Internal rescue tool; no open-source license chosen. Before use, verify the redistribution
terms of the Windows ADK, drivers and third-party tools you incorporate.
