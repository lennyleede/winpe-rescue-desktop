// wifi.exe —— WinPE 里的 WiFi 连接工具 + 服务依赖诊断器
// 只用 Go 标准库 syscall 直接调 wlanapi.dll / advapi32.dll, CGO_ENABLED=0 静态编译
// 用途: PE 里没有 netsh wlan 插件, 也没有 Get-NetAdapter 的 CIM provider, 更没有 Add-Type 需要的 csc,
//       所以连接管理和 SCM 诊断都得自己写一个。
// 注意: PE 控制台是 GBK, 所有 stdout 一律 ASCII。
package main

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	modWlan = syscall.NewLazyDLL("wlanapi.dll")
	modAdv  = syscall.NewLazyDLL("advapi32.dll")
	modSec  = syscall.NewLazyDLL("sechost.dll")
	modKern = syscall.NewLazyDLL("kernel32.dll")

	procRegOpen    = modAdv.NewProc("RegOpenKeyExW")
	procRegQuery   = modAdv.NewProc("RegQueryValueExW")
	procRegClose   = modAdv.NewProc("RegCloseKey")
	hklm       = uintptr(0x80000002)
	regSamRead = uint32(0x20019)
	procOpen    = modWlan.NewProc("WlanOpenHandle")
	procClose   = modWlan.NewProc("WlanCloseHandle")
	procEnumIf  = modWlan.NewProc("WlanEnumInterfaces")
	procFree    = modWlan.NewProc("WlanFreeMemory")
	procNetList = modWlan.NewProc("WlanGetAvailableNetworkList")
	procSetProf = modWlan.NewProc("WlanSetProfile")
	procConnect = modWlan.NewProc("WlanConnect")
	procDisc    = modWlan.NewProc("WlanDisconnect")

	procOpenSCM     = modAdv.NewProc("OpenSCManagerW")
	procOpenSvc     = modAdv.NewProc("OpenServiceW")
	procCloseHandle = modAdv.NewProc("CloseServiceHandle")
	procStartSvc    = modAdv.NewProc("StartServiceW")
	procCtrlSvc     = modAdv.NewProc("ControlService")
	procQueryCfg     = modAdv.NewProc("QueryServiceConfigW")
	procQueryCfgSec  = modSec.NewProc("QueryServiceConfigW")
	procQueryStat    = modAdv.NewProc("QueryServiceStatusEx")
	procQueryStatSec = modSec.NewProc("QueryServiceStatusEx")
	procQueryStatBas = modAdv.NewProc("QueryServiceStatus")
	procLoadLib      = syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW")
	procGetProcAddr  = syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcAddress")
	procFmtMsg       = syscall.NewLazyDLL("kernel32.dll").NewProc("FormatMessageW")
)

const (
	// 注意: 不能用 SERVICE_ALL_ACCESS / SC_MANAGER_ALL_ACCESS —— 服务的默认 SDDL 给
	// SYSTEM 的不是全权 (无 WRITE_DAC/WRITE_OWNER/DELETE), 请求全权会直接吃 ERROR_ACCESS_DENIED。
	// 这里只申请诊断需要的四项 + INTERROGATE。
	scManagerAccess = 0x0001 | 0x0004 | 0x0010 // CONNECT|ENUMERATE|QUERY_LOCK_STATUS
	serviceAccess   = 0x0001 | 0x0004 | 0x0010 | 0x0020 | 0x0080 // QUERY_CONFIG|QUERY_STATUS|START|STOP|INTERROGATE
	svcReadAccess   = 0x0001 | 0x0004 | 0x0080                   // 只读: 非管理员也能开(便于宿主机自测)
	srvControlStop  = 1
	stRunning       = 4

	ifStateNotReady  = 0
	// WLAN_INTERFACE_STATE (wlanapi.h, 官方): 0 not_ready, 1 connected, 2 adhoc_network_formed,
	// 3 disconnecting, 4 offline, 5 available, 6 auto_config, 7 connection_attempt, 8 reset,
	// 9 discovered_hidden_network, 10 hidden_network_transition.
	// 2026-10-13 实机定案: 之前写成 7(那是 connection_attempt!), 连接明明成功(state=1 且拿到
	// DHCP 192.168.0.100)却永远 TIMEOUT。面板一直按官方 1 判断, 所以它的绿点是对的。
	ifStateConnected = 1
)

func errText(err error) string {
	if err == nil {
		return "OK"
	}
	return err.Error()
}

func winErr(r uintptr) error {
	if r == 0 {
		return nil
	}
	return syscall.Errno(r)
}

// 把 Win32 错误码翻成人话 (SCM 常见几个)
func describe(err error) string {
	if err == nil {
		return "OK"
	}
	en, ok := err.(syscall.Errno)
	if !ok {
		return err.Error()
	}
	if en == 0 {
		return "0 OK"
	}
	names := map[syscall.Errno]string{
		5:    "ERROR_ACCESS_DENIED",
		1053: "ERROR_SERVICE_REQUEST_TIMEOUT(service did not answer SCM in time)",
		1056: "ERROR_SERVICE_ALREADY_RUNNING",
		1058: "ERROR_SERVICE_DISABLED",
		1060: "ERROR_SERVICE_DOES_NOT_EXIST",
		1061: "ERROR_SERVICE_CANNOT_ACCEPT_CTRL",
		1062: "ERROR_SERVICE_NOT_STARTED",
		1063: "ERROR_NOT_CONNECTED_TO_CONTROLLER",
		1067: "ERROR_PROCESS_ABORTED",
		1068: "ERROR_SERVICE_DEPENDENCY_FAIL",
		1069: "ERROR_SERVICE_LOGON_FAILURE",
		1072: "ERROR_SERVICE_MARKED_FOR_DELETE",
		1077: "ERROR_SERVICE_NEVER_STARTED",
		1079: "ERROR_DIFFERENT_SERVICE_ACCOUNT",
		1206: "ERROR_BAD_DB(profile xml rejected)",
		1721: "RPC_S_CALL_FAILED_DLL(wlansvc not serving)",
		1722: "RPC_S_SERVER_UNAVAILABLE(wlansvc not running)",
		1723: "RPC_S_OUT_OF_THREADS",
	}
	sysText := ""
	buf := make([]uint16, 1024)
	// FORMAT_MESSAGE_IGNORE_INSERTS(0x200) | FORMAT_MESSAGE_FROM_SYSTEM(0x1000)
	r, _, _ := procFmtMsg.Call(0x200|0x1000, 0, uintptr(uint32(en)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if r > 0 {
		sysText = strings.TrimSpace(syscall.UTF16ToString(buf))
	}
	// 名字表只是提示, 系统原文一定带上: 之前 1062 这类映射写错, 把人带偏了
	if s, ok := names[en]; ok {
		if sysText != "" && !strings.Contains(sysText, s) {
			return fmt.Sprintf("%d %s (%s)", int(en), s, sysText)
		}
		return fmt.Sprintf("%d %s", int(en), s)
	}
	if sysText != "" {
		return fmt.Sprintf("%d %s", int(en), sysText)
	}
	return fmt.Sprintf("%d errno", int(en))
}

type serviceStatusProcess struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessId               uint32
	ServiceFlags            uint32
}

type queryServiceConfig struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	_                uint32
	BinaryPathName   *uint16
	LoadOrderGroup   *uint16
	TagId            uint32
	_                uint32
	Dependencies     *uint16
	ServiceStartName *uint16
	DisplayName      *uint16
	Description      *uint16
}

// 双 null 结尾的 MULTI_SZ
func multiSz(p *uint16) []string {
	var out []string
	if p == nil {
		return out
	}
	buf := unsafe.Slice(p, 1<<16)
	cur := strings.Builder{}
	for _, c := range buf {
		if c == 0 {
			if cur.Len() == 0 {
				break
			}
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(rune(c))
	}
	return out
}

func openSCM() (syscall.Handle, error) {
	r, _, e := procOpenSCM.Call(0, 0, scManagerAccess)
	if r == 0 {
		return 0, e
	}
	return syscall.Handle(r), nil
}

func openService(scm syscall.Handle, name string, want uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	r, _, e := procOpenSvc.Call(uintptr(scm), uintptr(unsafe.Pointer(p)), uintptr(want))
	if r == 0 {
		return 0, e
	}
	return syscall.Handle(r), nil
}

func queryStatus(svc syscall.Handle) (serviceStatusProcess, error) {
	var st serviceStatusProcess
	var needed uint32
	r, _, e := procQueryStat.Call(uintptr(svc), uintptr(unsafe.Pointer(&st)), unsafe.Sizeof(st), uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return st, e
	}
	return st, nil
}

// SCM 状态: advapi32 的 Ex 版在 Win10+ 是转发到 sechost 的桩, PE 里可能回 124/1783,
// 所以三级降级 —— Ex(advapi) -> Ex(sechost) -> 基础 QueryServiceStatus(没有 ProcessId, 但状态和退出码一定拿得到)。
func statusAny(svc syscall.Handle) (serviceStatusProcess, string, error) {
	var st serviceStatusProcess
	var needed uint32
	cb := unsafe.Sizeof(st)
	r, _, e := procQueryStat.Call(uintptr(svc), uintptr(unsafe.Pointer(&st)), cb, uintptr(unsafe.Pointer(&needed)))
	if r != 0 {
		return st, "QueryServiceStatusEx", nil
	}
	firstErr := e
	r2, _, e2 := procQueryStatSec.Call(uintptr(svc), uintptr(unsafe.Pointer(&st)), cb, uintptr(unsafe.Pointer(&needed)))
	if r2 != 0 {
		return st, "QueryServiceStatusEx(sechost)", nil
	}
	var bs serviceStatusProcess
	r3, _, e3 := procQueryStatBas.Call(uintptr(svc), uintptr(unsafe.Pointer(&bs)))
	if r3 != 0 {
		bs.ProcessId = 0 // 基础版没有 pid 字段
		return bs, "QueryServiceStatus(basic)", nil
	}
	_ = firstErr
	_ = e2
	return st, "", fmt.Errorf("Ex:%s / ExSec:%s / Basic:%s", describe(firstErr), describe(e2), describe(e3))
}

func queryConfig(svc syscall.Handle) (queryServiceConfig, error) {
	var cfg queryServiceConfig
	buf := make([]byte, 16384)
	var needed uint32
	// pcbBytesNeeded 不能传 NULL, 否则直接返回 487 ERROR_INVALID_ADDRESS
	r, _, e := procQueryCfg.Call(uintptr(svc), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		// advapi32 的服务 API 在 Win10+ 是转发到 sechost.dll 的, 某些环境里转发桩会回 RPC_X_BAD_STUB_DATA(1783),
		// 再用 sechost 的实现试一次, 拿回来的数据是同一个结构。
		r2, _, e2 := procQueryCfgSec.Call(uintptr(svc), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed)))
		if r2 == 0 {
			if e2 != nil {
				return cfg, e2
			}
			return cfg, e
		}
		r = r2
	}
	ptr := (*queryServiceConfig)(unsafe.Pointer(&buf[0]))
	*(&cfg) = *ptr
	return cfg, nil
}

var stateNames = map[uint32]string{1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"}

// Go 1.22 起 syscall 不再导出注册表函数, 而 x/sys 需要联网取模块, 所以直接调 advapi32 的三个注册表 API。
type regKey uintptr

func regOpen(parent uintptr, path string) (regKey, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h uintptr
	r, _, e := procRegOpen.Call(parent, uintptr(unsafe.Pointer(p)), 0, uintptr(regSamRead), uintptr(unsafe.Pointer(&h)))
	if r != 0 {
		return 0, fmt.Errorf("%s", describe(syscall.Errno(r)))
	}
	_ = e
	return regKey(h), nil
}

func (k regKey) close() {
	if k != 0 {
		procRegClose.Call(uintptr(k))
	}
}

type regValue struct {
	Kind  uint32
	S     string
	DW    uint32
	Multi []string
}

func (k regKey) query(name string) (regValue, error) {
	var out regValue
	p, e := syscall.UTF16PtrFromString(name)
	if e != nil {
		return out, e
	}
	buf := make([]byte, 8192)
	cb := uint32(len(buf))
	var typ uint32
	r, _, _ := procRegQuery.Call(uintptr(k), uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&cb)))
	if r != 0 {
		return out, fmt.Errorf("%s", describe(syscall.Errno(r)))
	}
	out.Kind = typ
	// 字节数 -> UTF-16 单元数(奇数截掉半个字符)
	n := int(cb)
	if n%2 == 1 {
		n--
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), n/2)
	switch typ {
	case 4: // REG_DWORD
		out.DW = uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	case 1, 2: // REG_SZ / REG_EXPAND_SZ
		out.S = strings.TrimRight(syscall.UTF16ToString(u), "\x00")
	case 7: // REG_MULTI_SZ (不是 6, 6 是 REG_LINK): 不能交给 UTF16ToString(它在第一个 NUL 就停), 自己按 NUL 切: 不能交给 UTF16ToString(它在第一个 NUL 就停), 自己按 NUL 切
		var cur []uint16
		for _, c := range u {
			if c == 0 {
				if len(cur) > 0 {
					out.Multi = append(out.Multi, syscall.UTF16ToString(cur))
					cur = nil
				}
				continue
			}
			cur = append(cur, c)
		}
		if len(cur) > 0 {
			out.Multi = append(out.Multi, syscall.UTF16ToString(cur))
		}
	default:
		return out, fmt.Errorf("unsupported reg type %d", typ)
	}
	return out, nil
}

// PE 里 QueryServiceConfigW(advapi 与 sechost 两份都试过)会吃 1783 桩错误,
// 但服务配置本身就在注册表里, 直接读键既稳又能看出"烘焙进去的到底是什么"。
type svcRegInfo struct {
	Type    uint32
	Start   uint32
	Errctl  uint32
	Group   string
	Image   string
	Account string
	Deps    []string
	Dll     string
	Main    string
}

func regSvc(name string) (svcRegInfo, error) {
	var out svcRegInfo
	k, err := regOpen(hklm, `SYSTEM\CurrentControlSet\Services\`+name)
	if err != nil {
		return out, err
	}
	defer k.close()
	dw := func(vn string) uint32 { v, _ := k.query(vn); return v.DW }
	sr := func(vn string) string { v, _ := k.query(vn); return v.S }
	mz := func(vn string) []string { v, _ := k.query(vn); return v.Multi }
	out.Type = dw("Type")
	out.Start = dw("Start")
	out.Errctl = dw("ErrorControl")
	out.Group = sr("Group")
	out.Image = sr("ImagePath")
	out.Account = sr("ObjectName")
	out.Deps = mz("DependOnService")
	if pk, e := regOpen(uintptr(k), "Parameters"); e == nil {
		out.Dll = sr2(pk, "ServiceDll")
		out.Main = sr2(pk, "ServiceMain")
		pk.close()
	}
	return out, nil
}

func sr2(k regKey, vn string) string { v, _ := k.query(vn); return v.S }

func printRegInfo(name string, ri svcRegInfo, pad string) {
	fmt.Printf("%s%s: reg type=%d start=%d errctl=%d group=%s acct=%s\n", pad, name, ri.Type, ri.Start, ri.Errctl, ri.Group, ri.Account)
	fmt.Printf("%s   image=%s\n", pad, ri.Image)
	fmt.Printf("%s   deps=[%s] dll=%s main=%s\n", pad, strings.Join(ri.Deps, ","), ri.Dll, ri.Main)
}

func svcInfo(name string) error {
	ri, rerr := regSvc(name)
	if rerr != nil {
		fmt.Printf("  注册表里没有服务键 %s: %s\n", name, describe(rerr))
	} else {
		printRegInfo(name, ri, "  ")
	}
	scm, err := openSCM()
	if err != nil {
		return fmt.Errorf("OpenSCManager: %s", describe(err))
	}
	defer procCloseHandle.Call(uintptr(scm))
	svc, err := openService(scm, name, svcReadAccess)
	if err != nil {
		return fmt.Errorf("OpenService(%s): %s", name, describe(err))
	}
	defer procCloseHandle.Call(uintptr(svc))
	st, via, stErr := statusAny(svc)
	fmt.Printf("  state=%s(%d) pid=%d exit=%d(0x%X) specific=%d checkpoint=%d waithint=%d via=%s\n",
		stateNames[st.CurrentState], st.CurrentState, st.ProcessId, st.Win32ExitCode, st.Win32ExitCode,
		st.ServiceSpecificExitCode, st.CheckPoint, st.WaitHint, via)
	if stErr != nil {
		fmt.Println("  QueryServiceStatus: " + describe(stErr))
	}
	if cfg, err := queryConfig(svc); err == nil {
		fmt.Printf("  scm: type=%d start=%d deps=[%s] bin=%s\n",
			cfg.ServiceType, cfg.StartType, strings.Join(multiSz(cfg.Dependencies), ","), u16(cfg.BinaryPathName))
	}
	return nil
}

func u16(p *uint16) string {
	if p == nil {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice(p, 1<<16))
}

// 递归把依赖链的状态打出来 —— 1068 到底是哪个依赖没起来, 一眼看清
func svcDeps(name string, depth int, seen map[string]bool) {
	if depth > 6 || seen[name] {
		return
	}
	seen[name] = true
	pad := strings.Repeat("  ", depth)
	ri, rerr := regSvc(name)
	if rerr != nil {
		fmt.Printf("%s%s: 注册表没有这个服务键(%s)\n", pad, name, describe(rerr))
		return
	}
	scm, err := openSCM()
	if err != nil {
		fmt.Printf("%s%s: deps=[%s] dll=%s main=%s  (OpenSCManager %s)\n", pad, name,
			strings.Join(ri.Deps, ","), ri.Dll, ri.Main, describe(err))
		return
	}
	defer procCloseHandle.Call(uintptr(scm))
	var st serviceStatusProcess
	via := "-"
	if svc, err := openService(scm, name, svcReadAccess); err == nil {
		st, via, _ = statusAny(svc)
		procCloseHandle.Call(uintptr(svc))
	} else {
		fmt.Printf("%s%s: OpenService %s\n", pad, name, describe(err))
	}
	fmt.Printf("%s%s: state=%s(%d) pid=%d exit=%d(0x%X) via=%s type=%d start=%d deps=[%s]%s\n", pad, name,
		stateNames[st.CurrentState], st.CurrentState, st.ProcessId, st.Win32ExitCode, st.Win32ExitCode, via,
		ri.Type, ri.Start, strings.Join(ri.Deps, ","), stateHintReg(ri, st))
	for _, d := range ri.Deps {
		svcDeps(d, depth+1, seen)
	}
}

// svchost 组名(如 LocalSystemNetworkRestricted)不是服务依赖, 但组里少一个成员会让整组起不来
func stateHintReg(ri svcRegInfo, st serviceStatusProcess) string {
	if ri.Type == 1 && st.CurrentState != stRunning {
		return " <- kernel driver, never RUNNING without matching device"
	}
	return ""
}

// 起服务并逐状态采样: 服务"启动成功后马上退出"时, 只有边启动边采样才抓得到过渡态和退出码
func svcWatch(name string, ms int, doStart bool) {
	scm, err := openSCM()
	if err != nil {
		fmt.Println("OpenSCManager: " + describe(err))
		return
	}
	defer procCloseHandle.Call(uintptr(scm))
	want := uint32(svcReadAccess)
	if doStart {
		want = serviceAccess
	}
	svc, err := openService(scm, name, want)
	if err != nil {
		fmt.Println("OpenService: " + describe(err))
		return
	}
	defer procCloseHandle.Call(uintptr(svc))
	if doStart {
		r, _, e := procStartSvc.Call(uintptr(svc), 0, 0)
		if r == 0 {
			fmt.Printf("StartService -> %s\n", describe(e))
		} else {
			fmt.Println("StartService -> 已接受")
		}
	}
	last := uint32(0xFFFFFFFF)
	t0 := time.Now()
	for time.Since(t0) < time.Duration(ms)*time.Millisecond {
		st, via, serr := statusAny(svc)
		if st.CurrentState != last || serr != nil {
			extra := ""
			if serr != nil {
				extra = " queryErr=" + describe(serr)
			}
			fmt.Printf("+%6dms state=%s(%d) pid=%d exit=%d(0x%X) specific=%d via=%s%s\n",
				time.Since(t0).Milliseconds(), stateNames[st.CurrentState], st.CurrentState, st.ProcessId,
				st.Win32ExitCode, st.Win32ExitCode, st.ServiceSpecificExitCode, via, extra)
			last = st.CurrentState
		}
		time.Sleep(20 * time.Millisecond)
	}
	st, _, _ := statusAny(svc)
	fmt.Printf("最终: state=%s(%d) pid=%d exit=%d(0x%X)\n", stateNames[st.CurrentState], st.CurrentState, st.ProcessId, st.Win32ExitCode, st.Win32ExitCode)
}

// 直接把服务 DLL 载入本进程: 是不是"模块/导出找不到/不是有效程序"这类加载失败, 一条命令就能分清
func dllLoad(path, export string) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		fmt.Println("bad path: " + err.Error())
		return
	}
	r, _, e := procLoadLib.Call(uintptr(unsafe.Pointer(p)), 0, 0)
	if r == 0 {
		fmt.Printf("LoadLibraryEx(%s) FAIL: %s\n", path, describe(e))
		return
	}
	fmt.Printf("LoadLibraryEx OK base=0x%X\n", r)
	if export != "" {
		// GetProcAddress 的名字参数是 ANSI(或 MAKEINTRESOURCE 序号), 不是 UTF-16 ——
		// 传 UTF16PtrFromString 的结果会让它对所有真存在的导出都回 127。
		nb := append([]byte(export), 0)
		a, _, e2 := procGetProcAddr.Call(r, uintptr(unsafe.Pointer(&nb[0])))
		if a == 0 {
			fmt.Printf("GetProcAddress(%s) FAIL: %s\n", export, describe(e2))
		} else {
			fmt.Printf("GetProcAddress(%s) OK 0x%X\n", export, a)
		}
	}
}

// type=1 的内核驱动只有在对应设备存在时才会 RUNNING, 依赖它就等于赌硬件在场
func stateHint(cfg queryServiceConfig, st serviceStatusProcess, err error) string {
	if err != nil {
		return " (config 读不到)"
	}
	if cfg.ServiceType == 1 && st.CurrentState != stRunning {
		return " <- kernel driver, never RUNNING without matching device"
	}
	return fmt.Sprintf(" type=%d start=%d", cfg.ServiceType, cfg.StartType)
}

func svcStart(name string) error {
	scm, err := openSCM()
	if err != nil {
		return err
	}
	defer procCloseHandle.Call(uintptr(scm))
	svc, err := openService(scm, name, serviceAccess)
	if err != nil {
		return err
	}
	defer procCloseHandle.Call(uintptr(svc))
	r, _, e := procStartSvc.Call(uintptr(svc), 0, 0)
	if r == 0 {
		return e
	}
	return nil
}

func svcStop(name string) error {
	scm, err := openSCM()
	if err != nil {
		return err
	}
	defer procCloseHandle.Call(uintptr(scm))
	svc, err := openService(scm, name, serviceAccess)
	if err != nil {
		return err
	}
	defer procCloseHandle.Call(uintptr(svc))
	var st serviceStatusProcess
	r, _, e := procCtrlSvc.Call(uintptr(svc), srvControlStop, uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return e
	}
	return nil
}

// ---------- wlanapi ----------

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (g guid) String() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

type wlanInterfaceInfo struct {
	Guid        guid
	Description [256]uint16
	State       uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
	Items         [1]wlanInterfaceInfo
}

// DOT11_SSID: ULONG Length + UCHAR[32]
type dot11Ssid struct {
	Length uint32
	Ssid   [32]byte
}

// C 里 BOOLEAN 是 1 字节后接 4 字节对齐的枚举, 必须显式补 padding, 否则偏移全错。
// 实测(宿主机 hexdump)stride=628: ProfileName 0, Ssid 512, BssType 548, NumberOfBssids 552,
// NetworkConnectable 556, NotConnectableReason 560, NumberOfPhyTypes 564, PhyTypes 568,
// MorePhyTypes 600, SignalQuality 604, SecurityEnabled 608, Auth 612, Cipher 616, Flags 620, Reserved 624
type wlanAvailableNetwork struct {
	ProfileName            [256]uint16
	Ssid                   dot11Ssid
	BssType                uint32
	NumberOfBssids         uint32
	NetworkConnectable     byte
	_                      [3]byte
	NotConnectableReason   uint32
	NumberOfPhyTypes       uint32
	PhyTypes               [8]uint32
	MorePhyTypes           byte
	_                      [3]byte
	SignalQuality          uint32
	SecurityEnabled        byte
	_                      [3]byte
	DefaultAuthAlgorithm   uint32
	DefaultCipherAlgorithm uint32
	Flags                  uint32
	Reserved               uint32
}

type wlanAvailableNetworkList struct {
	NumberOfItems uint32
	Index         uint32
	Items         [1]wlanAvailableNetwork
}

type wlanConnectionParameters struct {
	Mode         uint32
	_            uint32
	Profile      *uint16
	Ssid         unsafe.Pointer
	DesiredBssid unsafe.Pointer
	BssType      uint32
	Flags        uint32
}

func wlanOpen() (syscall.Handle, uint32, error) {
	if err := modWlan.Load(); err != nil {
		return 0, 0, fmt.Errorf("load wlanapi.dll failed: %v", err)
	}
	var negotiated uint32
	var h uintptr
	r, _, _ := procOpen.Call(2, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&h)))
	if r != 0 {
		return 0, 0, fmt.Errorf("WlanOpenHandle: %s", describe(winErr(r)))
	}
	return syscall.Handle(h), negotiated, nil
}

func wlanIfList(h syscall.Handle) ([]wlanInterfaceInfo, error) {
	var p uintptr
	r, _, _ := procEnumIf.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&p)))
	if r != 0 {
		return nil, fmt.Errorf("WlanEnumInterfaces: %s", describe(winErr(r)))
	}
	defer procFree.Call(p)
	list := (*wlanInterfaceInfoList)(unsafe.Pointer(p))
	n := int(list.NumberOfItems)
	stride := unsafe.Sizeof(list.Items[0])
	base := uintptr(unsafe.Pointer(&list.Items[0]))
	out := make([]wlanInterfaceInfo, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, *(*wlanInterfaceInfo)(unsafe.Pointer(base + uintptr(i)*stride)))
	}
	return out, nil
}

func ssidString(s dot11Ssid) string {
	n := int(s.Length)
	if n > 32 {
		n = 32
	}
	return string(s.Ssid[:n])
}

const profileXml = `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>%s</name>
	<SSIDConfig><SSID><hex>%s</hex><name>%s</name></SSID></SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM><security><authEncryption><authentication>%s</authentication><encryption>%s</encryption><useOneX>false</useOneX></authEncryption>%s</security></MSM>
</WLANProfile>`

func buildProfile(ssid, key string) string {
	e := xmlEscape(ssid)
	// <hex> is the SSID's raw byte string (UTF-8 for non-ASCII) in uppercase hex.
	// WlanSetProfile tolerates name-only SSIDConfig, but WlanConnect then fails:
	// mode=profile -> 1206 "profile corrupted", mode=temporary -> 87 (host-measured 2026-10-13).
	// netsh-generated profiles always carry <hex>; match them.
	hx := strings.ToUpper(hex.EncodeToString([]byte(ssid)))
	auth, cipher, shared := "WPA2PSK", "AES", ""
	if key == "" {
		auth, cipher = "open", "none"
	} else {
		shared = "<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>" + xmlEscape(key) + "</keyMaterial></sharedKey>"
	}
	return fmt.Sprintf(profileXml, e, hx, e, auth, cipher, shared)
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func ifStateName(s uint32) string {
	// 官方 WLAN_INTERFACE_STATE 名称(2026-10-13 纠正: 之前整张表是错位的枚举)
	switch s {
	case 0:
		return "not_ready"
	case 1:
		return "connected"
	case 2:
		return "adhoc_network_formed"
	case 3:
		return "disconnecting"
	case 4:
		return "offline"
	case 5:
		return "available"
	case 6:
		return "auto_config"
	case 7:
		return "connection_attempt"
	case 8:
		return "reset"
	case 9:
		return "discovered_hidden"
	case 10:
		return "hidden_transition"
	}
	return "state" + strconv.Itoa(int(s))
}

func cmdStatus() int {
	h, ver, err := wlanOpen()
	if err != nil {
		fmt.Println("FAIL " + err.Error())
		fmt.Println("HINT if wlansvc is down WlanOpenHandle returns 1722/1723; run: wifi.exe deps wlansvc")
		return 1
	}
	defer procClose.Call(uintptr(h), 0)
	fmt.Printf("WlanOpenHandle OK negotiated=%d\n", ver)
	list, err := wlanIfList(h)
	if err != nil {
		fmt.Println("FAIL " + err.Error())
		return 1
	}
	fmt.Printf("interfaces=%d\n", len(list))
	for _, it := range list {
		fmt.Printf("  %s state=%d(%s) desc=%s\n", it.Guid.String(), it.State, ifStateName(it.State), syscall.UTF16ToString(it.Description[:]))
	}
	if len(list) == 0 {
		fmt.Println("HINT wlansvc OK but zero interface: this NIC's driver is not in the image, needs dism /Add-Driver with vendor INF")
	}
	return 0
}

func cmdScan() int {
	h, _, err := wlanOpen()
	if err != nil {
		fmt.Println("FAIL " + err.Error())
		return 1
	}
	defer procClose.Call(uintptr(h), 0)
	list, err := wlanIfList(h)
	if err != nil || len(list) == 0 {
		fmt.Printf("interfaces=%d err=%s\n", len(list), errText(err))
		return 1
	}
	g := list[0].Guid
	var p uintptr
	r, _, _ := procNetList.Call(uintptr(h), uintptr(unsafe.Pointer(&g)), 0, 0, uintptr(unsafe.Pointer(&p)))
	if r != 0 {
		fmt.Println("FAIL WlanGetAvailableNetworkList: " + describe(winErr(r)))
		return 1
	}
	defer procFree.Call(p)
	l := (*wlanAvailableNetworkList)(unsafe.Pointer(p))
	stride := unsafe.Sizeof(l.Items[0])
	if stride != 628 {
		fmt.Printf("BUG struct stride=%d (host-measured 628)\n", stride)
		return 1
	}
	base := uintptr(unsafe.Pointer(&l.Items[0]))
	fmt.Printf("networks=%d\n", l.NumberOfItems)
	for i := 0; i < int(l.NumberOfItems); i++ {
		n := *(*wlanAvailableNetwork)(unsafe.Pointer(base + uintptr(i)*stride))
		fmt.Printf("  %-32s prof=%-32s bss=%d sig=%3d%% sec=%d auth=%d cipher=%d conn=%d reason=%d flags=0x%X\n",
			ssidString(n.Ssid), syscall.UTF16ToString(n.ProfileName[:]), n.BssType, n.SignalQuality,
			n.SecurityEnabled, n.DefaultAuthAlgorithm, n.DefaultCipherAlgorithm,
			n.NetworkConnectable, n.NotConnectableReason, n.Flags)
	}
	return 0
}

func cmdConnect(ssid, key string, temp bool, mode uint32) int {
	h, _, err := wlanOpen()
	if err != nil {
		fmt.Println("FAIL " + err.Error())
		return 1
	}
	defer procClose.Call(uintptr(h), 0)
	list, err := wlanIfList(h)
	if err != nil || len(list) == 0 {
		fmt.Printf("interfaces=%d err=%s\n", len(list), errText(err))
		return 1
	}
	g := list[0].Guid
	xmlStr := buildProfile(ssid, key)
	xp, err := syscall.UTF16PtrFromString(xmlStr)
	if err != nil {
		fmt.Println("FAIL " + err.Error())
		return 1
	}
	np, _ := syscall.UTF16PtrFromString(ssid)

	var reason uint32
	r, _, _ := procSetProf.Call(uintptr(h), uintptr(unsafe.Pointer(&g)), 0, uintptr(unsafe.Pointer(xp)), 0, 1, 0, uintptr(unsafe.Pointer(&reason)))
	if r != 0 && !temp {
		fmt.Println("FAIL WlanSetProfile: " + describe(winErr(r)) + " reason=" + strconv.Itoa(int(reason)))
		fmt.Println("HINT 1206/reason=0x80001 = profile xml rejected by the schema (2026-10-13: was <MSSecurity>, must be <MSM><security>); also check WPA2PSK/WPAPSK/open matches the AP")
		return 1
	}
	if r != 0 {
		fmt.Println("WARN WlanSetProfile: " + describe(winErr(r)) + " (continuing with temporary profile)")
	} else {
		fmt.Printf("WlanSetProfile OK (profile=%s)\n", ssid)
	}

	profName := np
	params := wlanConnectionParameters{Mode: mode, Profile: profName, BssType: 1}
	if temp {
		params.Mode = 1 // wlan_connection_mode_temporary_profile=1: strProfile 放 XML 本身 (不是 2!)
		params.Profile = xp
	}
	r, _, _ = procConnect.Call(uintptr(h), uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(&params)), 0)
	if r != 0 {
		fmt.Println("FAIL WlanConnect: " + describe(winErr(r)))
		return 1
	}
	fmt.Println("WlanConnect submitted, polling interface state...")
	last := -1
	for i := 0; i < 40; i++ { // 40*1.5s=60s: 实机 AX211 关联+DHCP 慢的时候 30 秒不够
		time.Sleep(1500 * time.Millisecond)
		l2, err := wlanIfList(h)
		if err == nil && len(l2) > 0 {
			last = int(l2[0].State)
			if l2[0].State == ifStateConnected {
				fmt.Printf("CONNECTED (poll %d)\n", i+1)
				fmt.Println("next: ipconfig /renew")
				return 0
			}
		}
	}
	fmt.Printf("TIMEOUT still not connected after 40 polls (last state=%d %s)\n", last, ifStateName(uint32(last)))
	fmt.Println("HINT wrong passphrase / auth mismatch keeps the interface in not_ready; check auth value with: wifi.exe scan")
	return 1
}

func cmdDisconnect() int {
	h, _, err := wlanOpen()
	if err != nil {
		fmt.Println("FAIL " + err.Error())
		return 1
	}
	defer procClose.Call(uintptr(h), 0)
	list, err := wlanIfList(h)
	if err != nil || len(list) == 0 {
		fmt.Printf("interfaces=%d err=%s\n", len(list), errText(err))
		return 1
	}
	g := list[0].Guid
	r, _, _ := procDisc.Call(uintptr(h), uintptr(unsafe.Pointer(&g)), 0)
	if r != 0 {
		fmt.Println("FAIL WlanDisconnect: " + describe(winErr(r)))
		return 1
	}
	fmt.Println("DISCONNECTED")
	return 0
}

func usage() {
	fmt.Println(`wifi.exe -- WinPE WiFi tool (direct wlanapi/advapi32 syscalls)
  wifi status                   open wlanapi, list wireless interfaces
  wifi scan                     list visible networks (ssid/signal/auth)
  wifi connect <SSID> <key>     write profile and connect (--temp uses temporary profile, --mode=N)
  wifi disconnect
  wifi svc info <name>          registry-baked config + SCM state (state/pid/win32exit)
  wifi svc start <name>
  wifi svc stop  <name>
  wifi svc watch <name> [ms] [start]
                                sample state every 20ms (catch "started then exited" transitions)
  wifi deps <name>              recursive dependency chain with each link's state (diagnose 1068)
  wifi dllload <dll> [export]   LoadLibraryEx + GetProcAddress (module/entry problems show up here)
  wifi regq <HKLM-subkey> <value>  raw registry read (what actually got baked into the image)`)
}

func main() {
	a := os.Args[1:]
	if len(a) == 0 {
		usage()
		os.Exit(2)
	}
	switch a[0] {
	case "status":
		os.Exit(cmdStatus())
	case "scan":
		os.Exit(cmdScan())
	case "disconnect":
		os.Exit(cmdDisconnect())
	case "connect":
		if len(a) < 2 {
			usage()
			os.Exit(2)
		}
		ssid := a[1]
		key := ""
		if len(a) >= 3 {
			key = a[2]
		}
		temp := false
		mode := uint32(0) // wlan_connection_mode_profile=0 (wlanapi.h: profile=0, temporary_profile=1, discovery_secure=2)
		for _, x := range a[3:] {
			if x == "--temp" {
				temp = true
			}
			if strings.HasPrefix(x, "--mode=") {
				v, _ := strconv.Atoi(x[7:])
				mode = uint32(v)
			}
		}
		os.Exit(cmdConnect(ssid, key, temp, mode))
	case "svc":
		if len(a) < 3 {
			usage()
			os.Exit(2)
		}
		name := a[2]
		switch a[1] {
		case "info":
			if err := svcInfo(name); err != nil {
				fmt.Println("FAIL " + err.Error())
				os.Exit(1)
			}
			os.Exit(0)
		case "watch":
			ms := 6000
			start := false
			if len(a) >= 4 {
				if v, err := strconv.Atoi(a[3]); err == nil {
					ms = v
				}
			}
			if len(a) >= 5 && a[4] == "start" {
				start = true
			}
			svcWatch(name, ms, start)
			os.Exit(0)
		case "start":
			if err := svcStart(name); err != nil {
				fmt.Println("FAIL StartService " + describe(err))
				os.Exit(1)
			}
			fmt.Println("StartService OK")
			os.Exit(0)
		case "stop":
			if err := svcStop(name); err != nil {
				fmt.Println("FAIL ControlService " + describe(err))
				os.Exit(1)
			}
			fmt.Println("ControlService(STOP) OK")
			os.Exit(0)
		default:
			usage()
			os.Exit(2)
		}
	case "deps":
		if len(a) < 2 {
			usage()
			os.Exit(2)
		}
		svcDeps(a[1], 0, map[string]bool{})
		os.Exit(0)
	case "dllload":
		if len(a) < 2 {
			usage()
			os.Exit(2)
		}
		exp := ""
		if len(a) >= 3 {
			exp = a[2]
		}
		dllLoad(a[1], exp)
		os.Exit(0)
	case "regq":
		// wifi regq <HKLM相对子键> <值名>   —— 直接看烘焙进镜像的原始值(类型+内容)
		if len(a) < 3 {
			usage()
			os.Exit(2)
		}
		k, err := regOpen(hklm, a[1])
		if err != nil {
			fmt.Printf("OpenKey(%s) FAIL %s\n", a[1], describe(err))
			os.Exit(1)
		}
		defer k.close()
		v, err := k.query(a[2])
		if err != nil {
			fmt.Printf("QueryValue(%s\\%s) FAIL %s\n", a[1], a[2], describe(err))
			os.Exit(1)
		}
		switch {
		case len(v.Multi) > 0:
			fmt.Printf("%s = MULTI_SZ(kind=%d) [%s]\n", a[2], v.Kind, strings.Join(v.Multi, ","))
		case v.Kind == 4:
			fmt.Printf("%s = DWORD %d(0x%X)\n", a[2], v.DW, v.DW)
		default:
			fmt.Printf("%s = SZ(kind=%d) <%s>\n", a[2], v.Kind, v.S)
		}
		os.Exit(0)
	default:
		usage()
		os.Exit(2)
	}
}
