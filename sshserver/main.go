// pe-sshd: 面向 WinPE 的极简 SSH 服务端。
// Win32-OpenSSH 的 privsep 子进程在 WinPE 里必然 0xC0000142(实机十四轮验证),
// 它依赖 Windows 账号/LSA/令牌分离; 这里只保留 SSH 协议本身: 静态编译, 公钥认证, 直接起 cmd。
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	addr      = flag.String("addr", "0.0.0.0:22", "监听地址")
	hostKeyF  = flag.String("hostkey", `X:\SSH\pe_host_ed25519`, "主机密钥文件, 不存在则生成")
	authKeyF  = flag.String("authkeys", `X:\SSH\authorized_keys`, "允许的公钥列表(ssh authorized_keys 格式)")
	shellExe  = flag.String("shell", `X:\Windows\System32\cmd.exe`, "默认 shell")
	logF      = flag.String("log", `X:\sshd.log`, "日志文件")
	clientVer = flag.String("version", "SSH-2.0-pe-sshd_1.0", "对外的软件版本串")
	emptyOK   = flag.Bool("empty", true, "允许空密码/无凭证登录(救援盘默认); 关掉用 -empty=false")
	pass      = flag.String("pass", "", "附加口令; 非空时空密码不再被接受, 只能用这把口令或授权公钥")
)

type keyring struct {
	mu   sync.RWMutex
	keys [][]byte
	path string
}

func (kr *keyring) reload() int {
	data, err := os.ReadFile(kr.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("authkeys 读取失败 %s: %v", kr.path, err)
		}
		return 0
	}
	var out [][]byte
	rest := data
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		line := rest
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line, rest = line[:i], rest[i+1:]
		} else {
			rest = nil
		}
		if len(bytes.TrimSpace(line)) == 0 || bytes.HasPrefix(bytes.TrimSpace(line), []byte("#")) {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			log.Printf("忽略无法解析的公钥行: %v", err)
			continue
		}
		out = append(out, pk.Marshal())
	}
	kr.mu.Lock()
	kr.keys = out
	kr.mu.Unlock()
	return len(out)
}

func (kr *keyring) match(pub []byte) bool {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	for _, k := range kr.keys {
		if bytes.Equal(k, pub) {
			return true
		}
	}
	return false
}

func loadOrMakeHostKey(path string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("主机密钥 %s 解析失败: %w", path, err)
		}
		return signer, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "pe-sshd@winpe")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	log.Printf("已生成主机密钥 %s", path)
	return signer, nil
}

func peEnv(user string) []string {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `X:\Windows`
	}
	drive := filepath.VolumeName(sysroot)
	if drive == "" {
		drive = "X:"
	}
	return []string{
		"SystemRoot=" + sysroot,
		"windir=" + sysroot,
		"COMSPEC=" + sysroot + `\System32\cmd.exe`,
		"PATH=" + sysroot + `\System32;` + sysroot + `;` + drive + `\OpenSSH;` + drive + `\SSH`,
		"PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.JS;.MSC",
		"TEMP=" + drive + `\`,
		"TMP=" + drive + `\`,
		"USERPROFILE=" + drive + `\Users\Default`,
		"HOMEDRIVE=" + drive + `\`,
		"HOMEPATH=" + `\Users\Default`,
		"USERNAME=" + user,
		"USERDOMAIN=WINPE",
		"OS=Windows_NT",
		"COMPUTERNAME=WINPE",
		"PROCESSOR_ARCHITECTURE=AMD64",
		"SSHDIR=" + drive + `\SSH`,
	}
}

func runCommand(user, cmdline string, stdin io.Reader, stdout, stderr io.Writer, done chan<- error) {
	var cmd *exec.Cmd
	if strings.TrimSpace(cmdline) == "" {
		cmd = exec.Command(*shellExe)
	} else {
		cmd = exec.Command(*shellExe, "/c", cmdline)
	}
	cmd.Env = peEnv(user)
	cmd.Dir = filepath.VolumeName(os.Getenv("SystemRoot")) + `\`
	if len(cmd.Dir) < 3 {
		cmd.Dir = `X:\`
	}
	// 必须用 StdinPipe: 赋给 Cmd.Stdin 的话 Go 会自己起一个拷贝协程, Wait() 要等它 EOF,
	// 而通道的读端在交互会话里永远不会关 —— 命令跑完了 Wait 也不返回, 客户端就挂死。
	if stdin != nil {
		if w, err := cmd.StdinPipe(); err == nil {
			go io.Copy(w, stdin)
		}
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	log.Printf("会话开始: user=%s cmd=%q", user, cmdline)
	if err := cmd.Start(); err != nil {
		done <- err
		return
	}
	done <- cmd.Wait()
}

// ---------- 最小终端行规范(line discipline) ----------
// PE 里没有真控制台, cmd.exe 的 stdin 是管道: 它只认以 \n/\r\n 结尾的行, 而且会把读到的整行
// 连同提示符再打印一遍(这也是为什么服务端不能等到"有回显"才动手)。客户端一旦申请 pty 就会把
// 本地终端切成 raw 模式、关掉本地回显, 回车发的是裸 \r —— 服务端不转换时 cmd 永远等不到行尾,
// 用户看到的就是"连上了但敲什么都没反应"(2026-10-05 test\ssh_cr_test.ps1 对比 CRLF/裸CR/LF:
// 只有裸 CR 那一路超时, 证明断点就在这)。所以 pty 会话这层必须由我们补上:
// 收行 + 实时回显 + 退格 + Ctrl-C/Ctrl-D + 吞掉方向键转义序列, 输出补齐 \r。
type tty struct {
	out        io.Writer // 回显写给客户端
	dst        io.Writer // 行写给子进程 stdin
	closeChild func() error // Ctrl-D(空行)时给它 EOF, 让 cmd 自己退出
	buf        []byte
	esc        int // >0 表示正在吞 ESC 转义序列的方向键/功能键
}

func (t *tty) echo(s string) { io.WriteString(t.out, s) }

func (t *tty) feed(c byte) {
	if t.esc > 0 { // ESC [ A 这类序列: cmd 从管道读到只会变成乱码, 直接丢弃
		t.esc--
		if c >= 0x40 && c <= 0x7E && c != '[' {
			t.esc = 0
		}
		return
	}
	switch {
	case c == 0x1B:
		t.esc = 16
	case c == '\r' || c == '\n':
		line := append(append(make([]byte, 0, len(t.buf)+1), t.buf...), '\n')
		t.buf = t.buf[:0]
		// 先抹掉我们实时回显的这行, 再交给 cmd —— cmd 会把它自己那行"提示符+命令"重打一遍,
		// 于是屏幕上只有一行, 不会出现重复。(客户端 ssh 已开 VT 模式, ESC[K 可用)
		t.echo("\r\x1b[K")
		t.dst.Write(line)
	case c == 0x08 || c == 0x7F:
		if len(t.buf) > 0 {
			t.buf = t.buf[:len(t.buf)-1]
			t.echo("\b \b")
		}
	case c == 0x03: // Ctrl-C: 管道里的 cmd 收不到信号, 就当"丢弃当前输入行"
		t.buf = t.buf[:0]
		t.echo("^C\r\n")
	case c == 0x04: // Ctrl-D: 空行时等价 EOF
		if len(t.buf) == 0 {
			t.echo("\r\n")
			t.closeChild()
		}
	default:
		if c < 0x20 && c != '\t' {
			return
		}
		t.buf = append(t.buf, c)
		if c == '\t' {
			t.echo("\t")
		} else {
			t.out.Write([]byte{c})
		}
	}
}

// pumpTTY 逐字节读客户端输入。必须逐字节: 一次 Read 里可能混着"半行 + 回车 + 下一行的开头"。
func pumpTTY(r io.Reader, t *tty) {
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		for i := 0; i < n; i++ {
			t.feed(b[i])
		}
		if err != nil {
			return
		}
	}
}

// crlfWriter 把裸 \n 补成 \r\n。pty 模式下 stdout/stderr 合并走它(和真终端一致), 所以要带锁。
type crlfWriter struct {
	mu   sync.Mutex
	w    io.Writer
	prev byte
}

func (c *crlfWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, 0, len(p)+8)
	for _, b := range p {
		if b == '\n' && c.prev != '\r' {
			out = append(out, '\r')
		}
		out = append(out, b)
		c.prev = b
	}
	if len(out) > 0 {
		if _, err := c.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func handleConn(nConn net.Conn, cfg *ssh.ServerConfig) {
	remote := nConn.RemoteAddr().String()
	defer nConn.Close()
	conn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		log.Printf("握手失败 %s: %v", remote, err)
		return
	}
	defer conn.Close()
	log.Printf("已连接 %s user=%s client=%q", remote, conn.User(), string(conn.ClientVersion()))

	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			log.Printf("拒绝通道类型 %s (仅支持 session)", newChan.ChannelType())
			newChan.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			log.Printf("通道建立失败: %v", err)
			continue
		}
		wg.Add(1)
		go func(ch ssh.Channel, chReqs <-chan *ssh.Request) {
			defer wg.Done()
			defer ch.Close()
			serveSession(ch, chReqs, conn.User())
		}(ch, chReqs)
	}
	wg.Wait()
	log.Printf("会话结束 %s", remote)
}

func serveSession(ch ssh.Channel, chReqs <-chan *ssh.Request, user string) {
	var (
		mu      sync.Mutex
		started bool
		cmdline string
	)
	var (
		done           = make(chan error, 1)
		startedCh      = make(chan struct{})
		stdinR, stdinW = io.Pipe()
		ptyMode        bool
	)

	start := func() {
		mu.Lock()
		if started {
			mu.Unlock()
			return
		}
		started = true
		isPty := ptyMode
		close(startedCh)
		mu.Unlock()
		outW, errW := io.Writer(ch), io.Writer(ch.Stderr())
		if isPty {
			// pty 模式下 stdout/stderr 合并成一路(真终端就是这样), 顺便补 \r
			tw := &crlfWriter{w: ch}
			outW, errW = tw, tw
		}
		go runCommand(user, cmdline, stdinR, outW, errW, done)
	}

	// 输入通路要等 start() 之后才知道是不是 pty, 所以在这里接管; 期间客户端发的字节
	// 由 x/crypto 在通道内攒着, 不会丢。结束时给 cmd 一个 EOF, 否则用户一断线 cmd 就吊儿郎当地活着。
	go func() {
		<-startedCh
		mu.Lock()
		isPty := ptyMode
		mu.Unlock()
		if isPty {
			pumpTTY(ch, &tty{out: ch, dst: stdinW, closeChild: stdinW.Close})
		} else {
			io.Copy(stdinW, ch)
		}
		stdinW.Close()
	}()

	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		for req := range chReqs {
			switch req.Type {
			case "pty-req":
				// PE 里没有真控制台, 答应之后由本进程补一层行规范(见上面的 tty/pumpTTY)
				mu.Lock()
				ptyMode = true
				mu.Unlock()
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "shell":
				if req.WantReply {
					req.Reply(true, nil)
				}
				start()
			case "exec":
				var msg struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
					mu.Lock()
					cmdline = msg.Command
					mu.Unlock()
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
				start()
			case "env":
				if req.WantReply {
					req.Reply(true, nil)
				}
			default:
				// subsystem(sftp)/window-change/signal 等: 不需要应答就吞掉
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	// 客户端可能只开通道不发命令(探测), 那就等它关通道
	select {
	case <-startedCh:
	case <-reqDone:
		stdinW.Close()
		return
	}

	err := <-done
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
			log.Printf("命令执行错误: %v", err)
		}
	}
	payload := make([]byte, 4)
	payload[0] = byte(code >> 24)
	payload[1] = byte(code >> 16)
	payload[2] = byte(code >> 8)
	payload[3] = byte(code)
	ch.SendRequest("exit-status", false, payload)
	stdinW.Close()
}

func main() {
	flag.Parse()

	// -H=windowsgui 编译出来的进程没有可用的 stderr, io.MultiWriter 会在第一个 writer 报错就停,
	// 结果日志文件一个字都不写。所以只认文件, 打不开才退回 stderr。
	if f, err := os.OpenFile(*logF, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
		log.SetOutput(f)
	} else {
		log.SetOutput(os.Stderr)
		log.Printf("日志文件 %s 打不开: %v", *logF, err)
	}
	log.SetFlags(log.LstdFlags)

	signer, err := loadOrMakeHostKey(*hostKeyF)
	if err != nil {
		log.Fatalf("主机密钥: %v", err)
	}

	openAuth := *pass == "" && *emptyOK
	kr := &keyring{path: *authKeyF}
	n := kr.reload()
	if n == 0 {
		if openAuth {
			log.Printf("%s 没有可用公钥, 空密码模式不依赖它", *authKeyF)
		} else {
			go func() {
				// 开机时 authorized_keys 还没落盘(比如从 U 盘补放), 等到拿到钥匙为止
				for range time.Tick(10 * time.Second) {
					if kr.reload() > 0 {
						log.Printf("补加载授权公钥成功")
						return
					}
				}
			}()
		}
	} else {
		log.Printf("已加载 %d 把授权公钥", n)
	}

	cfg := &ssh.ServerConfig{
		ServerVersion: *clientVer,
		NoClientAuth:  openAuth,
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if kr.match(key.Marshal()) {
				return &ssh.Permissions{Extensions: map[string]string{"user": meta.User()}}, nil
			}
			// 公钥不在名单里: 空密码模式下照样放行(方便随手连), 但日志里标出来
			if openAuth {
				log.Printf("未授权公钥 %s 走空密码通道 user=%s", ssh.FingerprintSHA256(key), meta.User())
				return &ssh.Permissions{Extensions: map[string]string{"user": meta.User()}}, nil
			}
			log.Printf("拒绝未授权公钥 user=%s %s %s", meta.User(), key.Type(), ssh.FingerprintSHA256(key))
			return nil, fmt.Errorf("no authorization for this key")
		},
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if *pass != "" {
				if string(password) == *pass {
					return &ssh.Permissions{Extensions: map[string]string{"user": meta.User()}}, nil
				}
				return nil, fmt.Errorf("口令不符")
			}
			if *emptyOK {
				// 救援场景优先可用性: 空密码(或随手敲的)都放行, 想收紧就 -pass 设口令
				return &ssh.Permissions{Extensions: map[string]string{"user": meta.User()}}, nil
			}
			return nil, fmt.Errorf("未启用空密码登录")
		},
		AuthLogCallback: func(meta ssh.ConnMetadata, method string, err error) {
			if err != nil {
				log.Printf("认证失败 user=%s method=%s: %v", meta.User(), method, err)
			}
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", *addr, err)
	}
	mode := "公钥"
	if openAuth {
		mode = "空密码+公钥"
	} else if *pass != "" {
		mode = "口令+公钥"
	}
	log.Printf("pe-sshd 监听 %s 认证=%s (hostkey=%s authkeys=%s shell=%s)", *addr, mode, *hostKeyF, *authKeyF, *shellExe)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept 失败: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go handleConn(c, cfg)
	}
}
