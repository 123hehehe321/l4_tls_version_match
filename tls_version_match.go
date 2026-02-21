package tlsversionmatch

import (
    "bufio"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "net"
    "os"
    "sync"
    "syscall"
    "time"

    "github.com/caddyserver/caddy/v2"
    "github.com/mholt/caddy-l4/layer4"
)

func init() {
    caddy.RegisterModule(TLSVersionMatcher{})
}

// ── 常量 ──────────────────────────────────────────────────────────────────────

const (
    tlsRecordHeaderLen = 5
    tlsHandshake       = 0x16 // ContentType: Handshake
    tlsClientHello     = 0x01 // HandshakeType: ClientHello
    tlsMaxRecordLen    = 16384
    tlsMinRecordLen    = 4

    extSupportedVersions = 0x002b // supported_versions 扩展类型
    tlsVer12             = uint16(0x0303)
    tlsVer13             = uint16(0x0304)

    defaultHandshakeTimeout = 3 * time.Second
    peekBufSize             = 4096
)

// ── 模块定义 ──────────────────────────────────────────────────────────────────

// TLSVersionMatcher 匹配指定 TLS 版本的握手连接
// 支持僵尸连接检测（流量低于阈值时 RST 强制断开）
type TLSVersionMatcher struct {
    // "1.2" 或 "1.3"
    Version string `json:"version,omitempty"`

    // 握手阶段读取超时，默认 3s
    IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`

    // 僵尸连接检测周期，如 "600s"
    MaxIdleDuration caddy.Duration `json:"max_idle_duration,omitempty"`

    // 检测周期内最低流量字节数，低于此值视为僵尸连接
    MinBytesRead int64 `json:"min_bytes_read,omitempty"`

    // 僵尸连接日志文件路径
    LogFile string `json:"log_file,omitempty"`

    // 是否记录僵尸连接日志
    EnableLog bool `json:"enable_log,omitempty"`
}

func (TLSVersionMatcher) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "layer4.matchers.tls_version",
        New: func() caddy.Module { return new(TLSVersionMatcher) },
    }
}

// Validate 配置校验
func (m *TLSVersionMatcher) Validate() error {
    if m.Version != "1.2" && m.Version != "1.3" {
        return fmt.Errorf("tls_version: unsupported version %q, must be \"1.2\" or \"1.3\"", m.Version)
    }
    if (m.MaxIdleDuration == 0) != (m.MinBytesRead == 0) {
        return errors.New("tls_version: max_idle_duration and min_bytes_read must be set together")
    }
    return nil
}

// ── Match 主逻辑 ──────────────────────────────────────────────────────────────

func (m *TLSVersionMatcher) Match(conn *layer4.Connection) (bool, error) {
    rawConn := conn.Conn

    // ── Step1: 设置握手超时 ────────────────────────────────────
    timeout := defaultHandshakeTimeout
    if m.IdleTimeout != 0 {
        timeout = time.Duration(m.IdleTimeout)
    }
    if err := rawConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
        return false, err
    }
    // 握手完成后清除 deadline
    defer rawConn.SetReadDeadline(time.Time{})

    // ── Step2: 解析 ClientHello ────────────────────────────────
    br := bufio.NewReaderSize(rawConn, peekBufSize)

    data, err := peekClientHello(br)
    if err != nil {
        return false, err
    }

    // ── Step3: 检测 TLS 版本 ───────────────────────────────────
    matched, err := matchVersion(data, m.Version)
    if err != nil {
        return false, err
    }

    // ── Step4: 替换连接（保留 bufio 已读缓冲）─────────────────
    pc := newPeekedConn(rawConn, br)
    conn.Conn = pc

    // ── Step5: 版本匹配则启动僵尸监控 ─────────────────────────
    if matched && m.MaxIdleDuration > 0 && m.MinBytesRead > 0 {
        pc.startZombieMonitor(zombieConfig{
            window:    time.Duration(m.MaxIdleDuration),
            minBytes:  m.MinBytesRead,
            logFile:   m.LogFile,
            enableLog: m.EnableLog,
        })
    }

    return matched, nil
}

// ── TLS 解析 ──────────────────────────────────────────────────────────────────

// peekClientHello 通过 bufio.Peek 读取完整 ClientHello
// 不消耗缓冲区数据，后续 Read 仍可读到完整握手数据
func peekClientHello(br *bufio.Reader) ([]byte, error) {
    // 读取 Record Header
    hdr, err := br.Peek(tlsRecordHeaderLen)
    if err != nil {
        return nil, fmt.Errorf("read tls header: %w", err)
    }

    if hdr[0] != tlsHandshake {
        return nil, fmt.Errorf("not tls handshake, content_type=0x%02x", hdr[0])
    }

    // legacy_record_version 合法范围 0x0301~0x0304
    recVer := binary.BigEndian.Uint16(hdr[1:3])
    if recVer < 0x0301 || recVer > 0x0304 {
        return nil, fmt.Errorf("invalid record version 0x%04x", recVer)
    }

    recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
    if recLen < tlsMinRecordLen || recLen > tlsMaxRecordLen {
        return nil, fmt.Errorf("invalid record length %d", recLen)
    }

    total := tlsRecordHeaderLen + recLen
    data, err := br.Peek(total)
    if err != nil {
        return nil, fmt.Errorf("read clienthello body: %w", err)
    }

    if data[5] != tlsClientHello {
        return nil, fmt.Errorf("not clienthello, handshake_type=0x%02x", data[5])
    }

    return data, nil
}

// matchVersion 判断 ClientHello 中的 TLS 版本是否与目标匹配
func matchVersion(data []byte, target string) (bool, error) {
    if len(data) < 11 {
        return false, errors.New("clienthello too short")
    }

    legacyVer := binary.BigEndian.Uint16(data[9:11])

    // 低于 TLS 1.2 直接不匹配
    if legacyVer < tlsVer12 {
        return false, nil
    }

    var detected string

    // TLS 1.3 必须通过 supported_versions 扩展识别
    if legacyVer >= tlsVer12 {
        if hasTLS13(data) {
            detected = "1.3"
        } else if legacyVer == tlsVer12 {
            detected = "1.2"
        }
    }

    return detected == target, nil
}

// hasTLS13 解析 supported_versions 扩展(0x002b)
// 返回是否包含 TLS 1.3 (0x0304)
func hasTLS13(data []byte) bool {
    // ClientHello 最小结构：
    // [0..4]   = TLS Record Header (5B)
    // [5]      = HandshakeType (1B)
    // [6..8]   = Length (3B)
    // [9..10]  = legacy_version (2B)
    // [11..42] = Random (32B)
    // [43]     = SessionID length (1B)
    if len(data) < 44 {
        return false
    }

    pos := 44 + int(data[43]) // 跳过 SessionID

    // CipherSuites: 2字节长度 + 数据
    if pos+2 > len(data) {
        return false
    }
    pos += 2 + int(binary.BigEndian.Uint16(data[pos:pos+2]))

    // CompressionMethods: 1字节长度 + 数据
    if pos+1 > len(data) {
        return false
    }
    pos += 1 + int(data[pos])

    // Extensions: 2字节总长度
    if pos+2 > len(data) {
        return false
    }
    extEnd := pos + 2 + int(binary.BigEndian.Uint16(data[pos:pos+2]))
    pos += 2
    if extEnd > len(data) {
        extEnd = len(data)
    }

    // 遍历扩展列表
    for pos+4 <= extEnd {
        extType := binary.BigEndian.Uint16(data[pos : pos+2])
        extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
        pos += 4

        next := pos + extLen
        if next > extEnd {
            break
        }

        if extType == extSupportedVersions && extLen >= 3 {
            // supported_versions 结构：
            // list_len (1B) + version列表 (每项2B)
            listLen := int(data[pos])
            listEnd := pos + 1 + listLen
            if listEnd > next {
                listEnd = next
            }
            for i := pos + 1; i+1 < listEnd; i += 2 {
                if binary.BigEndian.Uint16(data[i:i+2]) == tlsVer13 {
                    return true
                }
            }
        }
        pos = next
    }

    return false
}

// ── peekedConn ────────────────────────────────────────────────────────────────

// peekedConn 包装底层连接
// 透明代理已经被 bufio 缓冲的数据，同时统计流量用于僵尸检测
type peekedConn struct {
    net.Conn                  // 底层 TCP 连接
    reader      io.Reader     // bufio.Reader（含已读缓冲）
    mu          sync.Mutex    // 保护 totalBytes
    totalBytes  int64         // 累计读取字节数
    stopOnce    sync.Once     // 保证 stopCh 只关闭一次
    stopCh      chan struct{}  // 通知监控 goroutine 退出
    closeOnce   sync.Once     // 保证 Close 只执行一次
}

func newPeekedConn(c net.Conn, r io.Reader) *peekedConn {
    return &peekedConn{
        Conn:   c,
        reader: r,
        stopCh: make(chan struct{}),
    }
}

// Read 优先从 bufio 缓冲读取（保证握手数据不丢失），同时统计字节数
func (c *peekedConn) Read(b []byte) (int, error) {
    n, err := c.reader.Read(b)
    if n > 0 {
        c.mu.Lock()
        c.totalBytes += int64(n)
        c.mu.Unlock()
    }
    return n, err
}

// Close 正常关闭（四次挥手）
func (c *peekedConn) Close() error {
    var err error
    c.closeOnce.Do(func() {
        c.stopOnce.Do(func() { close(c.stopCh) })
        err = c.Conn.Close()
    })
    return err
}

// rstClose SO_LINGER(0) 强制 RST 断开
// 直接发送 RST 包，跳过四次挥手
// 不产生 TIME_WAIT / CLOSE_WAIT / FIN_WAIT_2
func (c *peekedConn) rstClose() {
    c.closeOnce.Do(func() {
        c.stopOnce.Do(func() { close(c.stopCh) })
        setLinger0(c.Conn) // 设置 SO_LINGER=0
        c.Conn.Close()     // 触发 RST
    })
}

// ── 僵尸连接监控 ──────────────────────────────────────────────────────────────

type zombieConfig struct {
    window    time.Duration
    minBytes  int64
    logFile   string
    enableLog bool
}

// startZombieMonitor 启动僵尸连接监控 goroutine
// 每个 window 周期检查流量增量
// 若低于 minBytes 则判定为僵尸连接，执行 RST 断开
func (c *peekedConn) startZombieMonitor(cfg zombieConfig) {
    go func() {
        ticker := time.NewTicker(cfg.window)
        defer ticker.Stop()

        var lastBytes int64

        for {
            select {
            case <-ticker.C:
                c.mu.Lock()
                cur := c.totalBytes
                c.mu.Unlock()

                delta := cur - lastBytes
                lastBytes = cur

                if delta < cfg.minBytes {
                    // 记录僵尸连接 IP
                    if cfg.enableLog && cfg.logFile != "" {
                        addr := c.Conn.RemoteAddr().String()
                        go appendLog(cfg.logFile, addr+"\n")
                    }
                    // RST 强制断开，无任何 TCP 等待状态
                    c.rstClose()
                    return
                }

            case <-c.stopCh:
                return
            }
        }
    }()
}

// ── SO_LINGER(0) ─────────────────────────────────────────────────────────────

// setLinger0 对底层连接设置 SO_LINGER(onoff=1, linger=0)
// 关闭时内核立即发送 RST，不进入任何 TCP 等待状态
func setLinger0(conn net.Conn) {
    // 方式1：直接是 *net.TCPConn
    if tc, ok := conn.(*net.TCPConn); ok {
        _ = tc.SetLinger(0)
        return
    }

    // 方式2：通过 SyscallConn 操作原始 fd（适用于各种包装层）
    type syscallConner interface {
        SyscallConn() (syscall.RawConn, error)
    }
    if sc, ok := conn.(syscallConner); ok {
        if raw, err := sc.SyscallConn(); err == nil {
            _ = raw.Control(func(fd uintptr) {
                _ = syscall.SetsockoptLinger(
                    int(fd),
                    syscall.SOL_SOCKET,
                    syscall.SO_LINGER,
                    &syscall.Linger{Onoff: 1, Linger: 0},
                )
            })
        }
    }
}

// ── 日志 ──────────────────────────────────────────────────────────────────────

// appendLog 追加写入日志文件
func appendLog(path, msg string) {
    f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer f.Close()
    _, _ = f.WriteString(msg)
}

// ── 接口验证 ──────────────────────────────────────────────────────────────────

var (
    _ layer4.ConnMatcher    = (*TLSVersionMatcher)(nil)
    _ caddy.Validator       = (*TLSVersionMatcher)(nil)
)
