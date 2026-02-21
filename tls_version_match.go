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
    "sync/atomic"
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
    tlsRecordHeaderLen      = 5
    tlsHandshake            = byte(0x16)
    tlsClientHello          = byte(0x01)
    tlsMaxRecordLen         = 16384
    tlsMinRecordLen         = 4
    extSupportedVersions    = uint16(0x002b)
    tlsVer12                = uint16(0x0303)
    tlsVer13                = uint16(0x0304)
    defaultHandshakeTimeout = 3 * time.Second
    defaultCheckInterval    = 30 * time.Second
    peekBufSize             = tlsRecordHeaderLen + tlsMaxRecordLen
)

// ── 模块定义 ──────────────────────────────────────────────────────────────────

type TLSVersionMatcher struct {
    // TLS 版本："1.2" 或 "1.3"
    Version string `json:"version,omitempty"`

    // 握手阶段读取超时，默认 3s
    IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`

    // 连接空闲超时：无任何读写超过此时间则 RST 断开
    ConnIdleTimeout caddy.Duration `json:"conn_idle_timeout,omitempty"`

    // 空闲检测间隔，默认 30s
    CheckInterval caddy.Duration `json:"check_interval,omitempty"`

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

func (m *TLSVersionMatcher) Validate() error {
    if m.Version != "1.2" && m.Version != "1.3" {
        return fmt.Errorf(
            "tls_version: unsupported version %q, must be \"1.2\" or \"1.3\"",
            m.Version,
        )
    }
    return nil
}

// ── Match 主逻辑 ──────────────────────────────────────────────────────────────

func (m *TLSVersionMatcher) Match(cx *layer4.Connection) (bool, error) {
    rawConn := cx.Conn

    // Step1: 握手超时
    timeout := defaultHandshakeTimeout
    if m.IdleTimeout != 0 {
        timeout = time.Duration(m.IdleTimeout)
    }
    _ = rawConn.SetReadDeadline(time.Now().Add(timeout))
    defer rawConn.SetReadDeadline(time.Time{})

    // Step2: 启用 TCP Keepalive，内核层面检测死连接
    setTCPOptions(rawConn)

    // Step3: 提前替换连接，保证缓冲数据不丢失
    br := bufio.NewReaderSize(rawConn, peekBufSize)
    pc := newPeekedConn(rawConn, br)
    cx.Conn = pc

    // Step4: 解析 ClientHello
    data, err := peekClientHello(br)
    if err != nil {
        return false, nil
    }

    // Step5: 版本匹配
    matched, err := matchVersion(data, m.Version)
    if err != nil {
        return false, nil
    }

    // Step6: 匹配成功则启动应用层空闲检测
    if matched && m.ConnIdleTimeout > 0 {
        interval := time.Duration(m.CheckInterval)
        if interval <= 0 {
            interval = defaultCheckInterval
        }
        pc.startZombieMonitor(zombieConfig{
            connIdleTimeout: time.Duration(m.ConnIdleTimeout),
            checkInterval:   interval,
            logFile:         m.LogFile,
            enableLog:       m.EnableLog,
        })
    }

    return matched, nil
}

// ── TLS 解析 ──────────────────────────────────────────────────────────────────

func peekClientHello(br *bufio.Reader) ([]byte, error) {
    hdr, err := br.Peek(tlsRecordHeaderLen)
    if err != nil {
        return nil, err
    }
    if hdr[0] != tlsHandshake {
        return nil, errors.New("not tls handshake")
    }
    recVer := binary.BigEndian.Uint16(hdr[1:3])
    if recVer < 0x0301 || recVer > 0x0304 {
        return nil, errors.New("invalid record version")
    }
    recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
    if recLen < tlsMinRecordLen || recLen > tlsMaxRecordLen {
        return nil, errors.New("invalid record length")
    }
    total := tlsRecordHeaderLen + recLen
    data, err := br.Peek(total)
    if err != nil {
        return nil, err
    }
    if data[5] != tlsClientHello {
        return nil, errors.New("not clienthello")
    }
    return data, nil
}

func matchVersion(data []byte, target string) (bool, error) {
    if len(data) < 11 {
        return false, errors.New("clienthello too short")
    }
    legacyVer := binary.BigEndian.Uint16(data[9:11])
    if legacyVer < tlsVer12 {
        return false, nil
    }
    var detected string
    if hasTLS13(data) {
        detected = "1.3"
    } else if legacyVer == tlsVer12 {
        detected = "1.2"
    }
    return detected == target, nil
}

func hasTLS13(data []byte) bool {
    if len(data) < 44 {
        return false
    }
    pos := 44 + int(data[43])
    if pos+2 > len(data) {
        return false
    }
    pos += 2 + int(binary.BigEndian.Uint16(data[pos:pos+2]))
    if pos+1 > len(data) {
        return false
    }
    pos += 1 + int(data[pos])
    if pos+2 > len(data) {
        return false
    }
    extEnd := pos + 2 + int(binary.BigEndian.Uint16(data[pos:pos+2]))
    pos += 2
    if extEnd > len(data) {
        extEnd = len(data)
    }
    for pos+4 <= extEnd {
        extType := binary.BigEndian.Uint16(data[pos : pos+2])
        extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
        pos += 4
        next := pos + extLen
        if next > extEnd {
            break
        }
        if extType == extSupportedVersions && extLen >= 3 {
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

type peekedConn struct {
    net.Conn
    reader     io.Reader
    total      atomic.Int64 // 累计读取字节数
    lastActive atomic.Int64 // 最后活跃时间戳 UnixNano
    stopOnce   sync.Once
    stopCh     chan struct{}
    closeOnce  sync.Once
}

func newPeekedConn(c net.Conn, r io.Reader) *peekedConn {
    pc := &peekedConn{
        Conn:   c,
        reader: r,
        stopCh: make(chan struct{}),
    }
    // 初始化活跃时间为连接建立时刻
    pc.lastActive.Store(time.Now().UnixNano())
    return pc
}

// Read 从 bufio 缓冲读取，同时更新活跃时间
func (c *peekedConn) Read(b []byte) (int, error) {
    n, err := c.reader.Read(b)
    if n > 0 {
        c.total.Add(int64(n))
        c.lastActive.Store(time.Now().UnixNano())
    }
    return n, err
}

// Write 写入时同样更新活跃时间
func (c *peekedConn) Write(b []byte) (int, error) {
    n, err := c.Conn.Write(b)
    if n > 0 {
        c.lastActive.Store(time.Now().UnixNano())
    }
    return n, err
}

// Close 正常四次挥手关闭
func (c *peekedConn) Close() error {
    var err error
    c.closeOnce.Do(func() {
        c.stopOnce.Do(func() { close(c.stopCh) })
        err = c.Conn.Close()
    })
    return err
}

// rstClose SO_LINGER(0) 强制 RST 断开
// 不产生 TIME_WAIT / CLOSE_WAIT / FIN_WAIT_2
func (c *peekedConn) rstClose() {
    c.closeOnce.Do(func() {
        c.stopOnce.Do(func() { close(c.stopCh) })
        setLinger0(c.Conn)
        c.Conn.Close()
    })
}

// ── 僵尸连接监控 ──────────────────────────────────────────────────────────────

type zombieConfig struct {
    connIdleTimeout time.Duration // 无任何读写超过此时间则断开
    checkInterval   time.Duration // 检测间隔
    logFile         string
    enableLog       bool
}

// startZombieMonitor 真实空闲检测
// 只要有任何读写就更新活跃时间
// 连续空闲超过 connIdleTimeout 才断开
// 不会误判低频正常连接
func (c *peekedConn) startZombieMonitor(cfg zombieConfig) {
    go func() {
        ticker := time.NewTicker(cfg.checkInterval)
        defer ticker.Stop()

        for {
            select {
            case <-ticker.C:
                lastActive := time.Unix(0, c.lastActive.Load())
                idleDuration := time.Since(lastActive)

                if idleDuration >= cfg.connIdleTimeout {
                    if cfg.enableLog && cfg.logFile != "" {
                        globalLogger.send(
                            cfg.logFile,
                            fmt.Sprintf("%s idle=%s\n",
                                c.Conn.RemoteAddr().String(),
                                idleDuration.Round(time.Second),
                            ),
                        )
                    }
                    c.rstClose()
                    return
                }

            case <-c.stopCh:
                return
            }
        }
    }()
}

// ── 异步日志队列 ──────────────────────────────────────────────────────────────

type logEntry struct {
    path string
    msg  string
}

type asyncLogger struct {
    ch chan logEntry
}

var globalLogger = func() *asyncLogger {
    l := &asyncLogger{ch: make(chan logEntry, 1024)}
    go l.run()
    return l
}()

func (l *asyncLogger) send(path, msg string) {
    select {
    case l.ch <- logEntry{path, msg}:
    default:
        // 队列满时静默丢弃，不阻塞业务
    }
}

func (l *asyncLogger) run() {
    handles := make(map[string]*os.File)
    // 每 5 分钟关闭重开文件句柄，兼容 logrotate
    cleanupTicker := time.NewTicker(5 * time.Minute)
    defer cleanupTicker.Stop()
    defer func() {
        for _, f := range handles {
            _ = f.Close()
        }
    }()
    for {
        select {
        case entry := <-l.ch:
            f, ok := handles[entry.path]
            if !ok {
                var err error
                f, err = os.OpenFile(
                    entry.path,
                    os.O_APPEND|os.O_CREATE|os.O_WRONLY,
                    0644,
                )
                if err != nil {
                    continue
                }
                handles[entry.path] = f
            }
            _, _ = f.WriteString(entry.msg)

        case <-cleanupTicker.C:
            for k, f := range handles {
                _ = f.Close()
                delete(handles, k)
            }
        }
    }
}

// ── TCP 选项 ──────────────────────────────────────────────────────────────────

// setTCPOptions 启用 TCP Keepalive
// 内核层面检测死连接，与应用层空闲检测双重保障
func setTCPOptions(conn net.Conn) {
    tc, ok := conn.(*net.TCPConn)
    if !ok {
        return
    }
    _ = tc.SetKeepAlive(true)
    _ = tc.SetKeepAlivePeriod(30 * time.Second)
}

// ── SO_LINGER(0) ─────────────────────────────────────────────────────────────

func setLinger0(conn net.Conn) {
    if tc, ok := conn.(*net.TCPConn); ok {
        _ = tc.SetLinger(0)
        return
    }
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

// ── 接口验证 ──────────────────────────────────────────────────────────────────

var (
    _ layer4.ConnMatcher = (*TLSVersionMatcher)(nil)
    _ caddy.Validator    = (*TLSVersionMatcher)(nil)
)
