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
    peekBufSize             = tlsRecordHeaderLen + tlsMaxRecordLen // 16389，防止大包 ErrBufferFull
)

// ── 模块定义 ──────────────────────────────────────────────────────────────────
type TLSVersionMatcher struct {
    Version         string         `json:"version,omitempty"`
    IdleTimeout     caddy.Duration `json:"idle_timeout,omitempty"`
    MaxIdleDuration caddy.Duration `json:"max_idle_duration,omitempty"`
    MinBytesRead    int64          `json:"min_bytes_read,omitempty"`
    LogFile         string         `json:"log_file,omitempty"`
    EnableLog       bool           `json:"enable_log,omitempty"`
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
    if (m.MaxIdleDuration == 0) != (m.MinBytesRead == 0) {
        return errors.New(
            "tls_version: max_idle_duration and min_bytes_read must be set together",
        )
    }
    return nil
}

// ── Match 主逻辑 ──────────────────────────────────────────────────────────────
func (m *TLSVersionMatcher) Match(cx *layer4.Connection) (bool, error) {
    rawConn := cx.Conn

    // 1. 设置握手超时
    timeout := defaultHandshakeTimeout
    if m.IdleTimeout != 0 {
        timeout = time.Duration(m.IdleTimeout)
    }
    _ = rawConn.SetReadDeadline(time.Now().Add(timeout))

    // defer 统一清除 deadline，无论哪条路径返回都不影响后续路由
    defer rawConn.SetReadDeadline(time.Time{})

    br := bufio.NewReaderSize(rawConn, peekBufSize)
    
    // 2. 极其重要：提前替换连接，保证即使后续匹配失败，缓冲数据也不丢失
    pc := newPeekedConn(rawConn, br)
    cx.Conn = pc

    // 3. 窥探握手包
    data, err := peekClientHello(br)
    if err != nil {
        // 非 TLS 流量，返回 false 让其他路由继续匹配
        return false, nil
    }

    // 4. 解析版本
    matched, err := matchVersion(data, m.Version)
    if err != nil {
        return false, nil
    }

    // 5. 匹配成功时启动僵尸监控
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

    if pos+2 > len(data) { return false }
    pos += 2 + int(binary.BigEndian.Uint16(data[pos:pos+2]))
    
    if pos+1 > len(data) { return false }
    pos += 1 + int(data[pos])
    
    if pos+2 > len(data) { return false }
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
    reader    io.Reader
    total     atomic.Int64
    stopOnce  sync.Once
    stopCh    chan struct{}
    closeOnce sync.Once
}

func newPeekedConn(c net.Conn, r io.Reader) *peekedConn {
    return &peekedConn{
        Conn:   c,
        reader: r,
        stopCh: make(chan struct{}),
    }
}

func (c *peekedConn) Read(b []byte) (int, error) {
    n, err := c.reader.Read(b)
    if n > 0 {
        c.total.Add(int64(n))
    }
    return n, err
}

func (c *peekedConn) Close() error {
    var err error
    c.closeOnce.Do(func() {
        c.stopOnce.Do(func() { close(c.stopCh) })
        err = c.Conn.Close()
    })
    return err
}

func (c *peekedConn) rstClose() {
    c.closeOnce.Do(func() {
        c.stopOnce.Do(func() { close(c.stopCh) })
        setLinger0(c.Conn)
        c.Conn.Close()
    })
}

// ── 僵尸连接监控 ──────────────────────────────────────────────────────────────
type zombieConfig struct {
    window    time.Duration
    minBytes  int64
    logFile   string
    enableLog bool
}

func (c *peekedConn) startZombieMonitor(cfg zombieConfig) {
    go func() {
        ticker := time.NewTicker(cfg.window)
        defer ticker.Stop()
        var lastBytes int64
        // 跳过第一个周期，避免连接刚建立 delta=0 被误判
        first := true

        for {
            select {
            case <-ticker.C:
                cur := c.total.Load()
                delta := cur - lastBytes
                lastBytes = cur

                if first {
                    first = false
                    continue
                }

                if delta < cfg.minBytes {
                    if cfg.enableLog && cfg.logFile != "" {
                        // 通过全局异步队列写日志，防阻塞
                        globalLogger.send(cfg.logFile, c.Conn.RemoteAddr().String()+"\n")
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

// 全局日志队列，缓冲 1024 条，满时静默丢弃（不阻塞业务）
var globalLogger = func() *asyncLogger {
    l := &asyncLogger{ch: make(chan logEntry, 1024)}
    go l.run()
    return l
}()

func (l *asyncLogger) send(path, msg string) {
    select {
    case l.ch <- logEntry{path, msg}:
    default:
        // 丢弃策略，保护主协程
    }
}

func (l *asyncLogger) run() {
    handles := make(map[string]*os.File)
    
    // 定期清理文件句柄，完美兼容 logrotate 日志轮转，防止磁盘 fd 泄漏
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
            // 每 5 分钟关闭一次所有打开的文件句柄，下一次写入时会自动重新打开。
            // 这保证了如果外部删除了日志文件，空间可以被迅速释放。
            for k, f := range handles {
                _ = f.Close()
                delete(handles, k)
            }
        }
    }
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



