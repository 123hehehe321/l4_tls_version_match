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
    tlsRecordHeaderLen = 5
    tlsHandshake       = 0x16
    tlsClientHello     = 0x01
    tlsMaxRecordLen    = 16384
    tlsMinRecordLen    = 4

    extSupportedVersions = uint16(0x002b)
    tlsVer12             = uint16(0x0303)
    tlsVer13             = uint16(0x0304)

    defaultHandshakeTimeout = 3 * time.Second

    // ✅ 修复3：缓冲区覆盖最大 TLS Record
    peekBufSize = tlsRecordHeaderLen + tlsMaxRecordLen // 16389
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

// ✅ 修复1：正确的方法签名
func (m *TLSVersionMatcher) Match(conn *layer4.Connection) (bool, error) {
    rawConn := conn.Conn

    // Step1: 握手超时
    timeout := defaultHandshakeTimeout
    if m.IdleTimeout != 0 {
        timeout = time.Duration(m.IdleTimeout)
    }
    if err := rawConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
        return false, err
    }
    defer rawConn.SetReadDeadline(time.Time{})

    // Step2: 解析 ClientHello
    br := bufio.NewReaderSize(rawConn, peekBufSize)
    data, err := peekClientHello(br)
    if err != nil {
        return false, err
    }

    // Step3: 版本匹配
    matched, err := matchVersion(data, m.Version)
    if err != nil {
        return false, err
    }

    // Step4: 替换连接保留缓冲
    pc := newPeekedConn(rawConn, br)
    conn.Conn = pc

    // Step5: 仅匹配时启动僵尸监控
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
        return nil, fmt.Errorf("read tls header: %w", err)
    }
    if hdr[0] != tlsHandshake {
        return nil, fmt.Errorf("not tls handshake: content_type=0x%02x", hdr[0])
    }
    recVer := binary.BigEndian.Uint16(hdr[1:3])
    if recVer < 0x0301 || recVer > 0x0304 {
        return nil, fmt.Errorf("invalid record version: 0x%04x", recVer)
    }
    recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
    if recLen < tlsMinRecordLen || recLen > tlsMaxRecordLen {
        return nil, fmt.Errorf("invalid record length: %d", recLen)
    }
    total := tlsRecordHeaderLen + recLen
    data, err := br.Peek(total)
    if err != nil {
        return nil, fmt.Errorf("read clienthello body: %w", err)
    }
    if data[5] != tlsClientHello {
        return nil, fmt.Errorf("not clienthello: handshake_type=0x%02x", data[5])
    }
    return data, nil
}

// ✅ 修复2：移除永远成立的冗余 if
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
    totalBytes int64      // ✅ 修复6：atomic 操作，无需 Mutex
    stopOnce   sync.Once
    stopCh     chan struct{}
    closeOnce  sync.Once
}

func newPeekedConn(c net.Conn, r io.Reader) *peekedConn {
    return &peekedConn{
        Conn:   c,
        reader: r,
        stopCh: make(chan struct{}),
    }
}

// ✅ 修复6：atomic 替代 Mutex
func (c *peekedConn) Read(b []byte) (int, error) {
    n, err := c.reader.Read(b)
    if n > 0 {
        atomic.AddInt64(&c.totalBytes, int64(n))
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

        // ✅ 修复5：跳过第一个周期，避免连接刚建立时误判
        var lastBytes int64
        first := true

        for {
            select {
            case <-ticker.C:
                cur := atomic.LoadInt64(&c.totalBytes)
                delta := cur - lastBytes
                lastBytes = cur

                // 第一个周期只记录基准值，不判断
                if first {
                    first = false
                    continue
                }

                if delta < cfg.minBytes {
                    if cfg.enableLog && cfg.logFile != "" {
                        addr := c.Conn.RemoteAddr().String()
                        // ✅ 修复4：通过 channel 异步写日志
                        logQueue.send(cfg.logFile, addr+"\n")
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

// ✅ 修复4：全局单一 goroutine 串行写日志，避免并发 open/close 竞争
type logEntry struct {
    path string
    msg  string
}

type asyncLogger struct {
    ch chan logEntry
}

var logQueue = newAsyncLogger(512)

func newAsyncLogger(bufSize int) *asyncLogger {
    l := &asyncLogger{ch: make(chan logEntry, bufSize)}
    go l.run()
    return l
}

func (l *asyncLogger) send(path, msg string) {
    select {
    case l.ch <- logEntry{path, msg}:
    default:
        // 队列满时丢弃，不阻塞业务
    }
}

func (l *asyncLogger) run() {
    // 每个文件保持一个打开的句柄，减少 open/close 开销
    files := make(map[string]*os.File)
    defer func() {
        for _, f := range files {
            f.Close()
        }
    }()
    for entry := range l.ch {
        f, ok := files[entry.path]
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
            files[entry.path] = f
        }
        _, _ = f.WriteString(entry.msg)
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
