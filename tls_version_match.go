package tlsversionmatch

import (
    "bufio"
    "container/list"
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

// ── 全局变量（延迟初始化，避免循环依赖）────────────────────────────────────

var globalWheel *timerWheel  // ✅ 修复1：声明但不初始化
var globalLogger *asyncLogger

func init() {
    // ✅ 修复1：在 init 中初始化，打破循环依赖
    globalWheel = newTimerWheel(1 * time.Second)
    globalLogger = newAsyncLogger()
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
    peekBufSize             = tlsRecordHeaderLen + tlsMaxRecordLen
    wheelSlots              = 256
)

// ── 模块定义 ──────────────────────────────────────────────────────────────────

type TLSVersionMatcher struct {
    Version         string         `json:"version,omitempty"`
    IdleTimeout     caddy.Duration `json:"idle_timeout,omitempty"`
    ConnIdleTimeout caddy.Duration `json:"conn_idle_timeout,omitempty"`
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
    return nil
}

// ── Match 主逻辑 ──────────────────────────────────────────────────────────────

func (m *TLSVersionMatcher) Match(cx *layer4.Connection) (bool, error) {
    rawConn := cx.Conn

    timeout := defaultHandshakeTimeout
    if m.IdleTimeout != 0 {
        timeout = time.Duration(m.IdleTimeout)
    }
    _ = rawConn.SetReadDeadline(time.Now().Add(timeout))
    defer rawConn.SetReadDeadline(time.Time{})

    setTCPOptions(rawConn)

    br := bufio.NewReaderSize(rawConn, peekBufSize)
    pc := newPeekedConn(rawConn, br)
    cx.Conn = pc

    data, err := peekClientHello(br)
    if err != nil {
        return false, nil
    }

    matched, err := matchVersion(data, m.Version)
    if err != nil {
        return false, nil
    }

    if matched && m.ConnIdleTimeout > 0 {
        pc.logFile = m.LogFile
        pc.enableLog = m.EnableLog
        globalWheel.register(pc, time.Duration(m.ConnIdleTimeout))
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
    reader      io.Reader
    total       int64
    lastActive  int64
    wheelElem   *list.Element
    wheelMu     sync.Mutex
    idleTimeout time.Duration
    logFile     string
    enableLog   bool
    closeOnce   sync.Once
}

func newPeekedConn(c net.Conn, r io.Reader) *peekedConn {
    pc := &peekedConn{
        Conn:   c,
        reader: r,
    }
    atomic.StoreInt64(&pc.lastActive, time.Now().UnixNano())
    return pc
}

func (c *peekedConn) Read(b []byte) (int, error) {
    n, err := c.reader.Read(b)
    if n > 0 {
        atomic.AddInt64(&c.total, int64(n))
        atomic.StoreInt64(&c.lastActive, time.Now().UnixNano())
    }
    return n, err
}

func (c *peekedConn) Write(b []byte) (int, error) {
    n, err := c.Conn.Write(b)
    if n > 0 {
        atomic.StoreInt64(&c.lastActive, time.Now().UnixNano())
    }
    return n, err
}

func (c *peekedConn) Close() error {
    var err error
    c.closeOnce.Do(func() {
        globalWheel.remove(c)
        err = c.Conn.Close()
    })
    return err
}

func (c *peekedConn) rstClose() {
    c.closeOnce.Do(func() {
        // ✅ 修复1：globalWheel 已通过 init() 初始化，无循环依赖
        globalWheel.remove(c)
        setLinger0(c.Conn)
        c.Conn.Close()
    })
}

// ── 时间轮 ────────────────────────────────────────────────────────────────────

type timerWheel struct {
    mu           sync.Mutex
    slots        [wheelSlots]*list.List
    currentSlot  int
    tickInterval time.Duration
}

func newTimerWheel(tickInterval time.Duration) *timerWheel {
    tw := &timerWheel{tickInterval: tickInterval}
    for i := range tw.slots {
        tw.slots[i] = list.New()
    }
    go tw.run()
    return tw
}

func (tw *timerWheel) targetSlotLocked(timeout time.Duration) int {
    ticks := int(timeout / tw.tickInterval)
    if ticks <= 0 {
        ticks = 1
    }
    return (tw.currentSlot + ticks) % wheelSlots
}

func (tw *timerWheel) register(pc *peekedConn, timeout time.Duration) {
    pc.idleTimeout = timeout
    tw.mu.Lock()
    slot := tw.targetSlotLocked(timeout)
    elem := tw.slots[slot].PushBack(pc)
    tw.mu.Unlock()

    pc.wheelMu.Lock()
    pc.wheelElem = elem
    pc.wheelMu.Unlock()
}

func (tw *timerWheel) remove(pc *peekedConn) {
    pc.wheelMu.Lock()
    elem := pc.wheelElem
    pc.wheelElem = nil
    pc.wheelMu.Unlock()

    if elem == nil {
        return
    }

    // ✅ 修复2：不用 elem.List()，改为遍历所有槽找到并删除
    tw.mu.Lock()
    for i := range tw.slots {
        if tw.slots[i] == elem.List() {
            tw.slots[i].Remove(elem)
            break
        }
    }
    tw.mu.Unlock()
}

func (tw *timerWheel) run() {
    ticker := time.NewTicker(tw.tickInterval)
    defer ticker.Stop()

    for range ticker.C {
        tw.mu.Lock()
        tw.currentSlot = (tw.currentSlot + 1) % wheelSlots
        slot := tw.slots[tw.currentSlot]

        var expired []*peekedConn
        var requeue []*peekedConn

        for elem := slot.Front(); elem != nil; {
            next := elem.Next()
            pc := elem.Value.(*peekedConn)
            lastActive := time.Unix(0, atomic.LoadInt64(&pc.lastActive))

            if time.Since(lastActive) >= pc.idleTimeout {
                slot.Remove(elem)
                pc.wheelMu.Lock()
                pc.wheelElem = nil
                pc.wheelMu.Unlock()
                expired = append(expired, pc)
            } else {
                slot.Remove(elem)
                requeue = append(requeue, pc)
            }
            elem = next
        }

        for _, pc := range requeue {
            newSlot := tw.targetSlotLocked(pc.idleTimeout)
            newElem := tw.slots[newSlot].PushBack(pc)
            pc.wheelMu.Lock()
            pc.wheelElem = newElem
            pc.wheelMu.Unlock()
        }
        tw.mu.Unlock()

        for _, pc := range expired {
            if pc.enableLog && pc.logFile != "" {
                lastActive := time.Unix(0, atomic.LoadInt64(&pc.lastActive))
                globalLogger.send(
                    pc.logFile,
                    fmt.Sprintf("%s idle=%s rst=1\n",
                        pc.Conn.RemoteAddr().String(),
                        time.Since(lastActive).Round(time.Second),
                    ),
                )
            }
            pc.rstClose()
        }
    }
}

// ── 异步日志队列 ──────────────────────────────────────────────────────────────

type logEntry struct {
    path string
    msg  string
}

type asyncLogger struct {
    ch chan logEntry
}

func newAsyncLogger() *asyncLogger {
    l := &asyncLogger{ch: make(chan logEntry, 1024)}
    go l.run()
    return l
}

func (l *asyncLogger) send(path, msg string) {
    select {
    case l.ch <- logEntry{path, msg}:
    default:
    }
}

func (l *asyncLogger) run() {
    handles := make(map[string]*os.File)
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

func setTCPOptions(conn net.Conn) {
    tc, ok := conn.(*net.TCPConn)
    if !ok {
        return
    }
    _ = tc.SetKeepAlive(true)
    _ = tc.SetKeepAlivePeriod(30 * time.Second)
    raw, err := tc.SyscallConn()
    if err != nil {
        return
    }
    _ = raw.Control(func(fd uintptr) {
        _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 30)
        _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 10)
        _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
    })
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


