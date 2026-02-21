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

    peekBufSize = tlsRecordHeaderLen + tlsMaxRecordLen

    // 时间轮槽数，槽越多精度越高
    wheelSlots = 256
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

    // Step1: 握手超时
    timeout := defaultHandshakeTimeout
    if m.IdleTimeout != 0 {
        timeout = time.Duration(m.IdleTimeout)
    }
    _ = rawConn.SetReadDeadline(time.Now().Add(timeout))
    defer rawConn.SetReadDeadline(time.Time{})

    // Step2: TCP Keepalive 内核层兜底
    setTCPOptions(rawConn)

    // Step3: 替换连接保留缓冲
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

    // Step6: 匹配成功，注册到时间轮
    if matched && m.ConnIdleTimeout > 0 {
        idleTimeout := time.Duration(m.ConnIdleTimeout)
        pc.logFile = m.LogFile
        pc.enableLog = m.EnableLog
        // 注册到全局时间轮
        globalWheel.register(pc, idleTimeout)
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
    total      atomic.Int64
    lastActive atomic.Int64 // UnixNano 最后活跃时间

    // 时间轮相关
    wheelElem   *list.Element // 在时间轮槽链表中的位置
    wheelMu     sync.Mutex    // 保护 wheelElem
    idleTimeout time.Duration // 该连接的超时阈值

    // 日志
    logFile   string
    enableLog bool

    closeOnce sync.Once
}

func newPeekedConn(c net.Conn, r io.Reader) *peekedConn {
    pc := &peekedConn{
        Conn:   c,
        reader: r,
    }
    pc.lastActive.Store(time.Now().UnixNano())
    return pc
}

func (c *peekedConn) Read(b []byte) (int, error) {
    n, err := c.reader.Read(b)
    if n > 0 {
        c.total.Add(int64(n))
        c.lastActive.Store(time.Now().UnixNano())
        // 有数据：通知时间轮重置超时
        globalWheel.refresh(c)
    }
    return n, err
}

func (c *peekedConn) Write(b []byte) (int, error) {
    n, err := c.Conn.Write(b)
    if n > 0 {
        c.lastActive.Store(time.Now().UnixNano())
        // 有数据：通知时间轮重置超时
        globalWheel.refresh(c)
    }
    return n, err
}

func (c *peekedConn) Close() error {
    var err error
    c.closeOnce.Do(func() {
        // 从时间轮移除
        globalWheel.remove(c)
        err = c.Conn.Close()
    })
    return err
}

func (c *peekedConn) rstClose() {
    c.closeOnce.Do(func() {
        globalWheel.remove(c)
        setLinger0(c.Conn)
        c.Conn.Close()
    })
}

// ── 时间轮 ────────────────────────────────────────────────────────────────────

// timerWheel 单个全局 goroutine 管理所有连接的超时
// 原理：
//   slots[256] 每个槽代表一个时间片
//   连接注册时放入对应槽
//   指针每 tickInterval 前进一槽
//   指针扫过的槽里的连接检查是否真正超时
type timerWheel struct {
    mu           sync.Mutex
    slots        [wheelSlots]*list.List // 时间槽
    currentSlot  int                   // 当前指针位置
    tickInterval time.Duration         // 每槽时间精度
}

func newTimerWheel(tickInterval time.Duration) *timerWheel {
    tw := &timerWheel{
        tickInterval: tickInterval,
    }
    for i := range tw.slots {
        tw.slots[i] = list.New()
    }
    go tw.run()
    return tw
}

// 全局时间轮：精度 1s，256槽覆盖 256s
// 对于 600s 超时，连接会被放入 600%256=88 号槽的下一轮
// 时间轮会转多圈，每次扫到时检查真实 lastActive
var globalWheel = newTimerWheel(1 * time.Second)

// register 将连接注册到时间轮
func (tw *timerWheel) register(pc *peekedConn, timeout time.Duration) {
    pc.idleTimeout = timeout
    tw.mu.Lock()
    defer tw.mu.Unlock()

    slot := tw.targetSlot(timeout)
    elem := tw.slots[slot].PushBack(pc)

    pc.wheelMu.Lock()
    pc.wheelElem = elem
    pc.wheelMu.Unlock()
}

// refresh 连接有活动时，重新放入对应槽
func (tw *timerWheel) refresh(pc *peekedConn) {
    tw.mu.Lock()
    defer tw.mu.Unlock()

    pc.wheelMu.Lock()
    elem := pc.wheelElem
    pc.wheelMu.Unlock()

    if elem == nil {
        return
    }

    // 从当前槽移除
    for i := range tw.slots {
        if tw.slots[i] == elem.List() {
            tw.slots[i].Remove(elem)
            break
        }
    }

    // 重新放入新槽
    slot := tw.targetSlot(pc.idleTimeout)
    newElem := tw.slots[slot].PushBack(pc)

    pc.wheelMu.Lock()
    pc.wheelElem = newElem
    pc.wheelMu.Unlock()
}

// remove 连接关闭时从时间轮移除
func (tw *timerWheel) remove(pc *peekedConn) {
    tw.mu.Lock()
    defer tw.mu.Unlock()

    pc.wheelMu.Lock()
    elem := pc.wheelElem
    pc.wheelElem = nil
    pc.wheelMu.Unlock()

    if elem == nil {
        return
    }

    for i := range tw.slots {
        if tw.slots[i] == elem.List() {
            tw.slots[i].Remove(elem)
            return
        }
    }
}

// targetSlot 计算目标槽位
func (tw *timerWheel) targetSlot(timeout time.Duration) int {
    ticks := int(timeout / tw.tickInterval)
    tw.mu.Lock()
    slot := (tw.currentSlot + ticks) % wheelSlots
    tw.mu.Unlock()
    return slot
}

// run 时间轮驱动 goroutine，全局唯一
func (tw *timerWheel) run() {
    ticker := time.NewTicker(tw.tickInterval)
    defer ticker.Stop()

    for range ticker.C {
        tw.mu.Lock()
        tw.currentSlot = (tw.currentSlot + 1) % wheelSlots
        slot := tw.slots[tw.currentSlot]

        // 收集当前槽所有连接
        var expired []*peekedConn
        for elem := slot.Front(); elem != nil; elem = elem.Next() {
            pc := elem.Value.(*peekedConn)
            idleDuration := time.Since(
                time.Unix(0, pc.lastActive.Load()),
            )
            if idleDuration >= pc.idleTimeout {
                // 真正超时，加入待关闭列表
                expired = append(expired, pc)
            } else {
                // 未真正超时（时间轮转了一圈但连接仍活跃）
                // 重新放入正确的槽
                slot.Remove(elem)
                newSlot := tw.targetSlotLocked(pc.idleTimeout)
                newElem := tw.slots[newSlot].PushBack(pc)
                pc.wheelMu.Lock()
                pc.wheelElem = newElem
                pc.wheelMu.Unlock()
            }
        }
        tw.mu.Unlock()

        // 在锁外执行关闭，避免死锁
        for _, pc := range expired {
            if pc.enableLog && pc.logFile != "" {
                idleDuration := time.Since(
                    time.Unix(0, pc.lastActive.Load()),
                )
                globalLogger.send(
                    pc.logFile,
                    fmt.Sprintf("%s idle=%s\n",
                        pc.Conn.RemoteAddr().String(),
                        idleDuration.Round(time.Second),
                    ),
                )
            }
            pc.rstClose()
        }
    }
}

// targetSlotLocked 在已持有锁时计算槽位
func (tw *timerWheel) targetSlotLocked(timeout time.Duration) int {
    ticks := int(timeout / tw.tickInterval)
    return (tw.currentSlot + ticks) % wheelSlots
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
