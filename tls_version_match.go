package tlsversionmatch

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

const (
	TLSVersion12 = "1.2"
	TLSVersion13 = "1.3"
)

func init() {
	caddy.RegisterModule(TLSVersionMatcher{})
}

// TLSVersionMatcher 匹配 TLS1.2 或 TLS1.3
type TLSVersionMatcher struct {
	Version         string         `json:"version,omitempty"`
	IdleTimeout     caddy.Duration `json:"idle_timeout,omitempty"`
	MaxIdleDuration caddy.Duration `json:"max_idle_duration,omitempty"`
	MinBytesRead    int64          `json:"min_bytes_read,omitempty"`
	LogFile         string         `json:"log_file,omitempty"`
	EnableLog       bool           `json:"enable_log,omitempty"`

	logChan  chan string
	logOnce  sync.Once
	closeLog sync.Once
}

func (TLSVersionMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.tls_version",
		New: func() caddy.Module { return new(TLSVersionMatcher) },
	}
}

// Match 检查连接是否匹配指定 TLS 版本
func (m *TLSVersionMatcher) Match(conn *layer4.Connection) (bool, error) {
	rawConn := conn.Conn
	pconn := &timeoutConn{Conn: rawConn, idleTimeout: time.Duration(m.IdleTimeout)}
	br := bufio.NewReader(pconn)

	// Peek TLS Record Header (5字节)
	header, err := br.Peek(5)
	if err != nil && err != io.EOF {
		return false, err
	}
	if len(header) < 5 || header[0] != 0x16 {
		return false, nil
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen < 4 || recordLen > 1<<20 {
		return false, nil
	}

	// Peek 足够多的 ClientHello 数据，保证 TLS1.3 支持
	data, err := br.Peek(5 + recordLen + 1024) // 多加1KB扩展空间
	if err != nil && err != io.EOF {
		return false, err
	}

	version := parseClientHelloTLS12or13(data)
	if version == "" || version != m.Version {
		return false, nil
	}

	// 初始化日志
	if m.EnableLog && m.LogFile != "" {
		m.logOnce.Do(func() {
			m.logChan = make(chan string, 1024)
			go asyncLogger(m.LogFile, m.logChan)
		})
	}

	// 包装 peekedConn
	monitorConn := &peekedConn{
		Conn:           pconn,
		Reader:         br,
		monitorEnabled: m.MaxIdleDuration > 0 && m.MinBytesRead > 0,
		logChan:        m.logChan,
	}

	if monitorConn.monitorEnabled {
		monitorConn.StartMonitor(time.Duration(m.MaxIdleDuration), m.MinBytesRead)
	}

	conn.Conn = monitorConn
	return true, nil
}

// ========================= ClientHello 解析 =========================
func parseClientHelloTLS12or13(data []byte) string {
	if len(data) < 11 {
		return ""
	}

	offset := 5 + 1 + 2 + 32
	if offset >= len(data) {
		return ""
	}

	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(data) {
		return ""
	}

	cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherLen
	if offset >= len(data) {
		return ""
	}

	compLen := int(data[offset])
	offset += 1 + compLen
	if offset+2 > len(data) {
		return ""
	}

	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	extEnd := offset + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for extOff := offset; extOff+4 <= extEnd; {
		extType := binary.BigEndian.Uint16(data[extOff : extOff+2])
		extSize := int(binary.BigEndian.Uint16(data[extOff+2 : extOff+4]))
		extDataStart := extOff + 4
		extDataEnd := extDataStart + extSize
		if extDataEnd > len(data) {
			break
		}

		// TLS 1.3 supported_versions 扩展
		if extType == 0x002b && extSize >= 2 {
			extData := data[extDataStart:extDataEnd]
			if len(extData) < 3 {
				break
			}
			listLen := int(extData[0])
			for i := 0; i < listLen; i += 2 {
				if 1+i+2 > len(extData) {
					break
				}
				v := binary.BigEndian.Uint16(extData[1+i : 1+i+2])
				if v == tls.VersionTLS12 {
					return TLSVersion12
				}
				if v == tls.VersionTLS13 {
					return TLSVersion13
				}
			}
		}

		extOff = extDataEnd
	}

	// fallback legacy_version (兼容 TLS1.2/1.3)
	version := binary.BigEndian.Uint16(data[9:11])
	if version == tls.VersionTLS12 {
		return TLSVersion12
	}
	if version == tls.VersionTLS13 {
		return TLSVersion13
	}

	return ""
}

// ========================= peekedConn =========================
type peekedConn struct {
	net.Conn
	Reader         io.Reader
	totalBytes     int64
	monitorOnce    sync.Once
	monitorCancel  context.CancelFunc
	monitorEnabled bool
	logChan        chan string
	mu             sync.Mutex
}

func (c *peekedConn) Read(b []byte) (int, error) {
	n, err := c.Reader.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.totalBytes, int64(n))
	}
	if err != nil {
		c.stopMonitor()
	}
	return n, err
}

func (c *peekedConn) Close() error {
	c.stopMonitor()
	return c.Conn.Close()
}

func (c *peekedConn) stopMonitor() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.monitorEnabled && c.monitorCancel != nil {
		c.monitorCancel()
		c.monitorCancel = nil
	}
}

func (c *peekedConn) StartMonitor(window time.Duration, minBytes int64) {
	c.monitorOnce.Do(func() {
		if window <= 0 || minBytes <= 0 {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		c.monitorCancel = cancel
		var lastTotal int64

		go func() {
			ticker := time.NewTicker(window)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					current := atomic.LoadInt64(&c.totalBytes)
					delta := current - lastTotal
					lastTotal = current

					if delta < minBytes {
						if c.logChan != nil {
							c.logChan <- time.Now().Format(time.RFC3339) + " " + c.Conn.RemoteAddr().String()
						}
						_ = c.Close()
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	})
}

// ========================= timeoutConn =========================
type timeoutConn struct {
	net.Conn
	idleTimeout time.Duration
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	if c.idleTimeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
	}
	return c.Conn.Read(b)
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	if c.idleTimeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idleTimeout))
	}
	return c.Conn.Write(b)
}

// ========================= asyncLogger =========================
func asyncLogger(path string, logChan <-chan string) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file %s: %v\n", path, err)
		return
	}
	defer f.Close()

	for msg := range logChan {
		_, _ = f.WriteString(msg + "\n")
	}
}

// ========================= 接口实现 =========================
var _ layer4.ConnMatcher = (*TLSVersionMatcher)(nil)
