package tlsversionmatch

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(TLSVersionMatcher{})
}

// TLSVersionMatcher 匹配指定 TLS 版本
type TLSVersionMatcher struct {
	Version         string         `json:"version,omitempty"`           // 目标 TLS 版本，例如 "1.3"
	IdleTimeout     caddy.Duration `json:"idle_timeout,omitempty"`      // 初始 TLS 握手超时时间
	MaxIdleDuration caddy.Duration `json:"max_idle_duration,omitempty"` // 滑动窗口监控时间
	MinBytesRead    int64          `json:"min_bytes_read,omitempty"`    // 滑动窗口内最小读取字节数
	LogFile         string         `json:"log_file,omitempty"`          // 日志文件路径
	EnableLog       bool           `json:"enable_log,omitempty"`        // 是否启用日志记录
	logMu           sync.Mutex
}

func (TLSVersionMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.tls_version",
		New: func() caddy.Module { return new(TLSVersionMatcher) },
	}
}

// Match 检查连接是否匹配目标 TLS 版本
func (m *TLSVersionMatcher) Match(conn *layer4.Connection) (bool, error) {
	rawConn := conn.Conn

	pconn := &timeoutConn{
		Conn:        rawConn,
		idleTimeout: time.Duration(m.IdleTimeout),
	}

	br := bufio.NewReader(pconn)

	// 读取 TLS record header（前 5 字节）
	header, err := br.Peek(5)
	if err != nil {
		return false, err
	}
	if header[0] != 0x16 {
		return false, errors.New("not a TLS handshake record")
	}

	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLength < 4 || recordLength > 1<<20 {
		return false, errors.New("invalid TLS record length")
	}

	data, err := br.Peek(5 + recordLength)
	if err != nil {
		return false, err
	}
	if len(data) < 11 || data[5] != 0x01 { // ClientHello
		return false, errors.New("not a ClientHello message or too short")
	}

	// 解析 ClientHello 支持的版本
	supportedVersions := parseClientHelloSupportedVersions(data)

	// 匹配用户指定版本
	matched := false
	for _, v := range supportedVersions {
		if v == m.Version {
			matched = true
			break
		}
	}

	// 包装 peekedConn 监控滑动窗口
	monitorConn := &peekedConn{
		Conn:           pconn,
		Reader:         br,
		monitorEnabled: false,
		logFile:        m.LogFile,
		enableLog:      m.EnableLog,
		logMu:          &m.logMu,
	}

	if m.MaxIdleDuration > 0 && m.MinBytesRead > 0 {
		monitorConn.monitorEnabled = true
		monitorConn.StartMonitor(time.Duration(m.MaxIdleDuration), m.MinBytesRead)
	}

	conn.Conn = monitorConn
	return matched, nil
}

// parseClientHelloSupportedVersions 安全解析 ClientHello 返回 supported_versions 列表
func parseClientHelloSupportedVersions(data []byte) []string {
	var versions []string
	if len(data) < 44 {
		return versions
	}

	offset := 5 + 1 + 2 + 32 // HandshakeType + Length(3) + Version(2) + Random(32)
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(data) {
		return versions
	}

	cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherLen
	if offset >= len(data) {
		return versions
	}

	compLen := int(data[offset])
	offset += 1 + compLen
	if offset+2 > len(data) {
		return versions
	}

	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	extEnd := offset + extLen
	if extEnd > len(data) {
		return versions
	}

	for extOff := offset; extOff+4 <= extEnd; {
		extType := binary.BigEndian.Uint16(data[extOff : extOff+2])
		extSize := int(binary.BigEndian.Uint16(data[extOff+2 : extOff+4]))
		extDataStart := extOff + 4
		extDataEnd := extDataStart + extSize
		if extDataEnd > len(data) {
			break
		}

		if extType == 0x002b && extSize >= 2 { // supported_versions
			listLen := int(data[extDataStart])
			if extDataStart+1+listLen <= extDataEnd {
				for i := 0; i < listLen; i += 2 {
					v := binary.BigEndian.Uint16(data[extDataStart+1+i : extDataStart+1+i+2])
					versions = append(versions, tlsVersionToString(v))
				}
			}
		}

		extOff = extDataEnd
	}

	// fallback legacy_version
	if len(versions) == 0 && len(data) >= 11 {
		version := binary.BigEndian.Uint16(data[9:11])
		versions = append(versions, tlsVersionToString(version))
	}

	return versions
}

// ================= peekedConn 包装连接，用于监控数据传输 =================
type peekedConn struct {
	net.Conn
	Reader         io.Reader
	mu             sync.Mutex
	totalBytes     int64
	monitorOnce    sync.Once
	monitorClosed  chan struct{}
	monitorEnabled bool
	logFile        string
	enableLog      bool
	logMu          *sync.Mutex
}

func (c *peekedConn) Read(b []byte) (int, error) {
	n, err := c.Reader.Read(b)
	if n > 0 {
		c.mu.Lock()
		c.totalBytes += int64(n)
		c.mu.Unlock()
	}
	if err != nil && c.monitorEnabled && c.monitorClosed != nil {
		select {
		case <-c.monitorClosed:
		default:
			close(c.monitorClosed)
		}
	}
	return n, err
}

func (c *peekedConn) StartMonitor(window time.Duration, minBytes int64) {
	c.monitorOnce.Do(func() {
		if window <= 0 || minBytes <= 0 {
			return
		}
		c.monitorClosed = make(chan struct{})
		var lastTotal int64

		go func() {
			ticker := time.NewTicker(window)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					c.mu.Lock()
					delta := c.totalBytes - lastTotal
					lastTotal = c.totalBytes
					c.mu.Unlock()

					if delta < minBytes {
						if c.enableLog && c.logFile != "" && c.logMu != nil {
							c.logMu.Lock()
							appendLog(c.logFile, c.Conn.RemoteAddr().String()+"\n")
							c.logMu.Unlock()
						}
						_ = c.Close()
						return
					}
				case <-c.monitorClosed:
					return
				}
			}
		}()
	})
}

func (c *peekedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.monitorEnabled && c.monitorClosed != nil {
		select {
		case <-c.monitorClosed:
		default:
			close(c.monitorClosed)
		}
	}
	return c.Conn.Close()
}

// ================= timeoutConn 保证 IdleTimeout 全程生效 =================
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

// appendLog 追加日志（高并发安全）
func appendLog(path, msg string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(msg)
}

// tlsVersionToString 转换 TLS 版本号
func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return "unknown"
	}
}

// 确保实现 layer4.ConnMatcher 接口
var _ layer4.ConnMatcher = (*TLSVersionMatcher)(nil)

