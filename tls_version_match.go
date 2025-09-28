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
	// 注册模块到 Caddy
	caddy.RegisterModule(TLSVersionMatcher{})
}

// TLSVersionMatcher 用于匹配指定版本的 TLS 握手连接
type TLSVersionMatcher struct {
	Version         string         `json:"version,omitempty"`           // 目标 TLS 版本（例如 "1.3"）
	IdleTimeout     caddy.Duration `json:"idle_timeout,omitempty"`      // 初始握手超时
	MaxIdleDuration caddy.Duration `json:"max_idle_duration,omitempty"` // 滑动窗口检测时间
	MinBytesRead    int64          `json:"min_bytes_read,omitempty"`    // 窗口内最小总读取字节数
	LogFile         string         `json:"log_file,omitempty"`          // 日志文件路径
	EnableLog       bool           `json:"enable_log,omitempty"`        // 是否启用日志
}

func (TLSVersionMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.tls_version",
		New: func() caddy.Module { return new(TLSVersionMatcher) },
	}
}

// Match 实现连接匹配逻辑
func (m *TLSVersionMatcher) Match(conn *layer4.Connection) (bool, error) {
	rawConn := conn.Conn

	// 设置握手超时，默认 3s，可以通过 idle_timeout 参数覆盖
	timeout := 3 * time.Second
	if m.IdleTimeout != 0 {
		timeout = time.Duration(m.IdleTimeout)
	}
	_ = rawConn.SetReadDeadline(time.Now().Add(timeout))

	br := bufio.NewReader(rawConn)

	// =================== 读取 TLS Record Header ===================
	header, err := br.Peek(5) // TLS 记录层头部固定 5 字节
	if err != nil {
		return false, err
	}

	// 第一个字节必须是 handshake (0x16)
	if header[0] != 0x16 {
		return false, errors.New("not a TLS handshake record")
	}

	// 获取记录长度
	recordLength := binary.BigEndian.Uint16(header[3:5])
	if recordLength < 4 {
		return false, errors.New("invalid TLS record length")
	}

	// =================== 读取完整 ClientHello ===================
	data, err := br.Peek(5 + int(recordLength))
	if err != nil {
		return false, err
	}

	// Handshake 类型必须是 ClientHello (0x01)
	if data[5] != 0x01 {
		return false, errors.New("not a ClientHello message")
	}

	// 默认读取 client_version 字段 (bytes 9-10)，可能是 TLS1.0~1.2
	version := binary.BigEndian.Uint16(data[9:11])
	versionStr := tlsVersionToString(version)

	// =================== 尝试解析扩展 supported_versions (0x002b) ===================
	// ClientHello 格式：SessionID -> CipherSuites -> Compression -> Extensions
	if len(data) >= 44 {
		sessionIDL := int(data[43]) // Session ID 长度
		offset := 44 + sessionIDL   // 跳过 SessionID

		// CipherSuites
		if offset+2 <= len(data) {
			cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2 + cipherLen

			// Compression
			if offset < len(data) {
				compLen := int(data[offset])
				offset += 1 + compLen

				// Extensions
				if offset+2 <= len(data) {
					extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
					offset += 2

					// 遍历扩展
					for extOff := offset; extOff+4 <= offset+extLen; {
						extType := binary.BigEndian.Uint16(data[extOff : extOff+2])
						extSize := int(binary.BigEndian.Uint16(data[extOff+2 : extOff+4]))
						extDataStart := extOff + 4
						extDataEnd := extDataStart + extSize

						// 越界保护
						if extDataEnd > offset+extLen {
							break
						}

						// 找到 supported_versions 扩展
						if extType == 0x002b && extSize >= 3 {
							listLen := int(data[extDataStart])
							for i := extDataStart + 1; i < extDataStart+1+listLen; i += 2 {
								sver := binary.BigEndian.Uint16(data[i : i+2])
								if sver == tls.VersionTLS13 {
									versionStr = "1.3"
								}
							}
						}
						extOff = extDataEnd
					}
				}
			}
		}
	}

	// =================== 包装连接，避免 Peek 过的数据丢失 ===================
	pconn := &peekedConn{
		Conn:           rawConn,
		Reader:         br,
		monitorEnabled: false,
		logFile:        m.LogFile,
		enableLog:      m.EnableLog,
	}

	// =================== 启动滑动窗口监控 ===================
	if m.MaxIdleDuration > 0 && m.MinBytesRead > 0 {
		pconn.monitorEnabled = true
		pconn.StartMonitor(time.Duration(m.MaxIdleDuration), m.MinBytesRead)
	}

	conn.Conn = pconn

	// 清除超时设置
	_ = rawConn.SetReadDeadline(time.Time{})

	// 返回是否匹配
	return versionStr == m.Version, nil
}

// ========== 包装连接，带字节计数和监控 ==========
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
}

// Read 包装读取操作，记录总字节数
func (c *peekedConn) Read(b []byte) (int, error) {
	n, err := c.Reader.Read(b)

	c.mu.Lock()
	if n > 0 {
		c.totalBytes += int64(n)
	}
	c.mu.Unlock()

	// 如果启用了监控器，并且发生错误，则关闭监控协程
	if c.monitorEnabled && err != nil && c.monitorClosed != nil {
		select {
		case <-c.monitorClosed:
		default:
			close(c.monitorClosed)
		}
	}
	return n, err
}

// StartMonitor 启动一个 goroutine 定期检测字节流量
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

					// 如果在窗口内流量不足，记录日志并关闭连接
					if delta < minBytes {
						if c.enableLog && c.logFile != "" {
							remoteAddr := c.Conn.RemoteAddr().String()
							go appendLog(c.logFile, remoteAddr+"\n")
						}
						c.Close()
						return
					}

				case <-c.monitorClosed:
					return
				}
			}
		}()
	})
}

// Close 安全关闭连接和监控器
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

// 追加日志
func appendLog(path, msg string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(msg)
}

// ========== TLS版本转字符串 ==========
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

// 保证实现接口
var _ layer4.ConnMatcher = (*TLSVersionMatcher)(nil)
