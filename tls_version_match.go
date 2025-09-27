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

// TLSVersionMatcher 用于匹配指定版本的 TLS 握手连接
type TLSVersionMatcher struct {
	Version         string         `json:"version,omitempty"`           // 目标 TLS 版本（例如 "1.3"）
	IdleTimeout     caddy.Duration `json:"idle_timeout,omitempty"`      // 初始握手超时
	MaxIdleDuration caddy.Duration `json:"max_idle_duration,omitempty"` // 匹配成功后最大空闲时长
	MinBytesRead    int64          `json:"min_bytes_read,omitempty"`    // 最小总读取字节数
	LogFile         string         `json:"log_file,omitempty"`          // 日志文件路径
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

	// 设置初始握手的读取超时
	timeout := 3 * time.Second
	if m.IdleTimeout != 0 {
		timeout = time.Duration(m.IdleTimeout)
	}
	_ = rawConn.SetReadDeadline(time.Now().Add(timeout))

	   
	br := bufio.NewReader(rawConn)

	// 读取 TLS Record Header
	header, err := br.Peek(5)
	if err != nil {
		return false, err
	}

	if header[0] != 0x16 {
		return false, errors.New("not a TLS handshake record")
	}

	recordLength := binary.BigEndian.Uint16(header[3:5])
	if recordLength < 4 {
		return false, errors.New("invalid TLS record length")
	}

	// 读取完整 ClientHello
	data, err := br.Peek(5 + int(recordLength))
	if err != nil {
		return false, err
	}

	if data[5] != 0x01 {
		return false, errors.New("not a ClientHello message")
	}

	// 默认读取 client_version 字段 (bytes 9-10)
	version := binary.BigEndian.Uint16(data[9:11])
	versionStr := tlsVersionToString(version)

	// 尝试解析 extensions，检查 supported_versions (0x002b)
								   
	if len(data) < 44 {
		return false, errors.New("ClientHello too short")
	}
	sessionIDL := int(data[43])
	offset := 44 + sessionIDL

	// cipher suites
	if offset+2 > len(data) {
		return false, errors.New("malformed ClientHello (cipher suites)")
	}
	cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherLen

	// compression methods
	if offset >= len(data) {
		return false, errors.New("malformed ClientHello (compression)")
	}
	compLen := int(data[offset])
	offset += 1 + compLen

	// extensions length
	if offset+2 > len(data) {
		return false, errors.New("malformed ClientHello (extensions length)")
	}
	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+extLen > len(data) {
		return false, errors.New("malformed ClientHello (extensions)")
	}

	// 遍历 extensions
	for extOff := offset; extOff+4 <= offset+extLen; {
		extType := binary.BigEndian.Uint16(data[extOff : extOff+2])
		extSize := int(binary.BigEndian.Uint16(data[extOff+2 : extOff+4]))
		extDataStart := extOff + 4
		extDataEnd := extDataStart + extSize

		if extDataEnd > offset+extLen {
			break
		}

		// supported_versions (0x002b)
		if extType == 0x002b {
			if extSize < 3 {
				break
			}
			listLen := int(data[extDataStart])
			if extDataStart+1+listLen > extDataEnd {
				break
			}
			// 遍历 supported_versions 列表
			for i := extDataStart + 1; i < extDataStart+1+listLen; i += 2 {
				sver := binary.BigEndian.Uint16(data[i : i+2])
				if sver == tls.VersionTLS13 {
					versionStr = "1.3"
				}
			}
		}

		extOff = extDataEnd
	}

	// 包装 conn，避免数据丢失
	pconn := &peekedConn{
		Conn:           rawConn,
		Reader:         br,
		monitorEnabled: false,
		logFile:        m.LogFile,
	}

	// 启动最大空闲 & 最小数据监测
	if m.MaxIdleDuration > 0 || m.MinBytesRead > 0 {
		pconn.monitorEnabled = true
		pconn.StartMonitor(time.Duration(m.MaxIdleDuration), m.MinBytesRead)
	}

	conn.Conn = pconn

	// 清除读取超时
	_ = rawConn.SetReadDeadline(time.Time{})

	return versionStr == m.Version, nil
}

// ========== 包装连接 ==========
type peekedConn struct {
	net.Conn
	Reader         io.Reader
	mu             sync.Mutex
	totalBytes     int64
	lastReadTime   time.Time
	monitorOnce    sync.Once
	monitorClosed  chan struct{}
	monitorEnabled bool
	logFile        string
}

// Read 包装读取操作，记录总读取字节数和最后读取时间
func (c *peekedConn) Read(b []byte) (int, error) {
	n, err := c.Reader.Read(b)

	c.mu.Lock()
	defer c.mu.Unlock()

	if n > 0 {
		c.totalBytes += int64(n)
		c.lastReadTime = time.Now()
	}
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

// 启动监控协程
func (c *peekedConn) StartMonitor(maxIdle time.Duration, minBytes int64) {
	c.monitorOnce.Do(func() {
		c.monitorClosed = make(chan struct{})
		// 初始化最后读取时间
		
		c.lastReadTime = time.Now()

		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					c.mu.Lock()
					idle := time.Since(c.lastReadTime)
					total := c.totalBytes
					c.mu.Unlock()

					if maxIdle > 0 && idle > maxIdle {
						c.Close()
						return
					}

					if minBytes > 0 && total < minBytes && idle > maxIdle {
						// 写日志
						if c.logFile != "" {
							remoteAddr := c.Conn.RemoteAddr().String()
							msg := time.Now().Format(time.RFC3339) + " - closed due to MinBytesRead not met: " + remoteAddr + "\n"
							go appendLog(c.logFile, msg)
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

// Close 安全关闭连接与监控器
func (c *peekedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 安全关闭 channel，避免 panic
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

// 接口实现保证
var _ layer4.ConnMatcher = (*TLSVersionMatcher)(nil)																																									 
