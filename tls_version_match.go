package tlsversionmatch

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(TLSVersionMatcher{})
}

type TLSVersionMatcher struct {
	Version      string         `json:"version,omitempty"`       // 目标 TLS 版本（例如 "1.3"）
	IdleTimeout  caddy.Duration `json:"idle_timeout,omitempty"`  // 初始读入时限
	CheckInterval caddy.Duration `json:"check_interval,omitempty"` // 检查间隔时间，例：10s
}

func (TLSVersionMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.tls_version",
		New: func() caddy.Module { return new(TLSVersionMatcher) },
	}
}

func (m *TLSVersionMatcher) Match(conn *layer4.Connection) (bool, error) {
	rawConn := conn.Conn

	// 设置初始读取超时
	timeout := 3 * time.Second
	if m.IdleTimeout != 0 {
		timeout = time.Duration(m.IdleTimeout)
	}
	_ = rawConn.SetReadDeadline(time.Now().Add(timeout))

	// 使用 bufio 包装读取器
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

	version := binary.BigEndian.Uint16(data[9:11])
	versionStr := tlsVersionToString(version)

	// 包装 conn，避免数据丢失
	conn.Conn = &peekedConn{
		Conn:   rawConn,
		Reader: br,
	}

	// 清除超时
	_ = rawConn.SetReadDeadline(time.Time{})

	// 新增部分 启动周期性空闲检测（非阻塞）
	if m.CheckInterval > 0 {
		go startIdleMonitor(rawConn, time.Duration(m.CheckInterval))
	}

	return versionStr == m.Version, nil
}

// peekedConn 保留 Peek 后的 Reader
type peekedConn struct {
	net.Conn
	Reader io.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

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

// 周期性空闲检测逻辑
func startIdleMonitor(conn net.Conn, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	buffer := make([]byte, 1)

	for range ticker.C {
		_ = conn.SetReadDeadline(time.Now().Add(interval))

		// 尝试读取 1 字节，如果超时说明连接空闲
		_, err := conn.Read(buffer)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				_ = conn.Close()
				return
			}
			// 其它错误，例如连接已关闭，也结束检测
			return
		}

		// 有数据则继续下一轮
	}
}

// 声明该类型为 layer4.Matcher
var _ layer4.ConnMatcher = (*TLSVersionMatcher)(nil)
