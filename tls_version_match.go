package tlsversionmatch

import (
    "context"
    "crypto/tls"
    "encoding/binary"
    "errors"
    "io"
    "net"

    "github.com/caddyserver/caddy/v2"
    "github.com/mholt/caddy-l4/layer4"
)

func init() {
    caddy.RegisterModule(TLSVersionMatch{})
}

type TLSVersionMatch struct {
    Version string `json:"version,omitempty"`
}

func (TLSVersionMatch) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "layer4.handlers.tls_version_match",
        New: func() caddy.Module { return new(TLSVersionMatch) },
    }
}

// 这里必须符合 layer4.Handler 接口
func (h TLSVersionMatch) Handle(conn *layer4.Connection) error {
    // 读取 ClientHello，获得 TLS 版本
    version, err := readClientHello(conn.RawConn())
    if err != nil {
        return err
    }

    versionStr := tlsVersionToString(version)
    if versionStr != h.Version {
        // 不匹配就直接断开
        conn.Close()
        return nil // 不再继续处理
    }

    // 匹配成功，继续下一个 handler
    return layer4.NextHandler(conn)
}

func readClientHello(conn net.Conn) (uint16, error) {
    var recordHeader [5]byte
    if _, err := io.ReadFull(conn, recordHeader[:]); err != nil {
        return 0, err
    }

    if recordHeader[0] != 0x16 { // handshake
        return 0, errors.New("not a handshake record")
    }

    recordLength := binary.BigEndian.Uint16(recordHeader[3:5])
    if recordLength < 4 {
        return 0, errors.New("invalid record length")
    }

    handshake := make([]byte, recordLength)
    if _, err := io.ReadFull(conn, handshake); err != nil {
        return 0, err
    }

    if handshake[0] != 0x01 { // client hello
        return 0, errors.New("not a ClientHello")
    }

    version := binary.BigEndian.Uint16(handshake[4:6])
    return version, nil
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

// 确保实现 layer4.Handler 接口
var _ layer4.Handler = (*TLSVersionMatch)(nil)
