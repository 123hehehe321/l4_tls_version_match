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

func (h TLSVersionMatch) Handle(ctx context.Context, conn net.Conn) error {
    clientHello, err := readClientHello(conn)
    if err != nil {
        return err
    }

    versionStr := tlsVersionToString(clientHello.Version)
    if versionStr != h.Version {
        conn.Close() // 立即中断连接
        return nil   // 不往下传递了
    }

    // Version 匹配，继续后续处理
    return layer4.NextHandler(ctx, conn)
}

func readClientHello(conn net.Conn) (*tls.ClientHelloInfo, error) {
    var recordHeader [5]byte
    if _, err := io.ReadFull(conn, recordHeader[:]); err != nil {
        return nil, err
    }

    if recordHeader[0] != 0x16 { // Handshake
        return nil, errors.New("not a handshake record")
    }

    // TLS Version in recordHeader[1:3] (skip checking)
    recordLength := binary.BigEndian.Uint16(recordHeader[3:5])
    if recordLength < 4 {
        return nil, errors.New("invalid record length")
    }

    handshake := make([]byte, recordLength)
    if _, err := io.ReadFull(conn, handshake); err != nil {
        return nil, err
    }

    if handshake[0] != 0x01 { // ClientHello
        return nil, errors.New("not a ClientHello")
    }

    // TLS Version is in handshake[4:6]
    version := binary.BigEndian.Uint16(handshake[4:6])
    return &tls.ClientHelloInfo{Version: version}, nil
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

// Interface check
var _ layer4.Handler = (*TLSVersionMatch)(nil)
