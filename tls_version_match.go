package tlsversionmatch

import (
    "crypto/tls"
    "encoding/binary"
    "errors"
    "io"

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

func (h TLSVersionMatch) Handle(conn *layer4.Connection) error {
    // 先 Peek 出前 5 个字节 (TLS record header)
    recordHeader, err := conn.Peek(5)
    if err != nil {
        return err
    }

    if recordHeader[0] != 0x16 { // Handshake
        return errors.New("not a TLS handshake record")
    }

    recordLength := binary.BigEndian.Uint16(recordHeader[3:5])
    if recordLength < 4 {
        return errors.New("invalid TLS record length")
    }

    // Peek 完整的 ClientHello
    helloBytes, err := conn.Peek(5 + int(recordLength))
    if err != nil {
        return err
    }

    handshakeType := helloBytes[5]
    if handshakeType != 0x01 { // ClientHello
        return errors.New("not a ClientHello message")
    }

    // TLS Version is in helloBytes[9:11]
    version := binary.BigEndian.Uint16(helloBytes[9:11])
    versionStr := tlsVersionToString(version)

    if versionStr != h.Version {
        conn.Close()
        return nil // 不继续处理
    }

    // 继续后续 handler
    return conn.Next()
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

var _ layer4.Handler = (*TLSVersionMatch)(nil)
