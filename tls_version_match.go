package tlsversionmatch

import (
    "bufio"
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

func (h TLSVersionMatch) Handle(conn *layer4.Connection) error {
    br := bufio.NewReader(conn.Conn)

    // Peek TLS Record Header
    header, err := br.Peek(5)
    if err != nil {
        return err
    }

    if header[0] != 0x16 { // Handshake
        return errors.New("not a TLS handshake record")
    }

    recordLength := binary.BigEndian.Uint16(header[3:5])
    if recordLength < 4 {
        return errors.New("invalid TLS record length")
    }

    // Peek Full TLS Record
    data, err := br.Peek(5 + int(recordLength))
    if err != nil {
        return err
    }

    if data[5] != 0x01 { // ClientHello
        return errors.New("not a ClientHello message")
    }

    version := binary.BigEndian.Uint16(data[9:11])
    versionStr := tlsVersionToString(version)

    if versionStr != h.Version {
        conn.Conn.Close()
        return nil
    }

    // Wrap the conn.Conn with buffered reader data
    conn.Conn = &peekedConn{
        Conn:   conn.Conn,
        Reader: br,
    }

    return nil // continue to next handler
}

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

var _ layer4.Handler = (*TLSVersionMatch)(nil)


