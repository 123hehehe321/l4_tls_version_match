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
    caddy.RegisterModule(TLSVersionMatcher{})
}

type TLSVersionMatcher struct {
    Version string `json:"version,omitempty"`
}

func (TLSVersionMatcher) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "layer4.matchers.tls_version",
        New: func() caddy.Module { return new(TLSVersionMatcher) },
    }
}

func (m *TLSVersionMatcher) Match(conn *layer4.Connection) (bool, error) {
    br := bufio.NewReader(conn.Conn)

    // Peek TLS Record Header
    header, err := br.Peek(5)
    if err != nil {
        return false, err
    }

    if header[0] != 0x16 { // Handshake
        return false, errors.New("not a TLS handshake record")
    }

    recordLength := binary.BigEndian.Uint16(header[3:5])
    if recordLength < 4 {
        return false, errors.New("invalid TLS record length")
    }

    // Peek Full TLS Record
    data, err := br.Peek(5 + int(recordLength))
    if err != nil {
        return false, err
    }

    if data[5] != 0x01 { // ClientHello
        return false, errors.New("not a ClientHello message")
    }

    version := binary.BigEndian.Uint16(data[9:11])
    versionStr := tlsVersionToString(version)

    // Wrap back the buffered data
    conn.Conn = &peekedConn{
        Conn:   conn.Conn,
        Reader: br,
    }

    return versionStr == m.Version, nil
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

var _ layer4.ConnMatcher = (*TLSVersionMatcher)(nil)
