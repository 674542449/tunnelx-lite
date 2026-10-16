package wire

import (
	"errors"
	"io"
	"time"

	"github.com/apernet/quic-go"
)

// QUIC carries one proxied flow per bidirectional stream, so a lost packet
// only stalls the flow it belongs to. Every stream starts with
//
//	version(1) kind(1) len(1) token len(1) "host:port"
//
// and the server answers with one status byte before relaying raw bytes
// (TCP) or capsule-framed datagrams (UDP). A wrong key closes the whole
// connection without an answer.
const (
	QUICALPN    = "txlite-quic/1"
	QUICVersion = 1
	QUICTCP     = 1
	QUICUDP     = 2
	// QUICControl carries "cc=<mode>;rx=<bytes per second>" instead of a
	// target: how the server should send towards this client.
	QUICControl = 3

	QUICOK         = 0
	QUICBadRequest = 1
	QUICForbidden  = 2
	QUICBadGateway = 3
	QUICTimeout    = 4
	QUICBusy       = 5
)

// QUICStatus maps an answer byte to the HTTP status the H2 transport would report.
func QUICStatus(code byte) int {
	switch code {
	case QUICOK:
		return 200
	case QUICBadRequest:
		return 400
	case QUICForbidden:
		return 403
	case QUICTimeout:
		return 504
	case QUICBusy:
		return 429
	}
	return 502
}

// QUICConfig is shared by client and server so both sides agree on limits.
var QUICConfig = func() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           5 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		MaxIncomingStreams:             1024,
		MaxIncomingUniStreams:          -1,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         16 << 20,
		InitialConnectionReceiveWindow: 4 << 20,
		MaxConnectionReceiveWindow:     64 << 20,
	}
}

// QUICHeader builds the stream preamble sent by clients.
func QUICHeader(kind byte, token, target string) ([]byte, error) {
	if len(token) == 0 || len(token) > 255 || len(target) == 0 || len(target) > 255 {
		return nil, errors.New("token or target too long")
	}
	b := []byte{QUICVersion, kind, byte(len(token))}
	b = append(b, token...)
	b = append(b, byte(len(target)))
	return append(b, target...), nil
}

// ReadQUICHeader parses the preamble written by QUICHeader.
func ReadQUICHeader(r io.Reader) (kind byte, token, target string, err error) {
	head := make([]byte, 3)
	if _, err = io.ReadFull(r, head); err != nil {
		return
	}
	if head[0] != QUICVersion || head[1] < QUICTCP || head[1] > QUICControl || head[2] == 0 {
		return 0, "", "", errors.New("bad header")
	}
	b := make([]byte, int(head[2])+1)
	if _, err = io.ReadFull(r, b); err != nil {
		return
	}
	n := int(b[len(b)-1])
	if n == 0 {
		return 0, "", "", errors.New("bad target")
	}
	t := make([]byte, n)
	if _, err = io.ReadFull(r, t); err != nil {
		return
	}
	return head[1], string(b[:len(b)-1]), string(t), nil
}
