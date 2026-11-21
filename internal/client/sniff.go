package client

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
)

// sniffDomain inspects the initial client bytes of a TCP stream and returns
// the destination hostname from a TLS ClientHello SNI extension or an HTTP/1.x
// Host header. Literal IP addresses and non-matching protocols return "".
func sniffDomain(b []byte) string {
	if host := sniffTLSSNI(b); host != "" {
		return host
	}
	return sniffHTTPHost(b)
}

func sniffTLSSNI(b []byte) string {
	// TLS record header (5 bytes): ContentType=Handshake(22), Version(0x03xx), Length.
	if len(b) < 5 || b[0] != 0x16 || b[1] != 0x03 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 4 {
		return ""
	}
	rec := b[5:]
	if len(rec) > recLen {
		rec = rec[:recLen]
	}
	// Handshake header (4 bytes): MsgType=ClientHello(1), Length(3 bytes).
	if len(rec) < 4+2+32+1 || rec[0] != 0x01 {
		return ""
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	p := rec[4:]
	if len(p) > hsLen {
		p = p[:hsLen]
	}
	// Skip client_version(2) + random(32).
	if len(p) < 35 {
		return ""
	}
	p = p[34:]
	// Session ID.
	sidLen := int(p[0])
	if len(p) < 1+sidLen+2 {
		return ""
	}
	p = p[1+sidLen:]
	// Cipher suites.
	csLen := int(binary.BigEndian.Uint16(p[:2]))
	if len(p) < 2+csLen+1 {
		return ""
	}
	p = p[2+csLen:]
	// Compression methods.
	cmLen := int(p[0])
	if len(p) < 1+cmLen+2 {
		return ""
	}
	p = p[1+cmLen:]
	// Extensions.
	extLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) > extLen {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p[0:2])
		eLen := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if len(p) < eLen {
			return ""
		}
		if extType == 0x0000 { // server_name
			ext := p[:eLen]
			if len(ext) < 2 {
				return ""
			}
			listLen := int(binary.BigEndian.Uint16(ext[:2]))
			ext = ext[2:]
			if len(ext) > listLen {
				ext = ext[:listLen]
			}
			for len(ext) >= 3 {
				nameType := ext[0]
				nameLen := int(binary.BigEndian.Uint16(ext[1:3]))
				ext = ext[3:]
				if len(ext) < nameLen {
					return ""
				}
				if nameType == 0x00 {
					return validSniffedHost(string(ext[:nameLen]))
				}
				ext = ext[nameLen:]
			}
			return ""
		}
		p = p[eLen:]
	}
	return ""
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "),
}

func sniffHTTPHost(b []byte) string {
	matched := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			matched = true
			break
		}
	}
	if !matched {
		return ""
	}
	// Limit scan to header block.
	if end := bytes.Index(b, []byte("\r\n\r\n")); end >= 0 {
		b = b[:end]
	}
	lines := bytes.Split(b, []byte("\r\n"))
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(line[:colon])), "host") {
			val := strings.TrimSpace(string(line[colon+1:]))
			if h, _, err := net.SplitHostPort(val); err == nil {
				val = h
			}
			return validSniffedHost(val)
		}
	}
	return ""
}

func validSniffedHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\:@?#\r\n\t") {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	return host
}
