package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func selfSignedTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vision.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"vision.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type visionConn struct {
	*VisionReader
	*VisionWriter
	raw net.Conn
}

func (c *visionConn) Close() error                       { c.StopTimer(); return c.raw.Close() }
func (c *visionConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *visionConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *visionConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *visionConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *visionConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func visionOuterPair(t *testing.T, cert tls.Certificate) (clientVC, serverVC *visionConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	srvReady := make(chan *visionConn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		ec := NewExactRecordConn(raw)
		tc := tls.Server(ec, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return
		}
		st := NewVisionState()
		srvReady <- &visionConn{
			VisionReader: NewVisionReader(tc, ec, st, false),
			VisionWriter: NewVisionWriter(tc, raw, st, false, nil),
			raw:          raw,
		}
	}()

	rawC, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ecC := NewExactRecordConn(rawC)
	tcC := tls.Client(ecC, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if err := tcC.Handshake(); err != nil {
		t.Fatal(err)
	}
	stC := NewVisionState()
	clientVC = &visionConn{
		VisionReader: NewVisionReader(tcC, ecC, stC, true),
		VisionWriter: NewVisionWriter(tcC, rawC, stC, true, nil),
		raw:          rawC,
	}
	serverVC = <-srvReady
	t.Cleanup(func() { clientVC.Close(); serverVC.Close() })
	return clientVC, serverVC
}

func TestVisionInnerTLS13SwitchesBothSidesToDirect(t *testing.T) {
	cert := selfSignedTLS(t)
	clientVC, serverVC := visionOuterPair(t, cert)

	payload := make([]byte, 3<<20) // 3 MiB
	_, _ = rand.Read(payload)
	wantHash := sha256.Sum256(payload)

	srvErr := make(chan error, 1)
	go func() {
		innerSrv := tls.Server(serverVC, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
		if err := innerSrv.Handshake(); err != nil {
			srvErr <- err
			return
		}
		buf := make([]byte, 64<<10)
		for {
			n, err := innerSrv.Read(buf)
			if n > 0 {
				if _, we := innerSrv.Write(buf[:n]); we != nil {
					srvErr <- we
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				srvErr <- err
				return
			}
		}
	}()

	innerCli := tls.Client(clientVC, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if err := innerCli.Handshake(); err != nil {
		t.Fatal("inner TLS 1.3 handshake failed:", err)
	}
	go func() {
		_, _ = io.Copy(innerCli, bytes.NewReader(payload))
		_ = innerCli.CloseWrite()
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(innerCli, got); err != nil {
		t.Fatal("inner TLS 1.3 read failed:", err)
	}
	if sha256.Sum256(got) != wantHash {
		t.Fatal("inner TLS 1.3 payload mismatch")
	}
	innerCli.Close()
	if err := <-srvErr; err != nil {
		t.Fatal("inner server error:", err)
	}
	if !clientVC.VisionWriter.IsDirect() || !clientVC.VisionReader.IsDirect() ||
		!serverVC.VisionWriter.IsDirect() || !serverVC.VisionReader.IsDirect() {
		t.Fatalf("expected all 4 Vision directions to switch to direct raw TCP: cw=%v cr=%v sw=%v sr=%v",
			clientVC.VisionWriter.IsDirect(), clientVC.VisionReader.IsDirect(),
			serverVC.VisionWriter.IsDirect(), serverVC.VisionReader.IsDirect())
	}
}

func TestVisionInnerTLS12AndPlaintextStayInOuterTLS(t *testing.T) {
	cert := selfSignedTLS(t)

	// 1. Inner TLS 1.2 must NOT drop outer TLS.
	t.Run("tls12", func(t *testing.T) {
		clientVC, serverVC := visionOuterPair(t, cert)
		done := make(chan error, 1)
		go func() {
			s := tls.Server(serverVC, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
			if err := s.Handshake(); err != nil {
				done <- err
				return
			}
			buf := make([]byte, 16)
			n, _ := s.Read(buf)
			_, _ = s.Write(buf[:n])
			done <- nil
		}()
		c := tls.Client(clientVC, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true})
		if err := c.Handshake(); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("tls12-ok"))
		got := make([]byte, 8)
		if _, err := io.ReadFull(c, got); err != nil || string(got) != "tls12-ok" {
			t.Fatalf("tls12 echo failed: %q %v", string(got), err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if clientVC.VisionWriter.IsDirect() || serverVC.VisionWriter.IsDirect() {
			t.Fatal("TLS 1.2 unexpectedly switched to direct raw TCP")
		}
	})

	// 2. Plain HTTP must NOT drop outer TLS.
	t.Run("plaintext", func(t *testing.T) {
		clientVC, serverVC := visionOuterPair(t, cert)
		go func() {
			buf := make([]byte, 64)
			n, _ := serverVC.Read(buf)
			_, _ = serverVC.Write(buf[:n])
		}()
		msg := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		if _, err := clientVC.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(clientVC, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("plaintext echo failed: %q %v", string(got), err)
		}
		if clientVC.VisionWriter.IsDirect() || serverVC.VisionWriter.IsDirect() {
			t.Fatal("plaintext unexpectedly switched to direct raw TCP")
		}
		if !clientVC.VisionWriter.IsOuterTLS() {
			t.Fatal("plaintext did not settle into outer TLS pass-through")
		}
	})
}

func TestInspectServerHelloRejectsHRR(t *testing.T) {
	// Build a minimal ServerHello carrying the HelloRetryRequest random + 0x0304 supported_versions.
	ext := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	body := append([]byte{0x03, 0x03}, helloRetryRequestRandom[:]...)
	body = append(body, 0x00)       // session id len
	body = append(body, 0x13, 0x01) // cipher suite
	body = append(body, 0x00)       // compression
	body = append(body, 0x00, byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{0x02, 0x00, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}, hs...)

	matched, hrr, definite := InspectServerHello(rec)
	if matched || !hrr || !definite {
		t.Fatalf("expected HRR detection (matched=false,hrr=true,definite=true), got %v %v %v", matched, hrr, definite)
	}
}
