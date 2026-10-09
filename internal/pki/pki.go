package pki

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"github.com/674542449/tunnelx-lite/internal/config"
	"math/big"
	"time"
)

func ECH(publicName string) (config.ECHKey, []byte, error) {
	if len(publicName) < 1 || len(publicName) > 253 {
		return config.ECHKey{}, nil, errors.New("invalid ECH public name")
	}
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return config.ECHKey{}, nil, e
	}
	id := make([]byte, 1)
	if _, e = rand.Read(id); e != nil {
		return config.ECHKey{}, nil, e
	}
	// ECHConfig: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
	b := append([]byte{}, id...)
	b = binary.BigEndian.AppendUint16(b, 0x20)
	b = binary.BigEndian.AppendUint16(b, 32)
	b = append(b, k.PublicKey().Bytes()...)
	b = binary.BigEndian.AppendUint16(b, 4)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = append(b, 64, byte(len(publicName)))
	b = append(b, publicName...)
	b = binary.BigEndian.AppendUint16(b, 0)
	c := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	c = binary.BigEndian.AppendUint16(c, uint16(len(b)))
	c = append(c, b...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(c)))
	list = append(list, c...)
	return config.ECHKey{Config: c, PrivateKey: k.Bytes()}, list, nil
}
func Certificate(name string) (ca, cert, key []byte, err error) {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, nil, e
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, nil, e
	}
	now := time.Now()
	serial := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); return n }
	root := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "tunnelX private origin CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &caKey.PublicKey, caKey)
	if e != nil {
		return nil, nil, nil, e
	}
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 6, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, caKey)
	if e != nil {
		return nil, nil, nil, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		return nil, nil, nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), nil
}

// SelfSigned issues one long-lived certificate covering every name. Clients
// trust it by public-key pin, so it never needs a CA or a public domain.
func SelfSigned(names []string, years int) (cert, key []byte, err error) {
	if len(names) == 0 || years < 1 {
		return nil, nil, errors.New("self-signed certificate needs names and a lifetime")
	}
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, e
	}
	now := time.Now()
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(years, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if e != nil {
		return nil, nil, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return nil, nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), nil
}
