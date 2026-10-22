package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetCertFromPathValidity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	previousKeyFile := config.KeyFile
	config.KeyFile = keyPath
	t.Cleanup(func() { config.KeyFile = previousKeyFile })

	now := time.Now()
	for _, tc := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		domain    string
		valid     bool
	}{
		{"valid", now.Add(-time.Hour), now.Add(time.Hour), "example.com", true},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), "example.com", false},
		{"not yet valid", now.Add(time.Hour), now.Add(2 * time.Hour), "example.com", false},
		{"wrong hostname", now.Add(-time.Hour), now.Add(time.Hour), "other.example.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				DNSNames:     []string{"example.com"},
				NotBefore:    tc.notBefore,
				NotAfter:     tc.notAfter,
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			certPath := filepath.Join(dir, "cert.pem")
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			cert, err := getCertFromPath(tc.domain, certPath)
			if tc.valid {
				if err != nil || cert == nil {
					t.Fatalf("valid certificate rejected: %v", err)
				}
			} else if err == nil || cert != nil {
				t.Fatalf("invalid certificate accepted: cert=%v, err=%v", cert != nil, err)
			}
		})
	}
}
