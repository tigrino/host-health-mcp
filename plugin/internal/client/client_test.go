package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestKeypair generates an ephemeral leaf+CA pair and writes
// cert/key/ca PEM files into dir. Returns their paths. Used by the
// CAPath fail-closed tests; the certs are not actually verified
// against any server in these tests.
func writeTestKeypair(t *testing.T, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "operator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	caPath = filepath.Join(dir, "ca.pem")
	leafKeyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, caPath
}

// TestNewRejectsEmptyCAPathWithoutOptIn covers the M-6 fail-closed
// behaviour: an empty CAPath without the explicit env opt-in is an
// error, not a silent fallback to system root CAs.
func TestNewRejectsEmptyCAPathWithoutOptIn(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := writeTestKeypair(t, dir)
	t.Setenv(EnvTrustSystemRoots, "")
	_, err := New(Config{CertPath: cert, KeyPath: key, CAPath: ""})
	if err == nil {
		t.Fatal("New() accepted empty CAPath without opt-in; expected error")
	}
}

// TestNewAcceptsEmptyCAPathWithOptIn covers the opt-in branch.
func TestNewAcceptsEmptyCAPathWithOptIn(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := writeTestKeypair(t, dir)
	t.Setenv(EnvTrustSystemRoots, "1")
	c, err := New(Config{CertPath: cert, KeyPath: key, CAPath: ""})
	if err != nil {
		t.Fatalf("New() with opt-in returned error: %v", err)
	}
	if c == nil {
		t.Fatal("New() returned nil client without error")
	}
}

// TestNewAcceptsExplicitCAPath confirms the standard path still
// works.
func TestNewAcceptsExplicitCAPath(t *testing.T) {
	dir := t.TempDir()
	cert, key, ca := writeTestKeypair(t, dir)
	c, err := New(Config{CertPath: cert, KeyPath: key, CAPath: ca})
	if err != nil {
		t.Fatalf("New() with CAPath: %v", err)
	}
	if c == nil {
		t.Fatal("New() returned nil client")
	}
}
