package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"host-health-mcp/daemon/internal/daemon/audit"
	"host-health-mcp/daemon/internal/daemon/cache"
	"host-health-mcp/daemon/internal/daemon/config"
	"host-health-mcp/daemon/internal/daemon/ratelimit"
	"host-health-mcp/daemon/internal/daemon/tools"
	"host-health-mcp/daemon/internal/shared/schema"
)

// testTool always returns the same payload. Used to exercise the
// server's envelope handling without dragging in a real tool.
type testTool struct {
	name string
}

func (t *testTool) Name() string                  { return t.name }
func (*testTool) DefaultTTL() time.Duration       { return 1 * time.Second }
func (*testTool) DefaultTimeout() time.Duration   { return 1 * time.Second }
func (*testTool) Handle(ctx context.Context, body []byte) (any, []string, error) {
	return map[string]string{"ok": "yes"}, nil, nil
}

// nullAuditor discards entries.
type nullAuditor struct{}

func (nullAuditor) Log(audit.Entry) {}

func TestCallerIdentity(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "alice"},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/manifest", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if got := callerIdentity(req); got != "alice" {
		t.Errorf("CN extraction: got %q want %q", got, "alice")
	}

	dnsCert := &x509.Certificate{DNSNames: []string{"plugin.example.com"}}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{dnsCert}}
	if got := callerIdentity(req); got != "plugin.example.com" {
		t.Errorf("DNS SAN fallback: got %q want %q", got, "plugin.example.com")
	}

	req.TLS = nil
	if got := callerIdentity(req); got != "" {
		t.Errorf("no TLS: got %q want empty", got)
	}
}

// generateTestPKI returns paths to a server cert+key and a CA bundle,
// plus a client tls.Config that the test uses to connect.
func generateTestPKI(t *testing.T, dir string) (caPath, serverCert, serverKey string, clientTLS *tls.Config) {
	t.Helper()

	// CA
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

	// Server cert
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Client cert
	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caTmpl, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caPath = filepath.Join(dir, "ca.pem")
	serverCert = filepath.Join(dir, "srv.crt")
	serverKey = filepath.Join(dir, "srv.key")

	mustWritePEM(t, caPath, "CERTIFICATE", caDER)
	mustWritePEM(t, serverCert, "CERTIFICATE", srvDER)
	mustWritePKCS8(t, serverKey, srvKey)

	cliCertPEM := encodePEM("CERTIFICATE", cliDER)
	cliKeyPEM := mustMarshalPKCS8(t, cliKey)
	cliPair, err := tls.X509KeyPair(cliCertPEM, cliKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(encodePEM("CERTIFICATE", caDER))

	clientTLS = &tls.Config{
		Certificates: []tls.Certificate{cliPair},
		RootCAs:      rootPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
	return
}

func mustWritePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, encodePEM(typ, der), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustWritePKCS8(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	if err := os.WriteFile(path, mustMarshalPKCS8(t, key), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMarshalPKCS8(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encodePEM("PRIVATE KEY", der)
}

func encodePEM(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func startTestServer(t *testing.T) (s *Server, addr string, clientTLS *tls.Config, stop func()) {
	t.Helper()
	dir := t.TempDir()
	caPath, srvCert, srvKey, ctls := generateTestPKI(t, dir)

	cfg := config.Daemon{
		BindAddr:                "127.0.0.1:0",
		TLSCertPath:             srvCert,
		TLSKeyPath:              srvKey,
		ClientCAPath:            caPath,
		MaxConcurrentHandshakes: 4,
	}
	reg := tools.New()
	reg.Register(&testTool{name: "manifest"})

	srv := &Server{
		cfg:      cfg,
		host:     "testhost",
		registry: reg,
		cache:    cache.New(),
		limiter:  ratelimit.New(ratelimit.BucketCfg{SustainedPerMin: 600, Burst: 100}, nil),
		auditor:  nullAuditor{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for the listener to bind.
	deadline := time.Now().Add(2 * time.Second)
	for srv.listener == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.listener == nil {
		cancel()
		t.Fatal("listener did not bind in time")
	}
	return srv, srv.listener.Addr().String(), ctls, func() { cancel(); <-errCh }
}

func TestServerRequiresClientCert(t *testing.T) {
	srv, addr, _, stop := startTestServer(t)
	defer stop()
	_ = srv

	// Connect without presenting a client cert.
	rootPool := x509.NewCertPool()
	// Use the same CA we minted as the trust anchor.
	caPEM, _ := os.ReadFile(srv.cfg.TLSCertPath) // not used; left for symmetry
	_ = caPEM
	noCert := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		RootCAs:            rootPool,
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: noCert}}
	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/manifest", bytes.NewReader([]byte("{}")))
	resp, err := c.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected TLS handshake failure without client cert; got success")
	}
}

func TestServerEnvelopeShape(t *testing.T) {
	srv, addr, ctls, stop := startTestServer(t)
	defer stop()
	_ = srv

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: ctls}}
	resp, err := c.Post("https://"+addr+"/v1/manifest", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	var env schema.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.SchemaVersion == "" {
		t.Error("envelope missing schema_version")
	}
	if env.Host == "" {
		t.Error("envelope missing host")
	}
	if !strings.Contains(string(env.Data), `"ok"`) {
		t.Errorf("data: got %s want contains ok:yes", string(env.Data))
	}
}

func TestServerUnknownToolErrors(t *testing.T) {
	srv, addr, ctls, stop := startTestServer(t)
	defer stop()
	_ = srv

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: ctls}}
	resp, err := c.Post("https://"+addr+"/v1/bogus", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
	var env schema.ErrorEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Code != schema.ErrCodeUnknownTool {
		t.Errorf("error.code: got %q want %q", env.Error.Code, schema.ErrCodeUnknownTool)
	}
}

func TestServerRejectsOversizeBody(t *testing.T) {
	srv, addr, ctls, stop := startTestServer(t)
	defer stop()
	_ = srv

	big := make([]byte, MaxRequestBody+10)
	for i := range big {
		big[i] = '"'
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: ctls}}
	resp, err := c.Post("https://"+addr+"/v1/manifest", "application/json", bytes.NewReader(big))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status: got %d want 413", resp.StatusCode)
	}
}
