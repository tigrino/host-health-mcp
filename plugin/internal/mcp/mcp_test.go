package mcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tigr.net/host-health-mcp/plugin/internal/client"
)

// driveSession executes a sequence of newline-delimited JSON-RPC
// requests against a freshly constructed Server and returns the
// response lines (one entry per response, notification lines
// omitted).
func driveSession(t *testing.T, srv *Server, requests ...string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("response is not JSON: %q (%v)", line, err)
		}
		resps = append(resps, m)
	}
	return resps
}

func newTestClient(t *testing.T) *client.Client {
	t.Helper()
	dir := t.TempDir()
	cert, key := generateSelfSigned(t)
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	cli, err := client.New(client.Config{
		Port:     8443,
		CertPath: certPath,
		KeyPath:  keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cli
}

func generateSelfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

var standardTools = []Tool{
	{Name: "host_manifest", DaemonRPC: "manifest", Description: "manifest"},
	{Name: "host_system", DaemonRPC: "system", Description: "system"},
}

func TestInitializeReturnsProtocolAndCapabilities(t *testing.T) {
	srv := New(newTestClient(t), standardTools, "", "host-health-mcp", "test")
	resps := driveSession(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
	)
	if len(resps) != 1 {
		t.Fatalf("want 1 response, got %d", len(resps))
	}
	result, _ := resps[0]["result"].(map[string]any)
	if got := result["protocolVersion"]; got != "2024-11-05" {
		t.Errorf("protocolVersion=%v", got)
	}
	caps, _ := result["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Errorf("capabilities.tools missing: %v", caps)
	}
	info, _ := result["serverInfo"].(map[string]any)
	if info["name"] != "host-health-mcp" || info["version"] != "test" {
		t.Errorf("serverInfo=%v", info)
	}
}

func TestNotificationProducesNoResponse(t *testing.T) {
	srv := New(newTestClient(t), standardTools, "", "x", "0")
	resps := driveSession(t, srv,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
	)
	if len(resps) != 1 {
		t.Fatalf("want 1 response (ping only), got %d: %v", len(resps), resps)
	}
	if resps[0]["id"].(float64) != 1 {
		t.Errorf("ping response id mismatch: %v", resps[0])
	}
}

func TestUnknownMethodReturnsMethodNotFound(t *testing.T) {
	srv := New(newTestClient(t), standardTools, "", "x", "0")
	resps := driveSession(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`,
	)
	errObj, _ := resps[0]["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != -32601 {
		t.Errorf("want -32601, got %v", resps[0])
	}
}

func TestToolsListIncludesHostInputSchema(t *testing.T) {
	srv := New(newTestClient(t), standardTools, "", "x", "0")
	resps := driveSession(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	)
	result, _ := resps[0]["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != len(standardTools) {
		t.Fatalf("want %d tools, got %d", len(standardTools), len(tools))
	}
	first, _ := tools[0].(map[string]any)
	schema, _ := first["inputSchema"].(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	if _, ok := props["host"]; !ok {
		t.Errorf("inputSchema.properties.host missing: %v", schema)
	}
	if schema["additionalProperties"] != false {
		t.Errorf("additionalProperties should be false, got %v", schema["additionalProperties"])
	}
}

func TestCallWithoutHostAndNoDefaultIsToolError(t *testing.T) {
	srv := New(newTestClient(t), standardTools, "", "x", "0")
	resps := driveSession(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"host_system","arguments":{}}}`,
	)
	result, _ := resps[0]["result"].(map[string]any)
	if result["isError"] != true {
		t.Errorf("expected isError, got %v", resps[0])
	}
	content, _ := result["content"].([]any)
	first, _ := content[0].(map[string]any)
	if !strings.Contains(first["text"].(string), "host argument is required") {
		t.Errorf("error text mismatch: %v", first)
	}
}

func TestCallUnknownToolIsProtocolError(t *testing.T) {
	srv := New(newTestClient(t), standardTools, "", "x", "0")
	resps := driveSession(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"host_bogus","arguments":{"host":"h"}}}`,
	)
	errObj, _ := resps[0]["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != -32602 {
		t.Errorf("want -32602 unknown tool, got %v", resps[0])
	}
}

func TestSchemaIncompatibleHostShortCircuitsSubsequentCalls(t *testing.T) {
	mux := http.NewServeMux()
	calls := 0
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		calls++
		// Major mismatch: daemon claims 99.x, plugin compiled against 0.x.
		_, _ = fmt.Fprint(w, `{"host":"fake","schema_version":"99.0.0","data":{"daemon_version":"test"}}`)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	cli := newTestClient(t)
	cli.SetTransport(srv.Client().Transport)

	mcpSrv := New(cli, standardTools, addr, "x", "0")

	// First non-manifest call triggers the probe; daemon returns
	// 99.0.0 → incompatible → tool error.
	resps := driveSession(t, mcpSrv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"host_system","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"host_system","arguments":{}}}`,
	)
	if len(resps) != 2 {
		t.Fatalf("want 2 responses, got %d", len(resps))
	}
	for i, r := range resps {
		result, _ := r["result"].(map[string]any)
		if result["isError"] != true {
			t.Errorf("resp %d: expected isError, got %v", i, r)
			continue
		}
		txt := result["content"].([]any)[0].(map[string]any)["text"].(string)
		if !strings.Contains(txt, "schema_incompatible") {
			t.Errorf("resp %d: expected schema_incompatible message, got %q", i, txt)
		}
	}
	// Probe (1 call) + nothing else. The second tools/call MUST be
	// short-circuited from cache; if we see a third HTTP call, the
	// cache is broken.
	if calls != 1 {
		t.Errorf("expected exactly 1 HTTP call (probe), got %d", calls)
	}
}

func TestSchemaCompatibleHostCallsThrough(t *testing.T) {
	mux := http.NewServeMux()
	systemHits := 0
	mux.HandleFunc("/v1/manifest", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"host":"fake","schema_version":"0.1.0","data":{"daemon_version":"test"}}`)
	})
	mux.HandleFunc("/v1/system", func(w http.ResponseWriter, r *http.Request) {
		systemHits++
		_, _ = fmt.Fprint(w, `{"host":"fake","schema_version":"0.1.0","data":{"uptime_s":42}}`)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	cli := newTestClient(t)
	cli.SetTransport(srv.Client().Transport)

	mcpSrv := New(cli, standardTools, addr, "x", "0")
	resps := driveSession(t, mcpSrv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"host_system","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"host_system","arguments":{}}}`,
	)
	if len(resps) != 2 {
		t.Fatalf("want 2 responses, got %d", len(resps))
	}
	for i, r := range resps {
		if _, isErr := r["result"].(map[string]any)["isError"]; isErr {
			t.Errorf("resp %d: unexpected isError: %v", i, r)
		}
	}
	if systemHits != 2 {
		t.Errorf("expected 2 system hits (both forwarded), got %d", systemHits)
	}
}

