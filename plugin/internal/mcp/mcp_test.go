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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"host-health-mcp/plugin/internal/client"
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
	// The plugin client requires an explicit CA bundle or the
	// HOSTHEALTH_TRUST_SYSTEM_ROOTS=1 opt-in (M-6 fail-closed). These
	// tests never actually open a TLS connection to a daemon — the
	// transport is replaced by SetTransport with a roundtripper that
	// returns canned bodies — so the system-roots opt-in is the
	// minimum-surface way to keep the test scaffolding intact.
	t.Setenv(client.EnvTrustSystemRoots, "1")
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
		_, _ = fmt.Fprint(w, `{"host":"fake","schema_version":"1.0.0","data":{"daemon_version":"test"}}`)
	})
	mux.HandleFunc("/v1/system", func(w http.ResponseWriter, r *http.Request) {
		systemHits++
		_, _ = fmt.Fprint(w, `{"host":"fake","schema_version":"1.0.0","data":{"uptime_s":42}}`)
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

// TestBuildDaemonBody covers the host-stripping wire-shape promise:
// the routing argument `host` never reaches the daemon, and a tool
// called with only `host` still sends `{}` so argument-less daemon
// handlers see the pre-1.16 wire shape.
func TestBuildDaemonBody(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"nil args", nil, "{}"},
		{"empty args", map[string]any{}, "{}"},
		{"host only", map[string]any{"host": "h1"}, "{}"},
		{"forwarded scalar", map[string]any{"host": "h1", "query": "10.0.0.5"}, `{"query":"10.0.0.5"}`},
		{"multiple args", map[string]any{"severity": "err", "window": "1h"}, ""}, // ordering — compared structurally below
	}
	for _, c := range cases {
		got, err := buildDaemonBody(c.in)
		if err != nil {
			t.Fatalf("%s: buildDaemonBody: %v", c.name, err)
		}
		if c.want != "" {
			if string(got) != c.want {
				t.Errorf("%s: got %s, want %s", c.name, got, c.want)
			}
			continue
		}
		// Structural equality for multi-key cases — JSON object key
		// order is not deterministic across Go versions.
		var gotMap, wantMap map[string]any
		if err := json.Unmarshal(got, &gotMap); err != nil {
			t.Fatalf("%s: unmarshal got: %v", c.name, err)
		}
		want := map[string]any{}
		for k, v := range c.in {
			if k != "host" {
				want[k] = v
			}
		}
		wantMap = want
		if len(gotMap) != len(wantMap) {
			t.Errorf("%s: len(got)=%d, len(want)=%d", c.name, len(gotMap), len(wantMap))
		}
		for k, v := range wantMap {
			if gotMap[k] != v {
				t.Errorf("%s: %s = %v, want %v", c.name, k, gotMap[k], v)
			}
		}
	}
}

// TestPerToolInputSchemaSurfacesArgs verifies that tools/list emits
// the per-tool ArgsProperties (with `host` always present), and
// flags ArgsRequired in the schema's required[] array.
func TestPerToolInputSchemaSurfacesArgs(t *testing.T) {
	tools := []Tool{
		{
			Name: "host_logs", DaemonRPC: "logs", Description: "logs",
			ArgsProperties: map[string]any{
				"severity": map[string]any{"type": "string"},
				"window":   map[string]any{"type": "string"},
			},
		},
		{
			Name: "host_firewall_lookup", DaemonRPC: "firewall_lookup", Description: "lookup",
			ArgsProperties: map[string]any{
				"query": map[string]any{"type": "string"},
			},
			ArgsRequired: []string{"query"},
		},
		{Name: "host_system", DaemonRPC: "system", Description: "system"},
	}
	srv := New(newTestClient(t), tools, "", "x", "0")
	resps := driveSession(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	)
	result, _ := resps[0]["result"].(map[string]any)
	descs, _ := result["tools"].([]any)
	if len(descs) != 3 {
		t.Fatalf("want 3 tool descriptors, got %d", len(descs))
	}
	byName := map[string]map[string]any{}
	for _, d := range descs {
		m := d.(map[string]any)
		byName[m["name"].(string)] = m
	}

	logs := byName["host_logs"]["inputSchema"].(map[string]any)
	logsProps := logs["properties"].(map[string]any)
	for _, key := range []string{"host", "severity", "window"} {
		if _, ok := logsProps[key]; !ok {
			t.Errorf("host_logs.inputSchema.properties missing %q: %v", key, logsProps)
		}
	}
	if _, hasReq := logs["required"]; hasReq {
		t.Errorf("host_logs has no required args; schema should omit `required`")
	}

	fwlu := byName["host_firewall_lookup"]["inputSchema"].(map[string]any)
	required, _ := fwlu["required"].([]any)
	if len(required) != 1 || required[0] != "query" {
		t.Errorf("host_firewall_lookup required = %v, want [query]", required)
	}

	sys := byName["host_system"]["inputSchema"].(map[string]any)
	sysProps := sys["properties"].(map[string]any)
	if _, ok := sysProps["host"]; !ok {
		t.Errorf("host_system.inputSchema.properties.host missing")
	}
	if len(sysProps) != 1 {
		t.Errorf("host_system has no extra args; properties should only carry `host`, got %v", sysProps)
	}
}

// TestArgsForwardedToDaemon proves the end-to-end forwarding path:
// a tools/call with arguments lands as a JSON body on the daemon,
// `host` is stripped, and the wire shape matches what the daemon's
// per-tool handler expects.
func TestArgsForwardedToDaemon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/manifest", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"host":"fake","schema_version":"1.0.0","data":{"daemon_version":"test"}}`)
	})
	var sawBody string
	mux.HandleFunc("/v1/firewall_lookup", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sawBody = string(b)
		_, _ = fmt.Fprint(w, `{"host":"fake","schema_version":"1.0.0","data":{"query":"10.0.0.5","matches":[],"sets":[]}}`)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	cli := newTestClient(t)
	cli.SetTransport(srv.Client().Transport)

	tools := []Tool{
		{Name: "host_manifest", DaemonRPC: "manifest", Description: "manifest"},
		{
			Name: "host_firewall_lookup", DaemonRPC: "firewall_lookup", Description: "lookup",
			ArgsProperties: map[string]any{
				"query":                map[string]any{"type": "string"},
				"include_set_elements": map[string]any{"type": "boolean"},
			},
			ArgsRequired: []string{"query"},
		},
	}
	mcpSrv := New(cli, tools, addr, "x", "0")
	// defaultHost = addr, so the call selects the test server even
	// without an explicit `host` arg; we still pass one to prove
	// the host-stripping path strips the routing argument.
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"host_firewall_lookup","arguments":{"host":%q,"query":"10.0.0.5","include_set_elements":true}}}`, addr)
	resps := driveSession(t, mcpSrv, req)
	if len(resps) != 1 {
		t.Fatalf("want 1 response, got %d", len(resps))
	}
	if _, isErr := resps[0]["result"].(map[string]any)["isError"]; isErr {
		t.Fatalf("unexpected tool error: %v", resps[0])
	}
	var gotMap map[string]any
	if err := json.Unmarshal([]byte(sawBody), &gotMap); err != nil {
		t.Fatalf("daemon body is not JSON: %q (%v)", sawBody, err)
	}
	if gotMap["query"] != "10.0.0.5" {
		t.Errorf("forwarded body missing query: %v", gotMap)
	}
	if gotMap["include_set_elements"] != true {
		t.Errorf("forwarded body missing include_set_elements: %v", gotMap)
	}
	if _, hasHost := gotMap["host"]; hasHost {
		t.Errorf("host argument leaked into daemon body: %v", gotMap)
	}
}

// TestNoArgsTooStillSendsEmptyBody confirms the wire shape stays
// `{}` for tools with no ArgsProperties — i.e. that argument-less
// daemon handlers (system, certs, ...) keep working exactly as
// before across the 1.15 → 1.16 transition.
func TestNoArgsToolStillSendsEmptyBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/manifest", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"host":"fake","schema_version":"1.0.0","data":{"daemon_version":"test"}}`)
	})
	var sawBody string
	mux.HandleFunc("/v1/system", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sawBody = string(b)
		_, _ = fmt.Fprint(w, `{"host":"fake","schema_version":"1.0.0","data":{"uptime_s":1}}`)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	cli := newTestClient(t)
	cli.SetTransport(srv.Client().Transport)

	mcpSrv := New(cli, standardTools, addr, "x", "0")
	driveSession(t, mcpSrv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"host_system","arguments":{}}}`,
	)
	if sawBody != "{}" {
		t.Errorf("system body = %q, want %q", sawBody, "{}")
	}
}

