package httpserver

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// newHandlerServer builds a Server suitable for driving handleRequest
// directly. No TLS: callerIdentity reads r.TLS, which authedRequest
// populates by hand.
func newHandlerServer(t *testing.T, limiter *ratelimit.Limiter, a audit.Logger) *Server {
	t.Helper()
	reg := tools.New()
	reg.Register(&testTool{name: "manifest"})
	return &Server{
		cfg:      config.Daemon{},
		host:     "testhost",
		registry: reg,
		enabled:  map[string]bool{"manifest": true},
		cache:    cache.New(),
		limiter:  limiter,
		auditor:  a,
	}
}

func authedRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "alice"}}},
	}
	return req
}

// B-1: ReadHeaderTimeout alone leaves the body read unbounded —
// net/http resets the read deadline to wholeReqDeadline once headers
// are in, and that is the zero value when ReadTimeout is 0.
func TestListenerTimeoutsAreConfigured(t *testing.T) {
	srv, _, _, stop := startTestServer(t)
	defer stop()

	if srv.srv.ReadTimeout != readTimeout {
		t.Errorf("ReadTimeout = %v, want %v", srv.srv.ReadTimeout, readTimeout)
	}
	if srv.srv.ReadHeaderTimeout != readHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.srv.ReadHeaderTimeout, readHeaderTimeout)
	}
	if srv.srv.WriteTimeout != writeTimeout {
		t.Errorf("WriteTimeout = %v, want %v", srv.srv.WriteTimeout, writeTimeout)
	}
	if srv.srv.IdleTimeout != idleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.srv.IdleTimeout, idleTimeout)
	}
	if srv.srv.MaxHeaderBytes != maxHeaderBytes {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.srv.MaxHeaderBytes, maxHeaderBytes)
	}
}

// WriteTimeout runs from the end of the header read, so it has to
// cover the body read plus the slowest permitted tool call (REQ 5.1
// caps a per-tool timeout at 10 s) plus the response write. Setting it
// below that would cut off a legitimate slow tool.
func TestWriteTimeoutCoversTheSlowestTool(t *testing.T) {
	const reqCap = 10 * time.Second
	if writeTimeout <= reqCap+readTimeout {
		t.Errorf("writeTimeout %v must exceed the %v tool cap plus the %v read budget",
			writeTimeout, reqCap, readTimeout)
	}
}

// The live half of B-1: a caller that completes its headers and then
// never sends the promised body used to pin a cappedListener slot
// indefinitely, so max_concurrent_handshakes connections from one
// certificate denied the listener to everyone else.
func TestSlowBodyRequestIsTimedOut(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the listener's ReadTimeout to elapse")
	}
	_, addr, clientTLS, stop := startTestServer(t)
	defer stop()

	conn, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Complete headers, then nothing. Content-Length promises a body
	// that never arrives.
	if _, err := conn.Write([]byte(
		"POST /v1/manifest HTTP/1.1\r\nHost: x\r\nContent-Length: 16\r\n\r\n")); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(readTimeout + 10*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	start := time.Now()
	buf := make([]byte, 512)
	// The server either answers (400/408) or drops the connection.
	// Either outcome frees the slot; hanging forever is the failure.
	for {
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if ok := asNetError(err, &ne); ok && ne.Timeout() {
				t.Fatalf("connection still open after %v; the slow-body read was never bounded", time.Since(start))
			}
			break
		}
		if n > 0 {
			break
		}
	}
	if elapsed := time.Since(start); elapsed > readTimeout+5*time.Second {
		t.Errorf("took %v to bound the stalled body, want about %v", elapsed, readTimeout)
	}
}

func asNetError(err error, target *net.Error) bool {
	ne, ok := err.(net.Error)
	if ok {
		*target = ne
	}
	return ok
}

// The end-to-end half of B-2 exploit B. This has to go through the
// real listener: routing was the defect, so a test that calls
// handleRequest directly would pass with the /v1/-only ServeMux still
// in place and prove nothing.
func TestNonV1PathIsRoutedThroughTheAuditedHandler(t *testing.T) {
	_, addr, ctls, stop := startTestServer(t)
	defer stop()

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: ctls}}
	for _, path := range []string{"/", "/metrics", "/v1", "/v2/manifest"} {
		resp, err := c.Post("https://"+addr+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: post: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type = %q, want application/json (net/http's NotFoundHandler answers text/plain)",
				path, ct)
		}
		var env schema.ErrorEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Errorf("%s: body is not an error envelope: %v (%q)", path, err, body)
			continue
		}
		if env.Error.Code != schema.ErrCodeUnknownTool {
			t.Errorf("%s: code = %q, want %q", path, env.Error.Code, schema.ErrCodeUnknownTool)
		}
		if env.SchemaVersion == "" {
			t.Errorf("%s: envelope carries no schema_version", path)
		}
	}
}

// B-2 exploit B, at the handler level: the same paths must produce an
// audit record, which the default NotFoundHandler never did.
func TestNonV1PathIsAuditedAndEnveloped(t *testing.T) {
	ca := &captureAuditor{}
	s := newHandlerServer(t, ratelimit.New(ratelimit.BucketCfg{SustainedPerMin: 600, Burst: 100}, nil), ca)

	for _, path := range []string{"/", "/metrics", "/v1", "/v2/manifest", "/v1/a/b"} {
		ca.entries = nil
		w := httptest.NewRecorder()
		s.handleRequest(w, authedRequest(http.MethodPost, path, "{}"))

		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type = %q, want application/json", path, ct)
		}
		var env schema.ErrorEnvelope
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Errorf("%s: body is not an error envelope: %v (%s)", path, err, w.Body.String())
			continue
		}
		if env.Error.Code != schema.ErrCodeUnknownTool {
			t.Errorf("%s: code = %q, want %q", path, env.Error.Code, schema.ErrCodeUnknownTool)
		}
		if len(ca.entries) != 1 {
			t.Errorf("%s: %d audit entries, want 1", path, len(ca.entries))
		}
	}
}

// B-2 exploit A: every pre-dispatch rejection wrote an audit line
// without consuming a token, so an authenticated caller looping on any
// malformed request flooded journald at connection speed and rotated
// genuine audit records away — erasing the REQ 6.5 trail without ever
// invoking a tool.
func TestEveryRejectionPathIsMetered(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"bad path", http.MethodPost, "/v1/a/b"},
		{"outside /v1", http.MethodPost, "/metrics"},
		{"non-POST", http.MethodGet, "/v1/manifest"},
		{"unknown tool", http.MethodPost, "/v1/no_such_tool"},
		{"tool disabled in manifest", http.MethodPost, "/v1/disabled_tool"},
		{"successful call", http.MethodPost, "/v1/manifest"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// One token, no refill within the test.
			lim := ratelimit.New(ratelimit.BucketCfg{SustainedPerMin: 1, Burst: 1}, nil)
			ca := &captureAuditor{}
			s := newHandlerServer(t, lim, ca)
			s.registry.Register(&testTool{name: "disabled_tool"})

			first := httptest.NewRecorder()
			s.handleRequest(first, authedRequest(tc.method, tc.path, "{}"))
			if first.Code == http.StatusTooManyRequests {
				t.Fatalf("first request already rate-limited (%d)", first.Code)
			}

			second := httptest.NewRecorder()
			s.handleRequest(second, authedRequest(tc.method, tc.path, "{}"))
			if second.Code != http.StatusTooManyRequests {
				t.Errorf("second request: status %d, want 429 — this path consumes no token",
					second.Code)
			}
		})
	}
}

// The limiter runs after authentication, so its buckets stay keyed by
// a verified identity rather than by anything an unauthenticated peer
// controls.
func TestUnauthenticatedRequestIsRejectedBeforeMetering(t *testing.T) {
	lim := ratelimit.New(ratelimit.BucketCfg{SustainedPerMin: 1, Burst: 1}, nil)
	ca := &captureAuditor{}
	s := newHandlerServer(t, lim, ca)

	// No r.TLS at all: callerIdentity yields "".
	w := httptest.NewRecorder()
	s.handleRequest(w, httptest.NewRequest(http.MethodPost, "/v1/manifest", strings.NewReader("{}")))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}

	// The authenticated caller's single token must be untouched.
	w2 := httptest.NewRecorder()
	s.handleRequest(w2, authedRequest(http.MethodPost, "/v1/manifest", "{}"))
	if w2.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — the rejected request spent a token", w2.Code)
	}
}

// Rejections must still be audited; metering them is not a licence to
// drop the record.
func TestRejectionsAreStillAudited(t *testing.T) {
	ca := &captureAuditor{}
	s := newHandlerServer(t, ratelimit.New(ratelimit.BucketCfg{SustainedPerMin: 600, Burst: 100}, nil), ca)

	w := httptest.NewRecorder()
	s.handleRequest(w, authedRequest(http.MethodGet, "/v1/manifest", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if len(ca.entries) != 1 {
		t.Fatalf("%d audit entries, want 1", len(ca.entries))
	}
	if ca.entries[0].CallerIdentity != "alice" {
		t.Errorf("caller = %q, want alice", ca.entries[0].CallerIdentity)
	}
	if ca.entries[0].RejectReason != "method" {
		t.Errorf("reject_reason = %q, want method", ca.entries[0].RejectReason)
	}
}

// The tool name reaches the audit log, and for an unroutable path it is
// whatever the caller sent — bounded only by MaxHeaderBytes. Truncate
// it so one request cannot write a multi-KiB audit line.
func TestAuditToolNameIsTruncated(t *testing.T) {
	ca := &captureAuditor{}
	s := newHandlerServer(t, ratelimit.New(ratelimit.BucketCfg{SustainedPerMin: 600, Burst: 100}, nil), ca)

	long := strings.Repeat("a", 4096)
	w := httptest.NewRecorder()
	s.handleRequest(w, authedRequest(http.MethodPost, "/v1/"+long, "{}"))

	if len(ca.entries) != 1 {
		t.Fatalf("%d audit entries, want 1", len(ca.entries))
	}
	if n := len(ca.entries[0].Tool); n > maxAuditToolName+4 {
		t.Errorf("audit tool name is %d bytes, want it truncated near %d", n, maxAuditToolName)
	}
	// A registered name must survive untouched.
	if got := truncateToolName("systemd_units"); got != "systemd_units" {
		t.Errorf("truncateToolName mangled a real tool name: %q", got)
	}
}

// A cappedListener slot is released only at connection close, so an
// idle keep-alive connection holds one for idleTimeout. Holding all
// max_concurrent_handshakes slots then costs one request per
// connection per window; that rate must exceed the caller's sustained
// budget, or the limiter permits the caller to pin the whole listener
// indefinitely. Setting idleTimeout to 60 s made that attack cost
// 16/min against a 30/min budget — cheap, quiet, and within policy.
func TestIdleTimeoutKeepsSlotHoldingAboveTheRateBudget(t *testing.T) {
	// cmd/daemon wires the global bucket at 30/min sustained.
	const sustainedPerMin = 30
	const slots = 16 // config.Daemon default MaxConcurrentHandshakes

	costPerMin := float64(slots) * float64(time.Minute) / float64(idleTimeout)
	if costPerMin <= sustainedPerMin {
		t.Errorf("idleTimeout %v lets a caller hold all %d slots for %.0f req/min, "+
			"within the %d/min sustained budget — the limiter cannot reject it",
			idleTimeout, slots, costPerMin, sustainedPerMin)
	}
	// Keep-alive still has to be worth having.
	if idleTimeout < readHeaderTimeout {
		t.Errorf("idleTimeout %v is below readHeaderTimeout %v", idleTimeout, readHeaderTimeout)
	}
}
