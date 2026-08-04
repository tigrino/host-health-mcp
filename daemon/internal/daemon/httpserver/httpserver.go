// Package httpserver implements the daemon's mTLS HTTP/JSON listener.
// One endpoint per tool under /v1/<tool>; POST only; request body is
// the tool's typed argument shape (often empty {}). Successful
// responses carry the schema.Envelope; failures carry
// schema.ErrorEnvelope with one of the codes from schema/errors.go.
package httpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"host-health-mcp/daemon/internal/daemon/audit"
	"host-health-mcp/daemon/internal/daemon/cache"
	"host-health-mcp/daemon/internal/daemon/config"
	"host-health-mcp/daemon/internal/daemon/ratelimit"
	"host-health-mcp/daemon/internal/daemon/tools"
	"host-health-mcp/daemon/internal/shared/schema"
)

// MaxRequestBody caps POST bodies. Tool arguments are tiny (enums and
// short strings). 4 KiB is more than ample.
const MaxRequestBody = 4 * 1024

// Listener timeouts. ReadHeaderTimeout alone leaves the body read
// unbounded: net/http resets the read deadline to wholeReqDeadline
// once headers are in, and that is the zero value when ReadTimeout is
// 0. A caller that sends complete headers and then trickles the body
// pins a cappedListener slot for as long as it likes, so
// max_concurrent_handshakes connections from one certificate deny the
// listener to everyone else.
//
// ReadTimeout bounds headers plus body together. WriteTimeout is set
// from the end of the header read, so it has to cover the body read,
// the tool call (REQ 5.1 caps a per-tool timeout at 10 s) and the
// response write.
//
// idleTimeout is the one value here that must be kept SHORT, and the
// reason is not obvious. A cappedListener slot is released in
// cappedConn.Close — at connection close, not at end of handshake — so
// an idle keep-alive connection holds one of max_concurrent_handshakes
// slots (default 16) for the whole idle window. With no ReadTimeout
// and no IdleTimeout, net/http fell back to ReadHeaderTimeout and that
// window was 5 s. Setting a long IdleTimeout would widen it and hand
// back the availability attack this block exists to close: holding all
// 16 slots costs one request per connection per window, i.e.
// 16*60/idleTimeout requests a minute, and that has to stay well above
// the caller's sustained rate-limit budget (30/min by default) for the
// limiter to reject it. At 10 s that is 96/min — refused. At 60 s it
// would be 16/min, under budget and therefore permitted indefinitely.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 10 * time.Second
	maxHeaderBytes    = 16 * 1024
)

// Server is the daemon's HTTP listener.
type Server struct {
	cfg      config.Daemon
	host     string
	registry *tools.Registry
	enabled  map[string]bool
	cache    *cache.Cache
	limiter  *ratelimit.Limiter
	auditor  audit.Logger

	// mu guards listener and srv, which Start assigns from the
	// goroutine that calls it while tests (and any future readiness
	// probe) read them from another. Polling them without
	// synchronisation is a data race, and reading srv through a
	// barrier that only covers listener can observe a nil.
	mu       sync.Mutex
	listener net.Listener
	srv      *http.Server
	// serving is closed once both listener and srv are assigned.
	serving chan struct{}
}

// Serving returns a channel closed once the listener is bound and the
// http.Server is constructed. Start assigns both before closing it.
func (s *Server) Serving() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serving == nil {
		s.serving = make(chan struct{})
	}
	return s.serving
}

// Addr reports the bound listener address, or "" before Start binds.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) setServing(ln net.Listener, srv *http.Server) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listener, s.srv = ln, srv
	if s.serving == nil {
		s.serving = make(chan struct{})
	}
	close(s.serving)
}

// New constructs a Server. enabled is the set of tool names that
// actually accept requests (REQ 8.2, manifest.enabled_tools). A nil or
// empty map means "accept every registered tool" (legacy behaviour);
// callers that wish to enforce a manifest must pre-intersect.
func New(cfg config.Daemon, host string, reg *tools.Registry, enabled map[string]bool, c *cache.Cache, l *ratelimit.Limiter, a audit.Logger) *Server {
	return &Server{cfg: cfg, host: host, registry: reg, enabled: enabled, cache: c, limiter: l, auditor: a}
}

// Start begins serving until ctx is cancelled. Blocks until shutdown
// completes.
func (s *Server) Start(ctx context.Context) error {
	tlsCfg, err := buildTLSConfig(s.cfg)
	if err != nil {
		return err
	}

	// Wrap order matters: cappedListener must sit BELOW tls.NewListener
	// so that what comes out of Accept is *tls.Conn (so net/http's
	// type assertion populates r.TLS) and so that the cap counts
	// in-flight TLS handshakes (the design intent in §8).
	tcpLn, err := net.Listen("tcp", s.cfg.BindAddr)
	if err != nil {
		return fmt.Errorf("httpserver: listen %s: %w", s.cfg.BindAddr, err)
	}
	var underlying net.Listener = tcpLn
	if s.cfg.MaxConcurrentHandshakes > 0 {
		underlying = newCappedListener(tcpLn, s.cfg.MaxConcurrentHandshakes)
	}
	ln := tls.NewListener(underlying, tlsCfg)

	// No ServeMux: every request reaches handleRequest whatever its
	// path. Routing through a mux registered on "/v1/" left everything
	// outside that prefix to net/http's default NotFoundHandler, which
	// answers in plain text, consumes no rate-limit token, and emits no
	// audit record at all. Path validation belongs inside the audited
	// path, not in front of it.
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.handleRequest),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	// Publish both fields together, then signal. A reader that waited
	// on the listener alone could observe srv still nil.
	s.setServing(ln, srv)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// handleRequest is the single entry point for every request, whatever
// its path. It authenticates, meters, validates the URL shape,
// extracts the tool name, and dispatches through the registry;
// unknown tools surface as the structured unknown_tool error rather
// than net/http's plain-text 404.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Authenticate first, then meter, then decide anything else. Every
	// rejection below writeError's call site emits an audit line; when
	// the limiter sat further down (inside handleToolBody) each of
	// those lines was free, so a caller looping on any malformed
	// request could flood journald at connection speed and rotate
	// genuine audit records away — erasing the REQ 6.5 trail without
	// ever invoking a tool.
	caller := callerIdentity(r)
	if caller == "" {
		s.writeError(w, r, "", http.StatusUnauthorized,
			schema.ErrCodeAuthRequired, schema.MsgAuthRequired, start, "no_client_cert")
		return
	}

	// Empty for any path outside /v1/. The limiter only buckets
	// per-tool for the expensive set, so an unroutable path meters
	// against the caller's global bucket alone — which is the bucket
	// that has to bound this.
	//
	// Truncated because this value reaches the audit log and, for an
	// unroutable path, it is whatever the caller sent. The audit
	// logger %q-quotes it so control bytes cannot mangle a log line,
	// but a request line is only bounded by MaxHeaderBytes and a
	// multi-KiB "tool name" is no more diagnostic than its first 128
	// bytes. Registered names are far shorter, so a real tool call is
	// never affected.
	toolName, hasPrefix := strings.CutPrefix(r.URL.Path, "/v1/")
	toolName = truncateToolName(toolName)

	if allowed, reason := s.limiter.Allow(caller, toolName); !allowed {
		s.writeError(w, r, toolName, http.StatusTooManyRequests,
			schema.ErrCodeRateLimited, schema.MsgRateLimited, start, "rate_"+reason)
		return
	}

	if !hasPrefix || toolName == "" || strings.Contains(toolName, "/") {
		s.writeError(w, r, toolName, http.StatusNotFound,
			schema.ErrCodeUnknownTool, schema.MsgUnknownTool, start, "bad_path")
		return
	}

	if r.Method != http.MethodPost {
		s.writeError(w, r, toolName, http.StatusMethodNotAllowed,
			schema.ErrCodeBadArgument, "POST required", start, "method")
		return
	}

	tool, ok := s.registry.Lookup(toolName)
	if !ok {
		s.writeError(w, r, toolName, http.StatusNotFound,
			schema.ErrCodeUnknownTool, schema.MsgUnknownTool, start, "unknown_tool")
		return
	}
	// REQ 8.2: a tool the operator did not enable in manifest.yml is
	// not part of this deployment's attack surface, regardless of
	// what is compiled in.
	if len(s.enabled) > 0 && !s.enabled[toolName] {
		s.writeError(w, r, toolName, http.StatusNotFound,
			schema.ErrCodeUnknownTool, schema.MsgUnknownTool, start, "tool_disabled")
		return
	}

	s.handleToolBody(w, r, tool, toolName, caller, start)
}

// handleToolBody handles the post-routing portion of a request: body
// read, cache lookup, tool invocation, envelope write. The caller has
// already been authenticated and metered by handleRequest.
func (s *Server) handleToolBody(w http.ResponseWriter, r *http.Request, tool tools.Tool, toolName, caller string, start time.Time) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBody+1))
	if err != nil {
		s.writeError(w, r, toolName, http.StatusBadRequest,
			schema.ErrCodeBadArgument, schema.MsgBadArgument, start, "read_body")
		return
	}
	if len(body) > MaxRequestBody {
		s.writeError(w, r, toolName, http.StatusRequestEntityTooLarge,
			schema.ErrCodeBadArgument, "request body exceeds cap", start, "body_too_large")
		return
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	// Reject non-JSON bodies before they reach the cache. The cache
	// key derivation canonicalises JSON; an invalid body would
	// otherwise fall back to raw-byte hashing, letting a caller fill
	// the cache with byte-distinct invalid-JSON variants of the same
	// semantic call.
	if !json.Valid(body) {
		s.writeError(w, r, toolName, http.StatusBadRequest,
			schema.ErrCodeBadArgument, "request body is not valid JSON", start, "invalid_json")
		return
	}

	ttl := s.cfg.CacheTTL(toolName, tool.DefaultTTL())
	key := cache.Key(toolName, body)

	args := extractAuditArgs(tool, body)

	if entry, ok := s.cache.Lookup(key); ok {
		s.writeEnvelope(w, entry.Data, int(entry.Age().Seconds()), entry.Warnings)
		s.auditor.Log(audit.Entry{
			CallerIdentity: caller,
			Tool:           toolName,
			Args:           args,
			ResponseSize:   len(entry.Data),
			Duration:       time.Since(start),
			Result:         "ok",
		})
		return
	}

	timeout := s.cfg.Timeout(toolName, tool.DefaultTimeout())
	toolCtx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	entry, err := s.cache.Do(toolCtx, key, func() (cache.Entry, error) {
		result, warnings, herr := tool.Handle(toolCtx, body)
		if herr != nil {
			return cache.Entry{}, herr
		}
		raw, mErr := json.Marshal(result)
		if mErr != nil {
			return cache.Entry{}, mErr
		}
		e := cache.Entry{
			Data:     raw,
			Warnings: warnings,
			Builtat:  time.Now(),
			TTL:      ttl,
		}
		s.cache.Store(key, e)
		return e, nil
	})
	if err != nil {
		s.handleToolError(w, r, toolName, err, start)
		return
	}

	s.writeEnvelope(w, entry.Data, 0, entry.Warnings)
	s.auditor.Log(audit.Entry{
		CallerIdentity: caller,
		Tool:           toolName,
		Args:           args,
		ResponseSize:   len(entry.Data),
		Duration:       time.Since(start),
		Result:         "ok",
	})
}

// maxAuditToolName bounds the tool name carried into the audit log and
// the error envelope. No registered tool comes close.
const maxAuditToolName = 128

func truncateToolName(name string) string {
	if len(name) <= maxAuditToolName {
		return name
	}
	return name[:maxAuditToolName] + "…"
}

// extractAuditArgs runs the tool's optional AuditArgs hook (REQ 6.5).
// Tools without caller-controlled enum arguments do not implement the
// interface and contribute no args.
func extractAuditArgs(tool tools.Tool, body []byte) map[string]string {
	ex, ok := tool.(tools.AuditArgsExtractor)
	if !ok {
		return nil
	}
	return ex.AuditArgs(body)
}

func (s *Server) writeEnvelope(w http.ResponseWriter, data json.RawMessage, cacheAgeS int, warnings []string) {
	env := schema.Envelope{
		Host:          s.host,
		AsOf:          time.Now().UTC(),
		CacheAgeS:     cacheAgeS,
		SchemaVersion: schema.SchemaVersion,
		Data:          data,
		Warnings:      warnings,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(env)
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, toolName string, status int, code, msg string, start time.Time, rejectReason string) {
	env := schema.ErrorEnvelope{
		Host:          s.host,
		AsOf:          time.Now().UTC(),
		SchemaVersion: schema.SchemaVersion,
		Error:         schema.Error{Code: code, Message: msg},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
	caller := callerIdentity(r)
	s.auditor.Log(audit.Entry{
		CallerIdentity: caller,
		Tool:           toolName,
		Duration:       time.Since(start),
		Result:         code,
		RejectReason:   rejectReason,
	})
}

func (s *Server) handleToolError(w http.ResponseWriter, r *http.Request, toolName string, err error, start time.Time) {
	var te *tools.Error
	if errors.As(err, &te) {
		// bad_argument maps to HTTP 400 — the caller did something
		// wrong; the upstream (helper) is healthy. Every other typed
		// tool error is treated as upstream-side and surfaces 502.
		status := http.StatusBadGateway
		if te.Code == schema.ErrCodeBadArgument {
			status = http.StatusBadRequest
		}
		s.writeError(w, r, toolName, status, te.Code, te.Message, start, te.Code)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		s.writeError(w, r, toolName, http.StatusGatewayTimeout, schema.ErrCodeToolTimeout, schema.MsgToolTimeout, start, "deadline")
		return
	}
	s.writeError(w, r, toolName, http.StatusBadGateway, schema.ErrCodeToolFailed, schema.MsgToolFailed, start, "tool_error")
}

// callerIdentity returns the Subject CN, or first DNS SAN if CN is
// empty, of the verified client certificate. Empty string means no
// client cert was presented (caller should be rejected upstream).
func callerIdentity(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	cert := r.TLS.PeerCertificates[0]
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		return cn
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return ""
}

func buildTLSConfig(c config.Daemon) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.TLSCertPath, c.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("httpserver: load TLS keypair: %w", err)
	}
	caPEM, err := os.ReadFile(c.ClientCAPath)
	if err != nil {
		return nil, fmt.Errorf("httpserver: read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("httpserver: client CA bundle has no certs")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		// REQ 6: tighten beyond chain-to-CA. Reject leaf certs that
		// are CAs themselves, lack the clientAuth EKU, or carry an
		// empty Subject. RFC 5280 §4.2.1.12 says "no EKU = any
		// purpose allowed" — relying on that is implicit trust in
		// the operator CA's template hygiene; the daemon enforces
		// the contract explicitly instead. Operator PKI must issue
		// client certs with `extendedKeyUsage = clientAuth` for the
		// connection to be accepted.
		VerifyConnection: verifyClientCert,
	}, nil
}

// verifyClientCert runs after chain verification. The peer cert is
// guaranteed valid up to the configured CA; this function adds the
// template-level checks. Returning a non-nil error aborts the TLS
// handshake with bad_certificate.
func verifyClientCert(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return fmt.Errorf("httpserver: tls: no verified chain")
	}
	leaf := cs.VerifiedChains[0][0]
	if leaf.IsCA {
		return fmt.Errorf("httpserver: tls: leaf cert is a CA; client certs must be end-entities")
	}
	hasClientAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		return fmt.Errorf("httpserver: tls: leaf cert is missing extendedKeyUsage=clientAuth")
	}
	if strings.TrimSpace(leaf.Subject.CommonName) == "" && len(leaf.DNSNames) == 0 {
		return fmt.Errorf("httpserver: tls: leaf cert has no Subject CN and no DNS SAN; cannot derive caller identity")
	}
	return nil
}
