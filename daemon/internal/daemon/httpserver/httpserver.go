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

// Server is the daemon's HTTP listener.
type Server struct {
	cfg      config.Daemon
	host     string
	registry *tools.Registry
	cache    *cache.Cache
	limiter  *ratelimit.Limiter
	auditor  audit.Logger

	listener net.Listener
	srv      *http.Server
}

// New constructs a Server. The TLS configuration is built in Start.
func New(cfg config.Daemon, host string, reg *tools.Registry, c *cache.Cache, l *ratelimit.Limiter, a audit.Logger) *Server {
	return &Server{cfg: cfg, host: host, registry: reg, cache: c, limiter: l, auditor: a}
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
	s.listener = ln

	mux := http.NewServeMux()
	// Single catch-all so the server's own error envelope (not
	// net/http's plain-text "404 page not found") covers every
	// /v1/... path.
	mux.HandleFunc("/v1/", s.handleRequest)

	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// handleRequest is the single entry point for every /v1/... request.
// It validates the URL shape, extracts the tool name, and dispatches
// through the registry; unknown tools surface as the structured
// unknown_tool error rather than net/http's plain-text 404.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	toolName := strings.TrimPrefix(r.URL.Path, "/v1/")
	if toolName == "" || strings.Contains(toolName, "/") {
		s.writeError(w, r, toolName, http.StatusNotFound,
			schema.ErrCodeUnknownTool, schema.MsgUnknownTool, start, "bad_path")
		return
	}

	if r.Method != http.MethodPost {
		s.writeError(w, r, toolName, http.StatusMethodNotAllowed,
			schema.ErrCodeBadArgument, "POST required", start, "method")
		return
	}

	caller := callerIdentity(r)
	if caller == "" {
		s.writeError(w, r, toolName, http.StatusUnauthorized,
			schema.ErrCodeAuthRequired, schema.MsgAuthRequired, start, "no_client_cert")
		return
	}

	tool, ok := s.registry.Lookup(toolName)
	if !ok {
		s.writeError(w, r, toolName, http.StatusNotFound,
			schema.ErrCodeUnknownTool, schema.MsgUnknownTool, start, "unknown_tool")
		return
	}

	s.handleToolBody(w, r, tool, toolName, caller, start)
}

// handleToolBody handles the post-routing portion of a request:
// rate-limit check, body read, cache lookup, tool invocation,
// envelope write.
func (s *Server) handleToolBody(w http.ResponseWriter, r *http.Request, tool tools.Tool, toolName, caller string, start time.Time) {
	if allowed, reason := s.limiter.Allow(caller, toolName); !allowed {
		s.writeError(w, r, toolName, http.StatusTooManyRequests,
			schema.ErrCodeRateLimited, schema.MsgRateLimited, start, "rate_"+reason)
		return
	}

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

	if entry, ok := s.cache.Lookup(key); ok {
		s.writeEnvelope(w, entry.Data, int(entry.Age().Seconds()), entry.Warnings)
		s.auditor.Log(audit.Entry{
			CallerIdentity: caller,
			Tool:           toolName,
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
		ResponseSize:   len(entry.Data),
		Duration:       time.Since(start),
		Result:         "ok",
	})
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
		s.writeError(w, r, toolName, http.StatusBadGateway, te.Code, te.Message, start, te.Code)
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
	}, nil
}
