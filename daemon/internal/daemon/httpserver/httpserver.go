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

	"tigr.net/host-health-mcp/daemon/internal/daemon/audit"
	"tigr.net/host-health-mcp/daemon/internal/daemon/cache"
	"tigr.net/host-health-mcp/daemon/internal/daemon/config"
	"tigr.net/host-health-mcp/daemon/internal/daemon/ratelimit"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools"
	"tigr.net/host-health-mcp/daemon/internal/shared/schema"
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

	ln, err := tls.Listen("tcp", s.cfg.BindAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("httpserver: listen %s: %w", s.cfg.BindAddr, err)
	}
	if s.cfg.MaxConcurrentHandshakes > 0 {
		ln = newCappedListener(ln, s.cfg.MaxConcurrentHandshakes)
	}
	s.listener = ln

	mux := http.NewServeMux()
	for _, name := range s.registry.Names() {
		nm := name // capture
		mux.HandleFunc("/v1/"+nm, s.handleTool(nm))
	}

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

func (s *Server) handleTool(toolName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

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

		ttl := s.cfg.CacheTTL(toolName, tool.DefaultTTL())
		key := cache.Key(toolName, body)

		if entry, ok := s.cache.Lookup(key); ok {
			s.writeEnvelope(w, entry.Data, int(entry.Age().Seconds()), nil)
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

		data, err := s.cache.Do(toolCtx, key, func() (json.RawMessage, error) {
			result, warnings, herr := tool.Handle(toolCtx, body)
			if herr != nil {
				return nil, herr
			}
			env := buildEnvelopeBody(result, warnings)
			raw, mErr := json.Marshal(env.Data)
			if mErr != nil {
				return nil, mErr
			}
			s.cache.Store(key, cache.Entry{
				Data:    raw,
				Builtat: time.Now(),
				TTL:     ttl,
			})
			return raw, nil
		})
		if err != nil {
			s.handleToolError(w, r, toolName, err, start)
			return
		}

		s.writeEnvelope(w, data, 0, nil)
		s.auditor.Log(audit.Entry{
			CallerIdentity: caller,
			Tool:           toolName,
			ResponseSize:   len(data),
			Duration:       time.Since(start),
			Result:         "ok",
		})
	}
}

type envelopeBody struct {
	Data     json.RawMessage
	Warnings []string
}

func buildEnvelopeBody(result any, warnings []string) envelopeBody {
	raw, err := json.Marshal(result)
	if err != nil {
		raw = json.RawMessage(`null`)
	}
	return envelopeBody{Data: raw, Warnings: warnings}
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
