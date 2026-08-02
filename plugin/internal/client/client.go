// Package client is the plugin's HTTP/JSON client to a daemon's
// listener. Speaks mTLS only. One Client instance per process serves
// every target host: the TLS material is shared (one operator cert,
// one internal CA) and the http.Transport pools connections per host
// automatically. The target host is supplied per call (REQ 7.2).
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// EnvTrustSystemRoots, when set to "1", lets New() fall back to the
// system root CA pool if Config.CAPath is empty. Without the opt-in,
// an empty CAPath is a startup error: the production deployment model
// is an internal operator PKI, and trusting public CAs by default
// turns a missing config into an authentication-bypass foot-gun.
const EnvTrustSystemRoots = "HOSTHEALTH_TRUST_SYSTEM_ROOTS"

// Config configures a Client.
type Config struct {
	Port        int    // default port when a host arg has no :port
	CertPath    string
	KeyPath     string
	CAPath      string // server CA bundle; empty uses system roots
	DNSSuffix   string // appended to bare hostnames (no dot, no port)
	HTTPTimeout time.Duration
}

// Client speaks to any daemon reachable with the configured TLS
// material. The target host is provided per call.
type Client struct {
	cfg  Config
	http *http.Client
}

// New constructs a Client. The TLS config is built once and reused
// across calls; the http.Transport pools connections by host.
func New(cfg Config) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("client: load keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.CAPath != "" {
		ca, err := os.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("client: read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("client: CA bundle has no certs")
		}
		tlsCfg.RootCAs = pool
	} else if os.Getenv(EnvTrustSystemRoots) == "1" {
		log.Printf("client: WARNING CAPath is empty and %s=1; trusting system root CAs (override active)", EnvTrustSystemRoots)
	} else {
		return nil, fmt.Errorf("client: CAPath is empty; set HOSTHEALTH_TLS_CA to an internal CA bundle (recommended) or %s=1 to use system roots", EnvTrustSystemRoots)
	}

	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	return &Client{
		cfg: cfg,
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:   tlsCfg,
				DisableKeepAlives: false,
			},
			Timeout: timeout,
		},
	}, nil
}

// SetTransport replaces the HTTP transport. Test-only helper to
// inject a transport that trusts a httptest TLS cert; production
// code constructs the transport in New.
func (c *Client) SetTransport(rt http.RoundTripper) {
	c.http.Transport = rt
}

// ResolveHost expands a caller-supplied host into the host:port form
// used in URLs. Bare names get DNSSuffix appended; missing port gets
// cfg.Port (or 8443 if unset). Empty input returns an error.
//
// IPv6 literals must be supplied bracketed (`[fe80::1]` or
// `[fe80::1]:8443`); a bare `fe80::1` is ambiguous (last colon-group
// could be a port) and is rejected. Hostnames use net.SplitHostPort
// for port detection so we handle `host`, `host:port`, `[ipv6]`, and
// `[ipv6]:port` consistently.
func (c *Client) ResolveHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("client: host argument is empty and no default is configured")
	}
	hasExplicitPort, err := hostHasPort(host)
	if err != nil {
		return "", fmt.Errorf("client: %w", err)
	}
	if c.cfg.DNSSuffix != "" && !strings.Contains(host, ".") && !hasExplicitPort && host[0] != '[' {
		host = host + "." + c.cfg.DNSSuffix
	}
	if !hasExplicitPort {
		port := c.cfg.Port
		if port == 0 {
			port = 8443
		}
		// Bracket bare IPv6 literals before appending the port.
		if isBareIPv6(host) {
			host = "[" + host + "]"
		}
		host = fmt.Sprintf("%s:%d", host, port)
	}
	return host, nil
}

// Call posts the supplied body to https://<host>/v1/<tool> and returns
// the response body. host is taken verbatim (already resolved via
// ResolveHost).
func (c *Client) Call(ctx context.Context, host, tool string, body []byte) ([]byte, *Error, error) {
	if body == nil {
		body = []byte("{}")
	}
	url := "https://" + host + "/v1/" + tool
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("client: do: %w", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("client: read body: %w", err)
	}
	if resp.StatusCode >= 400 {
		var e errorBody
		if jerr := json.Unmarshal(out, &e); jerr != nil || e.Error.Code == "" {
			return nil, &Error{
				HTTPStatus: resp.StatusCode,
				Code:       "internal_error",
				Message:    fmt.Sprintf("unparseable error body (status %d)", resp.StatusCode),
			}, nil
		}
		return nil, &Error{
			HTTPStatus: resp.StatusCode,
			Code:       e.Error.Code,
			Message:    e.Error.Message,
		}, nil
	}
	return out, nil, nil
}

// Error is the typed error returned by Call on non-2xx HTTP status.
type Error struct {
	HTTPStatus int
	Code       string
	Message    string
}

func (e *Error) String() string {
	return fmt.Sprintf("daemon: %s: %s (http %d)", e.Code, e.Message, e.HTTPStatus)
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// hostHasPort reports whether s already carries an explicit port.
// Handles three input shapes:
//   - bracketed IPv6 with port:    "[fe80::1]:8443"  -> true
//   - bracketed IPv6 without port: "[fe80::1]"       -> false
//   - hostname or IPv4 with port:  "host:8443"       -> true
//   - hostname or IPv4 plain:      "host"            -> false
//
// Bare unbracketed IPv6 ("fe80::1") is ambiguous and rejected.
func hostHasPort(s string) (bool, error) {
	if s == "" {
		return false, fmt.Errorf("empty host")
	}
	if s[0] == '[' {
		// Bracketed form. With port: [...]:N. Without port: [...].
		close := strings.IndexByte(s, ']')
		if close < 0 {
			return false, fmt.Errorf("unterminated [ in host %q", s)
		}
		rest := s[close+1:]
		if rest == "" {
			return false, nil
		}
		if rest[0] == ':' {
			return true, nil
		}
		return false, fmt.Errorf("garbage after ] in host %q", s)
	}
	// Unbracketed. Two or more colons = bare IPv6 literal (ambiguous,
	// rejected). One colon = hostname:port. Zero colons = plain
	// hostname.
	colons := strings.Count(s, ":")
	switch {
	case colons == 0:
		return false, nil
	case colons == 1:
		return true, nil
	default:
		return false, fmt.Errorf("bare IPv6 literal %q must be bracketed ([%s])", s, s)
	}
}

// isBareIPv6 reports whether s is an unbracketed IPv6 literal. Used
// by ResolveHost to bracket it before appending a port.
func isBareIPv6(s string) bool {
	if s == "" || s[0] == '[' {
		return false
	}
	return strings.Count(s, ":") >= 2
}
