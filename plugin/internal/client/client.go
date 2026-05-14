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
	"net/http"
	"os"
	"strings"
	"time"
)

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

// ResolveHost expands a caller-supplied host into the host:port form
// used in URLs. Bare names get DNSSuffix appended; missing port gets
// cfg.Port (or 8443 if unset). Empty input returns an error.
func (c *Client) ResolveHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("client: host argument is empty and no default is configured")
	}
	if c.cfg.DNSSuffix != "" && !strings.Contains(host, ".") && !hasPort(host) {
		host = host + "." + c.cfg.DNSSuffix
	}
	if !hasPort(host) {
		port := c.cfg.Port
		if port == 0 {
			port = 8443
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

// hasPort returns true if s has an explicit port. Handles [ipv6]:port,
// host:port, and plain host.
func hasPort(s string) bool {
	if len(s) == 0 {
		return false
	}
	if s[0] == '[' {
		return strings.Contains(s, "]:")
	}
	return strings.Count(s, ":") == 1
}
