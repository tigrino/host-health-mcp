// Package client is the plugin's HTTP/JSON client to the daemon's
// listener. Speaks mTLS only; the caller provides cert and key paths
// at construction.
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
	"time"
)

// Config configures a Client.
type Config struct {
	Host        string // host or host:port
	Port        int    // used if Host has no :port
	CertPath    string
	KeyPath     string
	CAPath      string // server CA bundle; empty uses system roots
	DNSSuffix   string // appended to bare hostnames
	HTTPTimeout time.Duration
}

// Client speaks to one daemon.
type Client struct {
	cfg  Config
	http *http.Client
	base string
}

// New constructs a Client. The TLS config is built once and shared
// across calls.
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

	host := cfg.Host
	if cfg.DNSSuffix != "" && !hasDot(host) {
		host = host + "." + cfg.DNSSuffix
	}
	if !hasPort(host) {
		port := cfg.Port
		if port == 0 {
			port = 8443
		}
		host = fmt.Sprintf("%s:%d", host, port)
	}

	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	return &Client{
		cfg: cfg,
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
				DisableKeepAlives: false,
			},
			Timeout: timeout,
		},
		base: "https://" + host,
	}, nil
}

// Call posts an empty (or supplied) body to /v1/<tool> and returns the
// response body. Caller is responsible for unmarshalling.
func (c *Client) Call(ctx context.Context, tool string, body []byte) ([]byte, *Error, error) {
	if body == nil {
		body = []byte("{}")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/v1/"+tool, bytes.NewReader(body))
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

func hasDot(s string) bool {
	for _, c := range s {
		if c == '.' {
			return true
		}
	}
	return false
}

func hasPort(s string) bool {
	// host:port for IPv4/hostname; [::1]:port for IPv6 - the plugin
	// expects the operator-supplied host to use one of these
	// conventional forms.
	if len(s) == 0 {
		return false
	}
	if s[0] == '[' {
		return true
	}
	for _, c := range s {
		if c == ':' {
			return true
		}
	}
	return false
}
