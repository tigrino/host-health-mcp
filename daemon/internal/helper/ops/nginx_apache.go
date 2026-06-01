package ops

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// NginxApacheStatusResult is the typed result for op
// nginx_apache_status. Worker count comes from /proc, the recent
// 4xx/5xx counts from an operator-supplied bounded summary JSON
// file (REQ 6.2 — the daemon never reads raw access logs).
type NginxApacheStatusResult struct {
	Server      string `json:"server"`
	WorkerCount int    `json:"worker_count"`
	Recent4xx   int    `json:"recent_4xx"`
	Recent5xx   int    `json:"recent_5xx"`
	Warning     string `json:"warning,omitempty"`
}

// procRootForTest lets the test fixture point /proc at a temporary
// tree. The empty-string default means real /proc.
var procRootForTest = ""

// NginxApacheStatus produces the workload-nginx-apache typed result.
// Parameter is the access-log summary path; empty means counts
// default to zero. Server detection scans /proc/*/comm; the
// minus-one heuristic for worker count is documented inline as a
// known limitation that suffices for 1.18.0.
func NginxApacheStatus(ctx context.Context, param string) (any, error) {
	root := procRootForTest
	if root == "" {
		root = "/proc"
	}
	server, nginx, apache := detectServer(root)
	out := NginxApacheStatusResult{Server: server}

	switch server {
	case "nginx":
		out.WorkerCount = nginx - 1
	case "apache":
		out.WorkerCount = apache - 1
	}
	if out.WorkerCount < 0 {
		out.WorkerCount = 0
	}

	if param != "" {
		x4, x5, err := readAccessLogSummary(param)
		if err != nil {
			out.Warning = "summary: " + err.Error()
		} else {
			out.Recent4xx = x4
			out.Recent5xx = x5
		}
	}
	return out, nil
}

// detectServer counts nginx and apache2 processes by scanning
// /proc/<pid>/comm. Returns ("nginx", n, _) or ("apache", _, n) or
// ("none", 0, 0). The minus-one master-process heuristic applied by
// the caller is brittle when systemd-resolved or other processes
// reuse the comm name; for 1.18.0 it is good enough — a more
// reliable cmdline parse can come later.
func detectServer(procRoot string) (server string, nginxCount, apacheCount int) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return "none", 0, 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// Pid dirs are all digits.
		if !allDigits(name) {
			continue
		}
		commPath := filepath.Join(procRoot, name, "comm")
		b, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(b))
		switch comm {
		case "nginx":
			nginxCount++
		case "apache2", "httpd":
			apacheCount++
		}
	}
	switch {
	case nginxCount > 0:
		return "nginx", nginxCount, apacheCount
	case apacheCount > 0:
		return "apache", nginxCount, apacheCount
	default:
		return "none", 0, 0
	}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// accessLogSummary is the operator-supplied bounded summary file
// shape. The daemon never reads raw access logs (REQ 6.2); an
// operator-supplied cron or logrotate job writes this file. Only
// the two count fields are consumed; generated_at and window_minutes
// remain in the file format for operator-side tooling but are
// ignored on decode (encoding/json silently drops unknown keys).
type accessLogSummary struct {
	Count4xx int `json:"count_4xx"`
	Count5xx int `json:"count_5xx"`
}

// readAccessLogSummary reads and parses the operator-supplied
// summary JSON. Returns (count_4xx, count_5xx, err). Missing or
// malformed file returns a non-nil error; the op surfaces this as a
// warning rather than a hard failure. Read is bounded to 16 KiB to
// bound memory if the operator points at the wrong file.
func readAccessLogSummary(path string) (int, int, error) {
	const maxBytes = 16 * 1024
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return 0, 0, err
	}
	if len(b) == 0 {
		return 0, 0, errors.New("empty summary file")
	}
	return parseAccessLogSummary(b)
}

// parseAccessLogSummary is the pure parser exposed for testing.
func parseAccessLogSummary(b []byte) (int, int, error) {
	var s accessLogSummary
	if err := json.Unmarshal(b, &s); err != nil {
		return 0, 0, err
	}
	if s.Count4xx < 0 || s.Count5xx < 0 {
		return 0, 0, errors.New("negative counts in summary")
	}
	return s.Count4xx, s.Count5xx, nil
}
