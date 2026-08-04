package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"host-health-mcp/daemon/internal/shared/linescan"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// NginxApacheStatusParam is the typed parameter for op
// nginx_apache_status. The daemon-side plugin marshals this from
// manifest.workload_plugin_config.nginx_apache before invoking the
// helper.
type NginxApacheStatusParam struct {
	AccessLogPath      string `json:"access_log_path"`
	AccessLogWindowMin int    `json:"access_log_window_minutes"`
	AccessLogTailBytes int    `json:"access_log_tail_bytes"`
}

// NginxApacheStatusResult is the typed result for op
// nginx_apache_status. Recent4xx / Recent5xx are *int so JSON null is
// distinct from a measured zero on the wire (1.19.0+).
type NginxApacheStatusResult struct {
	Server              string `json:"server"`
	WorkerCount         int    `json:"worker_count"`
	Recent4xx           *int   `json:"recent_4xx"`
	Recent5xx           *int   `json:"recent_5xx"`
	RecentWindowMinutes int    `json:"recent_window_minutes"`
	RecentCoverage      string `json:"recent_coverage"`
	Warning             string `json:"warning,omitempty"`
}

// procRootForTest lets the test fixture point /proc at a temporary
// tree. The empty-string default means real /proc.
var procRootForTest = ""

const (
	defaultAccessLogWindowMin = 60
	defaultAccessLogTailBytes = 256 * 1024
	maxAccessLogTailBytes     = 4 * 1024 * 1024
	maxAccessLogLineBytes     = 64 * 1024
)

// NginxApacheStatus produces the workload-nginx-apache typed result.
// Server detection scans /proc/<pid>/comm. Recent 4xx / 5xx counts
// come from a bounded tail-read of the configured access log; the
// helper parses combined/common log format inside its own process
// so raw log bytes never cross the helper-to-daemon socket boundary
// (REQ 6.2).
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

	var p NginxApacheStatusParam
	if param != "" {
		if err := json.Unmarshal([]byte(param), &p); err != nil {
			out.RecentCoverage = "unavailable"
			out.Warning = "param: " + err.Error()
			return out, nil
		}
	}
	if p.AccessLogWindowMin == 0 {
		p.AccessLogWindowMin = defaultAccessLogWindowMin
	}
	if p.AccessLogTailBytes == 0 {
		p.AccessLogTailBytes = defaultAccessLogTailBytes
	}
	var capWarning string
	if p.AccessLogTailBytes > maxAccessLogTailBytes {
		capWarning = fmt.Sprintf("access_log_tail_bytes capped: requested %d, using %d", p.AccessLogTailBytes, maxAccessLogTailBytes)
		p.AccessLogTailBytes = maxAccessLogTailBytes
	}

	if server == "none" {
		out.RecentCoverage = "unavailable"
		out.Warning = "no nginx/apache process detected"
		return out, nil
	}
	if p.AccessLogPath == "" {
		out.RecentCoverage = "unavailable"
		out.Warning = "access_log_path not configured"
		return out, nil
	}

	if err := checkAccessLogPath(p.AccessLogPath); err != nil {
		out.RecentCoverage = "unavailable"
		out.Warning = "access_log_path: " + err.Error()
		return out, nil
	}

	tail, statErr := readAccessLogTail(p.AccessLogPath, p.AccessLogTailBytes)
	if statErr != nil {
		out.RecentCoverage = "unavailable"
		out.Warning = "access_log_path: " + statErr.Error()
		if capWarning != "" {
			out.Warning = capWarning + "; " + out.Warning
		}
		return out, nil
	}

	now := time.Now()
	window := time.Duration(p.AccessLogWindowMin) * time.Minute
	r4, r5, oldest, anyParsed := parseAccessLogTail(tail, now, window)

	switch {
	case !anyParsed:
		out.Recent4xx = nil
		out.Recent5xx = nil
		out.RecentCoverage = "unavailable"
		out.RecentWindowMinutes = 0
		out.Warning = "no parseable timestamps in tail"
	case !oldest.After(now.Add(-window)):
		out.Recent4xx = r4
		out.Recent5xx = r5
		out.RecentCoverage = "full"
		out.RecentWindowMinutes = p.AccessLogWindowMin
	default:
		out.Recent4xx = r4
		out.Recent5xx = r5
		out.RecentCoverage = "partial"
		mins := int(now.Sub(oldest).Minutes())
		if mins < 0 {
			mins = 0
		}
		out.RecentWindowMinutes = mins
	}

	if capWarning != "" {
		if out.Warning == "" {
			out.Warning = capWarning
		} else {
			out.Warning = capWarning + "; " + out.Warning
		}
	}
	return out, nil
}

// readAccessLogTail opens path, seeks to max(0, size-tailBytes), and
// returns up to tailBytes of trailing content. When the seek skipped
// past the start of the file, the first (necessarily partial) line is
// discarded so the caller sees only well-formed lines.
func readAccessLogTail(path string, tailBytes int) ([]byte, error) {
	// Open FIRST, then fstat the descriptor. Stat-then-open re-resolves
	// the path, so the regular-file check applied to one object and the
	// read to another: swapping the target for a FIFO in between
	// blocked the root helper in open(2) indefinitely. Checking the fd
	// we actually hold removes the window.
	//
	// O_NOFOLLOW refuses a symlinked final component, and O_NONBLOCK
	// makes open(2) on a FIFO return instead of waiting for a writer —
	// belt and braces, since the fstat below rejects it anyway.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // forbidden:allow — read-only; O_NOFOLLOW and the fstat below are the point.
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}

	var (
		off       int64
		truncated bool
	)
	if int64(tailBytes) < size {
		off = size - int64(tailBytes)
		truncated = true
	}
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return nil, err
		}
	}
	// Allocate what will actually be read, not the ceiling. A 1-byte
	// log with a 1 MiB tail request allocated 1 MiB per call.
	// Defend at the boundary, not by trusting the daemon's own
	// validation. tailBytes arrives from the request; a negative value
	// makes size-off negative too, so the comparison below leaves want
	// negative and make() panics — killing the privileged process,
	// which has no recover anywhere.
	if tailBytes <= 0 {
		return nil, errors.New("access_log_tail_bytes must be positive")
	}
	want := int64(tailBytes)
	if size-off < want {
		want = size - off
	}
	buf := make([]byte, want)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	buf = buf[:n]
	if truncated {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		} else {
			// Whole tail is one (likely partial) line - discard.
			return nil, nil
		}
	}
	return buf, nil
}

// parseAccessLogTail walks tail line-by-line, extracting the bracketed
// timestamp and the HTTP status code in combined/common log format,
// and counts 4xx / 5xx within [now-window, now]. The fourth return is
// the oldest successfully parsed timestamp across every line whose
// timestamp parsed cleanly (whether or not the status bucketed) and
// anyParsed reports whether any timestamp parsed at all. The caller
// uses oldest + anyParsed to classify the coverage as full / partial
// / unavailable.
func parseAccessLogTail(tail []byte, now time.Time, window time.Duration) (recent4xx, recent5xx *int, oldestParsed time.Time, anyParsed bool) {
	if len(tail) == 0 {
		return nil, nil, time.Time{}, false
	}
	cutoff := now.Add(-window)
	var c4, c5 int

	scanner := linescan.New(bytes.NewReader(tail), "access log")
	for scanner.Scan() {
		line := scanner.Bytes()
		ts, ok := extractLogTimestamp(line)
		if !ok {
			continue
		}
		if !anyParsed || ts.Before(oldestParsed) {
			oldestParsed = ts
			anyParsed = true
		}
		if ts.Before(cutoff) {
			continue
		}
		code, ok := extractLogStatus(line)
		if !ok {
			continue
		}
		switch {
		case code >= 400 && code < 500:
			c4++
		case code >= 500 && code < 600:
			c5++
		}
	}
	// Do NOT ignore this. The access log is the one input in the tree a
	// remote client fully controls — it writes the request URI and
	// User-Agent into the line. One request with an over-long URI stops
	// the scan, and because this is a TAIL read that line lands near the
	// start of the window, so the counts come back near-zero, non-nil,
	// with anyParsed true. The attacker suppresses the very counter
	// meant to detect them, and the response says status: ok.
	//
	// "Counts gathered before the failure are still valid" was the old
	// justification. They are not valid as COMPLETE counts, which is how
	// they are published.
	if scanner.Err() != nil {
		return nil, nil, time.Time{}, false
	}
	if !anyParsed {
		return nil, nil, time.Time{}, false
	}
	return &c4, &c5, oldestParsed, true
}

// extractLogTimestamp finds the first `[...]` pair on the line and
// parses its contents in combined/common log format. Returns (zero,
// false) if no bracket pair is found or the contents do not parse.
func extractLogTimestamp(line []byte) (time.Time, bool) {
	lb := bytes.IndexByte(line, '[')
	if lb < 0 {
		return time.Time{}, false
	}
	rest := line[lb+1:]
	rb := bytes.IndexByte(rest, ']')
	if rb < 0 {
		return time.Time{}, false
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(rest[:rb]))
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// extractLogStatus finds the first ` NNN ` triple following a `"`
// (the closing quote of the request field in combined/common log
// format), returns the integer status. Returns (0, false) if the
// pattern is not present.
func extractLogStatus(line []byte) (int, bool) {
	q := bytes.IndexByte(line, '"')
	if q < 0 {
		return 0, false
	}
	rest := line[q+1:]
	q2 := bytes.IndexByte(rest, '"')
	if q2 < 0 {
		return 0, false
	}
	after := rest[q2+1:]
	// Skip exactly one space, expect three digits, then a non-digit.
	if len(after) < 5 || after[0] != ' ' {
		return 0, false
	}
	d := after[1:]
	if len(d) < 4 {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if d[i] < '0' || d[i] > '9' {
			return 0, false
		}
	}
	if d[3] != ' ' && d[3] != '\t' {
		return 0, false
	}
	code := int(d[0]-'0')*100 + int(d[1]-'0')*10 + int(d[2]-'0')
	return code, true
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

// accessLogAllowedPrefixes constrains which paths nginx_apache_status
// will read. This was the only op of the 23 with no parameter
// allow-list: access_log_path reached the opener verbatim from the
// request, and the request comes from the daemon — the network-facing
// half the helper exists to be separate from.
//
// A compromised daemon had three primitives. An existence and
// permission oracle, since the raw os error string (including the
// path) is promoted to an envelope warning. A weak content oracle, as
// any root-readable regular file gets parsed and its combined-log-
// shaped lines tallied. And, before the open-then-fstat fix above, a
// TOCTOU into an indefinite block on a FIFO.
//
// Operator-settable via helper.yml because "where the web server keeps
// its logs" is a deployment fact, and the privileged side is the right
// place to hold that list.
var accessLogAllowedPrefixes = []string{"/var/log/"}

// SetAccessLogPrefixes replaces the allow-list. Empty input keeps the
// default rather than allowing everything: an empty allow-list that
// means "permit all" is the fail-open shape this is here to remove.
func SetAccessLogPrefixes(prefixes []string) {
	var clean []string
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
		clean = append(clean, p)
	}
	if len(clean) > 0 {
		accessLogAllowedPrefixes = clean
	}
}

// checkAccessLogPath rejects anything outside the allow-list. The path
// is cleaned first so "/var/log/../etc/shadow" cannot walk out, and
// compared against the cleaned prefix so "/var/logsecrets" does not
// pass as "/var/log".
func checkAccessLogPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("access_log_path must be absolute")
	}
	clean := filepath.Clean(path)
	for _, pre := range accessLogAllowedPrefixes {
		if strings.HasPrefix(clean, filepath.Clean(pre)+"/") {
			return nil
		}
	}
	return fmt.Errorf("access_log_path %s is outside the permitted prefixes %v",
		clean, accessLogAllowedPrefixes)
}
