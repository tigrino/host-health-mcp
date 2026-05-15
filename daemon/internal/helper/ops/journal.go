package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// JournalQueryResult is the typed result for op journal_query.
type JournalQueryResult struct {
	TotalCount int                 `json:"total_count"`
	ByUnit     map[string]int      `json:"by_unit"`
	Samples    []JournalSample     `json:"samples"`
}

// JournalSample is one log entry. Message is the raw journald
// MESSAGE field; the daemon-side logs tool runs each through the
// redaction filter (REQ 6.3) before placing it in the envelope.
type JournalSample struct {
	TS      string `json:"ts"`
	Unit    string `json:"unit"`
	Message string `json:"message"`
}

// paramRE accepts the helper's structured-parameter form
// "severity=<emerg|alert|crit|err|warning> window=<15m|1h|6h|24h> source=<journal|audit>".
// Anything else fails CodeBadParam.
var paramRE = regexp.MustCompile(
	`^severity=(emerg|alert|crit|err|warning) ` +
		`window=(15m|1h|6h|24h) ` +
		`source=(journal|audit)$`)

const journalSampleCap = 200

// JournalQuery invokes journalctl with bounded arguments and returns
// the parsed result. Requires no special capabilities on Debian/
// Ubuntu when the daemon user is in the systemd-journal group; the
// helper runs as root so the access is always permitted.
func JournalQuery(ctx context.Context, param string) (any, error) {
	m := paramRE.FindStringSubmatch(param)
	if m == nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeBadParam,
			Message: "param must match severity=<lvl> window=<dur> source=<journal|audit>",
		}
	}
	severity, window, source := m[1], m[2], m[3]
	since := windowToSince(window)
	prio := severityToNumeric(severity)

	args := []string{
		"--output=json",
		"--no-pager",
		"--since=" + since,
		"--priority=0.." + prio,
		"--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,MESSAGE",
		"-n", fmt.Sprintf("%d", journalSampleCap),
	}
	if source == "audit" {
		args = append(args, "_TRANSPORT=audit")
	}

	stdout, err := helperexec.Run(ctx, "journalctl", args...)
	if err != nil {
		return nil, err
	}

	out := JournalQueryResult{ByUnit: map[string]int{}, Samples: []JournalSample{}}
	for _, line := range strings.Split(string(stdout), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
			SystemdUnit       string `json:"_SYSTEMD_UNIT"`
			SyslogIdentifier  string `json:"SYSLOG_IDENTIFIER"`
			Message           string `json:"MESSAGE"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		unit := entry.SystemdUnit
		if unit == "" {
			unit = entry.SyslogIdentifier
		}
		if unit == "" {
			unit = "kernel"
		}
		out.TotalCount++
		out.ByUnit[unit]++
		if len(out.Samples) < 20 {
			ts := journalTSToRFC3339(entry.RealtimeTimestamp)
			out.Samples = append(out.Samples, JournalSample{
				TS: ts, Unit: unit, Message: entry.Message,
			})
		}
	}
	return out, nil
}

func windowToSince(window string) string {
	switch window {
	case "15m":
		return "15 minutes ago"
	case "1h":
		return "1 hour ago"
	case "6h":
		return "6 hours ago"
	case "24h":
		return "24 hours ago"
	}
	return "1 hour ago"
}

func severityToNumeric(s string) string {
	switch s {
	case "emerg":
		return "0"
	case "alert":
		return "1"
	case "crit":
		return "2"
	case "err":
		return "3"
	case "warning":
		return "4"
	}
	return "4"
}

func journalTSToRFC3339(ts string) string {
	if ts == "" {
		return ""
	}
	usec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ""
	}
	return time.UnixMicro(usec).UTC().Format(time.RFC3339Nano)
}
