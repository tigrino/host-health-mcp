package ops

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
)

// RkhunterSummaryResult is the typed result for op rkhunter_summary.
type RkhunterSummaryResult struct {
	Present      bool       `json:"present"`
	LastRunTS    *time.Time `json:"last_run_ts"`
	WarningCount *int       `json:"warning_count"`
}

// rkhunterLogPath is the canonical Debian location. rkhunter is
// invoked by cron.daily on Debian which appends to this file.
const rkhunterLogPath = "/var/log/rkhunter.log"

// RkhunterSummary reports the rkhunter log's mtime and the count of
// `Warning:` lines. Runs in the helper because rkhunter's log is
// `root:adm 0640` on Debian — the daemon (an unprivileged user not
// in `adm`) can stat the path but cannot read its contents. The
// helper has CAP_DAC_READ_SEARCH when the operator enables the
// security tool.
func RkhunterSummary(ctx context.Context, _ string) (any, error) {
	out := RkhunterSummaryResult{}

	info, err := os.Stat(rkhunterLogPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil // present=false, both fields nil
		}
		return nil, err
	}
	out.Present = true
	ts := info.ModTime().UTC()
	out.LastRunTS = &ts

	f, err := os.Open(rkhunterLogPath)
	if err != nil {
		// mtime is known but body is not readable; leave WarningCount
		// nil. The daemon's warnings[] will surface the gap when the
		// envelope is composed.
		return out, nil
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(io.LimitReader(f, 16*1024*1024))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "Warning:") {
			count++
		}
	}
	out.WarningCount = &count
	return out, nil
}
