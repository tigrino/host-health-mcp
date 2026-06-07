package ops

import (
	"bufio"
	"bytes"
	"context"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AideSummary is the typed result for op read_aide_summary.
type AideSummary struct {
	Present       bool       `json:"present"`
	LastRunTS     *time.Time `json:"last_run_ts"`
	LastExitCode  *int       `json:"last_exit_code"`
	ChangeCount   *int       `json:"change_count"`
}

// dbPaths lists the canonical AIDE database locations on Debian/Ubuntu.
// First match wins.
var dbPaths = []string{
	"/var/lib/aide/aide.db",
	"/var/lib/aide/aide.db.new",
}

// changeLineRE matches the summary line AIDE emits after --check:
//   "Total number of differences: 3"
// or in the verbose form:
//   "Total number of entries:        12345"
//   "Added entries:                  1"
//   "Removed entries:                0"
//   "Changed entries:                2"
// We sum Added+Removed+Changed when present, falling back to the
// "differences" line when only the summary is available.
var (
	diffRE    = regexp.MustCompile(`(?i)Total number of differences:\s+(\d+)`)
	addedRE   = regexp.MustCompile(`(?i)Added entries?:\s+(\d+)`)
	removedRE = regexp.MustCompile(`(?i)Removed entries?:\s+(\d+)`)
	changedRE = regexp.MustCompile(`(?i)Changed entries?:\s+(\d+)`)
)

// ReadAideSummary reports presence, last-run timestamp, and change
// count. The database file's mtime is the last-run signal; change
// count is parsed from the newest /var/log/aide/aide.log entry.
// Requires CAP_DAC_READ_SEARCH on the helper unit when the
// operator installs the AIDE DB root-only.
func ReadAideSummary(ctx context.Context, _ string) (any, error) {
	out := AideSummary{}

	dbPath := ""
	for _, p := range dbPaths {
		if info, err := os.Stat(p); err == nil {
			dbPath = p
			ts := info.ModTime().UTC()
			out.LastRunTS = &ts
			break
		}
	}
	if dbPath == "" {
		return out, nil
	}
	out.Present = true

	// Optional sanity check: confirm the file is a real AIDE DB. AIDE
	// gzip's by default; the first bytes are the gzip magic 0x1f 0x8b.
	// We don't require this; we use it only to surface clearer errors
	// upstream if the operator points us at the wrong file.
	if !looksLikeAideDB(dbPath) {
		// Not fatal - the operator may have a custom dbout setting.
		// Just don't try to read change_count from a bogus log path.
	}

	if cnt, exit := readAideLog(); cnt != nil {
		out.ChangeCount = cnt
		out.LastExitCode = exit
	}

	return out, nil
}

// looksLikeAideDB peeks at path's first two bytes; returns true if
// they are 0x1f 0x8b (gzip).
func looksLikeAideDB(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x1f && magic[1] == 0x8b
}

// readAideLog finds the most-recent log file under /var/log/aide and
// parses its tail for change_count and exit code. The Debian package
// writes aide.log on each scheduled run; logrotate then produces
// aide.log.1.gz, aide.log.2.gz, etc.
func readAideLog() (*int, *int) {
	logDir := "/var/log/aide"
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, nil
	}
	candidates := make([]os.DirEntry, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "aide.log") {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		ai, _ := candidates[i].Info()
		aj, _ := candidates[j].Info()
		return ai.ModTime().After(aj.ModTime())
	})
	for _, e := range candidates {
		path := filepath.Join(logDir, e.Name())
		body, err := readMaybeGzipped(path)
		if err != nil {
			continue
		}
		cnt, exit := parseAideLog(body)
		if cnt != nil {
			return cnt, exit
		}
	}
	return nil, nil
}

// readMaybeGzipped reads path; transparently decompresses if the file
// ends in .gz.
func readMaybeGzipped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return io.ReadAll(io.LimitReader(gz, 2*1024*1024))
	}
	return io.ReadAll(io.LimitReader(f, 2*1024*1024))
}

// parseAideLog extracts (change_count, last_exit_code) from a single
// log body. Conservative: returns nil pointers when nothing matches.
func parseAideLog(body []byte) (*int, *int) {
	var cnt *int
	var exit *int
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	var added, removed, changed int
	haveDetail := false
	foundDiff := false
	foundNoDiff := false

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.Contains(line, "AIDE found NO differences"):
			foundNoDiff = true
		case strings.Contains(line, "AIDE found differences"):
			foundDiff = true
		}
		if m := diffRE.FindStringSubmatch(line); m != nil {
			v, _ := strconv.Atoi(m[1])
			cnt = &v
		}
		if m := addedRE.FindStringSubmatch(line); m != nil {
			v, _ := strconv.Atoi(m[1])
			added = v
			haveDetail = true
		}
		if m := removedRE.FindStringSubmatch(line); m != nil {
			v, _ := strconv.Atoi(m[1])
			removed = v
			haveDetail = true
		}
		if m := changedRE.FindStringSubmatch(line); m != nil {
			v, _ := strconv.Atoi(m[1])
			changed = v
			haveDetail = true
		}
	}
	if haveDetail {
		total := added + removed + changed
		cnt = &total
	}
	// AIDE's clean-state report ("AIDE found NO differences between
	// database and filesystem") omits the "Total number of differences:"
	// header and the per-class "Added/Removed/Changed entries:" lines, so
	// the regex scan above yields nothing. Without this headline check a
	// clean newest log would parse as unparseable (nil) and readAideLog
	// would fall through to an older rotated log that may still carry a
	// non-zero count — reporting a stale change_count for a host that is
	// actually clean. The headline is authoritative: change_count and the
	// derived exit code are both zero.
	switch {
	case foundNoDiff && !foundDiff:
		zero := 0
		exit = &zero
		if cnt == nil {
			cnt = &zero
		}
	case foundDiff:
		one := 1
		exit = &one
	}
	return cnt, exit
}
