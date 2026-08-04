package ops

import (
	"bytes"
	"context"
	"host-health-mcp/daemon/internal/shared/linescan"
	"strconv"
	"strings"

	helperexec "host-health-mcp/daemon/internal/helper/exec"
)

// ZpoolStatusResult is the typed result for op zpool_status.
type ZpoolStatusResult struct {
	Pools []ZfsPool `json:"pools"`
}

// ZfsPool mirrors the daemon-side schema's zfs_pools[] row.
type ZfsPool struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	ScanState   string `json:"scan_state"`
	ErrorsTotal int    `json:"errors_total"`
}

// ZpoolStatus invokes `zpool list -H -o name` then `zpool status
// <name>` per pool, parsing the human-readable status output. We
// avoid `zpool status -j` since it requires ZFS 2.2+ and the text
// form is stable across the versions we target.
func ZpoolStatus(ctx context.Context, _ string) (any, error) {
	listOut, err := helperexec.Run(ctx, "zpool", "list", "-H", "-o", "name")
	if err != nil {
		return ZpoolStatusResult{Pools: []ZfsPool{}}, nil
	}
	names := strings.Fields(strings.TrimSpace(string(listOut)))
	if len(names) == 0 {
		return ZpoolStatusResult{Pools: []ZfsPool{}}, nil
	}

	out := ZpoolStatusResult{Pools: make([]ZfsPool, 0, len(names))}
	for _, name := range names {
		statusOut, err := helperexec.Run(ctx, "zpool", "status", name)
		if err != nil {
			continue
		}
		pool, perr := parseZpoolStatus(name, statusOut)
		if perr != nil {
			// Skip this pool, keep the others. Failing the op here
			// discarded every pool already parsed, so the daemon
			// emitted zfs_pools: [] — which reads as "this host has no
			// ZFS", the one answer that is certainly wrong. Matches how
			// the exec-failure branch above treats a single bad pool.
			continue
		}
		out.Pools = append(out.Pools, pool)
	}
	return out, nil
}

// parseZpoolStatus extracts state, scan, errors_total from the
// human-readable `zpool status` output.
//
//	pool: tank
//	state: ONLINE
//	scan: scrub repaired 0B in 00:30:00 with 0 errors on Sun ...
//	...
//	errors: No known data errors
func parseZpoolStatus(name string, out []byte) (ZfsPool, error) {
	p := ZfsPool{Name: name, State: "unknown", ScanState: "unknown"}

	scanner := linescan.New(bytes.NewReader(out), "zpool status")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "state:"):
			p.State = strings.TrimSpace(strings.TrimPrefix(line, "state:"))
		case strings.HasPrefix(line, "scan:"):
			body := strings.TrimSpace(strings.TrimPrefix(line, "scan:"))
			p.ScanState = summariseScan(body)
		case strings.HasPrefix(line, "errors:"):
			p.ErrorsTotal = parseErrors(strings.TrimSpace(strings.TrimPrefix(line, "errors:")))
		}
	}
	if err := scanner.Err(); err != nil {
		return ZfsPool{}, err
	}
	return p, nil
}

// summariseScan collapses the free-form scan line to a short tag
// matching the schema enum-ish expectation (idle/scrubbing/resilvering/
// scrubbed). Anything that fails to match returns "unknown".
func summariseScan(body string) string {
	low := strings.ToLower(body)
	switch {
	case strings.Contains(low, "none requested"):
		return "idle"
	case strings.Contains(low, "scrub in progress"):
		return "scrubbing"
	case strings.Contains(low, "resilver in progress"):
		return "resilvering"
	case strings.Contains(low, "scrub repaired"), strings.Contains(low, "scrub completed"):
		return "scrubbed"
	case strings.Contains(low, "resilver completed"):
		return "resilvered"
	}
	return "unknown"
}

// parseErrors returns the integer in "N data errors", or zero when
// the line reads "No known data errors".
func parseErrors(body string) int {
	if strings.Contains(strings.ToLower(body), "no known data errors") {
		return 0
	}
	for _, tok := range strings.Fields(body) {
		if v, err := strconv.Atoi(tok); err == nil {
			return v
		}
	}
	return 0
}
