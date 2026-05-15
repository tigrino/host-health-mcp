// Package audit emits the daemon's audit log entries to journald via
// the structured logging interface (REQ 6.5). Each accepted or
// rejected tool call produces exactly one entry; payload bodies are
// never logged.
package audit

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// Entry is one accepted or rejected call.
type Entry struct {
	CallerIdentity string
	Tool           string
	Args           map[string]string
	ResponseSize   int
	Duration       time.Duration
	Result         string // "ok" or one of the error codes from schema/errors.go
	RejectReason   string // populated for non-ok results
	HelperOps      []string // ops the helper performed for this call (sha-256 fingerprints of stderr where applicable)
}

// Logger writes audit entries. Implementations are expected to push to
// journald with SyslogIdentifier=host-health-mcp.
type Logger interface {
	Log(Entry)
}

// New returns a Logger that writes via the standard log package. When
// the daemon is running under systemd, stderr is captured by journald,
// so a Go log.Println line with KEY=VALUE structure is enough; a
// follow-up may use github.com/coreos/go-systemd/v22/journal for
// native journald fields, but that brings cgo or a CGO-less variant
// dependency that is not load-bearing for the audit contract.
func New() Logger {
	return &stdLogger{}
}

type stdLogger struct{}

func (l *stdLogger) Log(e Entry) {
	// All caller-influenced string fields are %q-quoted so that
	// control characters, '=', ']', spaces, or newlines inside a
	// client cert's CommonName cannot mangle a downstream
	// (now-hypothetical, later-real) log parser. Args map keys are
	// sorted to give deterministic output across calls — Go's range
	// over a map is intentionally non-deterministic, so two
	// otherwise-identical entries would render differently without
	// the sort.
	var args strings.Builder
	keys := make([]string, 0, len(e.Args))
	for k := range e.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i > 0 {
			args.WriteByte(',')
		}
		fmt.Fprintf(&args, "%q=%q", k, e.Args[k])
	}
	log.Printf("audit caller=%q tool=%q args=[%s] size=%d duration_ms=%d result=%q reject_reason=%q",
		e.CallerIdentity, e.Tool, args.String(), e.ResponseSize,
		e.Duration.Milliseconds(), e.Result, e.RejectReason)
}
