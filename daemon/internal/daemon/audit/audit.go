// Package audit emits the daemon's audit log entries to journald via
// the structured logging interface (REQ 6.5). Each accepted or
// rejected tool call produces exactly one entry; payload bodies are
// never logged.
package audit

import (
	"fmt"
	"log"
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
	var args strings.Builder
	first := true
	for k, v := range e.Args {
		if !first {
			args.WriteByte(',')
		}
		first = false
		fmt.Fprintf(&args, "%s=%s", k, v)
	}
	log.Printf("audit caller=%s tool=%s args=[%s] size=%d duration_ms=%d result=%s reject_reason=%q",
		e.CallerIdentity, e.Tool, args.String(), e.ResponseSize,
		e.Duration.Milliseconds(), e.Result, e.RejectReason)
}
