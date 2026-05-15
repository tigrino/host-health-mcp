package ops

import (
	"bytes"
	"context"
	"errors"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// SshJournalCountsResult is the typed result for op ssh_journal_counts.
type SshJournalCountsResult struct {
	Present           bool `json:"present"`
	AcceptedSinceBoot int  `json:"accepted_since_boot"`
	FailedSinceBoot   int  `json:"failed_since_boot"`
}

// SshJournalCounts counts since-boot Accepted/Failed SSH login lines
// emitted to the systemd journal by ssh.service. Used as a fallback
// when neither /var/log/auth.log nor /var/log/secure is present
// (journal-only Debian/RHEL hosts).
//
// Uses RunStreaming so the helper's 256 KiB stdout cap is never the
// limiting factor: each line is visited as it arrives and counted
// via the closure-captured `out` accumulator. The journalctl
// --grep filter still reduces the I/O on the hot path but is no
// longer load-bearing — public-target hosts whose ssh.service
// journal is dominated by long pubkey-hash lines (~120 bytes per
// "Accepted publickey ... SHA256:..." entry) used to overflow the
// cap even after pre-filtering. With streaming, the per-call memory
// ceiling is just one line (1 MiB max per MaxLineLength).
//
// The pre-filter is kept because it halves the bytes the journalctl
// process emits, which matters on busy hosts even though it no
// longer matters for correctness.
//
// Accepted-vs-Failed classification happens against the journalctl
// --output=cat shape: the daemon receives only the MESSAGE field, so
// "Accepted publickey for ..." starts at byte 0 and prefix-matching
// on "Accepted " / "Failed " is unambiguous (matches every flavour
// including "Failed password for invalid user").
func SshJournalCounts(ctx context.Context, _ string) (any, error) {
	out := SshJournalCountsResult{}

	var (
		acceptedPrefix = []byte("Accepted ")
		failedPrefix   = []byte("Failed ")
	)
	_, err := helperexec.RunStreaming(ctx, func(line []byte) {
		switch {
		case bytes.HasPrefix(line, acceptedPrefix):
			out.AcceptedSinceBoot++
		case bytes.HasPrefix(line, failedPrefix):
			out.FailedSinceBoot++
		}
	},
		"journalctl",
		"--boot",
		"-u", "ssh.service",
		"--output=cat",
		"--no-pager",
		"--grep=^(Accepted|Failed) ",
	)
	if err != nil {
		var de *dispatch.Error
		// journalctl missing → present=false rather than failing.
		if errors.As(err, &de) && de.Code == proto.CodeToolMissing {
			return SshJournalCountsResult{}, nil
		}
		return nil, err
	}
	out.Present = true
	return out, nil
}
