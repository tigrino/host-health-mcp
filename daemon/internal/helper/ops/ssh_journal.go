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
//
// On a key-only-SSH fleet the bare "Failed " pattern never fires —
// scanners disconnect during key exchange before reaching the
// publickey-auth stage. The preauth-disconnect and kex-error
// patterns below capture the actual rejection signal that
// `failed_since_boot` is supposed to represent. We deliberately
// skip "Received disconnect from" because it pairs with
// "Disconnected from" on every client-initiated SSH_MSG_DISCONNECT
// and would double-count the same probe.
// classifySshJournalLine maps one journalctl --output=cat line into
// one of {accepted, failed, other} for the SSH counter. Extracted
// so it can be unit-tested without spinning up journalctl.
type sshJournalClass int

const (
	sshJournalOther sshJournalClass = iota
	sshJournalAccepted
	sshJournalFailed
)

var (
	sshAcceptedPrefix      = []byte("Accepted ")
	sshFailedPrefix        = []byte("Failed ")
	sshDisconnectedPrefix  = []byte("Disconnected from ")
	sshConnClosedPrefix    = []byte("Connection closed by ")
	sshPreauthSuffix       = []byte("[preauth]")
	sshKexExchangeIDSubstr = []byte("kex_exchange_identification")
)

func classifySshJournalLine(line []byte) sshJournalClass {
	switch {
	case bytes.HasPrefix(line, sshAcceptedPrefix):
		return sshJournalAccepted
	case bytes.HasPrefix(line, sshFailedPrefix):
		return sshJournalFailed
	case bytes.HasSuffix(line, sshPreauthSuffix) &&
		(bytes.HasPrefix(line, sshDisconnectedPrefix) ||
			bytes.HasPrefix(line, sshConnClosedPrefix)):
		return sshJournalFailed
	case bytes.Contains(line, sshKexExchangeIDSubstr):
		return sshJournalFailed
	}
	return sshJournalOther
}

func SshJournalCounts(ctx context.Context, _ string) (any, error) {
	out := SshJournalCountsResult{}

	_, err := helperexec.RunStreaming(ctx, func(line []byte) {
		switch classifySshJournalLine(line) {
		case sshJournalAccepted:
			out.AcceptedSinceBoot++
		case sshJournalFailed:
			out.FailedSinceBoot++
		}
	},
		"journalctl",
		"--boot",
		"-u", "ssh.service",
		"--output=cat",
		"--no-pager",
		// Pre-filter is a perf optimisation only — the streaming
		// closure does the strict classification. Pattern is a
		// conservative superset of what we count so we don't have
		// to micromanage the journalctl regex flavour.
		"--grep=^(Accepted|Failed|Disconnected|Connection closed)|kex_exchange_identification",
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
