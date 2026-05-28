package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// SshJournalCountsResult is the typed result for op ssh_journal_counts.
//
// The Truncated / OldestEntryUnixS / BootUnixS fields are additive
// (added in 1.16.2). Pre-1.16.2 daemons unmarshal them with
// omitempty defaults; pre-1.16.2 plugins are agnostic to helper
// proto extensions.
type SshJournalCountsResult struct {
	Present           bool  `json:"present"`
	AcceptedSinceBoot int   `json:"accepted_since_boot"`
	FailedSinceBoot   int   `json:"failed_since_boot"`
	Truncated         bool  `json:"truncated,omitempty"`
	OldestEntryUnixS  int64 `json:"oldest_entry_unix_s,omitempty"`
	BootUnixS         int64 `json:"boot_unix_s,omitempty"`
}

// sshJournalTruncationThresholdS is how far the journal's oldest
// retained entry can sit after the kernel boot before we flag the
// window as truncated. Ten minutes accommodates the typical
// service-start gap on hosts with delayed mount/network units
// (encrypted disks, late nss-resolve, etc.) without missing the
// volatile-journal case where the gap is hours-to-days.
const sshJournalTruncationThresholdS = int64(600)

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
// ceiling is just one line (64 KiB max per MaxLineLength).
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

	// Truncation probe: if the journal's oldest retained entry for
	// the current boot is significantly newer than the kernel boot
	// time, the counters above only cover the retained window
	// (typical on volatile-journal hosts where the ring buffer
	// rotates within hours of a 4-day boot). Failures here are
	// non-fatal — counters still ship, just without the truncation
	// flag. The daemon turns Truncated=true into an envelope
	// warning.
	if btime, oldest, ok := probeSshJournalTruncation(ctx); ok {
		out.BootUnixS = btime
		out.OldestEntryUnixS = oldest
		if oldest-btime > sshJournalTruncationThresholdS {
			out.Truncated = true
		}
	}

	return out, nil
}

// probeSshJournalTruncation returns (btime, oldestEntryUnixS, ok)
// where ok=false means we couldn't determine either timestamp and
// the caller should ship without truncation metadata. The journal
// uses microseconds; we normalise to whole seconds matching
// /proc/stat's btime field.
func probeSshJournalTruncation(ctx context.Context) (btime, oldest int64, ok bool) {
	btime, err := readSystemBootTime()
	if err != nil {
		return 0, 0, false
	}
	oldestUsec, err := readOldestJournalEntryForCurrentBoot(ctx)
	if err != nil {
		return 0, 0, false
	}
	return btime, oldestUsec / 1_000_000, true
}

// readSystemBootTime reads the kernel boot time (unix seconds) from
// /proc/stat. Layout: a line `btime <unix_seconds>` near the top.
func readSystemBootTime() (int64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	return parseBtimeFromProcStat(data)
}

// parseBtimeFromProcStat extracts the btime field from a /proc/stat
// payload. Kept separate from the file read so it can be unit-tested
// against synthetic inputs.
func parseBtimeFromProcStat(data []byte) (int64, error) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("btime ")) {
			return strconv.ParseInt(string(bytes.TrimSpace(line[len("btime "):])), 10, 64)
		}
	}
	return 0, errors.New("btime not found in /proc/stat")
}

// readOldestJournalEntryForCurrentBoot asks journalctl for the
// per-boot timestamp index and returns the first_entry of the
// current boot (index 0) in unix microseconds. systemd v247+
// (Debian 12+ ships v252) supports `--list-boots --output=json`.
func readOldestJournalEntryForCurrentBoot(ctx context.Context) (int64, error) {
	out, err := helperexec.Run(ctx, "journalctl", "--list-boots", "--output=json", "--no-pager")
	if err != nil {
		return 0, err
	}
	var boots []struct {
		Index      int   `json:"index"`
		FirstEntry int64 `json:"first_entry"`
	}
	if err := json.Unmarshal(out, &boots); err != nil {
		return 0, fmt.Errorf("parse list-boots: %w", err)
	}
	for _, b := range boots {
		if b.Index == 0 {
			return b.FirstEntry, nil
		}
	}
	return 0, errors.New("current boot (index=0) absent from list-boots")
}
