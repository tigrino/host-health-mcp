package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"

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
// The --grep filter is done by journalctl itself so the helper's
// stdout cap (256 KiB) is not the limiting factor on hosts with long
// uptime or noisy public surfaces — public-target hosts can easily
// emit hundreds of KiB of ssh.service journal entries per boot, and
// piping unfiltered output through the helper would trip the
// truncation cap (and previously masked the truncation as a generic
// ExitError because the kernel SIGPIPE-killed journalctl before the
// truncatedError reached classify()). With --grep, the data crossing
// the pipe is bounded by the count of matching lines, which is the
// answer we want anyway.
func SshJournalCounts(ctx context.Context, _ string) (any, error) {
	out := SshJournalCountsResult{}

	stdout, err := helperexec.Run(ctx,
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
			return out, nil
		}
		return nil, err
	}
	out.Present = true

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Accepted "):
			out.AcceptedSinceBoot++
		case strings.HasPrefix(line, "Failed "):
			out.FailedSinceBoot++
		}
	}
	return out, nil
}
