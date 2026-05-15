package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
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
// (journal-only Debian/RHEL hosts). The helper runs journalctl with a
// fixed arg vector and counts via prefix matching on "Accepted " and
// "Failed " — both are operator-controlled prefixes, but using a
// prefix instead of a substring match avoids being confused by lines
// like "Failed password for invalid user" (which still starts with
// "Failed ", so we still count it — that's the intended semantics).
func SshJournalCounts(ctx context.Context, _ string) (any, error) {
	out := SshJournalCountsResult{}

	stdout, err := helperexec.Run(ctx,
		"journalctl",
		"--boot",
		"-u", "ssh.service",
		"--output=cat",
		"--no-pager",
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
