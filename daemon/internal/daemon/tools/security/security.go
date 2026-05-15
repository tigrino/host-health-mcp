// Package security implements tool 4.5: presence and last-run state
// for AIDE, auditd, rkhunter, debsums; intrusion-prevention backend;
// SSH login counters. Daemon-side presence detection plus helper-op
// calls for the deep fields (audit queue/lost, AIDE change count).
package security

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"tigr.net/host-health-mcp/daemon/internal/daemon/helperinvoke"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// Data is the response data for tool security.
type Data struct {
	AideOrEquivalent     Aide      `json:"aide_or_equivalent"`
	Auditd               Auditd    `json:"auditd"`
	Rkhunter             Rkhunter  `json:"rkhunter"`
	DebsumsOrEquivalent  Debsums   `json:"debsums_or_equivalent"`
	IntrusionPrevention  IPS       `json:"intrusion_prevention"`
	SSHLogins            SSHLogins `json:"ssh_logins"`
}

// Aide mirrors the aide_or_equivalent block.
type Aide struct {
	Present       bool       `json:"present"`
	LastRunTS     *time.Time `json:"last_run_ts"`
	LastExitCode  *int       `json:"last_exit_code"`
	ChangeCount   *int       `json:"change_count"`
}

// Auditd mirrors the auditd block.
type Auditd struct {
	Present         bool       `json:"present"`
	QueueDepth      *int       `json:"queue_depth"`
	LostEvents      *int       `json:"lost_events"`
	LastRotationTS  *time.Time `json:"last_rotation_ts"`
}

// Rkhunter mirrors the rkhunter block.
type Rkhunter struct {
	Present       bool       `json:"present"`
	LastRunTS     *time.Time `json:"last_run_ts"`
	WarningCount  *int       `json:"warning_count"`
}

// Debsums mirrors the debsums_or_equivalent block.
type Debsums struct {
	Present       bool       `json:"present"`
	LastRunTS     *time.Time `json:"last_run_ts"`
	ModifiedCount *int       `json:"modified_count"`
}

// IPS mirrors the intrusion_prevention block. CurrentBanCount is
// populated when the backend is fail2ban and the helper's
// fail2ban_status op succeeds; -1 means the backend exists but the
// ban count could not be retrieved (the operator should check the
// matching warning in warnings[]).
type IPS struct {
	BackendInUse    string `json:"backend_in_use"`
	CurrentBanCount int    `json:"current_ban_count"`
}

// SSHLogins mirrors the ssh_logins block.
type SSHLogins struct {
	AcceptedSinceBoot int `json:"accepted_since_boot"`
	FailedSinceBoot   int `json:"failed_since_boot"`
}

// Tool is the registered tool.
type Tool struct {
	hc *helperinvoke.Client
}

// New returns a new tool instance.
func New(hc *helperinvoke.Client) *Tool { return &Tool{hc: hc} }

// Name returns the tool name.
func (*Tool) Name() string { return "security" }

// DefaultTTL: security posture moves slowly.
func (*Tool) DefaultTTL() time.Duration { return 60 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 5 * time.Second }

// helperAide mirrors the helper's AideSummary.
type helperAide struct {
	Present       bool       `json:"present"`
	LastRunTS     *time.Time `json:"last_run_ts"`
	LastExitCode  *int       `json:"last_exit_code"`
	ChangeCount   *int       `json:"change_count"`
}

// helperAudit mirrors the helper's AuditStatus.
type helperAudit struct {
	Present         bool       `json:"present"`
	QueueDepth      *int       `json:"queue_depth"`
	LostEvents      *int       `json:"lost_events"`
	LastRotationTS  *time.Time `json:"last_rotation_ts"`
}

// helperFail2ban mirrors the helper's Fail2banStatusResult.
type helperFail2ban struct {
	Present     bool `json:"present"`
	JailCount   int  `json:"jail_count"`
	TotalBanned int  `json:"total_banned"`
}

// Handle composes the security envelope. Presence is detected daemon-
// side by binary or socket presence; deep fields come from the helper
// ops where available.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{}
	var (
		warnings   []string
		warningsMu sync.Mutex
	)
	addWarning := func(s string) {
		warningsMu.Lock()
		warnings = append(warnings, s)
		warningsMu.Unlock()
	}

	var (
		aide     helperAide
		audit    helperAudit
		fail2ban helperFail2ban
	)
	fail2banAttempted := false

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := t.hc.CallJSON(ctx, proto.OpReadAideSummary, "", &aide); err != nil {
			addWarning("security: read_aide_summary: " + err.Error())
		}
	}()
	go func() {
		defer wg.Done()
		if err := t.hc.CallJSON(ctx, proto.OpReadAuditStatus, "", &audit); err != nil {
			addWarning("security: read_audit_status: " + err.Error())
		}
	}()
	wg.Wait()

	// fail2ban probe runs only when the backend is detected to avoid
	// invoking the helper for an absent binary.
	if detectIPS() == "fail2ban" {
		fail2banAttempted = true
		if err := t.hc.CallJSON(ctx, proto.OpFail2banStatus, "", &fail2ban); err != nil {
			addWarning("security: fail2ban_status: " + err.Error())
		}
	}

	d.AideOrEquivalent = Aide{
		Present:      aide.Present || anyExists("/usr/bin/aide", "/usr/sbin/aide"),
		LastRunTS:    aide.LastRunTS,
		LastExitCode: aide.LastExitCode,
		ChangeCount:  aide.ChangeCount,
	}
	d.Auditd = Auditd{
		Present:        audit.Present || anyExists("/sbin/auditd", "/usr/sbin/auditd"),
		QueueDepth:     audit.QueueDepth,
		LostEvents:     audit.LostEvents,
		LastRotationTS: audit.LastRotationTS,
	}

	d.Rkhunter.Present = anyExists("/usr/bin/rkhunter", "/usr/sbin/rkhunter")
	if d.Rkhunter.Present {
		if info, err := os.Stat("/var/log/rkhunter.log"); err == nil {
			ts := info.ModTime().UTC()
			d.Rkhunter.LastRunTS = &ts
			if w := readRkhunterWarningCount("/var/log/rkhunter.log"); w != nil {
				d.Rkhunter.WarningCount = w
			}
		}
	}

	d.DebsumsOrEquivalent.Present = anyExists("/usr/bin/debsums")

	d.IntrusionPrevention.BackendInUse = detectIPS()
	switch {
	case !fail2banAttempted:
		d.IntrusionPrevention.CurrentBanCount = 0
	case fail2ban.Present:
		d.IntrusionPrevention.CurrentBanCount = fail2ban.TotalBanned
	default:
		// Backend detected but helper couldn't reach fail2ban-server.
		// -1 signals "indeterminate"; the warnings[] entry carries the
		// reason.
		d.IntrusionPrevention.CurrentBanCount = -1
	}

	// SSH login counters from /var/log/auth.log mtime is too coarse;
	// the journal_query helper op gives us severity-filtered samples
	// but counting requires a separate ssh-targeted query the helper
	// doesn't expose today. /var/log/auth.log fallback parser counts
	// "Accepted " and "Failed " lines since the file's mtime is
	// post-boot; good enough as an MVP signal.
	d.SSHLogins.AcceptedSinceBoot, d.SSHLogins.FailedSinceBoot = readAuthLogCounters()

	return d, warnings, nil
}

func anyExists(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		} else if !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func detectIPS() string {
	switch {
	case anyExists("/usr/bin/fail2ban-client", "/usr/local/bin/fail2ban-client"):
		return "fail2ban"
	case anyExists("/usr/bin/crowdsec", "/usr/local/bin/crowdsec"):
		return "crowdsec"
	default:
		return "none"
	}
}

// readRkhunterWarningCount scans rkhunter's log for "Warning:" lines.
// Returns nil when the file is empty or unreadable.
func readRkhunterWarningCount(path string) *int {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Warning:") {
			count++
		}
	}
	return &count
}

// authLogPaths lists candidate SSH login log files in preference
// order. Debian uses /var/log/auth.log; some distros (RHEL family,
// containers) use /var/log/secure; journal-only systems have neither.
var authLogPaths = []string{
	"/var/log/auth.log",
	"/var/log/secure",
}

// readAuthLogCounters returns (accepted, failed) counts from the
// first existing path in authLogPaths. Best-effort: rotation
// truncates the file at midnight, so this is "since the last
// rotation" rather than "since boot". The schema's "since boot"
// semantics are approximated; a future helper op can do a precise
// journalctl --boot count when the journal is the only source.
func readAuthLogCounters() (int, int) {
	var path string
	for _, p := range authLogPaths {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		return 0, 0
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var accepted, failed int
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.Contains(line, "sshd[") && strings.Contains(line, "Accepted "):
			accepted++
		case strings.Contains(line, "sshd[") && strings.Contains(line, "Failed "):
			failed++
		}
	}
	return accepted, failed
}
