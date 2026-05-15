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
	hc             *helperinvoke.Client
	debsumsLogPath string
}

// New returns a new tool instance. debsumsLogPath is the
// manifest-declared `/var/log/debsums.log` style path; empty disables
// the path-based last-run lookup (a debsums-check.timer timestamp
// will be used as a secondary fallback).
func New(hc *helperinvoke.Client, debsumsLogPath string) *Tool {
	return &Tool{hc: hc, debsumsLogPath: debsumsLogPath}
}

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

// helperRkhunter mirrors the helper's RkhunterSummaryResult.
type helperRkhunter struct {
	Present      bool       `json:"present"`
	LastRunTS    *time.Time `json:"last_run_ts"`
	WarningCount *int       `json:"warning_count"`
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
	// AIDE often shows a DB mtime (last_run_ts) without any matching
	// log entries because Debian's cron wrapper doesn't always write
	// to /var/log/aide. Surface that case rather than emit silent
	// nulls.
	if d.AideOrEquivalent.Present && aide.LastRunTS != nil && aide.ChangeCount == nil {
		addWarning("security: aide DB mtime found but change_count unparseable; " +
			"ensure /var/log/aide/aide.log captures 'Total number of differences:' or " +
			"'Added/Removed/Changed entries:' totals")
	}

	d.Auditd = Auditd{
		Present:        audit.Present || anyExists("/sbin/auditd", "/usr/sbin/auditd"),
		QueueDepth:     audit.QueueDepth,
		LostEvents:     audit.LostEvents,
		LastRotationTS: audit.LastRotationTS,
	}
	// auditctl may be absent (Present:false from helper, no error) on
	// hosts that have auditd installed but never invoke auditctl.
	// When daemon binary detection says yes but helper says no, that
	// is a contradiction worth surfacing: queue_depth and friends
	// will be null and the operator should know why.
	if !audit.Present && anyExists("/sbin/auditd", "/usr/sbin/auditd") {
		addWarning("security: auditd binary present but auditctl not installed or unreachable; " +
			"queue_depth/lost_events/last_rotation_ts null")
	}

	// rkhunter scan moved to the helper: /var/log/rkhunter.log is
	// root:adm 0640 on Debian and the daemon user can stat but not
	// read it. The helper (root, CAP_DAC_READ_SEARCH) covers both.
	var rk helperRkhunter
	if err := t.hc.CallJSON(ctx, proto.OpRkhunterSummary, "", &rk); err != nil {
		addWarning("security: rkhunter_summary: " + err.Error())
	}
	d.Rkhunter.Present = rk.Present || anyExists("/usr/bin/rkhunter", "/usr/sbin/rkhunter")
	d.Rkhunter.LastRunTS = rk.LastRunTS
	d.Rkhunter.WarningCount = rk.WarningCount
	if d.Rkhunter.Present && rk.LastRunTS == nil {
		addWarning("security: rkhunter binary present but /var/log/rkhunter.log absent; " +
			"last_run_ts and warning_count null")
	} else if d.Rkhunter.Present && rk.LastRunTS != nil && rk.WarningCount == nil {
		addWarning("security: rkhunter log present but unreadable from the helper; warning_count null")
	}

	d.DebsumsOrEquivalent.Present = anyExists("/usr/bin/debsums")
	if d.DebsumsOrEquivalent.Present {
		t.fillDebsums(ctx, &d.DebsumsOrEquivalent, addWarning)
	}

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

	// SSH login counters: file-based first (auth.log on Debian,
	// secure on RHEL-family), helper-backed journal fallback for
	// journal-only systems.
	if a, f, found := readAuthLogCounters(); found {
		d.SSHLogins.AcceptedSinceBoot = a
		d.SSHLogins.FailedSinceBoot = f
	} else {
		var jc helperSshJournalCounts
		if err := t.hc.CallJSON(ctx, proto.OpSshJournalCounts, "", &jc); err != nil {
			addWarning("security: ssh_journal_counts: " + err.Error())
		} else if jc.Present {
			d.SSHLogins.AcceptedSinceBoot = jc.AcceptedSinceBoot
			d.SSHLogins.FailedSinceBoot = jc.FailedSinceBoot
		}
	}

	return d, warnings, nil
}

// helperSshJournalCounts mirrors the helper op's response.
type helperSshJournalCounts struct {
	Present           bool `json:"present"`
	AcceptedSinceBoot int  `json:"accepted_since_boot"`
	FailedSinceBoot   int  `json:"failed_since_boot"`
}

// helperSystemdTimer mirrors the helper op's response.
type helperSystemdTimer struct {
	Present     bool       `json:"present"`
	LastTrigger *time.Time `json:"last_trigger"`
}

// fillDebsums fills LastRunTS and ModifiedCount from one of three
// sources, in preference order:
//   1. operator-supplied debsums_log_path (manifest);
//   2. debsums-check.timer's LastTriggerUSec via the helper (Debian
//      packages of debsums-mail ship this timer);
//   3. nothing — emit a warning so the operator sees the config gap.
func (t *Tool) fillDebsums(ctx context.Context, d *Debsums, addWarning func(string)) {
	if t.debsumsLogPath != "" {
		info, err := os.Stat(t.debsumsLogPath)
		if err != nil {
			addWarning("security: debsums_log_path: " + err.Error())
			return
		}
		ts := info.ModTime().UTC()
		d.LastRunTS = &ts
		if n, err := countDebsumsChanged(t.debsumsLogPath); err == nil {
			d.ModifiedCount = &n
		} else {
			addWarning("security: debsums log parse: " + err.Error())
		}
		return
	}

	// No path configured: try the timer as a secondary signal.
	var tim helperSystemdTimer
	if err := t.hc.CallJSON(ctx, proto.OpSystemdTimerLastTrigger, "debsums-check.timer", &tim); err != nil {
		addWarning("security: debsums installed but no debsums_log_path is configured " +
			"and debsums-check.timer is unreachable (" + err.Error() + ")")
		return
	}
	switch {
	case tim.Present && tim.LastTrigger != nil:
		d.LastRunTS = tim.LastTrigger
		// ModifiedCount stays nil — the timer doesn't carry it.
		addWarning("security: debsums last_run_ts derived from debsums-check.timer; " +
			"modified_count unknown (set debsums_log_path in manifest.yml to populate)")
	case tim.Present:
		// Timer is registered with systemd but has never fired.
		addWarning("security: debsums installed; no debsums_log_path is configured; " +
			"debsums-check.timer is registered but has never been triggered " +
			"(LastTriggerUSec=0); last_run_ts and modified_count are null")
	default:
		addWarning("security: debsums installed; no debsums_log_path is configured " +
			"and no debsums-check.timer present; last_run_ts and modified_count are null")
	}
}

// countDebsumsChanged counts lines in the debsums log that look like
// the CHANGED-file output of `debsums -c` / `debsums-mail`. The
// canonical line shape is:
//
//	/path/to/file FAILED
//
// Some operator wrappers emit just `/path/to/file` per line; both
// patterns are accepted because a non-zero count is the operator
// signal that matters. Empty lines and lines beginning with `debsums:`
// (progress / status lines) are ignored.
func countDebsumsChanged(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "debsums:") {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			continue
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return count, err
	}
	return count, nil
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

// authLogPaths lists candidate SSH login log files in preference
// order. Debian uses /var/log/auth.log; some distros (RHEL family,
// containers) use /var/log/secure; journal-only systems have neither.
var authLogPaths = []string{
	"/var/log/auth.log",
	"/var/log/secure",
}

// readAuthLogCounters returns (accepted, failed, found) counts from
// the first existing path in authLogPaths. found=false means no
// file-based source exists and the caller should fall back to the
// helper's journal counter. The file-based path approximates
// "since boot" via "since the last rotation".
func readAuthLogCounters() (accepted, failed int, found bool) {
	var path string
	for _, p := range authLogPaths {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		return 0, 0, false
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
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
	return accepted, failed, true
}
