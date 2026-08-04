// Package security implements tool 4.5: presence and last-run state
// for AIDE, auditd, rkhunter, debsums; intrusion-prevention backend;
// SSH login counters. Daemon-side presence detection plus helper-op
// calls for the deep fields (audit queue/lost, AIDE change count).
package security

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"host-health-mcp/daemon/internal/shared/linescan"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
	"host-health-mcp/daemon/internal/shared/schema"
)

// Data is the response data for tool security. Errors carries one
// entry per failed helper invocation with the full structured
// diagnostics (argv, exit, stderr fingerprint, stderr prefix);
// warnings[] in the envelope carries only the section + op + code
// summary (1.11.0 structured-error refactor).
type Data struct {
	AideOrEquivalent    Aide                   `json:"aide_or_equivalent"`
	Auditd              Auditd                 `json:"auditd"`
	Rkhunter            Rkhunter               `json:"rkhunter"`
	DebsumsOrEquivalent Debsums                `json:"debsums_or_equivalent"`
	IntrusionPrevention IPS                    `json:"intrusion_prevention"`
	SSHLogins           SSHLogins              `json:"ssh_logins"`
	Errors              []schema.HelperOpError `json:"errors,omitempty"`
}

// Aide mirrors the aide_or_equivalent block.
type Aide struct {
	Present      bool       `json:"present"`
	LastRunTS    *time.Time `json:"last_run_ts"`
	LastExitCode *int       `json:"last_exit_code"`
	ChangeCount  *int       `json:"change_count"`
}

// Auditd mirrors the auditd block.
type Auditd struct {
	Present        bool       `json:"present"`
	QueueDepth     *int       `json:"queue_depth"`
	LostEvents     *int       `json:"lost_events"`
	LastRotationTS *time.Time `json:"last_rotation_ts"`
}

// Rkhunter mirrors the rkhunter block.
type Rkhunter struct {
	Present      bool       `json:"present"`
	LastRunTS    *time.Time `json:"last_run_ts"`
	WarningCount *int       `json:"warning_count"`
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

// SSHLogins mirrors the ssh_logins block. The two counts cover a
// different window depending on the source, and Window records which:
// "since_log_rotation" for the file-based path (auth.log / secure),
// "last_24h" for the journal path, "unavailable" when neither source
// could be read. Counts are null (not zero) when unavailable so a
// quiet host is distinguishable from a missing source. Renamed from
// accepted_since_boot / failed_since_boot as an authorised breaking
// change in schema 1.0.0 / release 2.0.0.
type SSHLogins struct {
	AcceptedRecent *int   `json:"accepted_recent"`
	FailedRecent   *int   `json:"failed_recent"`
	Window         string `json:"window"`
}

// SSH login window discriminators for SSHLogins.Window.
const (
	sshWindowLast24h          = "last_24h"
	sshWindowSinceLogRotation = "since_log_rotation"
	sshWindowUnavailable      = "unavailable"
)

// Tool is the registered tool.
type Tool struct {
	hc             *helperinvoke.Client
	debsumsLogPath string
	aideLogPath    string
}

// New returns a new tool instance. debsumsLogPath is the
// manifest-declared `/var/log/debsums.log` style path; empty disables
// the path-based last-run lookup (a debsums-check.timer timestamp
// will be used as a secondary fallback). aideLogPath is similar for
// AIDE: when set the daemon parses it for change_count and a derived
// last_exit_code, overriding whatever the helper's AIDE-DB lookup
// reports.
func New(hc *helperinvoke.Client, debsumsLogPath, aideLogPath string) *Tool {
	return &Tool{hc: hc, debsumsLogPath: debsumsLogPath, aideLogPath: aideLogPath}
}

// Name returns the tool name.
func (*Tool) Name() string { return "security" }

// DefaultTTL: security posture moves slowly.
func (*Tool) DefaultTTL() time.Duration { return 60 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 5 * time.Second }

// helperAide mirrors the helper's AideSummary.
type helperAide struct {
	Present      bool       `json:"present"`
	LastRunTS    *time.Time `json:"last_run_ts"`
	LastExitCode *int       `json:"last_exit_code"`
	ChangeCount  *int       `json:"change_count"`
}

// helperAudit mirrors the helper's AuditStatus. NetlinkError is the
// soft-error channel for AUDIT_GET failures that should not suppress
// the filesystem-derived LastRotationTS.
type helperAudit struct {
	Present        bool       `json:"present"`
	QueueDepth     *int       `json:"queue_depth"`
	LostEvents     *int       `json:"lost_events"`
	LastRotationTS *time.Time `json:"last_rotation_ts"`
	NetlinkError   string     `json:"netlink_error,omitempty"`
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
	// addOpError records a structured helper-call failure in
	// d.Errors AND emits a short, code-only warning. The
	// argv/stderr_prefix diagnostics live in d.Errors only; the
	// warning string stays clean.
	addOpError := func(opName string, err error) {
		if err == nil {
			return
		}
		oe := helperinvoke.OpErrorFrom(err)
		oe.Op = opName
		warningsMu.Lock()
		d.Errors = append(d.Errors, *oe)
		warningsMu.Unlock()
		addWarning("security: " + opName + ": " + helperinvoke.CodeOf(err))
	}

	var (
		aide        helperAide
		audit       helperAudit
		fail2ban    helperFail2ban
		aideErr     error
		auditErr    error
		fail2banErr error
	)
	fail2banAttempted := false

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aideErr = t.hc.CallJSON(ctx, proto.OpReadAideSummary, "", &aide)
	}()
	go func() {
		defer wg.Done()
		auditErr = t.hc.CallJSON(ctx, proto.OpReadAuditStatus, "", &audit)
	}()
	wg.Wait()
	addOpError(proto.OpReadAideSummary, aideErr)
	addOpError(proto.OpReadAuditStatus, auditErr)

	// fail2ban probe runs only when the backend is detected to avoid
	// invoking the helper for an absent binary.
	if detectIPS() == "fail2ban" {
		fail2banAttempted = true
		fail2banErr = t.hc.CallJSON(ctx, proto.OpFail2banStatus, "", &fail2ban)
		addOpError(proto.OpFail2banStatus, fail2banErr)
	}

	d.AideOrEquivalent = Aide{
		Present:      aide.Present || existsOrWarn("aide", addWarning, "/usr/bin/aide", "/usr/sbin/aide"),
		LastRunTS:    aide.LastRunTS,
		LastExitCode: aide.LastExitCode,
		ChangeCount:  aide.ChangeCount,
	}
	// AIDE: when the operator points at an aide_log_path, the daemon
	// stat + parses it. Overrides the helper's DB-mtime LastRunTS
	// because the log mtime is the run-end timestamp.
	if t.aideLogPath != "" {
		t.fillAideFromLog(&d.AideOrEquivalent, addWarning)
	}
	// AIDE often shows a DB mtime (last_run_ts) without any matching
	// log entries because Debian's cron wrapper doesn't always write
	// to /var/log/aide. Surface that case rather than emit silent
	// nulls.
	if d.AideOrEquivalent.Present && d.AideOrEquivalent.LastRunTS != nil && d.AideOrEquivalent.ChangeCount == nil {
		hint := "ensure /var/log/aide/aide.log captures 'Total number of differences:' or " +
			"'Added/Removed/Changed entries:' totals, or set aide_log_path in manifest.yml"
		if t.aideLogPath != "" {
			hint = "aide_log_path is set to " + t.aideLogPath +
				" but no 'Total number of differences:' / 'Added/Removed/Changed entries:' totals were found"
		}
		addWarning("security: aide change_count unparseable; " + hint)
	}

	d.Auditd = Auditd{
		Present:        audit.Present || existsOrWarn("auditd", addWarning, "/sbin/auditd", "/usr/sbin/auditd"),
		QueueDepth:     audit.QueueDepth,
		LostEvents:     audit.LostEvents,
		LastRotationTS: audit.LastRotationTS,
	}
	if audit.NetlinkError != "" {
		addWarning("security: AUDIT_GET netlink failed: " + audit.NetlinkError +
			" (queue_depth/lost_events null; last_rotation_ts still derived from /var/log/audit/)")
	} else if present, _ := anyExists("/sbin/auditd", "/usr/sbin/auditd"); !audit.Present && present {
		// kernel reported CONFIG_AUDIT=n while userspace has the
		// auditd binary — a real contradiction worth surfacing.
		addWarning("security: auditd binary present but kernel has no audit subsystem " +
			"(CONFIG_AUDIT=n); queue_depth/lost_events null")
	}

	// rkhunter scan moved to the helper: /var/log/rkhunter.log is
	// root:adm 0640 on Debian and the daemon user can stat but not
	// read it. The helper (root, CAP_DAC_READ_SEARCH) covers both.
	var rk helperRkhunter
	if err := t.hc.CallJSON(ctx, proto.OpRkhunterSummary, "", &rk); err != nil {
		addOpError(proto.OpRkhunterSummary, err)
	}
	d.Rkhunter.Present = rk.Present || existsOrWarn("rkhunter", addWarning, "/usr/bin/rkhunter", "/usr/sbin/rkhunter")
	d.Rkhunter.LastRunTS = rk.LastRunTS
	d.Rkhunter.WarningCount = rk.WarningCount
	if d.Rkhunter.Present && rk.LastRunTS == nil {
		addWarning("security: rkhunter binary present but /var/log/rkhunter.log absent; " +
			"last_run_ts and warning_count null")
	} else if d.Rkhunter.Present && rk.LastRunTS != nil && rk.WarningCount == nil {
		addWarning("security: rkhunter log present but unreadable from the helper; warning_count null")
	}

	d.DebsumsOrEquivalent.Present = existsOrWarn("debsums", addWarning, "/usr/bin/debsums")
	if d.DebsumsOrEquivalent.Present {
		t.fillDebsums(ctx, &d.DebsumsOrEquivalent, addWarning, addOpError)
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

	// SSH login counters: file-based first (auth.log on Debian, secure
	// on RHEL-family) covering "since last log rotation"; helper-backed
	// journal fallback covering the last 24h on journal-only systems.
	// Window records which applies so the count is never ambiguous
	// (see SSHLogins and REQ 4.5). A partial file read (fileErr) is not
	// reported as authoritative: it warns and falls through to the
	// journal path.
	a, f, fileOK, fileTruncated, fileErr := readAuthLogCounters()
	if fileErr != nil {
		addWarning("security: auth log read incomplete (" + fileErr.Error() +
			"); falling back to journal counters")
	}
	if fileOK && fileTruncated {
		// The counts cover the tail only, so do NOT label them
		// since_log_rotation — that discriminator was added in 2.0.0
		// precisely so a count is never ambiguous about what it spans.
		// A sustained brute-force is what grows auth.log past the cap,
		// so this fires during exactly the event the counters exist to
		// surface.
		addWarning("security: auth log exceeded the read cap; ssh_logins counts " +
			"cover only the most recent portion of the file")
		d.SSHLogins.Window = sshWindowUnavailable
	} else if fileOK {
		d.SSHLogins.AcceptedRecent = &a
		d.SSHLogins.FailedRecent = &f
		d.SSHLogins.Window = sshWindowSinceLogRotation
	} else {
		var jc helperSshJournalCounts
		if err := t.hc.CallJSON(ctx, proto.OpSshJournalCounts, "", &jc); err != nil {
			addOpError(proto.OpSshJournalCounts, err)
			d.SSHLogins.Window = sshWindowUnavailable
		} else if jc.Present {
			ja, jf := jc.AcceptedLast24h, jc.FailedLast24h
			d.SSHLogins.AcceptedRecent = &ja
			d.SSHLogins.FailedRecent = &jf
			d.SSHLogins.Window = sshWindowLast24h
			if jc.Truncated && jc.OldestEntryUnixS > 0 {
				addWarning(formatSshJournalTruncationWarning(jc.OldestEntryUnixS))
			}
		} else {
			d.SSHLogins.Window = sshWindowUnavailable
		}
	}

	return d, warnings, nil
}

// helperSshJournalCounts mirrors the helper op's ssh_journal_counts
// response: last-24h counts plus the coverage-probe fields
// (Truncated / OldestEntryUnixS / BootUnixS).
type helperSshJournalCounts struct {
	Present          bool  `json:"present"`
	AcceptedLast24h  int   `json:"accepted_last_24h"`
	FailedLast24h    int   `json:"failed_last_24h"`
	Truncated        bool  `json:"truncated,omitempty"`
	OldestEntryUnixS int64 `json:"oldest_entry_unix_s,omitempty"`
	BootUnixS        int64 `json:"boot_unix_s,omitempty"`
}

// formatSshJournalTruncationWarning composes the envelope warning
// emitted when the journal retains less than the full 24h window and
// the host has been up longer than 24h — so the last_24h counters
// actually cover only the retained tail (now - oldest_entry).
func formatSshJournalTruncationWarning(oldestEntryUnixS int64) string {
	oldest := time.Unix(oldestEntryUnixS, 0).UTC().Format(time.RFC3339)
	retainedS := time.Now().UTC().Unix() - oldestEntryUnixS
	if retainedS < 0 {
		retainedS = 0
	}
	return fmt.Sprintf(
		"ssh_logins: journal retains less than 24h — oldest entry %s; last_24h counters reflect only ~%s of the 24h window (volatile journald or aggressive rotation)",
		oldest,
		shortDuration(time.Duration(retainedS)*time.Second),
	)
}

// shortDuration renders a duration as "Xd", "Xh", or "Xm" — the
// shortest unit that keeps the magnitude legible. Used only in
// human-facing warning strings.
func shortDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
}

// helperSystemdTimer mirrors the helper op's response.
type helperSystemdTimer struct {
	Present     bool       `json:"present"`
	LastTrigger *time.Time `json:"last_trigger"`
}

// fillDebsums fills LastRunTS and ModifiedCount from one of three
// sources, in preference order:
//  1. operator-supplied debsums_log_path (manifest);
//  2. debsums-check.timer's LastTriggerUSec via the helper (Debian
//     packages of debsums-mail ship this timer);
//  3. nothing — emit a warning so the operator sees the config gap.
func (t *Tool) fillDebsums(ctx context.Context, d *Debsums, addWarning func(string), addOpError func(string, error)) {
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
		addOpError(proto.OpSystemdTimerLastTrigger, err)
		addWarning("security: debsums installed but no debsums_log_path is configured " +
			"and debsums-check.timer is unreachable; see errors[] for cause")
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

// fillAideFromLog parses the operator-supplied aide_log_path and
// fills LastRunTS (from mtime), ChangeCount (sum of
// Added/Removed/Changed or the Total-differences line), and
// LastExitCode (1 when "AIDE found differences" appears, 0 when
// "AIDE found NO differences" appears).
func (t *Tool) fillAideFromLog(d *Aide, addWarning func(string)) {
	info, err := os.Stat(t.aideLogPath)
	if err != nil {
		addWarning("security: aide_log_path " + t.aideLogPath + ": " + err.Error())
		return
	}
	ts := info.ModTime().UTC()
	d.LastRunTS = &ts

	f, err := os.Open(t.aideLogPath)
	if err != nil {
		addWarning("security: aide_log_path open: " + err.Error())
		return
	}
	defer f.Close()

	var (
		total       *int
		added       int
		removed     int
		changed     int
		haveDetail  bool
		foundDiff   bool
		foundNoDiff bool
	)
	scanner := linescan.New(f, t.aideLogPath)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.Contains(line, "AIDE found NO differences"):
			foundNoDiff = true
		case strings.Contains(line, "AIDE found differences"):
			foundDiff = true
		}
		if m := aideTotalRE.FindStringSubmatch(line); m != nil {
			v, _ := strconv.Atoi(m[1])
			total = &v
		}
		if m := aideAddedRE.FindStringSubmatch(line); m != nil {
			added, _ = strconv.Atoi(m[1])
			haveDetail = true
		}
		if m := aideRemovedRE.FindStringSubmatch(line); m != nil {
			removed, _ = strconv.Atoi(m[1])
			haveDetail = true
		}
		if m := aideChangedRE.FindStringSubmatch(line); m != nil {
			changed, _ = strconv.Atoi(m[1])
			haveDetail = true
		}
	}
	if haveDetail {
		sum := added + removed + changed
		d.ChangeCount = &sum
	} else if total != nil {
		d.ChangeCount = total
	}
	switch {
	case foundNoDiff && !foundDiff:
		// AIDE's clean-state report is "AIDE found NO differences
		// between database and filesystem". On that path AIDE omits the
		// "Total number of differences:" header and the per-class
		// "Added/Removed/Changed entries:" lines entirely — the headline
		// is the only signal, and it is authoritative: change_count is
		// zero by definition. Force it unconditionally. The helper op may
		// have pre-seeded a non-nil count parsed from a different or
		// rotated /var/log/aide log; leaving that in place would emit a
		// stale non-zero change_count beside last_exit_code=0.
		zero := 0
		d.LastExitCode = &zero
		d.ChangeCount = &zero
	case foundDiff:
		one := 1
		d.LastExitCode = &one
	}
	if err := scanner.Err(); err != nil {
		addWarning("security: aide log: " + err.Error())
	}
}

// AIDE log regexes mirror the helper's parser but match the
// operator-supplied log shape (which may or may not match the
// Debian package's /var/log/aide/aide.log conventions).
var (
	aideTotalRE   = regexp.MustCompile(`(?i)Total number of differences:\s+(\d+)`)
	aideAddedRE   = regexp.MustCompile(`(?i)Added entries?:\s+(\d+)`)
	aideRemovedRE = regexp.MustCompile(`(?i)Removed entries?:\s+(\d+)`)
	aideChangedRE = regexp.MustCompile(`(?i)Changed entries?:\s+(\d+)`)
)

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

// anyExists reports whether any of paths is present.
//
// A stat error other than ErrNotExist — EACCES, ELOOP, ENOTDIR —
// used to count as "present", so a permission problem made the tool
// report AIDE, auditd, rkhunter or fail2ban as INSTALLED when it had
// no idea. For a security-posture tool that is the wrong direction to
// fail: "cannot verify" must never render as "verified present". The
// second return distinguishes the two so the caller can warn.
func anyExists(paths ...string) (present bool, uncertain error) {
	for _, p := range paths {
		_, err := os.Stat(p)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			// Keep looking: another path may exist outright.
			uncertain = err
		}
	}
	return false, uncertain
}

// existsOrWarn adapts anyExists for the common call site: an
// uncertain stat becomes a warning rather than a silent "present".
func existsOrWarn(what string, addWarning func(string), paths ...string) bool {
	present, uncertain := anyExists(paths...)
	if uncertain != nil {
		addWarning("security: cannot determine whether " + what +
			" is installed: " + uncertain.Error() + " (reported as absent)")
	}
	return present
}

// firstOf drops the uncertainty return where the caller has no
// warning channel. detectIPS reports an IPS name, and "unknown"
// correctly degrades to "none" there.
func firstOf(present bool, _ error) bool { return present }

func detectIPS() string {
	switch {
	case firstOf(anyExists("/usr/bin/fail2ban-client", "/usr/local/bin/fail2ban-client")):
		return "fail2ban"
	case firstOf(anyExists("/usr/bin/crowdsec", "/usr/local/bin/crowdsec")):
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

// isSSHDLine reports whether the auth.log line was emitted by an
// OpenSSH daemon process. Matches both pre-9.8 `sshd[PID]` and
// post-9.8 `sshd-session[PID]` (Debian 13 / trixie split the
// daemon into a listener and a per-connection handler — auth-
// related messages now come from `sshd-session`). Without the
// second branch the auth-log path silently returned zero on every
// post-trixie host.
func isSSHDLine(line string) bool {
	return strings.Contains(line, "sshd[") || strings.Contains(line, "sshd-session[")
}

// isSSHFailedLine reports whether a sshd-emitted line is a failed
// connection attempt. The pre-1.16.1 implementation only matched
// `Failed `; on key-only fleets that pattern never fires because
// scanners disconnect during key exchange before reaching the
// publickey-auth stage, so the counter was permanently zero. The
// preauth-disconnect and kex-error branches capture the actual
// rejection signal.
//
// We deliberately do NOT count "Received disconnect from" — it
// pairs with "Disconnected from" on every client-initiated
// SSH_MSG_DISCONNECT and would double-count the same probe.
func isSSHFailedLine(line string) bool {
	if strings.Contains(line, "Failed ") {
		return true
	}
	if strings.Contains(line, "[preauth]") &&
		(strings.Contains(line, "Disconnected from ") ||
			strings.Contains(line, "Connection closed by ")) {
		return true
	}
	if strings.Contains(line, "kex_exchange_identification") {
		return true
	}
	return false
}

// readAuthLogCounters returns (accepted, failed, found, truncated,
// err) counts from the first existing path in authLogPaths.
// found=false means no usable file-based source exists and the caller
// should fall back to the helper's journal counter; err is non-nil
// when a file source existed but could not be read to completion.
//
// truncated=true means the file exceeded maxAuthLogBytes and only its
// tail was read, so the counts do NOT cover the whole rotation period
// and the caller must not label them "since_log_rotation".
// maxAuthLogBytes caps the tail read of auth.log. 8 MiB is far more
// than a day of legitimate sshd chatter and bounds the cost of a
// brute-force flood.
const maxAuthLogBytes = 8 * 1024 * 1024

func readAuthLogCounters() (accepted, failed int, found, truncated bool, err error) {
	var path string
	for _, p := range authLogPaths {
		if _, statErr := os.Stat(p); statErr == nil {
			path = p
			break
		}
	}
	if path == "" {
		return 0, 0, false, false, nil
	}
	f, openErr := os.Open(path)
	if openErr != nil {
		return 0, 0, false, false, nil
	}
	defer f.Close()
	// Bound the read. auth.log is a file an EXTERNAL attacker grows,
	// one line per SSH probe, and this walked all of it with no cap.
	// A sustained brute-force turns a health check into an unbounded
	// read on every poll. The tail is also the only interesting part:
	// these counters describe recent activity.
	if st, statErr := f.Stat(); statErr == nil && st.Size() > maxAuthLogBytes {
		if _, seekErr := f.Seek(st.Size()-maxAuthLogBytes, io.SeekStart); seekErr == nil {
			truncated = true
		}
	}
	scanner := linescan.New(f, path)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		// After a seek the first line is a fragment; counting it could
		// double-count or invent a match.
		if truncated && first {
			first = false
			continue
		}
		first = false
		if !isSSHDLine(line) {
			continue
		}
		switch {
		case strings.Contains(line, "Accepted "):
			accepted++
		case isSSHFailedLine(line):
			failed++
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		// A line exceeding the 1 MiB buffer (bufio.ErrTooLong) or a
		// read error stops the scan mid-file, so the counts so far are
		// partial. Return found=false with the error so the caller
		// does not report them as authoritative "since_log_rotation"
		// figures and instead falls back to the bounded journal path.
		return accepted, failed, false, truncated, scanErr
	}
	return accepted, failed, true, truncated, nil
}
