// Package security implements tool 4.5 (MVP): presence and last-run
// state for AIDE, auditd, rkhunter, debsums; intrusion-prevention
// backend; SSH login counters. Where a subsystem requires root for
// deep state (auditd queue depth, AIDE last-run timestamp), today's
// MVP reports present=true and leaves the deep fields null. The
// follow-up wires those through the helper's read_audit_status and
// read_aide_summary ops once they land.
package security

import (
	"context"
	"errors"
	"os"
	"time"
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

// IPS mirrors the intrusion_prevention block.
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
type Tool struct{}

// New returns a new tool instance.
func New() *Tool { return &Tool{} }

// Name returns the tool name.
func (*Tool) Name() string { return "security" }

// DefaultTTL: security posture moves slowly.
func (*Tool) DefaultTTL() time.Duration { return 60 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 3 * time.Second }

// Handle composes the security envelope. Presence is detected by
// binary or socket presence; deep fields await the matching helper
// ops.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{}

	d.AideOrEquivalent.Present = anyExists("/usr/bin/aide", "/usr/sbin/aide")
	if d.AideOrEquivalent.Present {
		// /var/lib/aide/aide.db is the canonical database location;
		// mtime is the last-run signal until the helper op lands.
		if info, err := os.Stat("/var/lib/aide/aide.db"); err == nil {
			ts := info.ModTime().UTC()
			d.AideOrEquivalent.LastRunTS = &ts
		}
	}

	d.Auditd.Present = anyExists("/sbin/auditd", "/usr/sbin/auditd")
	d.Rkhunter.Present = anyExists("/usr/bin/rkhunter", "/usr/sbin/rkhunter")
	if d.Rkhunter.Present {
		if info, err := os.Stat("/var/log/rkhunter.log"); err == nil {
			ts := info.ModTime().UTC()
			d.Rkhunter.LastRunTS = &ts
		}
	}

	d.DebsumsOrEquivalent.Present = anyExists("/usr/bin/debsums")

	d.IntrusionPrevention.BackendInUse = detectIPS()

	// SSH login counters are populated from a journald scan once the
	// logs helper op lands. MVP returns zero rather than a fabricated
	// value.

	return d, nil, nil
}

func anyExists(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		} else if !errors.Is(err, os.ErrNotExist) {
			// Permission errors and similar count as "present, can't
			// read"; report present to avoid false negatives.
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
