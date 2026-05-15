// Package updates implements tool 4.12: pending updates and restart-
// required services. End-to-end demonstration of daemon→helper round-
// trip: apt_pending and needrestart ops are invoked via the helper
// service; the daemon composes the UpdatesData envelope around their
// typed results plus locally-read /var/lib/apt/periodic data.
package updates

import (
	"context"
	"errors"
	"os"
	"sort"
	"sync"
	"time"

	"tigr.net/host-health-mcp/daemon/internal/daemon/helperinvoke"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// Data is the response data for tool updates. Mirrors UpdatesData in
// doc/schema-draft.yaml.
type Data struct {
	AptLockState                   string     `json:"apt_lock_state"`
	SecurityUpdatesPending         *int       `json:"security_updates_pending"`
	RegularUpdatesPending          *int       `json:"regular_updates_pending"`
	HeldPackages                   []string   `json:"held_packages"`
	LastAptUpdateTS                *time.Time `json:"last_apt_update_ts"`
	UnattendedUpgradesEnabled      bool       `json:"unattended_upgrades_enabled"`
	UnattendedUpgradesLastRunTS    *time.Time `json:"unattended_upgrades_last_run_ts"`
	UnattendedUpgradesLastExitCode *int       `json:"unattended_upgrades_last_exit_code"`
	NeedrestartPendingServices     []string   `json:"needrestart_pending_services"`
}

// Tool is the registered tool.
type Tool struct {
	hc *helperinvoke.Client
}

// New returns a new tool instance.
func New(hc *helperinvoke.Client) *Tool { return &Tool{hc: hc} }

// Name returns the tool name.
func (*Tool) Name() string { return "updates" }

// DefaultTTL: package state changes slowly; one minute is a reasonable
// default that still keeps "security updates pending" reasonably fresh.
func (*Tool) DefaultTTL() time.Duration { return 60 * time.Second }

// DefaultTimeout caps the per-call duration. apt-get -s upgrade can be
// slow on a host with a lot of pending work; 8 s leaves the helper a
// 500 ms grace before the per-tool timeout trips.
func (*Tool) DefaultTimeout() time.Duration { return 8 * time.Second }

// aptPendingResult mirrors the helper's apt_pending response shape
// (daemon/internal/helper/ops/apt_pending.go).
type aptPendingResult struct {
	LockState              string   `json:"lock_state"`
	SecurityUpdatesPending *int     `json:"security_updates_pending"`
	RegularUpdatesPending  *int     `json:"regular_updates_pending"`
	HeldPackages           []string `json:"held_packages"`
}

// needrestartResult mirrors the helper's needrestart response shape.
type needrestartResult struct {
	PendingServices []string `json:"pending_services"`
}

// unattendedResult mirrors the helper's UnattendedUpgradesStatusResult.
type unattendedResult struct {
	Enabled      bool       `json:"enabled"`
	LastRunTS    *time.Time `json:"last_run_ts"`
	LastExitCode *int       `json:"last_exit_code"`
}

// Handle invokes both helper ops in parallel, then composes the
// envelope around their results plus locally-read state.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	var (
		apt    aptPendingResult
		need   needrestartResult
		uu     unattendedResult
		aptErr, needErr, uuErr error
	)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		aptErr = t.hc.CallJSON(ctx, proto.OpAptPending, "", &apt)
	}()
	go func() {
		defer wg.Done()
		needErr = t.hc.CallJSON(ctx, proto.OpNeedrestart, "", &need)
	}()
	go func() {
		defer wg.Done()
		uuErr = t.hc.CallJSON(ctx, proto.OpUnattendedUpgradesStatus, "", &uu)
	}()
	wg.Wait()

	var warnings []string

	d := Data{
		HeldPackages:               []string{},
		NeedrestartPendingServices: []string{},
		AptLockState:               "unknown",
	}

	if aptErr != nil {
		warnings = append(warnings, "updates: apt_pending: "+aptErr.Error())
	} else {
		if apt.LockState == "" {
			// Helper returned an empty envelope. Treat as a non-fatal
			// parse anomaly and surface it rather than silently leaving
			// the default "unknown" with no explanation.
			warnings = append(warnings, "updates: apt_pending returned empty lock_state")
		} else {
			d.AptLockState = apt.LockState
		}
		d.SecurityUpdatesPending = apt.SecurityUpdatesPending
		d.RegularUpdatesPending = apt.RegularUpdatesPending
		if apt.HeldPackages != nil {
			d.HeldPackages = apt.HeldPackages
			sort.Strings(d.HeldPackages)
		}
	}

	if needErr != nil {
		warnings = append(warnings, "updates: needrestart: "+needErr.Error())
	} else if need.PendingServices != nil {
		d.NeedrestartPendingServices = need.PendingServices
		sort.Strings(d.NeedrestartPendingServices)
	}

	// /var/lib/apt/periodic/update-success-stamp is touched by the apt
	// timer when an update succeeds. Treat its mtime as the last apt
	// update timestamp; absence is worth a warning so the operator can
	// confirm Update-Package-Lists is on.
	const aptStampPath = "/var/lib/apt/periodic/update-success-stamp"
	if info, err := os.Stat(aptStampPath); err == nil {
		ts := info.ModTime().UTC()
		d.LastAptUpdateTS = &ts
	} else if errors.Is(err, os.ErrNotExist) {
		warnings = append(warnings,
			"updates: "+aptStampPath+" absent; APT::Periodic::Update-Package-Lists "+
				"may not be enabled or apt-daily.timer has never run successfully")
	} else {
		warnings = append(warnings, "updates: stat "+aptStampPath+": "+err.Error())
	}

	// Unattended-upgrades source-of-truth is `apt-config dump` (read
	// via the helper, since /var/log/unattended-upgrades is
	// root:root 0750 and the daemon user can't traverse it).
	// Falling back to /etc/apt/apt.conf.d/*unattended-upgrades* glob
	// missed the canonical "20auto-upgrades" file shipped by the
	// unattended-upgrades package.
	if uuErr != nil {
		warnings = append(warnings, "updates: unattended_upgrades_status: "+uuErr.Error())
	} else {
		d.UnattendedUpgradesEnabled = uu.Enabled
		d.UnattendedUpgradesLastRunTS = uu.LastRunTS
		d.UnattendedUpgradesLastExitCode = uu.LastExitCode
	}

	return d, warnings, nil
}
