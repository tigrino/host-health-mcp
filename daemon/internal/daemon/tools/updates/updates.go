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
	"path/filepath"
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

// Handle invokes both helper ops in parallel, then composes the
// envelope around their results plus locally-read state.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	var (
		apt   aptPendingResult
		need  needrestartResult
		aptErr, needErr error
	)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aptErr = t.hc.CallJSON(ctx, proto.OpAptPending, "", &apt)
	}()
	go func() {
		defer wg.Done()
		needErr = t.hc.CallJSON(ctx, proto.OpNeedrestart, "", &need)
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
		d.AptLockState = apt.LockState
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
	// update timestamp.
	if info, err := os.Stat("/var/lib/apt/periodic/update-success-stamp"); err == nil {
		ts := info.ModTime().UTC()
		d.LastAptUpdateTS = &ts
	}

	// unattended-upgrades presence is detected by the /var/log/unattended-
	// upgrades directory; last-run via the newest log file in the dir.
	if entries, err := os.ReadDir("/var/log/unattended-upgrades"); err == nil {
		d.UnattendedUpgradesEnabled = true
		var newest time.Time
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
		if !newest.IsZero() {
			ts := newest.UTC()
			d.UnattendedUpgradesLastRunTS = &ts
		}
	} else if errors.Is(err, os.ErrNotExist) {
		d.UnattendedUpgradesEnabled = isUnattendedUpgradesAptConfig()
	}

	return d, warnings, nil
}

// isUnattendedUpgradesAptConfig checks whether
// /etc/apt/apt.conf.d/*unattended-upgrades* is present without
// reading its contents. The presence itself indicates the operator
// has chosen to ship the config; the value cannot be inferred from a
// stat-only read but the package being installed is the operationally
// useful signal.
func isUnattendedUpgradesAptConfig() bool {
	matches, _ := filepath.Glob("/etc/apt/apt.conf.d/*unattended-upgrades*")
	return len(matches) > 0
}
