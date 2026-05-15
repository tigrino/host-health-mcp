// Package storage implements tool 4.13: mdraid, LVM, per-device SMART
// summary, btrfs scrub, zfs pool status. Per-device errors land
// inside the data rather than failing the whole call (REQ 4.13;
// design §7.3.2 "per-source error reporting").
package storage

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
)

// Data is the response data for tool storage. Mirrors StorageData in
// doc/schema-draft.yaml.
type Data struct {
	Mdraid   []MdraidArray  `json:"mdraid"`
	LvmVgs   []LvmVg        `json:"lvm_vgs"`
	LvmLvs   []LvmLv        `json:"lvm_lvs"`
	Smart    []SmartSummary `json:"smart"`
	Btrfs    []BtrfsScrub   `json:"btrfs"`
	ZfsPools []ZfsPool      `json:"zfs_pools"`
}

// LvmVg mirrors the helper's typed VG row.
type LvmVg struct {
	Name  string `json:"name"`
	SizeB int64  `json:"size_b"`
	FreeB int64  `json:"free_b"`
}

// LvmLv mirrors the helper's typed LV row.
type LvmLv struct {
	VG            string  `json:"vg"`
	Name          string  `json:"name"`
	SizeB         int64   `json:"size_b"`
	HealthStatus  *string `json:"health_status"`
}

// BtrfsScrub mirrors the helper's typed btrfs row.
type BtrfsScrub struct {
	Mountpoint       string     `json:"mountpoint"`
	LastScrubTS      *time.Time `json:"last_scrub_ts"`
	LastScrubStatus  *string    `json:"last_scrub_status"`
	ErrorsCount      int        `json:"errors_count"`
}

// ZfsPool mirrors the helper's typed zpool row.
type ZfsPool struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	ScanState   string `json:"scan_state"`
	ErrorsTotal int    `json:"errors_total"`
}

// MdraidArray mirrors the helper-side result. The daemon copies these
// through so the schema is stable in one place; the helper does the
// parsing per design §6.2.
type MdraidArray struct {
	ArrayName        string   `json:"array_name"`
	Level            string   `json:"level"`
	State            string   `json:"state"`
	Devices          []string `json:"devices"`
	Degraded         bool     `json:"degraded"`
	SyncProgressPct  *float64 `json:"sync_progress_pct,omitempty"`
}

// SmartSummary mirrors the schema. Per-device collection failures are
// recorded in the Error block; smart_overall and the detail fields
// are null on failure. SmartctlExitCode (0.3.0) surfaces smartctl's
// raw exit code when it is non-zero but the JSON was still parseable
// (status-bit-only exits — bits 2-7 of smartctl's bit-encoded exit).
type SmartSummary struct {
	Device              string       `json:"device"`
	Model               *string      `json:"model,omitempty"`
	SmartOverall        *string      `json:"smart_overall,omitempty"`
	TemperatureC        *int         `json:"temperature_c,omitempty"`
	ReallocatedSectors  *int         `json:"reallocated_sectors,omitempty"`
	PowerOnHours        *int         `json:"power_on_hours,omitempty"`
	SmartctlExitCode    *int         `json:"smartctl_exit_code,omitempty"`
	Error               *SmartError  `json:"error,omitempty"`
}

// SmartError is the structured per-device collection failure. Code is
// drawn from a fixed enum (REQ 4.13). Argv, ExitCode, StderrSHA256,
// and StderrPrefix were added in schema 0.2.0 so single-canary
// diagnoses don't require a round-trip; clients that don't know the
// new fields ignore them (additive-minor, version-matrix C2).
type SmartError struct {
	Code         string   `json:"code"`
	Message      string   `json:"message"`
	Argv         []string `json:"argv,omitempty"`
	ExitCode     *int     `json:"exit_code,omitempty"`
	StderrSHA256 string   `json:"stderr_sha256,omitempty"`
	StderrPrefix string   `json:"stderr_prefix,omitempty"`
}

// Tool is the registered tool.
type Tool struct {
	hc *helperinvoke.Client

	// fanout caps the simultaneous helper ops this tool initiates.
	// design §7.4: per-tool helper-fan-out cap (default 8).
	fanout int

	// btrfsMountpoints is the manifest-declared set; the helper also
	// verifies via statfs(2) before invoking btrfs(8). We send the
	// validated path through the helper for each entry.
	btrfsMountpoints []string
}

// New returns a new tool instance.
func New(hc *helperinvoke.Client, btrfsMountpoints []string) *Tool {
	bm := make([]string, len(btrfsMountpoints))
	copy(bm, btrfsMountpoints)
	return &Tool{hc: hc, fanout: 8, btrfsMountpoints: bm}
}

// Name returns the tool name.
func (*Tool) Name() string { return "storage" }

// DefaultTTL: SMART data moves slowly; one minute is reasonable. mdraid
// state moves faster (rebuild progress) but the operator-facing
// granularity of one minute is enough for routine inspection.
func (*Tool) DefaultTTL() time.Duration { return 60 * time.Second }

// DefaultTimeout caps the per-call duration. SMART reads can be slow;
// the cap aligns with REQ 5.1's 10 s ceiling.
func (*Tool) DefaultTimeout() time.Duration { return 10 * time.Second }

// Handle composes the storage envelope. Each subsystem is queried in
// parallel up to the fanout cap; per-subsystem failures populate the
// data without failing the whole call.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{
		Mdraid:   []MdraidArray{},
		LvmVgs:   []LvmVg{},
		LvmLvs:   []LvmLv{},
		Smart:    []SmartSummary{},
		Btrfs:    []BtrfsScrub{},
		ZfsPools: []ZfsPool{},
	}
	var warnings []string

	devices, err := enumerateBlockDevices()
	if err != nil {
		warnings = append(warnings, "storage: enumerate block devices: "+err.Error())
	}
	if len(devices) > 0 {
		d.Smart = t.collectSmart(ctx, devices)
	}

	arrays, err := enumerateMdraidArrays()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		warnings = append(warnings, "storage: read /proc/mdstat: "+err.Error())
	}
	for _, arr := range arrays {
		var ma MdraidArray
		if err := t.hc.CallJSON(ctx, proto.OpMdraidDetail, arr, &ma); err != nil {
			warnings = append(warnings, "storage: mdraid_detail "+arr+": "+err.Error())
			continue
		}
		d.Mdraid = append(d.Mdraid, ma)
	}

	// LVM via the helper. The helper does both vgs and lvs and returns
	// typed entries.
	var lvm struct {
		VGs []LvmVg `json:"vgs"`
		LVs []LvmLv `json:"lvs"`
	}
	if err := t.hc.CallJSON(ctx, proto.OpLvmReport, "", &lvm); err != nil {
		warnings = append(warnings, "storage: lvm_report: "+err.Error())
	} else {
		d.LvmVgs = lvm.VGs
		d.LvmLvs = lvm.LVs
	}

	// ZFS via the helper. Absent ZFS surfaces as an empty Pools list.
	var zfs struct {
		Pools []ZfsPool `json:"pools"`
	}
	if err := t.hc.CallJSON(ctx, proto.OpZpoolStatus, "", &zfs); err != nil {
		warnings = append(warnings, "storage: zpool_status: "+err.Error())
	} else {
		d.ZfsPools = zfs.Pools
	}

	// btrfs per manifest-declared mountpoint. Each call hits the
	// helper, which independently verifies via statfs(2) that the
	// path is btrfs.
	for _, mp := range t.btrfsMountpoints {
		var b BtrfsScrub
		if err := t.hc.CallJSON(ctx, proto.OpBtrfsScrub, mp, &b); err != nil {
			warnings = append(warnings, "storage: btrfs_scrub "+mp+": "+err.Error())
			continue
		}
		d.Btrfs = append(d.Btrfs, b)
	}

	return d, warnings, nil
}

// collectSmart calls smart_summary for each device in parallel up to
// t.fanout. Per-device collection failures populate
// SmartSummary.Error rather than dropping the device.
func (t *Tool) collectSmart(ctx context.Context, devices []string) []SmartSummary {
	out := make([]SmartSummary, len(devices))
	sem := make(chan struct{}, t.fanout)
	var wg sync.WaitGroup
	for i, dev := range devices {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, dev string) {
			defer wg.Done()
			defer func() { <-sem }()

			var s SmartSummary
			s.Device = dev
			err := t.hc.CallJSON(ctx, proto.OpSmartSummary, dev, &s)
			if err != nil {
				s = SmartSummary{
					Device: dev,
					Error:  helperErrorToSmartError(err),
				}
			}
			out[i] = s
		}(i, dev)
	}
	wg.Wait()
	return out
}

func helperErrorToSmartError(err error) *SmartError {
	var he *helperinvoke.HelperError
	if errors.As(err, &he) {
		return &SmartError{
			Code:         mapHelperCode(he.Code),
			Message:      he.Message,
			Argv:         he.Argv,
			ExitCode:     he.ToolExit,
			StderrSHA256: he.StderrSHA256,
			StderrPrefix: he.StderrPrefix,
		}
	}
	return &SmartError{Code: "tool_failed", Message: err.Error()}
}

// mapHelperCode collapses the helper's proto.Code* set into the
// SmartError code enum defined by REQ 4.13.
func mapHelperCode(code string) string {
	switch code {
	case proto.CodeToolMissing:
		return "tool_missing"
	case proto.CodeToolFailed:
		return "tool_failed"
	case proto.CodeDeadline:
		return "deadline"
	case proto.CodeOutputTruncated:
		return "output_truncated"
	default:
		return "parse_failed"
	}
}

// enumerateBlockDevices reads /sys/class/block and returns whole-device
// names (no partition entries). The names we return must satisfy the
// helper's smart_summary whitelist; this is enforced again by the
// helper before invocation.
func enumerateBlockDevices() ([]string, error) {
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		// Filter partitions: their entries are symlinks to a parent
		// device sysfs path containing the partition number. Check
		// for /sys/class/block/<name>/partition presence.
		if _, err := os.Stat("/sys/class/block/" + name + "/partition"); err == nil {
			continue
		}
		// Filter virtual block devices (loop*, ram*, dm-*, sr*); not
		// useful for SMART and the daemon's allowlist regex excludes
		// them anyway.
		switch {
		case strings.HasPrefix(name, "loop"),
			strings.HasPrefix(name, "ram"),
			strings.HasPrefix(name, "dm-"),
			strings.HasPrefix(name, "sr"),
			strings.HasPrefix(name, "zram"):
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// enumerateMdraidArrays reads /proc/mdstat and returns the names of
// active md devices (md0, md1, ...).
func enumerateMdraidArrays() ([]string, error) {
	b, err := os.ReadFile("/proc/mdstat")
	if err != nil {
		return nil, err
	}
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := scanner.Text()
		// Lines describing an array begin "mdN :". Skip header,
		// "unused devices:" and the per-array detail lines that
		// follow.
		if len(line) >= 3 && line[:2] == "md" {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == ":" {
				out = append(out, fields[0])
			}
		}
	}
	return out, nil
}
