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

	"tigr.net/host-health-mcp/daemon/internal/daemon/helperinvoke"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// Data is the response data for tool storage. Mirrors StorageData in
// doc/schema-draft.yaml.
type Data struct {
	Mdraid   []MdraidArray  `json:"mdraid"`
	LvmVgs   []any          `json:"lvm_vgs"`
	LvmLvs   []any          `json:"lvm_lvs"`
	Smart    []SmartSummary `json:"smart"`
	Btrfs    []any          `json:"btrfs"`
	ZfsPools []any          `json:"zfs_pools"`
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
// are null on failure.
type SmartSummary struct {
	Device              string       `json:"device"`
	Model               *string      `json:"model,omitempty"`
	SmartOverall        *string      `json:"smart_overall,omitempty"`
	TemperatureC        *int         `json:"temperature_c,omitempty"`
	ReallocatedSectors  *int         `json:"reallocated_sectors,omitempty"`
	PowerOnHours        *int         `json:"power_on_hours,omitempty"`
	Error               *SmartError  `json:"error,omitempty"`
}

// SmartError is the structured per-device collection failure. Code is
// drawn from a fixed enum (REQ 4.13).
type SmartError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Tool is the registered tool.
type Tool struct {
	hc *helperinvoke.Client

	// fanout caps the simultaneous helper ops this tool initiates.
	// design §7.4: per-tool helper-fan-out cap (default 8).
	fanout int
}

// New returns a new tool instance.
func New(hc *helperinvoke.Client) *Tool {
	return &Tool{hc: hc, fanout: 8}
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
		LvmVgs:   []any{},
		LvmLvs:   []any{},
		Smart:    []SmartSummary{},
		Btrfs:    []any{},
		ZfsPools: []any{},
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

	// LVM, ZFS, btrfs are helper-stubbed today; surface that as
	// envelope warnings rather than failing the whole call. When the
	// helper ops land these become real entries in lvm_vgs[] etc.
	if err := t.hc.CallJSON(ctx, proto.OpLvmReport, "", &struct{}{}); err != nil {
		warnings = append(warnings, "storage: lvm_report: "+err.Error())
	}
	if err := t.hc.CallJSON(ctx, proto.OpZpoolStatus, "", &struct{}{}); err != nil {
		warnings = append(warnings, "storage: zpool_status: "+err.Error())
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
			Code:    mapHelperCode(he.Code),
			Message: he.Message,
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
