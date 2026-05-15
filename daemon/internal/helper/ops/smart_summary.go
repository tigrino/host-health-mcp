package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// deviceRE matches a whole-device name. Trailing-digit partition names
// like sda1 are deliberately excluded; SMART is a per-device feature
// and a partition is at best a no-op.
var deviceRE = regexp.MustCompile(`^(sd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|hd[a-z]+|xvd[a-z]+)$`)

// nvmeRE matches an NVMe namespace device name. smartctl's auto-detect
// heuristic walks /sys/class/block/ and on some kernel versions fails
// to discover the NVMe device type from a namespace path (nvme0n1
// rather than nvme0). Forcing -d nvme makes the invocation
// deterministic on every kernel the helper might see.
var nvmeRE = regexp.MustCompile(`^nvme[0-9]+n[0-9]+$`)

// SmartSummary is the typed result for op smart_summary, populated from
// smartctl --json -a /dev/<dev>. Fields not reported by smartctl are
// left null; per-device collection failures are reported by the
// daemon-side schema's error block, not here.
//
// SmartctlExitCode (schema 0.3.0) surfaces smartctl's raw exit code
// when it is non-zero but the JSON was still parseable. smartctl's
// exit code is a bit field (see man smartctl §EXIT STATUS): bits 0
// (parse error) and 1 (device open error) are real failures with no
// valid JSON; bits 2-7 are status flags that travel alongside a
// complete JSON document. The helper now passes through the status-
// flag cases instead of dropping the response.
type SmartSummary struct {
	Device              string  `json:"device"`
	Model               *string `json:"model,omitempty"`
	SmartOverall        *string `json:"smart_overall,omitempty"`
	TemperatureC        *int    `json:"temperature_c,omitempty"`
	ReallocatedSectors  *int    `json:"reallocated_sectors,omitempty"`
	PowerOnHours        *int    `json:"power_on_hours,omitempty"`
	SmartctlExitCode    *int    `json:"smartctl_exit_code,omitempty"`
}

// smartctlExitBits names the bit positions that mean "real failure".
// Anything outside this mask is a status flag and the JSON body is
// valid.
const smartctlFatalBits = 1<<0 | 1<<1

// rawSmart matches the subset of smartctl --json output we read.
type rawSmart struct {
	ModelName        string `json:"model_name"`
	SmartStatus      *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current int `json:"current"`
	} `json:"temperature"`
	AtaSmartAttributes *struct {
		Table []struct {
			ID    int    `json:"id"`
			Name  string `json:"name"`
			Raw   struct {
				Value int `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	PowerOnTime *struct {
		Hours int `json:"hours"`
	} `json:"power_on_time"`
}

// SmartSummaryHandler runs smartctl against a whitelisted device name
// and returns a parsed summary.
func SmartSummaryHandler(ctx context.Context, param string) (any, error) {
	if !deviceRE.MatchString(param) {
		return nil, &dispatch.Error{
			Code:    proto.CodeBadParam,
			Message: "device name failed whitelist",
		}
	}
	devPath := "/dev/" + param
	args := []string{"--json", "-a"}
	if nvmeRE.MatchString(param) {
		args = append(args, "-d", "nvme")
	}
	args = append(args, devPath)
	stdout, err := helperexec.Run(ctx, "smartctl", args...)

	// smartctl uses a bit-encoded exit code: bits 0 (parse error)
	// and 1 (device open error) are real failures with no JSON;
	// bits 2-7 are status flags (one SMART command failed, prefail
	// thresholds, etc.) that travel alongside a complete JSON
	// document. The helper passes those status-flag cases through
	// to the parser instead of dropping the response.
	var smartExit *int
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) && de.Code == proto.CodeToolFailed && de.ToolExit != nil {
			exit := *de.ToolExit
			if exit > 0 && exit&smartctlFatalBits == 0 && len(stdout) > 0 {
				smartExit = &exit
				err = nil
			}
		}
		if err != nil {
			return nil, err
		}
	}

	var raw rawSmart
	if jerr := json.Unmarshal(stdout, &raw); jerr != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: fmt.Sprintf("smartctl JSON parse: %s", jerr.Error()),
		}
	}

	out := SmartSummary{Device: param, SmartctlExitCode: smartExit}
	if raw.ModelName != "" {
		m := raw.ModelName
		out.Model = &m
	}
	if raw.SmartStatus != nil {
		v := "unknown"
		if raw.SmartStatus.Passed {
			v = "passed"
		} else {
			v = "failed"
		}
		out.SmartOverall = &v
	}
	if raw.Temperature != nil {
		t := raw.Temperature.Current
		out.TemperatureC = &t
	}
	if raw.PowerOnTime != nil {
		h := raw.PowerOnTime.Hours
		out.PowerOnHours = &h
	}
	if raw.AtaSmartAttributes != nil {
		for _, a := range raw.AtaSmartAttributes.Table {
			if a.ID == 5 || a.Name == "Reallocated_Sector_Ct" {
				v := a.Raw.Value
				out.ReallocatedSectors = &v
				break
			}
		}
	}
	return out, nil
}
