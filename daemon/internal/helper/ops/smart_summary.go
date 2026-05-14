package ops

import (
	"context"
	"encoding/json"
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

// SmartSummary is the typed result for op smart_summary, populated from
// smartctl --json -a /dev/<dev>. Fields not reported by smartctl are
// left null; per-device collection failures are reported by the
// daemon-side schema's error block, not here.
type SmartSummary struct {
	Device              string  `json:"device"`
	Model               *string `json:"model,omitempty"`
	SmartOverall        *string `json:"smart_overall,omitempty"`
	TemperatureC        *int    `json:"temperature_c,omitempty"`
	ReallocatedSectors  *int    `json:"reallocated_sectors,omitempty"`
	PowerOnHours        *int    `json:"power_on_hours,omitempty"`
}

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
	stdout, err := helperexec.Run(ctx, "smartctl", "--json", "-a", devPath)
	if err != nil {
		// smartctl exits with low-bits-set status to signal SMART
		// conditions (e.g. exit 4 = checksum error) while still
		// emitting valid JSON. Surface failures through the per-
		// device error path; do not pretend the device is healthy.
		return nil, err
	}

	var raw rawSmart
	if err := json.Unmarshal(stdout, &raw); err != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: fmt.Sprintf("smartctl JSON parse: %s", err.Error()),
		}
	}

	out := SmartSummary{Device: param}
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
