package ops

import (
	"context"
	"encoding/json"
	"strconv"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// LvmReportResult is the typed result for op lvm_report.
type LvmReportResult struct {
	VGs []LvmVg `json:"vgs"`
	LVs []LvmLv `json:"lvs"`
}

// LvmVg mirrors the daemon-side schema's lvm_vgs[] entry.
type LvmVg struct {
	Name   string `json:"name"`
	SizeB  int64  `json:"size_b"`
	FreeB  int64  `json:"free_b"`
}

// LvmLv mirrors the daemon-side schema's lvm_lvs[] entry. HealthStatus
// is null when LVM didn't report one.
type LvmLv struct {
	VG            string  `json:"vg"`
	Name          string  `json:"name"`
	SizeB         int64   `json:"size_b"`
	HealthStatus  *string `json:"health_status"`
}

// LvmReport invokes `vgs` and `lvs` with --reportformat=json and the
// minimal column set we care about. Bytes-suffix output is parsed
// without invoking lvm a second time for a numeric conversion.
//
// Replaces the not-yet-implemented stub in stubs.go.
func LvmReport(ctx context.Context, _ string) (any, error) {
	out := LvmReportResult{VGs: []LvmVg{}, LVs: []LvmLv{}}

	vgOut, err := helperexec.Run(ctx, "vgs",
		"--reportformat=json", "--units=b", "--nosuffix",
		"-o", "vg_name,vg_size,vg_free")
	if err != nil {
		return nil, err
	}
	if err := parseVGs(vgOut, &out); err != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: "vgs JSON parse: " + err.Error(),
		}
	}

	lvOut, err := helperexec.Run(ctx, "lvs",
		"--reportformat=json", "--units=b", "--nosuffix",
		"-o", "vg_name,lv_name,lv_size,lv_health_status")
	if err != nil {
		return nil, err
	}
	if err := parseLVs(lvOut, &out); err != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: "lvs JSON parse: " + err.Error(),
		}
	}

	return out, nil
}

// vgsEnvelope is the shape vgs --reportformat=json emits:
//   { "report": [ { "vg": [ { "vg_name": "...", "vg_size": "...", "vg_free": "..." } ] } ] }
type vgsEnvelope struct {
	Report []struct {
		VG []struct {
			VGName string `json:"vg_name"`
			VGSize string `json:"vg_size"`
			VGFree string `json:"vg_free"`
		} `json:"vg"`
	} `json:"report"`
}

func parseVGs(b []byte, out *LvmReportResult) error {
	var env vgsEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	for _, r := range env.Report {
		for _, vg := range r.VG {
			size, _ := strconv.ParseInt(vg.VGSize, 10, 64)
			free, _ := strconv.ParseInt(vg.VGFree, 10, 64)
			out.VGs = append(out.VGs, LvmVg{
				Name: vg.VGName, SizeB: size, FreeB: free,
			})
		}
	}
	return nil
}

// lvsEnvelope mirrors lvs --reportformat=json output.
type lvsEnvelope struct {
	Report []struct {
		LV []struct {
			VGName         string `json:"vg_name"`
			LVName         string `json:"lv_name"`
			LVSize         string `json:"lv_size"`
			LVHealthStatus string `json:"lv_health_status"`
		} `json:"lv"`
	} `json:"report"`
}

func parseLVs(b []byte, out *LvmReportResult) error {
	var env lvsEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	for _, r := range env.Report {
		for _, lv := range r.LV {
			size, _ := strconv.ParseInt(lv.LVSize, 10, 64)
			entry := LvmLv{VG: lv.VGName, Name: lv.LVName, SizeB: size}
			if lv.LVHealthStatus != "" {
				h := lv.LVHealthStatus
				entry.HealthStatus = &h
			}
			out.LVs = append(out.LVs, entry)
		}
	}
	return nil
}
