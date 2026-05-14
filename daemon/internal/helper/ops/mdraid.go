package ops

import (
	"bufio"
	"bytes"
	"context"
	"regexp"
	"strconv"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

var mdraidNameRE = regexp.MustCompile(`^md[0-9]+$`)

// MdraidDetailResult is the typed result for op mdraid_detail.
type MdraidDetailResult struct {
	ArrayName    string   `json:"array_name"`
	Level        string   `json:"level"`
	State        string   `json:"state"`
	Devices      []string `json:"devices"`
	Degraded     bool     `json:"degraded"`
	SyncProgress *float64 `json:"sync_progress_pct,omitempty"`
}

// MdraidDetail runs `mdadm --detail --export /dev/<array>`. The --export
// form emits MD_*=value lines that are simpler to parse than the
// default human-readable form.
func MdraidDetail(ctx context.Context, param string) (any, error) {
	if !mdraidNameRE.MatchString(param) {
		return nil, &dispatch.Error{
			Code:    proto.CodeBadParam,
			Message: "array name failed whitelist",
		}
	}
	stdout, err := helperexec.Run(ctx, "mdadm", "--detail", "--export", "/dev/"+param)
	if err != nil {
		return nil, err
	}

	out := MdraidDetailResult{ArrayName: param}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Bytes()
		eq := bytes.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := string(line[:eq])
		val := string(line[eq+1:])
		switch key {
		case "MD_LEVEL":
			out.Level = val
		case "MD_DEGRADED":
			out.Degraded = val != "0"
		case "MD_ARRAY_STATE":
			out.State = val
		case "MD_RESYNC_ACTION":
			if val != "idle" {
				zero := 0.0
				out.SyncProgress = &zero
			}
		default:
			if len(key) > len("MD_DEVICE_") && key[:len("MD_DEVICE_")] == "MD_DEVICE_" && bytes.HasSuffix([]byte(key), []byte("_ROLE")) {
				// MD_DEVICE_<id>_ROLE=<role>; role is the slot or "spare".
				// We collect device names from MD_DEVICE_<id>_DEV.
				_ = key
				continue
			}
			if len(key) > len("MD_DEVICE_") && key[:len("MD_DEVICE_")] == "MD_DEVICE_" && bytes.HasSuffix([]byte(key), []byte("_DEV")) {
				out.Devices = append(out.Devices, val)
			}
		}
	}
	if out.State == "" {
		out.State = "unknown"
	}
	// If MD_RESYNC_PCT is exposed it can be parsed and assigned here in
	// a follow-up; the --export form does not include it on every
	// mdadm version, so we leave SyncProgress nil unless we saw a
	// non-idle resync action above.
	_ = strconv.Atoi // silence unused-import in case the file is extended
	return out, nil
}
