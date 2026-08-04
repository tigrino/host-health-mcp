package ops

import (
	"bytes"
	"context"
	"host-health-mcp/daemon/internal/shared/linescan"
	"os"
	"regexp"
	"strconv"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

var mdraidNameRE = regexp.MustCompile(`^md[0-9]+$`)

// mdstatPercentRE matches the resync/recovery progress line that
// follows the device-status line in /proc/mdstat. Example:
//
//	[=>...................]  recovery = 12.5% (...)
var mdstatPercentRE = regexp.MustCompile(`(\d+(?:\.\d+)?)%`)

// mdstatPathForTest lets the test fixture point /proc/mdstat at a
// temporary file. The empty-string default means real /proc/mdstat.
var mdstatPathForTest = ""

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
	res, perr := mdraidDetailFromExport(param, stdout)
	if perr != nil {
		return nil, &dispatch.Error{Code: proto.CodeToolFailed, Message: perr.Error()}
	}
	return res, nil
}

// mdraidDetailFromExport is the pure parse-plus-fallback decision
// logic for MdraidDetail. Extracted from the shellout site so the
// fallback trigger (no MD_RESYNC_PCT but a non-idle MD_RESYNC_ACTION)
// is testable against synthetic --export output combined with the
// existing mdstatPathForTest-controlled /proc/mdstat fixture.
func mdraidDetailFromExport(name string, stdout []byte) (MdraidDetailResult, error) {
	out := MdraidDetailResult{ArrayName: name}
	var resyncAction string
	var sawResyncPct bool
	scanner := linescan.New(bytes.NewReader(stdout), "mdadm --detail")
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
			resyncAction = val
		case "MD_RESYNC_PCT":
			if pct, err := strconv.ParseFloat(val, 64); err == nil {
				out.SyncProgress = &pct
				sawResyncPct = true
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
	// MD_RESYNC_PCT is not in every mdadm version's --export output.
	// When a non-idle resync action is reported but no percentage came
	// through, fall back to /proc/mdstat for the percentage on the
	// device's progress line.
	if !sawResyncPct && resyncAction != "" && resyncAction != "idle" {
		if pct, ok := readMdstatProgress(name); ok {
			out.SyncProgress = &pct
		} else {
			zero := 0.0
			out.SyncProgress = &zero
		}
	}
	if err := scanner.Err(); err != nil {
		return MdraidDetailResult{}, err
	}
	return out, nil
}

// readMdstatProgress parses /proc/mdstat for the resync/recovery
// percentage of array `name`. /proc/mdstat groups three lines per
// array: the device-status line ("mdN : ..."), the blocks line, and
// (when active) a progress line like:
//
//	[=>...................]  recovery = 12.5% (131136/1048512) finish=2.0min speed=8000K/sec
//
// We scan for the array's leading line and then look at subsequent
// lines until either the percentage line is found or a blank line /
// new array header ends the block.
func readMdstatProgress(name string) (float64, bool) {
	path := mdstatPathForTest
	if path == "" {
		path = "/proc/mdstat"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	scanner := linescan.New(bytes.NewReader(b), "/proc/mdstat")
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	in := false
	for scanner.Scan() {
		line := scanner.Text()
		if !in {
			// Array header lines begin with the device name followed
			// by " :" (e.g. "md0 : active raid1 ...").
			if len(line) > len(name)+2 &&
				line[:len(name)] == name &&
				(line[len(name)] == ' ' || line[len(name)] == ':') {
				in = true
			}
			continue
		}
		if line == "" {
			return 0, false
		}
		// A new array header inside the same block means we've left
		// our array without finding a progress line.
		if len(line) > 2 && line[0] != ' ' && line[0] != '\t' {
			return 0, false
		}
		m := mdstatPercentRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pct, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, false
		}
		return pct, true
	}
	// A truncated read yields a confidently wrong number. Report
	// "unknown" instead — for a health check the two are not the
	// same thing.
	if scanner.Err() != nil {
		return 0, false
	}
	return 0, false
}
