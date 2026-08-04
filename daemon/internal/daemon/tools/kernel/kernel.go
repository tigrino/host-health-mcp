// Package kernel implements tool 4.14: taint flags, MCE/EDAC counters,
// OOM kills, last panic, recognised cmdline keys (names only, never
// values).
package kernel

import (
	"bytes"
	"context"
	"host-health-mcp/daemon/internal/shared/linescan"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Data is the response data for tool kernel.
type Data struct {
	TaintedMask                  int        `json:"tainted_mask"`
	TaintedFlags                 []string   `json:"tainted_flags"`
	MCECount                     *int       `json:"mce_count"`
	EDACCorrectableErrorsTotal   *int       `json:"edac_correctable_errors_total"`
	EDACUncorrectableErrorsTotal *int       `json:"edac_uncorrectable_errors_total"`
	OOMKillsSinceBoot            int        `json:"oom_kills_since_boot"`
	LastPanicTS                  *time.Time `json:"last_panic_ts"`
	CmdlineKeysPresent           []string   `json:"cmdline_keys_present"`
}

// taintBits maps single-letter taint flags from /proc/sys/kernel/tainted
// to human-readable names. Source: Documentation/admin-guide/tainted-kernels.rst
var taintBits = []struct {
	bit  int
	name string
}{
	{0, "proprietary_module"},
	{1, "forced_module"},
	{2, "unsafe_smp"},
	{3, "forced_rmmod"},
	{4, "machine_check"},
	{5, "bad_page"},
	{6, "user"},
	{7, "die"},
	{8, "override_acpi_table"},
	{9, "warning"},
	{10, "crap"},
	{11, "firmware_workaround"},
	{12, "out_of_tree_module"},
	{13, "unsigned_module"},
	{14, "soft_lockup"},
	{15, "live_patched"},
	{16, "aux"},
	{17, "struct_random_layout"},
}

// allowlistedCmdlineKeys is the set of /proc/cmdline keys whose
// PRESENCE we report (never values). REQ 4.14: "values are never
// returned because the kernel command line may carry operator
// secrets (resume= device names, root= UUID values)."
var allowlistedCmdlineKeys = map[string]bool{
	"BOOT_IMAGE":                       true,
	"console":                          true,
	"crashkernel":                      true,
	"ipv6.disable":                     true,
	"loglevel":                         true,
	"nmi_watchdog":                     true,
	"panic":                            true,
	"quiet":                            true,
	"ro":                               true,
	"rw":                               true,
	"selinux":                          true,
	"systemd.unified_cgroup_hierarchy": true,
}

// Tool is the registered tool.
type Tool struct{}

// New returns a new tool instance.
func New() *Tool { return &Tool{} }

// Name returns the tool name.
func (*Tool) Name() string { return "kernel" }

// DefaultTTL: this can be cached longer since these change rarely.
func (*Tool) DefaultTTL() time.Duration { return 60 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 1 * time.Second }

// Handle gathers kernel data.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{
		TaintedFlags:       []string{},
		CmdlineKeysPresent: []string{},
	}

	if mask, err := readInt("/proc/sys/kernel/tainted"); err == nil {
		d.TaintedMask = mask
		for _, b := range taintBits {
			if mask&(1<<b.bit) != 0 {
				d.TaintedFlags = append(d.TaintedFlags, b.name)
			}
		}
	}

	d.MCECount = readMCECount()
	d.EDACCorrectableErrorsTotal, d.EDACUncorrectableErrorsTotal = readEDAC()

	if kills := readOOMKills(); kills >= 0 {
		d.OOMKillsSinceBoot = kills
	}

	d.CmdlineKeysPresent = readCmdlineKeys()

	return d, nil, nil
}

func readInt(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func readMCECount() *int {
	entries, err := os.ReadDir("/sys/devices/system/machinecheck")
	if err != nil {
		return nil
	}
	count := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "machinecheck") {
			continue
		}
		// Each CPU's machinecheck dir has a /count if non-zero events
		// have been observed. We sum across CPUs.
		v, err := readInt(filepath.Join("/sys/devices/system/machinecheck", e.Name(), "count"))
		if err == nil {
			count += v
		}
	}
	return &count
}

func readEDAC() (*int, *int) {
	var ce, ue int
	any := false
	entries, err := os.ReadDir("/sys/devices/system/edac/mc")
	if err != nil {
		return nil, nil
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "mc") {
			continue
		}
		if v, err := readInt(filepath.Join("/sys/devices/system/edac/mc", e.Name(), "ce_count")); err == nil {
			ce += v
			any = true
		}
		if v, err := readInt(filepath.Join("/sys/devices/system/edac/mc", e.Name(), "ue_count")); err == nil {
			ue += v
			any = true
		}
	}
	if !any {
		return nil, nil
	}
	return &ce, &ue
}

func readOOMKills() int {
	b, err := os.ReadFile("/proc/vmstat")
	if err != nil {
		return -1
	}
	scanner := linescan.New(bytes.NewReader(b), "/proc/vmstat")
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "oom_kill" {
			if v, err := strconv.Atoi(fields[1]); err == nil {
				return v
			}
		}
	}
	// A truncated read yields a confidently wrong number, so report
	// unknown. The sentinel here is -1, not 0: the caller tests
	// `kills >= 0`, so returning 0 would assert "this host has had
	// zero OOM kills" on the strength of a read that failed.
	if scanner.Err() != nil {
		return -1
	}
	return 0
}

func readCmdlineKeys() []string {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		if !os.IsNotExist(err) {
			return nil
		}
		// On some hardened kernels /proc/cmdline is restricted; treat
		// as empty rather than failing.
		_ = fs.ErrPermission
		return []string{}
	}
	out := []string{}
	for _, token := range strings.Fields(string(b)) {
		key := token
		if eq := strings.IndexByte(token, '='); eq >= 0 {
			key = token[:eq]
		}
		if allowlistedCmdlineKeys[key] {
			out = append(out, key)
		}
	}
	return out
}
