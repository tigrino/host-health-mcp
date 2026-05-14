// Package system implements tool 4.1: uptime, load, memory, swap,
// per-mount disks, kernel, distribution, time-sync, reboot-required.
package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Data is the response data for tool system. Mirrors SystemData in
// doc/schema-draft.yaml.
type Data struct {
	UptimeS         int64        `json:"uptime_s"`
	Load1           float64      `json:"load_1"`
	Load5           float64      `json:"load_5"`
	Load15          float64      `json:"load_15"`
	CPUCount        int          `json:"cpu_count"`
	MemTotalB       int64        `json:"mem_total_b"`
	MemAvailableB   int64        `json:"mem_available_b"`
	SwapTotalB      int64        `json:"swap_total_b"`
	SwapUsedB       int64        `json:"swap_used_b"`
	Disk            []DiskEntry  `json:"disk"`
	KernelRelease   string       `json:"kernel_release"`
	Distro          string       `json:"distro"`
	DistroVersion   string       `json:"distro_version"`
	TimeSyncSource  string       `json:"time_sync_source"`
	TimeOffsetS     *float64     `json:"time_offset_s"`
	RebootRequired  bool         `json:"reboot_required"`
}

// DiskEntry mirrors the DiskEntry schema in schema-draft.yaml.
type DiskEntry struct {
	Mountpoint   string `json:"mountpoint"`
	FS           string `json:"fs"`
	SizeB        int64  `json:"size_b"`
	UsedB        int64  `json:"used_b"`
	InodesTotal  int64  `json:"inodes_total"`
	InodesUsed   int64  `json:"inodes_used"`
}

// Tool is the registered tool.
type Tool struct{}

// New returns a new tool instance.
func New() *Tool { return &Tool{} }

// Name returns the tool name.
func (*Tool) Name() string { return "system" }

// DefaultTTL keeps system data fresh; load/uptime change quickly.
func (*Tool) DefaultTTL() time.Duration { return 15 * time.Second }

// DefaultTimeout caps the tool's per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 3 * time.Second }

// Handle gathers system data from /proc, /etc/os-release, and statfs.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	var warnings []string
	d := Data{CPUCount: runtime.NumCPU()}

	if upS, err := readUptime(); err == nil {
		d.UptimeS = upS
	} else {
		warnings = append(warnings, "system: uptime: "+err.Error())
	}

	if l1, l5, l15, err := readLoadAvg(); err == nil {
		d.Load1, d.Load5, d.Load15 = l1, l5, l15
	} else {
		warnings = append(warnings, "system: loadavg: "+err.Error())
	}

	if mt, ma, st, su, err := readMemInfo(); err == nil {
		d.MemTotalB, d.MemAvailableB = mt, ma
		d.SwapTotalB, d.SwapUsedB = st, su
	} else {
		warnings = append(warnings, "system: meminfo: "+err.Error())
	}

	if kr, err := readKernelRelease(); err == nil {
		d.KernelRelease = kr
	}

	if id, ver, err := readOSRelease(); err == nil {
		d.Distro, d.DistroVersion = id, ver
	}

	d.TimeSyncSource = detectTimeSync()

	d.RebootRequired = fileExists("/var/run/reboot-required")

	// Disk usage on each currently-mounted filesystem from /proc/mounts.
	if mounts, err := readMounts(); err == nil {
		for _, m := range mounts {
			var st unix.Statfs_t
			if err := unix.Statfs(m.Mountpoint, &st); err != nil {
				continue
			}
			d.Disk = append(d.Disk, DiskEntry{
				Mountpoint:  m.Mountpoint,
				FS:          m.FS,
				SizeB:       int64(st.Blocks) * int64(st.Bsize),
				UsedB:       int64(st.Blocks-st.Bavail) * int64(st.Bsize),
				InodesTotal: int64(st.Files),
				InodesUsed:  int64(st.Files - st.Ffree),
			})
		}
	}

	return d, warnings, nil
}

func readUptime() (int64, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, fmt.Errorf("uptime: empty")
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return int64(v), nil
}

func readLoadAvg() (l1, l5, l15 float64, err error) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		err = fmt.Errorf("loadavg: short")
		return
	}
	l1, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return
	}
	l5, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return
	}
	l15, err = strconv.ParseFloat(fields[2], 64)
	return
}

func readMemInfo() (memTotal, memAvail, swapTotal, swapUsed int64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var swapFree int64
	for scanner.Scan() {
		line := scanner.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := line[:colon]
		val := strings.Fields(line[colon+1:])
		if len(val) < 1 {
			continue
		}
		n, perr := strconv.ParseInt(val[0], 10, 64)
		if perr != nil {
			continue
		}
		// /proc/meminfo reports in KiB.
		bytesV := n * 1024
		switch key {
		case "MemTotal":
			memTotal = bytesV
		case "MemAvailable":
			memAvail = bytesV
		case "SwapTotal":
			swapTotal = bytesV
		case "SwapFree":
			swapFree = bytesV
		}
	}
	swapUsed = swapTotal - swapFree
	return
}

func readKernelRelease() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(u.Release[:]), nil
}

func readOSRelease() (id, ver string, err error) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := line[:eq]
		val := strings.Trim(line[eq+1:], `"`)
		switch key {
		case "ID":
			id = val
		case "VERSION_ID":
			ver = val
		}
	}
	return
}

func detectTimeSync() string {
	for _, p := range []struct {
		path, name string
	}{
		{"/var/run/chrony/chronyd.pid", "chrony"},
		{"/run/chrony/chronyd.pid", "chrony"},
		{"/var/run/ntpd.pid", "ntpd"},
		{"/run/systemd/timesync/synchronized", "systemd-timesyncd"},
	} {
		if fileExists(p.path) {
			return p.name
		}
	}
	return "none"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type mountEntry struct {
	Mountpoint string
	FS         string
}

func readMounts() ([]mountEntry, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []mountEntry
	scanner := bufio.NewScanner(f)
	seen := make(map[string]bool)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		mp := fields[1]
		fs := fields[2]
		// Skip pseudo-filesystems and bind mounts we'd double-count.
		switch fs {
		case "proc", "sysfs", "cgroup", "cgroup2", "devpts", "tmpfs", "devtmpfs",
			"mqueue", "debugfs", "tracefs", "securityfs", "pstore", "bpf",
			"fusectl", "configfs", "fuse.gvfsd-fuse", "rpc_pipefs", "nsfs",
			"autofs", "binfmt_misc", "overlay", "ramfs":
			continue
		}
		if seen[mp] {
			continue
		}
		seen[mp] = true
		out = append(out, mountEntry{Mountpoint: mp, FS: fs})
	}
	return out, nil
}
