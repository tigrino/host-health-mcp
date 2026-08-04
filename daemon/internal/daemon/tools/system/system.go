// Package system implements tool 4.1: uptime, load, memory, swap,
// per-mount disks, kernel, distribution, time-sync, reboot-required.
package system

import (
	"context"
	"fmt"
	"host-health-mcp/daemon/internal/shared/linescan"
	"io"
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
	UptimeS        int64       `json:"uptime_s"`
	Load1          float64     `json:"load_1"`
	Load5          float64     `json:"load_5"`
	Load15         float64     `json:"load_15"`
	CPUCount       int         `json:"cpu_count"`
	MemTotalB      int64       `json:"mem_total_b"`
	MemAvailableB  int64       `json:"mem_available_b"`
	SwapTotalB     int64       `json:"swap_total_b"`
	SwapUsedB      int64       `json:"swap_used_b"`
	Disk           []DiskEntry `json:"disk"`
	KernelRelease  string      `json:"kernel_release"`
	Distro         string      `json:"distro"`
	DistroVersion  string      `json:"distro_version"`
	TimeSyncSource string      `json:"time_sync_source"`
	TimeOffsetS    *float64    `json:"time_offset_s"`
	RebootRequired bool        `json:"reboot_required"`
}

// DiskEntry mirrors the DiskEntry schema in schema-draft.yaml.
type DiskEntry struct {
	Mountpoint  string `json:"mountpoint"`
	FS          string `json:"fs"`
	SizeB       int64  `json:"size_b"`
	UsedB       int64  `json:"used_b"`
	InodesTotal int64  `json:"inodes_total"`
	InodesUsed  int64  `json:"inodes_used"`
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
	measured, skipped, err := readMounts()
	if err != nil {
		// Report what was read, and say the list is short. Returning
		// here would emit an EMPTY disk[] with status: ok — strictly
		// worse than the partial list this change set set out to stop
		// being silent about, and indistinguishable from "this host
		// has no filesystems".
		warnings = append(warnings, "system: /proc/mounts: "+err.Error()+
			"; disk[] is incomplete")
	}
	{
		if len(skipped) > 0 {
			// Never silent. A mail or file server whose largest volume
			// is NFS- or virtiofs-backed would otherwise lose capacity
			// reporting for the volume that matters most, with nothing
			// in the response to say why.
			names := make([]string, 0, len(skipped))
			for _, m := range skipped {
				names = append(names, m.Mountpoint+" ("+m.FS+")")
			}
			warnings = append(warnings, "system: disk usage not measured for "+
				strings.Join(names, ", ")+
				": statfs on these filesystems can block uninterruptibly")
		}
		for _, m := range measured {
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
	scanner := linescan.New(f, "/proc/meminfo")
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
	if serr := scanner.Err(); serr != nil {
		err = serr
		return
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

// blockingFSTypes are the /proc/mounts fstype values whose statfs can
// block uninterruptibly. Two classes, deliberately in one list because
// the consequence is identical: network filesystems whose server stops
// answering, and locally-mounted filesystems serviced by a userspace
// daemon that can die while the mount stays. Either way the caller
// sits in D-state where no timeout and no signal reach it.
//
// Matched exactly; FUSE is additionally matched by prefix, since its
// fstype carries the backing implementation ("fuse.sshfs").
var blockingFSTypes = map[string]bool{
	// Network.
	"nfs": true, "nfs4": true,
	"cifs": true, "smb3": true, "smbfs": true,
	"afs": true, "coda": true, "ncpfs": true,
	"9p": true, "ceph": true, "glusterfs": true,
	"lustre": true, "beegfs": true, "orangefs": true,
	"gfs2": true, "ocfs2": true, "davfs": true,
	"gpfs": true, "mmfs": true,

	// Serviced by a userspace daemon. virtiofs is the one that matters
	// most now — it is FUSE-based but reports fstype "virtiofs", so
	// neither the exact list nor the "fuse." prefix would catch it, and
	// its statfs is answered by virtiofsd on the hypervisor. Common on
	// KubeVirt, Kata and cloud-hypervisor guests.
	"virtiofs": true,
	"vboxsf":   true,
	"prl_fs":   true,
	// fuseblk backs ntfs-3g and exfat-fuse over a LOCAL block device.
	// Listed because a SIGKILLed ntfs-3g leaves the mount hung, not
	// because it is remote.
	"fuseblk": true,
}

// mayBlockOnStatfs reports whether statfs on this filesystem type may
// block on a remote or userspace server.
func mayBlockOnStatfs(fs string) bool {
	if blockingFSTypes[fs] {
		return true
	}
	// "fuse", "fuse.sshfs", "fuse.rclone", ... The prefix carries the
	// dot deliberately: without it "fusectl" would match. The
	// pseudo-FUSE filesystems that never block (fusectl,
	// fuse.gvfsd-fuse) are excluded by the switch above in any case.
	return fs == "fuse" || strings.HasPrefix(fs, "fuse.")
}

// procMountsPath is the mount table source. A package var, not a
// constant, so tests can point it at a fixture — the same seam
// procRootForTest uses in the nginx_apache op. Never written outside
// tests.
var procMountsPath = "/proc/mounts"

func readMounts() (measured, skipped []mountEntry, err error) {
	f, err := os.Open(procMountsPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	measured, skipped, err = parseMounts(f)
	return measured, skipped, err
}

// parseMounts splits /proc/mounts into the filesystems safe to statfs
// and the ones deliberately left alone. Taking an io.Reader keeps it
// testable without a real /proc, matching how the helper's parsers are
// structured (design §7.3).
//
// skipped carries only the mounts dropped for being unsafe to statfs.
// Pseudo-filesystems are not reported: nobody expects a usage figure
// for procfs, whereas a missing NFS volume is a monitoring blind spot
// the operator has to be told about.
func parseMounts(r io.Reader) (measured, skipped []mountEntry, err error) {
	scanner := linescan.New(r, procMountsPath)
	seen := make(map[string]bool)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		mp := unescapeMountField(fields[1])
		fs := fields[2]
		// Skip pseudo-filesystems and bind mounts we'd double-count.
		switch fs {
		case "proc", "sysfs", "cgroup", "cgroup2", "devpts", "tmpfs", "devtmpfs",
			"mqueue", "debugfs", "tracefs", "securityfs", "pstore", "bpf",
			"fusectl", "configfs", "fuse.gvfsd-fuse", "rpc_pipefs", "nsfs",
			// nfsd is the pseudo-filesystem at /proc/fs/nfsd, not a
			// mounted NFS share. statfs on it does not block, so
			// listing it as blocking made every NFS SERVER report a
			// skipped mount it never needed to skip.
			"nfsd",
			"autofs", "binfmt_misc", "overlay", "ramfs":
			continue
		}
		if seen[mp] {
			continue
		}
		seen[mp] = true
		// Anything whose statfs can block uninterruptibly is recorded
		// but not measured. A stale NFS or CIFS mount, or a FUSE mount
		// whose userspace daemon has died, puts the caller in D-state
		// indefinitely: no timeout and no signal reaches it, because
		// the block is in the kernel waiting on a server that is not
		// answering. A health check must not wedge a goroutine to
		// report one filesystem's usage — but it must say so.
		if mayBlockOnStatfs(fs) {
			skipped = append(skipped, mountEntry{Mountpoint: mp, FS: fs})
			continue
		}
		measured = append(measured, mountEntry{Mountpoint: mp, FS: fs})
	}
	// A truncated /proc/mounts would silently drop filesystems from
	// disk[], which reads as "that volume is gone" rather than "the
	// read failed".
	return measured, skipped, scanner.Err()
}

// unescapeMountField decodes the octal escapes the kernel writes into
// /proc/mounts for space, tab, newline and backslash. Without this a
// mountpoint containing a space is reported with a literal "\040".
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
