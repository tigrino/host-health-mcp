package system

import (
	"strings"
	"testing"
)

// C-3 root cause: readMounts excluded the pseudo-filesystems but not
// the ones that actually hang. unix.Statfs on a stale NFS or CIFS
// mount, or on a mount whose userspace daemon has died, blocks in
// D-state — no timeout and no signal reaches it.
func TestMayBlockOnStatfs(t *testing.T) {
	blocking := []string{
		// Network.
		"nfs", "nfs4", "cifs", "smb3", "smbfs", "afs", "ceph",
		"glusterfs", "lustre", "9p", "davfs", "ocfs2", "gfs2", "gpfs",
		// Serviced by a userspace daemon.
		"virtiofs", "vboxsf", "prl_fs", "fuseblk",
		"fuse", "fuse.sshfs", "fuse.rclone", "fuse.s3fs",
	}
	for _, fs := range blocking {
		if !mayBlockOnStatfs(fs) {
			t.Errorf("%q should be skipped: statfs on it can block uninterruptibly", fs)
		}
	}

	local := []string{
		"ext4", "ext3", "xfs", "btrfs", "zfs", "vfat", "exfat",
		"f2fs", "jfs", "reiserfs", "ntfs3", "iso9660", "squashfs",
	}
	for _, fs := range local {
		if mayBlockOnStatfs(fs) {
			t.Errorf("%q is a local filesystem and must still be measured", fs)
		}
	}
}

// virtiofs is FUSE-based but reports fstype "virtiofs", so neither the
// exact list nor the "fuse." prefix catches it on its own. Its statfs
// is answered by virtiofsd on the hypervisor and blocks indefinitely
// if that dies — the most current member of the class being defended
// against, and the one a prefix-only rule misses.
func TestVirtiofsIsCovered(t *testing.T) {
	if !mayBlockOnStatfs("virtiofs") {
		t.Error("virtiofs is not caught by the fuse. prefix and must be listed exactly")
	}
	if strings.HasPrefix("virtiofs", "fuse.") {
		t.Error("test premise wrong: virtiofs does not carry the fuse. prefix")
	}
}

// The prefix test must be "fuse." with the dot. Without it "fusectl" —
// a kernel pseudo-filesystem that never blocks — would match, and so
// would any future fstype merely starting with those four letters.
func TestFusePrefixDoesNotOvermatch(t *testing.T) {
	for _, fs := range []string{"fusectl", "fused", "fusion"} {
		if mayBlockOnStatfs(fs) {
			t.Errorf("%q matched the FUSE prefix rule; it should not", fs)
		}
	}
	if !mayBlockOnStatfs("fuseblk") {
		t.Error("fuseblk is listed exactly and should be skipped")
	}
}

// M-2: the skip must be visible to the caller. A silent omission turns
// a slow tool into a monitoring blind spot — the operator's largest
// volume disappears from disk[] with nothing to explain it.
func TestParseMountsSeparatesMeasuredFromSkipped(t *testing.T) {
	const procMounts = `sysfs /sys sysfs rw,nosuid 0 0
proc /proc proc rw,nosuid 0 0
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /var xfs rw,relatime 0 0
tmpfs /run tmpfs rw,nosuid 0 0
fileserver:/export /mnt/nfs nfs4 rw,relatime 0 0
//smb/share /mnt/smb cifs rw 0 0
myfs /mnt/virtiofs virtiofs rw 0 0
sshfs#user@host:/ /mnt/ssh fuse.sshfs rw 0 0
/dev/sdb1 /data btrfs rw 0 0
`
	measured, skipped, err := parseMounts(strings.NewReader(procMounts))
	if err != nil {
		t.Fatalf("parseMounts: %v", err)
	}

	wantMeasured := map[string]string{"/": "ext4", "/var": "xfs", "/data": "btrfs"}
	if len(measured) != len(wantMeasured) {
		t.Fatalf("measured = %v, want %v", measured, wantMeasured)
	}
	for _, m := range measured {
		if wantMeasured[m.Mountpoint] != m.FS {
			t.Errorf("measured %q as %q, unexpected", m.Mountpoint, m.FS)
		}
	}

	wantSkipped := map[string]string{
		"/mnt/nfs": "nfs4", "/mnt/smb": "cifs",
		"/mnt/virtiofs": "virtiofs", "/mnt/ssh": "fuse.sshfs",
	}
	if len(skipped) != len(wantSkipped) {
		t.Fatalf("skipped = %v, want %v", skipped, wantSkipped)
	}
	for _, m := range skipped {
		if wantSkipped[m.Mountpoint] != m.FS {
			t.Errorf("skipped %q as %q, unexpected", m.Mountpoint, m.FS)
		}
	}
}

// Pseudo-filesystems are dropped entirely, not reported as skipped:
// nobody expects a usage figure for procfs, and listing them would
// bury the mounts that genuinely went missing.
func TestParseMountsDoesNotReportPseudoFilesystemsAsSkipped(t *testing.T) {
	const procMounts = `sysfs /sys sysfs rw 0 0
proc /proc proc rw 0 0
tmpfs /run tmpfs rw 0 0
devtmpfs /dev devtmpfs rw 0 0
fusectl /sys/fs/fuse/connections fusectl rw 0 0
/dev/sda1 / ext4 rw 0 0
`
	measured, skipped, err := parseMounts(strings.NewReader(procMounts))
	if err != nil {
		t.Fatalf("parseMounts: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want none — pseudo-filesystems are not a blind spot", skipped)
	}
	if len(measured) != 1 || measured[0].Mountpoint != "/" {
		t.Errorf("measured = %v, want just /", measured)
	}
}

// The same mountpoint appearing twice (bind mounts) must not be
// double-counted, and the dedup must apply before the safe/unsafe
// split so a mount cannot land in both lists.
func TestParseMountsDeduplicatesMountpoints(t *testing.T) {
	const procMounts = `/dev/sda1 / ext4 rw 0 0
/dev/sda1 / ext4 ro,remount 0 0
srv:/export /mnt/x nfs4 rw 0 0
srv:/export /mnt/x nfs4 rw 0 0
`
	measured, skipped, err := parseMounts(strings.NewReader(procMounts))
	if err != nil {
		t.Fatalf("parseMounts: %v", err)
	}
	if len(measured) != 1 {
		t.Errorf("measured = %v, want one entry", measured)
	}
	if len(skipped) != 1 {
		t.Errorf("skipped = %v, want one entry", skipped)
	}
}

// The kernel octal-escapes space, tab, newline and backslash in
// /proc/mounts. Without decoding, a mountpoint with a space is
// reported as "/mnt/my\040disk" and the statfs on it fails.
func TestUnescapeMountField(t *testing.T) {
	cases := map[string]string{
		`/mnt/plain`:           "/mnt/plain",
		`/mnt/my\040disk`:      "/mnt/my disk",
		`/mnt/tab\011here`:     "/mnt/tab\there",
		`/mnt/back\134slash`:   "/mnt/back\\slash",
		`/mnt/two\040of\040em`: "/mnt/two of em",
		`/mnt/trailing\`:       `/mnt/trailing\`,
		`/mnt/bad\09`:          `/mnt/bad\09`,
	}
	for in, want := range cases {
		if got := unescapeMountField(in); got != want {
			t.Errorf("unescapeMountField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMountsDecodesEscapedMountpoints(t *testing.T) {
	measured, _, err := parseMounts(strings.NewReader(
		`/dev/sda1 /mnt/my\040disk ext4 rw 0 0` + "\n"))
	if err != nil {
		t.Fatalf("parseMounts: %v", err)
	}
	if len(measured) != 1 {
		t.Fatalf("measured = %v", measured)
	}
	if measured[0].Mountpoint != "/mnt/my disk" {
		t.Errorf("Mountpoint = %q, want %q", measured[0].Mountpoint, "/mnt/my disk")
	}
}

// Short or malformed lines must not panic or produce entries.
func TestParseMountsIgnoresMalformedLines(t *testing.T) {
	measured, skipped, err := parseMounts(strings.NewReader(
		"\n\nshort\ntwo fields\n/dev/sda1 / ext4 rw 0 0\n"))
	if err != nil {
		t.Fatalf("parseMounts: %v", err)
	}
	if len(measured) != 1 || len(skipped) != 0 {
		t.Errorf("measured = %v, skipped = %v", measured, skipped)
	}
}
