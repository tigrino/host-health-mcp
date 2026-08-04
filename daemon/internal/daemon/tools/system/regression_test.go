package system

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withMounts(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := procMountsPath
	procMountsPath = p
	t.Cleanup(func() { procMountsPath = orig })
}

// NEGATIVE: a /proc/mounts read that fails partway must still report
// the filesystems it did read, and must say the list is short.
//
// Emitting an empty disk[] with status ok is indistinguishable from
// "this host has no filesystems", and is strictly worse than the
// partial list it replaced. Regression guard for the fix applied after
// the 2.3.0 audit.
func TestHandleKeepsPartialDiskListOnReadError(t *testing.T) {
	// A line over linescan.MaxLine stops the scan; the mounts before
	// it were parsed and must survive.
	withMounts(t, "/dev/sda1 / ext4 rw 0 0\n"+
		"/dev/sdb1 /data "+strings.Repeat("x", 1<<20+1)+" rw 0 0\n"+
		"/dev/sdc1 /srv xfs rw 0 0\n")

	out, warnings, err := (&Tool{}).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	d := out.(Data)

	if len(d.Disk) == 0 {
		t.Error("disk[] is empty; the mounts parsed before the failure were discarded")
	}
	var found bool
	for _, w := range warnings {
		if strings.Contains(w, "/proc/mounts") && strings.Contains(w, "incomplete") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning naming the truncated read; warnings = %v", warnings)
	}
}

// POSITIVE: a clean mount table produces no read warning.
func TestHandleCleanMountsProducesNoReadWarning(t *testing.T) {
	withMounts(t, "/dev/sda1 / ext4 rw 0 0\nproc /proc proc rw 0 0\n")

	_, warnings, err := (&Tool{}).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "/proc/mounts") {
			t.Errorf("unexpected read warning on a clean mount table: %q", w)
		}
	}
}

// POSITIVE + NEGATIVE: a blocking filesystem is reported as skipped,
// a local one is measured, and the skip is never silent.
func TestHandleReportsSkippedBlockingMounts(t *testing.T) {
	withMounts(t, "/dev/sda1 / ext4 rw 0 0\nsrv:/export /mnt/nfs nfs4 rw 0 0\n")

	_, warnings, err := (&Tool{}).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	var said bool
	for _, w := range warnings {
		if strings.Contains(w, "/mnt/nfs") && strings.Contains(w, "nfs4") {
			said = true
		}
	}
	if !said {
		t.Errorf("skipped mount not reported; warnings = %v", warnings)
	}
}

// NEGATIVE: nfsd is the pseudo-filesystem at /proc/fs/nfsd, not a
// mounted NFS share. statfs on it does not block, so listing it as
// blocking made every NFS SERVER emit a skipped-mount warning for a
// mount it never needed to skip — noise in the field, on exactly the
// hosts most likely to also have real NFS mounts.
func TestNfsdIsNotTreatedAsBlocking(t *testing.T) {
	if mayBlockOnStatfs("nfsd") {
		t.Error("nfsd classified as blocking; it is /proc/fs/nfsd and does not block")
	}
	// The real network filesystems still are.
	for _, fs := range []string{"nfs", "nfs4"} {
		if !mayBlockOnStatfs(fs) {
			t.Errorf("%q must still be treated as blocking", fs)
		}
	}
}

// NEGATIVE: an NFS server's /proc/fs/nfsd must not appear in the
// skipped list at all — it is dropped as a pseudo-filesystem.
func TestNfsdProducesNoSkippedWarning(t *testing.T) {
	withMounts(t, "/dev/sda1 / ext4 rw 0 0\nnfsd /proc/fs/nfsd nfsd rw 0 0\n")

	_, warnings, err := (&Tool{}).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "nfsd") {
			t.Errorf("spurious skipped-mount warning on an NFS server: %q", w)
		}
	}
}
