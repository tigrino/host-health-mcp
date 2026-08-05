package system

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mountsFixture points the tool at a /proc/mounts fixture.
func mountsFixture(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := procMountsPath
	procMountsPath = p
	t.Cleanup(func() { procMountsPath = orig })
}

func systemDisk(t *testing.T) ([]DiskEntry, []string) {
	t.Helper()
	got, warnings, err := (&Tool{}).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	return got.(Data).Disk, warnings
}

// A network or userspace-backed mount must APPEAR in disk[]. Excluding
// it made a capacity panel for the volume go to no-data with nothing
// naming the volume that vanished — silent, in a tool whose job is to
// be loud.
func TestNetworkAndUserspaceMountsAreListed(t *testing.T) {
	// The mountpoints do not exist, so statfs fails fast; the point of
	// this test is that the entries are present at all.
	dir := t.TempDir()
	mountsFixture(t, ""+
		"server:/export "+dir+"/nfs nfs4 rw 0 0\n"+
		"//srv/share "+dir+"/cifs cifs rw 0 0\n"+
		"myfs "+dir+"/vfs virtiofs rw 0 0\n"+
		"sshfs#u@h:/ "+dir+"/sshfs fuse.sshfs rw 0 0\n")

	disk, _ := systemDisk(t)

	want := map[string]string{
		dir + "/nfs": "nfs4", dir + "/cifs": "cifs",
		dir + "/vfs": "virtiofs", dir + "/sshfs": "fuse.sshfs",
	}
	got := map[string]string{}
	for _, e := range disk {
		got[e.Mountpoint] = e.FS
	}
	for mp, fs := range want {
		if got[mp] != fs {
			t.Errorf("%s (%s) is missing from disk[]; every mount must be listed", mp, fs)
		}
	}
}

// An unmeasurable mount is listed with NULL measurements, not zeros.
// Zero would read as "this volume is empty", which is a number an
// alert can act on and a lie.
func TestAnUnmeasurableMountReportsNullNotZero(t *testing.T) {
	dir := t.TempDir()
	mountsFixture(t, "server:/export "+dir+"/gone nfs4 rw 0 0\n")

	disk, warnings := systemDisk(t)

	var e *DiskEntry
	for i := range disk {
		if disk[i].Mountpoint == dir+"/gone" {
			e = &disk[i]
		}
	}
	if e == nil {
		t.Fatal("the mount is absent from disk[]")
	}
	if e.SizeB != nil || e.UsedB != nil || e.InodesTotal != nil || e.InodesUsed != nil {
		t.Errorf("unmeasurable mount reported numbers: %+v", e)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "not measured") && strings.Contains(w, dir+"/gone") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning naming the unmeasured mount, got %v", warnings)
	}
}

// Positive: a real, local, healthy mount still reports real numbers.
// A bound that made everything null would be no better than dropping
// the entries.
func TestALocalMountStillReportsMeasurements(t *testing.T) {
	dir := t.TempDir()
	mountsFixture(t, "/dev/sda1 "+dir+" ext4 rw 0 0\n")

	disk, _ := systemDisk(t)

	if len(disk) != 1 {
		t.Fatalf("expected one entry, got %d: %+v", len(disk), disk)
	}
	if disk[0].SizeB == nil || *disk[0].SizeB <= 0 {
		t.Fatalf("a healthy local mount must report a size, got %+v", disk[0])
	}
	if disk[0].InodesTotal == nil {
		t.Error("a healthy local mount must report inode counts")
	}
}

// The schema lists all four measurements as required, so the keys must
// be present and explicitly null rather than omitted.
func TestNullMeasurementsAreExplicitNotOmitted(t *testing.T) {
	b, err := json.Marshal(DiskEntry{Mountpoint: "/x", FS: "nfs4"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"size_b", "used_b", "inodes_total", "inodes_used"} {
		raw, present := m[k]
		if !present {
			t.Errorf("%s is omitted; the schema lists it as required", k)
			continue
		}
		if string(raw) != "null" {
			t.Errorf("%s: got %s, want null", k, raw)
		}
	}
}

// A mount whose statfs never returns must not be probed again on the
// next poll. Without the in-flight guard every poll abandons another
// uninterruptible goroutine against the same dead mount, and they
// accumulate for the life of the process.
func TestAHangingMountIsNotProbedTwice(t *testing.T) {
	// A REAL, healthy directory: statfs on it would succeed. The only
	// thing that can make the probe report unmeasured is the in-flight
	// guard, so this discriminates. An earlier version used a
	// nonexistent path, where statfs fails fast on its own and the
	// test passed with the guard removed.
	dir := t.TempDir()

	if st, ok := statfsBounded(dir); !ok || st.Blocks == 0 {
		t.Fatalf("precondition: statfs on %s should succeed, got ok=%v", dir, ok)
	}

	// Claim the slot, as a goroutine still in D-state would have.
	statfsInFlight.Store(dir, struct{}{})
	t.Cleanup(func() { statfsInFlight.Delete(dir) })

	start := time.Now()
	_, ok := statfsBounded(dir)
	elapsed := time.Since(start)

	if ok {
		t.Fatal("a mount with an outstanding probe must report unmeasured; " +
			"without this guard every poll abandons another uninterruptible " +
			"goroutine against the same dead mount")
	}
	if elapsed > 10*time.Millisecond {
		t.Errorf("waited %v for a mount already known to be wedged; the second "+
			"poll must return immediately", elapsed)
	}
}

// The guard must release when the probe finishes, or one slow poll
// would mark a healthy mount unmeasurable forever.
func TestTheInFlightSlotIsReleasedAfterASuccessfulProbe(t *testing.T) {
	dir := t.TempDir()

	if _, ok := statfsBounded(dir); !ok {
		t.Fatal("precondition: the first probe should succeed")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, busy := statfsInFlight.Load(dir); !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the in-flight slot was never released")
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := statfsBounded(dir); !ok {
		t.Fatal("a healthy mount became permanently unmeasurable after one probe")
	}
}
