package ops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadMdstatProgress_RecoveryLine(t *testing.T) {
	in := `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      1048512 blocks super 1.2 [2/2] [UU]
      [=>...................]  recovery = 12.5% (131136/1048512) finish=2.0min speed=8000K/sec

unused devices: <none>
`
	withMdstat(t, in)
	pct, ok := readMdstatProgress("md0")
	if !ok {
		t.Fatal("expected progress line to be found")
	}
	if pct != 12.5 {
		t.Fatalf("pct = %v want 12.5", pct)
	}
}

func TestReadMdstatProgress_NoArray(t *testing.T) {
	in := `Personalities : [raid1]
unused devices: <none>
`
	withMdstat(t, in)
	if _, ok := readMdstatProgress("md0"); ok {
		t.Fatal("expected no progress for missing array")
	}
}

func TestReadMdstatProgress_IdleArray(t *testing.T) {
	in := `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      1048512 blocks super 1.2 [2/2] [UU]

unused devices: <none>
`
	withMdstat(t, in)
	if _, ok := readMdstatProgress("md0"); ok {
		t.Fatal("expected no progress on idle array")
	}
}

func TestReadMdstatProgress_MultipleArrays(t *testing.T) {
	in := `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      1048512 blocks super 1.2 [2/2] [UU]

md1 : active raid1 sdc1[0] sdd1[1]
      2097024 blocks super 1.2 [2/1] [U_]
      [===>.................]  recovery = 18.7% (393216/2097024) finish=3.0min speed=8000K/sec

unused devices: <none>
`
	withMdstat(t, in)
	if _, ok := readMdstatProgress("md0"); ok {
		t.Fatal("md0 should be idle")
	}
	pct, ok := readMdstatProgress("md1")
	if !ok || pct != 18.7 {
		t.Fatalf("md1 progress = (%v,%v) want (18.7,true)", pct, ok)
	}
}

// Integration of the parse-plus-fallback decision: --export output
// omits MD_RESYNC_PCT but reports a non-idle MD_RESYNC_ACTION, so the
// op must consult /proc/mdstat for the percentage. Older mdadm
// versions in the field do not emit MD_RESYNC_PCT at all.
func TestMdraidDetailFromExport_FallbackToMdstat(t *testing.T) {
	withMdstat(t, `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      1048512 blocks super 1.2 [2/1] [U_]
      [=====>...............]  recovery = 27.3% (286208/1048512) finish=2.0min speed=8000K/sec

unused devices: <none>
`)
	export := []byte("MD_LEVEL=raid1\n" +
		"MD_DEVNAME=md0\n" +
		"MD_ARRAY_STATE=clean\n" +
		"MD_DEGRADED=1\n" +
		"MD_RESYNC_ACTION=recover\n" +
		"MD_DEVICE_dev_sda1_DEV=/dev/sda1\n" +
		"MD_DEVICE_dev_sda1_ROLE=0\n" +
		"MD_DEVICE_dev_sdb1_DEV=/dev/sdb1\n" +
		"MD_DEVICE_dev_sdb1_ROLE=1\n")
	got, err := mdraidDetailFromExport("md0", export)
	if err != nil {
		t.Fatal(err)
	}
	if got.SyncProgress == nil {
		t.Fatal("expected SyncProgress to be non-nil via mdstat fallback")
	}
	if *got.SyncProgress != 27.3 {
		t.Fatalf("SyncProgress = %v want 27.3", *got.SyncProgress)
	}
	if got.Level != "raid1" || !got.Degraded || got.State != "clean" {
		t.Fatalf("export-derived fields wrong: %+v", got)
	}
}

// Counterpart: when --export already carries MD_RESYNC_PCT the
// fallback must NOT consult /proc/mdstat. Verified by providing an
// mdstat with a different percentage and asserting the export value
// wins.
func TestMdraidDetailFromExport_NoFallbackWhenPctPresent(t *testing.T) {
	withMdstat(t, `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      1048512 blocks super 1.2 [2/1] [U_]
      [=====>...............]  recovery = 27.3% (286208/1048512) finish=2.0min speed=8000K/sec

unused devices: <none>
`)
	export := []byte("MD_LEVEL=raid1\n" +
		"MD_ARRAY_STATE=clean\n" +
		"MD_DEGRADED=1\n" +
		"MD_RESYNC_ACTION=recover\n" +
		"MD_RESYNC_PCT=88.5\n")
	got, err := mdraidDetailFromExport("md0", export)
	if err != nil {
		t.Fatal(err)
	}
	if got.SyncProgress == nil || *got.SyncProgress != 88.5 {
		t.Fatalf("SyncProgress = %v want 88.5", got.SyncProgress)
	}
}

// Idle action with no pct: no fallback, no progress field.
func TestMdraidDetailFromExport_IdleActionNoProgress(t *testing.T) {
	withMdstat(t, "")
	export := []byte("MD_LEVEL=raid1\n" +
		"MD_ARRAY_STATE=clean\n" +
		"MD_DEGRADED=0\n" +
		"MD_RESYNC_ACTION=idle\n")
	got, err := mdraidDetailFromExport("md0", export)
	if err != nil {
		t.Fatal(err)
	}
	if got.SyncProgress != nil {
		t.Fatalf("expected nil SyncProgress on idle, got %v", *got.SyncProgress)
	}
}

func withMdstat(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mdstat")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := mdstatPathForTest
	mdstatPathForTest = p
	t.Cleanup(func() { mdstatPathForTest = prev })
}
