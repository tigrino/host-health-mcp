package ops

import (
	"strings"
	"testing"
)

// NEGATIVE: dovecot must not return a negative connection count.
//
// connection_count is a required, non-nullable integer with minimum 0
// in the wire schema, inside a strict workload schema. Returning -1 as
// an "unknown" sentinel put a value on the wire a validating client is
// entitled to reject, and it travelled with no warning attached.
func TestParseDoveadmWhoReportsErrorRatherThanNegative(t *testing.T) {
	poisoned := "alice 1 imap (127.0.0.1)\n" + strings.Repeat("x", 1<<20+1) + "\nbob 1 imap (127.0.0.1)\n"
	n, err := parseDoveadmWho([]byte(poisoned))
	if err == nil {
		t.Fatal("a truncated listing was reported as a complete count")
	}
	if n < 0 {
		t.Errorf("count = %d; the schema declares minimum 0 and the field is non-nullable", n)
	}
}

// POSITIVE: a clean listing still counts.
func TestParseDoveadmWhoCountsCleanInput(t *testing.T) {
	n, err := parseDoveadmWho([]byte("alice 1 imap (127.0.0.1)\nbob 2 pop3 (127.0.0.1)\n"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
}

// NEGATIVE: a truncated apt-get output must not be reported as a
// complete update count. An understated pending-update count reads as
// "this host is patched".
func TestCountUpgradesRefusesTruncatedInput(t *testing.T) {
	poisoned := "Inst pkg1 [1] (2 Debian:13/stable [amd64])\n" +
		strings.Repeat("x", 1<<20+1) + "\n" +
		"Inst pkg2 [1] (2 Debian:13/stable-security [amd64])\n"
	if _, _, err := countUpgrades([]byte(poisoned)); err == nil {
		t.Error("a truncated apt-get -s upgrade was reported as a complete count")
	}
}

// POSITIVE: clean apt output counts security and regular separately.
func TestCountUpgradesCleanInput(t *testing.T) {
	in := "Inst pkg1 [1] (2 Debian:13/stable [amd64])\n" +
		"Inst pkg2 [1] (2 Debian:13/stable-security [amd64])\n"
	sec, reg, err := countUpgrades([]byte(in))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if sec != 1 || reg != 1 {
		t.Errorf("sec=%d reg=%d, want 1/1", sec, reg)
	}
}

// NEGATIVE: a truncated zpool status for one pool must not discard the
// pools already parsed. Emitting zfs_pools: [] is indistinguishable
// from "this host has no ZFS", which is certainly wrong on a host that
// just listed pools.
func TestParseZpoolStatusReportsTruncationPerPool(t *testing.T) {
	poisoned := "  pool: tank\n state: ONLINE\n" + strings.Repeat("x", 1<<20+1) + "\n"
	if _, err := parseZpoolStatus("tank", []byte(poisoned)); err == nil {
		t.Error("a truncated zpool status was parsed as complete")
	}
	// And a clean one still parses, so the loop can skip only the bad pool.
	p, err := parseZpoolStatus("tank", []byte("  pool: tank\n state: ONLINE\n  scan: none requested\nerrors: No known data errors\n"))
	if err != nil {
		t.Fatalf("clean pool: %v", err)
	}
	if p.Name != "tank" || p.State != "ONLINE" {
		t.Errorf("parsed %+v", p)
	}
}
