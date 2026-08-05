package caps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withStatus(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := statusPath
	statusPath = p
	t.Cleanup(func() { statusPath = orig })
}

// POSITIVE: a set carrying CAP_SYS_ADMIN reports it, and reports the
// absence of one it does not carry.
func TestEffectiveParsesCapEff(t *testing.T) {
	// bit 21 (CAP_SYS_ADMIN) | bit 2 (CAP_DAC_READ_SEARCH)
	withStatus(t, "Name:\thelper\nCapEff:\t0000000000200004\nThreads:\t1\n")
	s := Effective()
	if !s.Has("CAP_SYS_ADMIN") {
		t.Error("CAP_SYS_ADMIN present in the mask but not reported")
	}
	if !s.Has("CAP_DAC_READ_SEARCH") {
		t.Error("CAP_DAC_READ_SEARCH present in the mask but not reported")
	}
	if s.Has("CAP_SYS_RAWIO") {
		t.Error("CAP_SYS_RAWIO absent from the mask but reported present")
	}
}

// NEGATIVE: this is the case the whole package exists for. A helper
// on a ZFS host whose manifest never declared the backend runs without
// CAP_SYS_ADMIN, and zpool_status silently reports nothing.
func TestMissingSysAdminIsDetected(t *testing.T) {
	// bit 2 only: DAC_READ_SEARCH, the default storage grant.
	withStatus(t, "CapEff:\t0000000000000004\n")
	if Effective().Has("CAP_SYS_ADMIN") {
		t.Fatal("a helper without CAP_SYS_ADMIN reported having it; the " +
			"degradation would stay silent")
	}
}

// FAIL OPEN: an unreadable or malformed status must NOT report
// capabilities as missing. A fleet-wide false warning is worse than no
// warning — it trains the reader to ignore the channel.
func TestUnreadableStatusFailsOpen(t *testing.T) {
	orig := statusPath
	statusPath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { statusPath = orig })
	s := Effective()
	for _, c := range []string{"CAP_SYS_ADMIN", "CAP_SYS_RAWIO", "CAP_NET_ADMIN"} {
		if !s.Has(c) {
			t.Errorf("%s reported missing from an unreadable status; that is a "+
				"false warning on every host", c)
		}
	}
	if got := s.String(); got != "<unreadable>" {
		t.Errorf("String() = %q, want <unreadable>", got)
	}
}

func TestMalformedCapEffFailsOpen(t *testing.T) {
	withStatus(t, "CapEff:\tnot-hex\n")
	if !Effective().Has("CAP_SYS_ADMIN") {
		t.Error("a malformed CapEff produced a false 'missing' report")
	}
}

// An unknown capability name must not produce a warning either.
func TestUnknownNameFailsOpen(t *testing.T) {
	withStatus(t, "CapEff:\t0000000000000000\n")
	if !Effective().Has("CAP_NOT_A_REAL_CAPABILITY") {
		t.Error("an unknown name reported as missing")
	}
	if Known("CAP_NOT_A_REAL_CAPABILITY") {
		t.Error("Known() accepted a name not in the table")
	}
	if !Known("CAP_SYS_ADMIN") {
		t.Error("Known() rejected a name that is in the table")
	}
}

// The startup line must name what it has, and must not silently omit a
// capability outside the lookup table.
func TestStringNamesEverySetBit(t *testing.T) {
	withStatus(t, "CapEff:\t0000000000200004\n")
	got := Effective().String()
	for _, want := range []string{"CAP_SYS_ADMIN", "CAP_DAC_READ_SEARCH"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %s", got, want)
		}
	}
	// bit 5 is CAP_KILL, deliberately not in the table.
	withStatus(t, "CapEff:\t0000000000000020\n")
	if got := Effective().String(); !strings.Contains(got, "cap_5") {
		t.Errorf("String() = %q; a capability outside the table must still appear", got)
	}
	withStatus(t, "CapEff:\t0000000000000000\n")
	if got := Effective().String(); got != "<none>" {
		t.Errorf("String() = %q, want <none>", got)
	}
}
