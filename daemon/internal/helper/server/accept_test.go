package server

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// A-2: the accept loop returned a fatal error on any non-ErrClosed
// accept failure, reaching log.Fatalf in main. EMFILE is reachable
// from a burst of daemon connections — a self-inflicted, transient
// condition — so the privileged half of the system exited on something
// that clears by itself.
func TestTemporaryAcceptErrorsAreRetryable(t *testing.T) {
	retryable := []error{
		syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
	}
	for _, err := range retryable {
		if !isTemporaryAcceptErr(err) {
			t.Errorf("%v should be retried, not fatal", err)
		}
		// Must survive wrapping, which is how net returns them.
		if !isTemporaryAcceptErr(&testWrap{err}) {
			t.Errorf("wrapped %v should be retried", err)
		}
	}

	// EINTR and ECONNABORTED are absent on purpose: internal/poll's
	// accept loop retries both before returning, so treating them here
	// would be handling for paths that cannot occur.
	fatal := []error{
		syscall.EINVAL, syscall.EBADF, syscall.ENOTSOCK,
		syscall.EINTR, syscall.ECONNABORTED, errors.New("other"),
	}
	for _, err := range fatal {
		if isTemporaryAcceptErr(err) {
			t.Errorf("%v is not transient and must not be retried in a loop", err)
		}
	}
}

type testWrap struct{ err error }

func (w *testWrap) Error() string { return "wrapped: " + w.err.Error() }
func (w *testWrap) Unwrap() error { return w.err }

// Backoff must start small, grow, and stop growing — an unbounded
// doubling would stall the helper for minutes after a transient blip.
func TestNextBackoff(t *testing.T) {
	if got := nextBackoff(0); got != acceptBackoffMin {
		t.Errorf("first backoff = %v, want %v", got, acceptBackoffMin)
	}
	d := nextBackoff(0)
	for i := 0; i < 20; i++ {
		prev := d
		d = nextBackoff(d)
		if d < prev {
			t.Fatalf("backoff shrank: %v -> %v", prev, d)
		}
		if d > acceptBackoffMax {
			t.Fatalf("backoff %v exceeded the %v ceiling", d, acceptBackoffMax)
		}
	}
	if d != acceptBackoffMax {
		t.Errorf("backoff settled at %v, want the %v ceiling", d, acceptBackoffMax)
	}
}

// The semaphore is the in-process half of A-2. The daemon caps its own
// helper fan-out at 8, but a privilege boundary must not depend on the
// unprivileged side's self-restraint.
func TestConnectionSemaphoreIsBounded(t *testing.T) {
	s := New(Config{})
	if cap(s.sem) != maxConns {
		t.Fatalf("sem capacity = %d, want maxConns = %d", cap(s.sem), maxConns)
	}
	for i := 0; i < maxConns; i++ {
		select {
		case s.sem <- struct{}{}:
		default:
			t.Fatalf("semaphore refused slot %d of %d", i+1, maxConns)
		}
	}
	// The next one must be refused, which is what makes the accept loop
	// close the connection rather than queue it.
	select {
	case s.sem <- struct{}{}:
		t.Error("semaphore admitted more than maxConns")
	default:
	}
}

// maxConns and the unit's MemoryMax= are derived from each other, so
// the relation has to be asserted rather than assumed. An earlier
// revision paired 32 connections with MemoryMax=512M — off by a factor
// of three, which would have OOM-killed the ROOT helper on any host
// with the large nftables sets firewall_inspect is sized for.
//
// This test reads the shipped unit file, so it fails if either number
// moves without the other.
func TestMaxConnsAgreesWithTheUnitMemoryCeiling(t *testing.T) {
	unit := readHelperUnit(t)

	memMaxMiB := parseUnitBytesMiB(t, unit, "MemoryMax")
	// Worst case per connection: firewallRulesetCap 32 MiB of captured
	// stdout plus firewallSetListCap 16 MiB per set fetch.
	const worstCasePerConnMiB = 48

	if got := maxConns * worstCasePerConnMiB; got > memMaxMiB {
		t.Errorf("maxConns=%d admits %d MiB of captured bytes against MemoryMax=%d MiB; "+
			"the root helper would be OOM-killed under a legitimate workload",
			maxConns, got, memMaxMiB)
	}
	// MemoryHigh must throttle before MemoryMax kills.
	if high := parseUnitBytesMiB(t, unit, "MemoryHigh"); high >= memMaxMiB {
		t.Errorf("MemoryHigh=%d MiB does not sit below MemoryMax=%d MiB", high, memMaxMiB)
	}
	// The cap exists for a compromised daemon, so it must not bind on a
	// well-behaved one: the daemon's own helper fan-out cap is 8.
	if maxConns < 8 {
		t.Errorf("maxConns = %d is below the daemon's own fan-out cap of 8", maxConns)
	}
}

func readHelperUnit(t *testing.T) string {
	t.Helper()
	// internal/helper/server -> repo root is four levels up, then build/.
	path := filepath.Join("..", "..", "..", "..", "build", "systemd",
		"host-health-mcp-helper.service")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read helper unit: %v", err)
	}
	return string(b)
}

// parseUnitBytesMiB pulls a systemd byte-suffixed directive out of a
// unit file and returns it in MiB.
func parseUnitBytesMiB(t *testing.T, unit, key string) int {
	t.Helper()
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, key+"=")
		if !ok {
			continue
		}
		mult := 1
		switch {
		case strings.HasSuffix(rest, "G"):
			mult, rest = 1024, strings.TrimSuffix(rest, "G")
		case strings.HasSuffix(rest, "M"):
			mult, rest = 1, strings.TrimSuffix(rest, "M")
		default:
			t.Fatalf("%s=%s: expected an M or G suffix", key, rest)
		}
		n, err := strconv.Atoi(rest)
		if err != nil {
			t.Fatalf("%s=%s: %v", key, rest, err)
		}
		return n * mult
	}
	t.Fatalf("%s= not found in the helper unit", key)
	return 0
}
