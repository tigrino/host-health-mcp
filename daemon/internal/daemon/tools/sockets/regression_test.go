package sockets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A minimal /proc/net/tcp: header line, then one row. st=0A is LISTEN.
func procNetTCP(rows ...string) string {
	h := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	return h + strings.Join(rows, "")
}

func row(local, st string) string {
	return "   0: " + local + " 00000000:0000 " + st +
		" 00000000:00000000 00:00000000 00000000     0        0 1 1 1 1 1\n"
}

func withSources(t *testing.T, srcs []procNetSource) {
	t.Helper()
	orig := procNetSources
	procNetSources = srcs
	t.Cleanup(func() { procNetSources = orig })
}

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "netfile")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// NEGATIVE: a /proc/net read that fails partway must not make the
// whole address family vanish silently. "No TCP listeners on this
// host" is a materially misleading answer for a security inventory,
// and it is worse than the partial list it replaced.
func TestHandleWarnsWhenAFamilyCannotBeRead(t *testing.T) {
	bad := writeTmp(t, procNetTCP(row("0100007F:0016", "0A"))+
		"   1: "+strings.Repeat("x", 1<<20+1)+"\n")
	withSources(t, []procNetSource{{bad, "tcp", "inet", "0A"}})

	_, warnings, err := (&Tool{}).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	var said bool
	for _, w := range warnings {
		if strings.Contains(w, "incomplete") {
			said = true
		}
	}
	if !said {
		t.Errorf("an unreadable family was dropped silently; warnings = %v", warnings)
	}
}

// POSITIVE: a clean file yields the listener and no warning.
func TestHandleCleanSourceProducesNoWarning(t *testing.T) {
	good := writeTmp(t, procNetTCP(row("0100007F:0016", "0A")))
	withSources(t, []procNetSource{{good, "tcp", "inet", "0A"}})

	out, warnings, err := (&Tool{}).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings on a clean read: %v", warnings)
	}
	if got := len(out.(Data).Listening); got != 1 {
		t.Errorf("listening[] has %d rows, want 1", got)
	}
}

// UDP has no LISTEN state: /proc/net/udp reports 07 (TCP_CLOSE) for a
// bound socket with no peer and 01 for one that has been connect()ed.
// Both are returned. Filtering to 07 dropped genuine UDP servers that
// connect() back to a client — ordinary for TFTP, some DNS forwarders
// and QUIC — so a real listener disappeared from the inventory in the
// name of removing client noise. The label lets the caller decide.
func TestBothBoundAndConnectedUDPSocketsAreReturned(t *testing.T) {
	f := writeTmp(t, procNetTCP(
		row("0100007F:0035", "07"), // bound, no peer
		row("0100007F:9999", "01"), // connect()ed to a peer
	))
	withSources(t, []procNetSource{{f, "udp", "inet", udpUnconnectedState}})

	out, _, err := (&Tool{}).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rows := out.(Data).Listening
	if len(rows) != 2 {
		t.Fatalf("got %d UDP rows, want 2 — neither may be dropped: %+v", len(rows), rows)
	}

	byPort := map[int]ListeningSocket{}
	for _, r := range rows {
		byPort[r.Port] = r
	}
	if r, ok := byPort[0x35]; !ok {
		t.Error("the bound-unconnected socket is missing")
	} else if r.Connected {
		t.Error("a socket in state 07 must be labelled connected=false")
	}
	if r, ok := byPort[0x9999]; !ok {
		t.Error("the connected socket is missing; it was previously filtered out")
	} else if !r.Connected {
		t.Error("a socket in state 01 must be labelled connected=true")
	}
}

// NEGATIVE: TCP keeps its filter. LISTEN already carries the
// distinction there, so a non-LISTEN TCP row is not a listener by any
// reading and must not appear.
func TestTCPIsStillFilteredToListenState(t *testing.T) {
	f := writeTmp(t, procNetTCP(
		row("0100007F:0016", "0A"), // LISTEN
		row("0100007F:8888", "01"), // ESTABLISHED
	))
	withSources(t, []procNetSource{{f, "tcp", "inet", "0A"}})

	out, _, err := (&Tool{}).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rows := out.(Data).Listening
	if len(rows) != 1 {
		t.Fatalf("got %d TCP rows, want 1: %+v", len(rows), rows)
	}
	if rows[0].Port != 0x16 {
		t.Errorf("kept the wrong socket: port %d", rows[0].Port)
	}
	if rows[0].Connected {
		t.Error("TCP rows must always report connected=false")
	}
}
