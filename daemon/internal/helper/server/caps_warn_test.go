package server

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"

	"host-health-mcp/daemon/internal/helper/caps"
	"host-health-mcp/daemon/internal/helper/dispatch"
	"host-health-mcp/daemon/internal/helper/ops"
	"host-health-mcp/daemon/internal/shared/proto"
)

// capOp is an op that declares a required capability, so the warning
// path is reachable. Picked from the table rather than hardcoded, so
// this stops compiling loudly if the entry is ever dropped.
const capOp = "zpool_status"

// statusWith renders a /proc/self/status fragment whose CapEff mask has
// exactly the given bits set. Bit 21 is CAP_SYS_ADMIN.
func statusWith(bits ...uint) string {
	var m uint64
	for _, b := range bits {
		m |= 1 << b
	}
	return "Name:\thelper\nCapEff:\t" + strings.TrimSpace(hex16(m)) + "\n"
}

func hex16(m uint64) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 16)
	for i := 15; i >= 0; i-- {
		out[i] = digits[m&0xf]
		m >>= 4
	}
	return string(out)
}

func capServer(t *testing.T, status string) (*Server, *bytes.Buffer) {
	t.Helper()
	if _, ok := ops.RequiredCap[capOp]; !ok {
		t.Fatalf("%s no longer declares a required capability", capOp)
	}
	reg := dispatch.New()
	reg.Register(capOp, func(context.Context, string) (any, error) { return struct{}{}, nil })
	s := New(Config{Registry: reg, OpDeadline: func(string, int) time.Duration { return time.Second }})
	s.caps = caps.ParseStatus(strings.NewReader(status))

	var buf bytes.Buffer
	old := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(old); log.SetFlags(flags) })
	return s, &buf
}

// Positive: the capability is absent, so the op's silent degradation is
// announced. This is the whole point of the mechanism — zpool_status
// without CAP_SYS_ADMIN returns an empty pool list, which reads exactly
// like a host with no pools.
func TestDispatchWarnsWhenARequiredCapabilityIsAbsent(t *testing.T) {
	s, logged := capServer(t, statusWith()) // no bits at all

	s.dispatch(context.Background(), &proto.Request{Op: capOp})

	got := logged.String()
	if !strings.Contains(got, capOp) || !strings.Contains(got, ops.RequiredCap[capOp]) {
		t.Fatalf("expected a warning naming %s and %s, got %q",
			capOp, ops.RequiredCap[capOp], got)
	}
}

// Negative: the capability is present, so there is nothing to say. A
// warning here would fire on every correctly-installed host and train
// operators to ignore the line.
func TestDispatchIsSilentWhenTheCapabilityIsHeld(t *testing.T) {
	s, logged := capServer(t, statusWith(21)) // CAP_SYS_ADMIN

	s.dispatch(context.Background(), &proto.Request{Op: capOp})

	if got := logged.String(); got != "" {
		t.Fatalf("expected silence when the capability is held, got %q", got)
	}
}

// Negative: an unreadable or unparseable status must not be reported as
// "capability missing". The diagnostic fails open; a false warning on
// every host is worse than no warning.
func TestDispatchIsSilentWhenTheCapabilitySetIsUnknown(t *testing.T) {
	s, logged := capServer(t, "Name:\thelper\nCapEff:\tnot-a-mask\n")

	s.dispatch(context.Background(), &proto.Request{Op: capOp})

	if got := logged.String(); got != "" {
		t.Fatalf("expected silence on an unreadable capability set, got %q", got)
	}
}

// The op sits on a polling path: the daemon calls it on every storage
// probe. One line per op for the life of the process, not one per poll.
func TestTheMissingCapabilityWarningIsLoggedOnce(t *testing.T) {
	s, logged := capServer(t, statusWith())

	for i := 0; i < 5; i++ {
		s.dispatch(context.Background(), &proto.Request{Op: capOp})
	}

	if n := strings.Count(logged.String(), capOp); n != 1 {
		t.Fatalf("expected exactly one warning across 5 dispatches, got %d:\n%s",
			n, logged.String())
	}
}

// The warning is diagnostic. It must not change what the op returns —
// an operator debugging a capability problem should still get whatever
// answer the op would otherwise have produced.
func TestTheWarningDoesNotAlterTheResponse(t *testing.T) {
	s, _ := capServer(t, statusWith())

	resp := s.dispatch(context.Background(), &proto.Request{Op: capOp})

	if resp == nil || resp.Status != "ok" {
		t.Fatalf("warning path must not turn a working op into a failure: %+v", resp)
	}
}
