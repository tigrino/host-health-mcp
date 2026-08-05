package mail

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
)

// fakeHelper answers one op with a canned response frame, or refuses
// to answer at all. Enough to drive both sides of the queue-depth
// branch without a real helper.
func fakeHelper(t *testing.T, respond func(req proto.Request) proto.Response) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var req proto.Request
				if err := proto.ReadFrame(c, &req); err != nil {
					return
				}
				resp := respond(req)
				_ = proto.WriteFrameWithCap(c, resp, proto.MaxResponseFrame)
			}()
		}
	}()
	return sock
}

// withPostfixPresent points the MTA probe at a fixture so the postfix
// branch runs regardless of what is installed on the test machine.
func withPostfixPresent(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "postfix")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := mtaProbes
	mtaProbes = []struct{ path, name string }{{bin, "postfix"}}
	t.Cleanup(func() { mtaProbes = orig })
}

func handle(t *testing.T, sock string) Data {
	t.Helper()
	tool := New(helperinvoke.NewClient(sock, 4, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, _, err := tool.Handle(ctx, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	d, ok := got.(Data)
	if !ok {
		t.Fatalf("Handle returned %T, want Data", got)
	}
	return d
}

// Positive: a successful measurement is reported as itself.
func TestQueueDepthIsReportedWhenMeasured(t *testing.T) {
	withPostfixPresent(t)
	sock := fakeHelper(t, func(proto.Request) proto.Response {
		return proto.Response{Status: "ok", Data: json.RawMessage(`{"queue_depth":42}`)}
	})

	d := handle(t, sock)

	if d.QueueDepth == nil {
		t.Fatal("queue_depth is null on a successful measurement")
	}
	if *d.QueueDepth != 42 {
		t.Errorf("queue_depth: got %d, want 42", *d.QueueDepth)
	}
}

// A genuinely empty queue must still report 0, not null. Null means
// "not measured"; conflating the two would replace one lie with
// another.
func TestAnEmptyQueueIsReportedAsZeroNotNull(t *testing.T) {
	withPostfixPresent(t)
	sock := fakeHelper(t, func(proto.Request) proto.Response {
		return proto.Response{Status: "ok", Data: json.RawMessage(`{"queue_depth":0}`)}
	})

	d := handle(t, sock)

	if d.QueueDepth == nil {
		t.Fatal("an empty queue must report 0, not null")
	}
	if *d.QueueDepth != 0 {
		t.Errorf("queue_depth: got %d, want 0", *d.QueueDepth)
	}
}

// The finding: when the postqueue op fails, the depth was reported as
// 0 — indistinguishable from an empty queue, and read by exactly the
// alert that is supposed to fire when mail stops flowing.
func TestAFailedMeasurementIsNullNotZero(t *testing.T) {
	withPostfixPresent(t)
	sock := fakeHelper(t, func(proto.Request) proto.Response {
		return proto.Response{Status: "error", Code: proto.CodeToolFailed, Message: "postqueue: exit 1"}
	})

	d := handle(t, sock)

	if d.QueueDepth != nil {
		t.Fatalf("queue_depth is %d after a failed measurement; a measurement "+
			"that failed is not a measurement of zero", *d.QueueDepth)
	}
	if len(d.Errors) == 0 {
		t.Error("a failed measurement must also appear in errors[]")
	}
}

// A helper that cannot be reached at all is the same class of failure.
func TestAnUnreachableHelperLeavesQueueDepthNull(t *testing.T) {
	withPostfixPresent(t)

	d := handle(t, filepath.Join(t.TempDir(), "absent.sock"))

	if d.QueueDepth != nil {
		t.Fatalf("queue_depth is %d with no helper reachable", *d.QueueDepth)
	}
	if len(d.Errors) == 0 {
		t.Error("an unreachable helper must appear in errors[]")
	}
}

// Nothing measures a non-Postfix queue, so reporting 0 for one was a
// fabricated measurement on every exim, sendmail and msmtp host.
func TestAnUnmeasuredMTALeavesQueueDepthNull(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "exim4")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := mtaProbes
	mtaProbes = []struct{ path, name string }{{bin, "exim"}}
	t.Cleanup(func() { mtaProbes = orig })

	d := handle(t, filepath.Join(t.TempDir(), "unused.sock"))

	if d.MTAInUse != "exim" {
		t.Fatalf("mta_in_use: got %q, want exim", d.MTAInUse)
	}
	if d.QueueDepth != nil {
		t.Fatalf("queue_depth is %d for an MTA whose queue is never read", *d.QueueDepth)
	}
}

// A host with no MTA at all has no queue to measure either.
func TestNoMTALeavesQueueDepthNull(t *testing.T) {
	orig := mtaProbes
	mtaProbes = []struct{ path, name string }{{filepath.Join(t.TempDir(), "nothing"), "postfix"}}
	t.Cleanup(func() { mtaProbes = orig })

	d := handle(t, filepath.Join(t.TempDir(), "unused.sock"))

	if d.MTAInUse != "none" {
		t.Fatalf("mta_in_use: got %q, want none", d.MTAInUse)
	}
	if d.QueueDepth != nil {
		t.Fatalf("queue_depth is %d on a host with no MTA", *d.QueueDepth)
	}
}

// schema-draft.yaml keeps queue_depth in MailData.required, so the key
// must be present and explicitly null — not omitted. A client that
// distinguishes the two would otherwise see the field disappear.
func TestQueueDepthSerialisesAsAnExplicitNull(t *testing.T) {
	b, err := json.Marshal(Data{MTAInUse: "none"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	raw, present := m["queue_depth"]
	if !present {
		t.Fatal("queue_depth is omitted; the schema lists it as required")
	}
	if string(raw) != "null" {
		t.Errorf("queue_depth: got %s, want null", raw)
	}
}
