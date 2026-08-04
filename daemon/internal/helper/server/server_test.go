package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"host-health-mcp/daemon/internal/helper/dispatch"
	"host-health-mcp/daemon/internal/shared/proto"
)

// op is any token from proto.AllOps; dispatch rejects unknown ones
// before it ever reaches the deadline logic.
const op = "read_reboot_marker"

func newServer(t *testing.T, h dispatch.Handler, opDeadline func(string, int) time.Duration) *Server {
	t.Helper()
	reg := dispatch.New()
	reg.Register(op, h)
	return New(Config{Registry: reg, OpDeadline: opDeadline})
}

// A-1: the context reaching a handler must carry a deadline. Before
// this, dispatch passed the process-lifetime context straight through,
// so exec.CommandContext's cancel path — and the whole
// SIGTERM/KillGrace/SIGKILL chain behind it — could never fire. A
// smartctl blocked on a failing device leaked a subprocess and a
// goroutine per poll.
func TestDispatchAppliesADeadline(t *testing.T) {
	var seen bool
	var remaining time.Duration
	s := newServer(t, func(ctx context.Context, _ string) (any, error) {
		dl, ok := ctx.Deadline()
		seen = ok
		if ok {
			remaining = time.Until(dl)
		}
		return struct{}{}, nil
	}, func(string, int) time.Duration { return 2 * time.Second })

	resp := s.dispatch(context.Background(), &proto.Request{Op: op})
	if resp.Status != proto.StatusOK {
		t.Fatalf("status = %q (%s)", resp.Status, resp.Message)
	}
	if !seen {
		t.Fatal("handler context carried no deadline")
	}
	if remaining <= 0 || remaining > 2*time.Second {
		t.Errorf("remaining budget %v, want (0, 2s]", remaining)
	}
}

// The parent context is the process lifetime and carries no deadline
// of its own. A nil OpDeadline must therefore still bound the handler,
// not fall through to "no deadline".
func TestDispatchWithoutConfiguredDeadlineStillBounds(t *testing.T) {
	var seen bool
	var remaining time.Duration
	s := newServer(t, func(ctx context.Context, _ string) (any, error) {
		dl, ok := ctx.Deadline()
		seen = ok
		if ok {
			remaining = time.Until(dl)
		}
		return struct{}{}, nil
	}, nil)

	s.dispatch(context.Background(), &proto.Request{Op: op})
	if !seen {
		t.Fatal("nil OpDeadline left the handler context unbounded")
	}
	// A deadline far enough out is indistinguishable from none: the
	// subprocess still outlives the request that started it. Assert
	// the actual budget, not merely that one exists.
	if remaining <= 0 || remaining > fallbackOpDeadline {
		t.Errorf("remaining budget %v, want (0, %v]", remaining, fallbackOpDeadline)
	}
}

// The resolver is consulted with the op and the caller's budget from
// the request frame, so per-op helper.yml overrides actually apply.
func TestDispatchPassesOpAndCallerBudgetToTheResolver(t *testing.T) {
	var gotOp string
	var gotMS int
	s := newServer(t, func(context.Context, string) (any, error) {
		return struct{}{}, nil
	}, func(o string, ms int) time.Duration {
		gotOp, gotMS = o, ms
		return time.Second
	})

	s.dispatch(context.Background(), &proto.Request{Op: op, DeadlineMS: 1234})
	if gotOp != op {
		t.Errorf("op = %q, want %q", gotOp, op)
	}
	if gotMS != 1234 {
		t.Errorf("callerMS = %d, want 1234", gotMS)
	}
}

// A handler that blocks past its deadline must be reported as
// CodeDeadline, which was dead code on the helper side before A-1.
func TestDispatchReportsDeadlineExceeded(t *testing.T) {
	s := newServer(t, func(ctx context.Context, _ string) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, func(string, int) time.Duration { return 20 * time.Millisecond })

	resp := s.dispatch(context.Background(), &proto.Request{Op: op})
	if resp.Status != proto.StatusErr {
		t.Fatalf("status = %q, want %q", resp.Status, proto.StatusErr)
	}
	if resp.Code != proto.CodeDeadline {
		t.Errorf("code = %q, want %q", resp.Code, proto.CodeDeadline)
	}
}

// A typed dispatch.Error keeps its own code and its stderr summary; the
// deadline branch must not swallow the richer error.
func TestDispatchPreservesTypedErrors(t *testing.T) {
	s := newServer(t, func(context.Context, string) (any, error) {
		return nil, &dispatch.Error{
			Code:        proto.CodeToolMissing,
			Message:     "smartctl: not found",
			StderrBytes: 7,
		}
	}, func(string, int) time.Duration { return time.Second })

	resp := s.dispatch(context.Background(), &proto.Request{Op: op})
	if resp.Code != proto.CodeToolMissing {
		t.Errorf("code = %q, want %q", resp.Code, proto.CodeToolMissing)
	}
	if resp.StderrBytes != 7 {
		t.Errorf("stderr_bytes = %d, want 7", resp.StderrBytes)
	}
}

func TestDispatchRejectsUnknownOp(t *testing.T) {
	s := newServer(t, func(context.Context, string) (any, error) {
		t.Fatal("handler must not run for an unknown op")
		return nil, nil
	}, nil)

	resp := s.dispatch(context.Background(), &proto.Request{Op: "no_such_op"})
	if resp.Code != proto.CodeBadOp {
		t.Errorf("code = %q, want %q", resp.Code, proto.CodeBadOp)
	}
}

// The daemon and helper ship in one package, but the field is still
// optional on the wire: an absent deadline_ms must decode as 0 and
// select the helper's configured deadline.
func TestRequestDeadlineIsOptionalOnTheWire(t *testing.T) {
	var req proto.Request
	if err := json.Unmarshal([]byte(`{"op":"read_reboot_marker"}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.DeadlineMS != 0 {
		t.Errorf("DeadlineMS = %d, want 0", req.DeadlineMS)
	}

	b, err := json.Marshal(proto.Request{Op: op})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"op":"read_reboot_marker"}` {
		t.Errorf("marshalled %s, want deadline_ms omitted when zero", b)
	}
}
