package exec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"host-health-mcp/daemon/internal/helper/dispatch"
	"host-health-mcp/daemon/internal/shared/proto"
)

// TestRun_TruncationMaskedBySignal regression-tests the case the
// ssh_journal_counts op hit on long-uptime public-target hosts:
// stdout exceeds MaxStdout, cappedWriter returns *truncatedError, the
// os/exec copy goroutine closes the pipe, the subprocess gets
// SIGPIPE on its next write, cmd.Wait() returns *exec.ExitError
// (signal: pipe) — and the *exec.ExitError masks the *truncatedError
// inside Run's err. Without the sticky `truncated` flag on
// cappedWriter, classify() would fall through to the generic
// tool_failed branch and report exit=-1 instead of output_truncated.
//
// Uses `yes` from coreutils because it produces unbounded output
// deterministically. The safeEnv PATH already includes /usr/bin.
func TestRun_TruncationMaskedBySignal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := Run(ctx, "yes")
	if err == nil {
		t.Fatal("expected error from runaway-output subprocess, got nil")
	}
	var de *dispatch.Error
	if !errors.As(err, &de) {
		t.Fatalf("expected *dispatch.Error, got %T: %v", err, err)
	}
	if de.Code != proto.CodeOutputTruncated {
		t.Errorf("expected code %q, got %q (message: %q, exit: %v)",
			proto.CodeOutputTruncated, de.Code, de.Message, de.ToolExit)
	}
	// Cap is enforced — captured stdout should be at or just under
	// MaxStdout, not the multi-megabyte output `yes` would otherwise
	// produce.
	if len(out) > MaxStdout {
		t.Errorf("captured stdout %d bytes exceeds cap %d", len(out), MaxStdout)
	}
	if len(out) < 1024 {
		t.Errorf("captured stdout suspiciously short (%d bytes); cappedWriter may have skipped buffering", len(out))
	}
}

// TestRun_NormalSuccess sanity-checks the happy path.
func TestRun_NormalSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := Run(ctx, "echo", "hello")
	if err != nil {
		t.Fatalf("Run(echo): %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("Run(echo) output = %q want %q", string(out), "hello")
	}
}

// TestRunStreaming_NoBufferCap drives a subprocess that produces
// well over MaxStdout bytes of output and asserts RunStreaming
// counts every matching line without tripping the truncation cap.
// Regression for the observed case where ssh.service journal output ran
// 451 KiB even after the journalctl --grep pre-filter — Run's
// 256 KiB cap would have classified that as output_truncated.
func TestRunStreaming_NoBufferCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// `seq 1 200000` produces ~1.16 MiB of output (each line is
	// "<n>\n", 4-7 bytes for the values 1..200000). Far beyond the
	// 256 KiB Run cap. Visitor counts all lines starting with '1'.
	visited := 0
	matched := 0
	_, err := RunStreaming(ctx, func(line []byte) {
		visited++
		if len(line) > 0 && line[0] == '1' {
			matched++
		}
	}, "seq", "1", "200000")
	if err != nil {
		t.Fatalf("RunStreaming(seq): %v", err)
	}
	if visited != 200000 {
		t.Errorf("visited = %d, want 200000", visited)
	}
	// Numbers 1, 10..19, 100..199, 1000..1999, 10000..19999,
	// 100000..199999 start with '1'. Just check we got a sane
	// nonzero count rather than enumerate; the point is that the
	// visitor saw lines.
	if matched < 100000 {
		t.Errorf("matched = %d, want >=100000", matched)
	}
}

// TestRunStreaming_ToolMissing verifies CodeToolMissing on a
// non-existent binary.
func TestRunStreaming_ToolMissing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := RunStreaming(ctx, func([]byte) {}, "this-binary-deliberately-does-not-exist-host-health-mcp")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var de *dispatch.Error
	if !errors.As(err, &de) {
		t.Fatalf("expected *dispatch.Error, got %T: %v", err, err)
	}
	if de.Code != proto.CodeToolMissing {
		t.Errorf("expected code %q, got %q", proto.CodeToolMissing, de.Code)
	}
}

// TestRun_ToolMissing verifies the CodeToolMissing classification
// when the binary doesn't exist on PATH.
func TestRun_ToolMissing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := Run(ctx, "this-binary-deliberately-does-not-exist-host-health-mcp")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var de *dispatch.Error
	if !errors.As(err, &de) {
		t.Fatalf("expected *dispatch.Error, got %T: %v", err, err)
	}
	if de.Code != proto.CodeToolMissing {
		t.Errorf("expected code %q, got %q", proto.CodeToolMissing, de.Code)
	}
}
