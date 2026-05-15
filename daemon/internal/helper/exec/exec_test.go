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
