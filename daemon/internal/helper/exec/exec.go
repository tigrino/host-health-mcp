// Package exec is the SOLE site for os/exec inside the helper. Every
// underlying tool invocation routes through Run. The custom forbidden-
// call linter exempts this package only (design §7.4).
//
// Run sanitises the environment to {PATH, LANG, LC_ALL}, applies a
// per-call deadline, bounds captured stdout, and returns a fingerprint
// of stderr rather than the bytes themselves so that raw subprocess
// stderr never crosses to the daemon's audit log (design §7.2).
package exec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"syscall"
	"time"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// MaxStdout is the per-call cap on captured stdout. Tools whose
// output exceeds this fail with CodeOutputTruncated; the daemon
// surfaces this to the caller without forwarding any of the truncated
// content. 256 KiB is more than ample for the parsed forms in the
// design surface and bounds memory pressure under attacker-induced
// log floods.
const MaxStdout = 256 * 1024

// KillGrace is the time between SIGTERM and SIGKILL when a deadline
// fires. The daemon's per-tool timeout is set to (helper deadline +
// 500 ms) so the helper has time to escalate without the outer
// timeout tripping (design §7.2).
const KillGrace = 500 * time.Millisecond

// safeEnv is the only environment passed to subprocesses. LD_*, GOROOT,
// PYTHONPATH, and similar are deliberately absent.
var safeEnv = []string{
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	"LANG=C",
	"LC_ALL=C",
}

// Run invokes name with args and waits for completion under ctx. On
// success it returns the captured stdout (bounded by MaxStdout). On
// failure it returns a *dispatch.Error with a code from
// proto/codes.go.
func Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = safeEnv

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &cappedWriter{buf: &stdout, max: MaxStdout}
	cmd.Stderr = &stderr

	cmd.Cancel = func() error {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		time.AfterFunc(KillGrace, func() {
			_ = cmd.Process.Kill()
		})
		return nil
	}

	err := cmd.Run()
	if err != nil {
		return nil, classify(err, &stdout, &stderr, cmd)
	}
	return stdout.Bytes(), nil
}

func classify(runErr error, stdout, stderr *bytes.Buffer, cmd *exec.Cmd) error {
	stderrBytes := stderr.Len()
	sum := sha256.Sum256(stderr.Bytes())
	stderrHex := hex.EncodeToString(sum[:])

	// Deadline / killed by context.
	if errors.Is(runErr, context.DeadlineExceeded) {
		return &dispatch.Error{
			Code:         proto.CodeDeadline,
			Message:      "deadline exceeded",
			StderrBytes:  stderrBytes,
			StderrSHA256: stderrHex,
		}
	}

	// Truncated.
	var truncErr *truncatedError
	if errors.As(runErr, &truncErr) {
		return &dispatch.Error{
			Code:         proto.CodeOutputTruncated,
			Message:      fmt.Sprintf("stdout exceeded %d bytes", MaxStdout),
			StderrBytes:  stderrBytes,
			StderrSHA256: stderrHex,
		}
	}

	// Tool not found.
	if errors.Is(runErr, exec.ErrNotFound) {
		return &dispatch.Error{
			Code:    proto.CodeToolMissing,
			Message: cmd.Path + ": not found",
		}
	}

	// Generic tool failure.
	var ee *exec.ExitError
	exit := -1
	if errors.As(runErr, &ee) {
		exit = ee.ExitCode()
	}
	return &dispatch.Error{
		Code:         proto.CodeToolFailed,
		Message:      cmd.Path + " exited non-zero",
		StderrBytes:  stderrBytes,
		StderrSHA256: stderrHex,
		ToolExit:     &exit,
	}
}

// truncatedError is returned by cappedWriter when the configured cap
// would be exceeded. Surfaced to the caller as CodeOutputTruncated.
type truncatedError struct{ Max int }

func (e *truncatedError) Error() string {
	return fmt.Sprintf("output exceeded %d bytes", e.Max)
}

type cappedWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		room := w.max - w.buf.Len()
		if room > 0 {
			_, _ = w.buf.Write(p[:room])
		}
		return 0, &truncatedError{Max: w.max}
	}
	return w.buf.Write(p)
}

// ensure io.Writer interface used elsewhere if needed.
var _ io.Writer = (*cappedWriter)(nil)
