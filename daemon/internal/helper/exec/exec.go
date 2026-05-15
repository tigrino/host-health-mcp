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
	"sync"
	"syscall"
	"time"

	"host-health-mcp/daemon/internal/helper/dispatch"
	"host-health-mcp/daemon/internal/shared/proto"
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
	stdoutWriter := &cappedWriter{buf: &stdout, max: MaxStdout}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = &stderr

	// killTimer is captured at cancel time so the post-Wait code can
	// Stop it. Without this, a child that exits within KillGrace
	// after a SIGTERM would still have a pending timer firing
	// `cmd.Process.Kill()` against a reaped pid - safe on modern
	// kernels via pidfd, but the dependency on that invariant is
	// best avoided.
	var (
		timerMu   sync.Mutex
		killTimer *time.Timer
	)
	cmd.Cancel = func() error {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		timerMu.Lock()
		killTimer = time.AfterFunc(KillGrace, func() {
			_ = cmd.Process.Kill()
		})
		timerMu.Unlock()
		return nil
	}

	err := cmd.Run()

	timerMu.Lock()
	if killTimer != nil {
		killTimer.Stop()
	}
	timerMu.Unlock()

	// If the stdout writer truncated, surface that as the proximate
	// cause regardless of what cmd.Run reported. The chain is:
	// cappedWriter returns *truncatedError -> os/exec stops copying ->
	// process gets SIGPIPE on its next write OR our Cancel SIGTERMs
	// it -> cmd.Wait reports *exec.ExitError (signal: pipe / signal:
	// terminated). That ExitError masks the original truncatedError
	// at classify-time, so the helper would report a generic
	// tool_failed with exit=-1 instead of output_truncated. The
	// sticky flag on the writer is the only reliable signal.
	if stdoutWriter.truncated {
		err = &truncatedError{Max: stdoutWriter.max}
	}

	if err != nil {
		// Return the captured stdout along with the classified
		// error. Most callers ignore stdout when err != nil, but
		// some tools (smartctl with bit-encoded exit codes,
		// btrfs-progs returning non-zero with valid output) need to
		// inspect the body to distinguish status-bit-only from
		// fatal exits.
		return stdout.Bytes(), classify(err, &stdout, &stderr, cmd)
	}
	return stdout.Bytes(), nil
}

func classify(runErr error, stdout, stderr *bytes.Buffer, cmd *exec.Cmd) error {
	stderrBytes := stderr.Len()
	sum := sha256.Sum256(stderr.Bytes())
	stderrHex := hex.EncodeToString(sum[:])
	stderrPref := sanitiseStderrPrefix(stderr.Bytes())
	// Clone argv so the dispatch.Error is independent of the cmd
	// lifetime. cmd.Args is [name, ...args].
	argv := make([]string, len(cmd.Args))
	copy(argv, cmd.Args)

	// Deadline / killed by context.
	if errors.Is(runErr, context.DeadlineExceeded) {
		return &dispatch.Error{
			Code:         proto.CodeDeadline,
			Message:      "deadline exceeded",
			StderrBytes:  stderrBytes,
			StderrSHA256: stderrHex,
			StderrPrefix: stderrPref,
			Argv:         argv,
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
			StderrPrefix: stderrPref,
			Argv:         argv,
		}
	}

	// Tool not found.
	if errors.Is(runErr, exec.ErrNotFound) {
		return &dispatch.Error{
			Code:    proto.CodeToolMissing,
			Message: cmd.Path + ": not found",
			Argv:    argv,
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
		StderrPrefix: stderrPref,
		ToolExit:     &exit,
		Argv:         argv,
	}
}

// sanitiseStderrPrefix copies up to stderrPrefixMax bytes from b,
// replacing every non-printable byte (outside the ASCII printable
// range with tab/newline preserved) with '.'. The result is safe to
// include in JSON error envelopes that the daemon-side audit log
// and the MCP client both consume. Operator-controlled stderr from
// canonical tools rarely contains addresses or hostnames; the
// redactor's allowlist is not consulted here because the helper
// does not know the operator's network config.
func sanitiseStderrPrefix(b []byte) string {
	if len(b) > stderrPrefixMax {
		b = b[:stderrPrefixMax]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		switch {
		case c == '\n', c == '\t', c == ' ':
			out[i] = c
		case c >= 0x20 && c < 0x7f:
			out[i] = c
		default:
			out[i] = '.'
		}
	}
	return string(out)
}

// stderrPrefixMax bounds the per-call stderr prefix that crosses the
// helper socket. 200 bytes is enough to carry one line of a real
// error message ("Permission denied", "Invalid argument", a smartctl
// status line, etc.) without bloating the envelope.
const stderrPrefixMax = 200

// truncatedError is returned by cappedWriter when the configured cap
// would be exceeded. Surfaced to the caller as CodeOutputTruncated.
type truncatedError struct{ Max int }

func (e *truncatedError) Error() string {
	return fmt.Sprintf("output exceeded %d bytes", e.Max)
}

type cappedWriter struct {
	buf *bytes.Buffer
	max int
	// truncated is sticky once the cap is hit. The os/exec copy
	// goroutine stops on the first Write error, but the process may
	// already be dying from SIGPIPE/SIGTERM and cmd.Wait()'s
	// *exec.ExitError will mask our *truncatedError. The post-Wait
	// path in Run reads this flag to surface truncation as the
	// proximate cause.
	truncated bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		room := w.max - w.buf.Len()
		if room > 0 {
			_, _ = w.buf.Write(p[:room])
		}
		w.truncated = true
		return 0, &truncatedError{Max: w.max}
	}
	return w.buf.Write(p)
}

// ensure io.Writer interface used elsewhere if needed.
var _ io.Writer = (*cappedWriter)(nil)
