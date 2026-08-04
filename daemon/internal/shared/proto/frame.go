// Package proto defines the wire types used between the daemon and helper
// processes over the unix socket described in design-overview.md §7.1.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxRequestFrame is the cap on a daemon->helper request frame. See
// design §7.1: 16 KiB is more than ample for op + param and bounds the
// cost of a daemon-side RCE attempting to OOM the helper.
const MaxRequestFrame = 16 * 1024

// MaxResponseFrame is the cap on a helper->daemon response frame.
// Sized to accommodate tools whose typed result contains caller-
// tunable per-element lists — most prominently host_firewall, which
// can return inline ban-set elements for sets containing tens of
// thousands of entries on busy public-target hosts. 4 MiB at
// ~100 bytes per element gives headroom for ~40k inline elements
// without forcing artificial pagination at this layer. The helper's
// per-op handler is still responsible for its own per-set / per-
// response budgeting (see ops.firewallElemBudget). Bumped from
// 256 KiB in schema 0.5.0.
const MaxResponseFrame = 4 * 1024 * 1024

// MaxFrameSize is retained as an alias for MaxRequestFrame to avoid
// a major bump of code that read the old constant; new code should
// use the request/response-specific constants.
const MaxFrameSize = MaxRequestFrame

var (
	// ErrFrameTooLarge is returned when a frame's declared length
	// exceeds the relevant cap. Callers should close the connection.
	ErrFrameTooLarge = errors.New("proto: frame exceeds maximum size")
)

// Request is the body the daemon sends to the helper per call.
type Request struct {
	Op    string `json:"op"`
	Param string `json:"param,omitempty"`
	// DeadlineMS is the caller's remaining budget in milliseconds. It
	// is advisory and can only ever SHORTEN the helper's own per-op
	// deadline, never extend it — the peer is the thing being defended
	// against. Zero or absent means "use the helper's configured
	// deadline for this op". Without it the helper cannot align its
	// SIGTERM/SIGKILL escalation with the daemon giving up, and a
	// subprocess outlives the request that started it.
	DeadlineMS int `json:"deadline_ms,omitempty"`
}

// Response is the body the helper returns to the daemon per call.
// Status is "ok" or "err". On "ok", Data carries the typed payload. On
// "err", Code is one of the constants in this package; StderrBytes,
// StderrSHA256 and ToolExit summarise the underlying tool's stderr and
// exit without forwarding the bytes themselves (design §7.2).
type Response struct {
	Status       string          `json:"status"`
	Data         json.RawMessage `json:"data,omitempty"`
	Code         string          `json:"code,omitempty"`
	Message      string          `json:"message,omitempty"`
	StderrBytes  int             `json:"stderr_bytes,omitempty"`
	StderrSHA256 string          `json:"stderr_sha256,omitempty"`
	StderrPrefix string          `json:"stderr_prefix,omitempty"`
	ToolExit     *int            `json:"tool_exit,omitempty"`
	Argv         []string        `json:"argv,omitempty"`
}

// WriteFrame writes a length-prefixed JSON-encoded value under the
// request cap. Use WriteFrameWithCap for response-side writes.
func WriteFrame(w io.Writer, v any) error {
	return WriteFrameWithCap(w, v, MaxRequestFrame)
}

// WriteFrameWithCap writes a length-prefixed JSON-encoded value under
// the caller-supplied cap.
func WriteFrameWithCap(w io.Writer, v any, cap int) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: marshal: %w", err)
	}
	if len(body) > cap {
		return fmt.Errorf("%w: marshalled %d > cap %d", ErrFrameTooLarge, len(body), cap)
	}
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(len(body)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// ReadFrame reads a length-prefixed JSON-encoded value into v under
// the request cap. Use ReadFrameWithCap for response-side reads.
func ReadFrame(r io.Reader, v any) error {
	return ReadFrameWithCap(r, v, MaxRequestFrame)
}

// ReadFrameWithCap reads a length-prefixed JSON-encoded value into v
// under the caller-supplied cap. Frames whose declared length exceeds
// cap are rejected before the body is read.
func ReadFrameWithCap(r io.Reader, v any, cap int) error {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return err
	}
	n := binary.LittleEndian.Uint32(prefix[:])
	if int(n) > cap {
		return fmt.Errorf("%w: declared %d > cap %d", ErrFrameTooLarge, n, cap)
	}
	// Up-front allocation is intentional: the 4 MiB cap was raised in schema 0.5.0 to fit legitimate firewall ban-set responses, and the deployment target's memory budget tolerates the worst-case fan-out alloc.
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
