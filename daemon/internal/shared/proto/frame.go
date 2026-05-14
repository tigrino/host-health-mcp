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

// MaxResponseFrame is the cap on a helper->daemon response frame. The
// helper's parsed-and-typed output for tools like `journal_query`,
// `lvm_report`, and `nft_table_counts` can exceed the request cap;
// 256 KiB matches the stdout cap in helper/exec.
const MaxResponseFrame = 256 * 1024

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
	ToolExit     *int            `json:"tool_exit,omitempty"`
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
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
