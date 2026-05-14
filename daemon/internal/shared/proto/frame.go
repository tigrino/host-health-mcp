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

// MaxFrameSize is the cap on a single length-prefixed frame body. See
// design §7.1: 16 KiB is more than ample for op + param and bounds the
// cost of a daemon-side RCE attempting to OOM the helper.
const MaxFrameSize = 16 * 1024

var (
	// ErrFrameTooLarge is returned when a frame's declared length exceeds
	// MaxFrameSize. The connection should be closed when this is seen.
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

// WriteFrame writes a length-prefixed JSON-encoded value. The length
// prefix is a little-endian uint32 and is rejected by the reader if it
// exceeds MaxFrameSize.
func WriteFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: marshal: %w", err)
	}
	if len(body) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(len(body)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// ReadFrame reads a length-prefixed JSON-encoded value into v. A frame
// whose declared length exceeds MaxFrameSize is rejected before the
// body is read.
func ReadFrame(r io.Reader, v any) error {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return err
	}
	n := binary.LittleEndian.Uint32(prefix[:])
	if n > MaxFrameSize {
		return fmt.Errorf("%w: declared %d > max %d", ErrFrameTooLarge, n, MaxFrameSize)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
