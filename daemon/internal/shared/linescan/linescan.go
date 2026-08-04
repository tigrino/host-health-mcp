// Package linescan provides the project's one way to read a
// line-oriented file or command output.
//
// bufio.Scanner has two defaults that are wrong for this daemon. Its
// buffer caps a line at 64 KiB, and on a longer line it simply stops
// scanning — Scan() returns false exactly as it does at clean EOF. If
// the caller does not then check Err(), an over-long line silently
// truncates the input and the tool returns a WRONG COUNT with
// status: ok. That is worse than a failure: a health check reporting
// "3 queued messages" when there are 30 000 is trusted.
//
// Both halves matter, and both were missing across the tree. Postfix
// queue output and fail2ban jail output carry remote-attacker-
// influenced content, so an attacker who can produce one long line can
// choose what the operator sees.
//
// This package exists so the decision is made once. Prefer New over a
// bare bufio.NewScanner; the forbidden-call linter does not enforce
// that, but a reviewer should.
package linescan

import (
	"bufio"
	"fmt"
	"io"
)

const (
	// InitialBuffer is the starting allocation per scanner.
	InitialBuffer = 64 * 1024
	// MaxLine is the longest single line accepted. Beyond this the
	// scan stops and Err reports it rather than truncating quietly.
	// 1 MiB is far past any legitimate line in the formats parsed
	// here and bounds memory under attacker-influenced input.
	MaxLine = 1 << 20
)

// Scanner wraps bufio.Scanner with the project's buffer limits. Use
// Err after the scan loop; it distinguishes a genuine read failure and
// an over-long line from a clean end of input.
type Scanner struct {
	*bufio.Scanner
	what string
}

// New returns a Scanner over r. what names the source and appears in
// the error, so an operator reading a warning knows which file or
// command produced it.
func New(r io.Reader, what string) *Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, InitialBuffer), MaxLine)
	return &Scanner{Scanner: sc, what: what}
}

// Err returns nil at clean end of input, or a described error. It
// names the line cap explicitly, because bufio.ErrTooLong on its own
// ("bufio.Scanner: token too long") does not tell an operator which
// input was truncated or why the count they are looking at is wrong.
func (s *Scanner) Err() error {
	err := s.Scanner.Err()
	if err == nil {
		return nil
	}
	if err == bufio.ErrTooLong {
		return fmt.Errorf("%s: line exceeds %d bytes; output truncated and any count from it is incomplete", s.what, MaxLine)
	}
	return fmt.Errorf("%s: %w", s.what, err)
}
