package linescan

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// The bug this package exists to prevent: bufio.Scanner stops on an
// over-long line and Scan() returns false exactly as at clean EOF, so
// a caller that does not check Err() reports a silently wrong count
// with status: ok.
func TestOverLongLineIsAnErrorNotASilentTruncation(t *testing.T) {
	long := strings.Repeat("x", MaxLine+1)
	sc := New(strings.NewReader("first\n"+long+"\nthird\n"), "test-input")

	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err == nil {
		t.Fatal("an over-long line ended the scan with no error; the caller would report a truncated count as ok")
	} else {
		if !strings.Contains(err.Error(), "test-input") {
			t.Errorf("err = %v; it must name the source", err)
		}
		if !strings.Contains(err.Error(), "truncated") {
			t.Errorf("err = %v; it must say the output was truncated", err)
		}
	}
	// It stopped early — that is the point.
	if len(lines) != 1 {
		t.Errorf("read %d lines before stopping, want 1", len(lines))
	}
}

// A line under the cap but over bufio's 64 KiB default must be read,
// not rejected: that default is the reason several ops truncated.
func TestLinesAboveTheBufioDefaultAreRead(t *testing.T) {
	line := strings.Repeat("y", 256*1024)
	sc := New(strings.NewReader(line+"\n"), "test-input")
	if !sc.Scan() {
		t.Fatalf("a %d-byte line was rejected: %v", len(line), sc.Err())
	}
	if got := len(sc.Text()); got != len(line) {
		t.Errorf("read %d bytes, want %d", got, len(line))
	}
	if err := sc.Err(); err != nil {
		t.Errorf("Err() = %v, want nil", err)
	}
}

func TestCleanEOFIsNotAnError(t *testing.T) {
	sc := New(strings.NewReader("a\nb\nc\n"), "test-input")
	n := 0
	for sc.Scan() {
		n++
	}
	if err := sc.Err(); err != nil {
		t.Errorf("Err() = %v, want nil at clean EOF", err)
	}
	if n != 3 {
		t.Errorf("read %d lines, want 3", n)
	}
}

// A genuine read failure must surface too, and be distinguishable.
func TestReadErrorSurfaces(t *testing.T) {
	want := errors.New("disk went away")
	sc := New(io.MultiReader(strings.NewReader("a\n"), errReader{want}), "test-input")
	for sc.Scan() {
	}
	err := sc.Err()
	if err == nil {
		t.Fatal("a read failure was swallowed")
	}
	if !errors.Is(err, want) {
		t.Errorf("err = %v; the underlying cause must be unwrappable", err)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestEmptyInput(t *testing.T) {
	sc := New(strings.NewReader(""), "test-input")
	if sc.Scan() {
		t.Error("Scan() returned true on empty input")
	}
	if err := sc.Err(); err != nil {
		t.Errorf("Err() = %v, want nil", err)
	}
}
