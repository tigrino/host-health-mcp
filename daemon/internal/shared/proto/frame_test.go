package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestRoundTripRequest(t *testing.T) {
	cases := []Request{
		{Op: OpReadRebootMarker},
		{Op: OpSmartSummary, Param: "sda"},
		{Op: OpBtrfsScrub, Param: "/var/lib/docker"},
	}
	for _, want := range cases {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, want); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
		var got Request
		if err := ReadFrame(&buf, &got); err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if got != want {
			t.Errorf("round-trip: got %+v want %+v", got, want)
		}
	}
}

func TestWriteFrameRejectsOversize(t *testing.T) {
	big := make([]byte, MaxFrameSize+1)
	for i := range big {
		big[i] = 'x'
	}
	var buf bytes.Buffer
	err := WriteFrame(&buf, Request{Op: OpReadRebootMarker, Param: string(big)})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrame on oversize: got %v want ErrFrameTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Errorf("buffer should be untouched on reject; got %d bytes", buf.Len())
	}
}

func TestReadFrameRejectsDeclaredOversize(t *testing.T) {
	// Craft a frame whose declared length exceeds the cap. The reader
	// must reject before allocating the body.
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], MaxFrameSize+1)
	r := bytes.NewReader(prefix[:])
	var req Request
	err := ReadFrame(r, &req)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame on oversize declared length: got %v want ErrFrameTooLarge", err)
	}
}

func TestReadFrameShortBody(t *testing.T) {
	// Declare length 10 but provide 3 bytes. The reader must surface
	// io.ErrUnexpectedEOF from io.ReadFull.
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], 10)
	buf := append([]byte{}, prefix[:]...)
	buf = append(buf, []byte("abc")...)
	r := bytes.NewReader(buf)
	var req Request
	err := ReadFrame(r, &req)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadFrame on truncated body: got %v want io.ErrUnexpectedEOF", err)
	}
}

func TestIsKnownOp(t *testing.T) {
	for _, op := range AllOps {
		if !IsKnownOp(op) {
			t.Errorf("AllOps contains %q but IsKnownOp reports unknown", op)
		}
	}
	if IsKnownOp("bogus_op") {
		t.Error("IsKnownOp returned true for an unknown token")
	}
}
