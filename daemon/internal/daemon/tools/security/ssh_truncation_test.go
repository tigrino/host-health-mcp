package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
)

// journalHelper answers ssh_journal_counts with the given payload and
// fails every other op, so a test can tell which source a count came
// from without guessing.
func journalHelper(t *testing.T, resp proto.Response) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var req proto.Request
				if proto.ReadFrame(c, &req) != nil {
					return
				}
				out := proto.Response{Status: "error", Code: proto.CodeToolMissing, Message: "not this op"}
				if req.Op == proto.OpSshJournalCounts {
					out = resp
				}
				_ = proto.WriteFrameWithCap(c, out, proto.MaxResponseFrame)
			}()
		}
	}()
	return sock
}

// authLogOfSize writes an auth.log with n "Failed password" lines and
// points the tool at it.
func authLogOfSize(t *testing.T, lines int) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	var b strings.Builder
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&b, "Jan  1 00:00:00 h sshd[1]: Failed password for invalid user u%d from 192.0.2.1 port 1 ssh2\n", i)
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := authLogPaths
	authLogPaths = []string{p}
	t.Cleanup(func() { authLogPaths = orig })
}

func runSecurity(t *testing.T, sock string) (Data, []string) {
	t.Helper()
	tool := New(helperinvoke.NewClient(sock, 4, nil), "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, warnings, err := tool.Handle(ctx, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	d, ok := got.(Data)
	if !ok {
		t.Fatalf("Handle returned %T", got)
	}
	return d, warnings
}

// The finding: an auth.log over the read cap produced no counts at all
// and window "unavailable". A sustained brute force is what grows the
// file, so the counters vanished during exactly the event they exist to
// surface, and "no data" reads as "no attacks" on a dashboard.
// Nothing is not the same as too many.
func TestATruncatedAuthLogFallsBackToTheJournal(t *testing.T) {
	authLogOfSize(t, 90000) // comfortably over the 8 MiB cap
	sock := journalHelper(t, proto.Response{
		Status: "ok",
		Data:   json.RawMessage(`{"present":true,"accepted_last_24h":3,"failed_last_24h":4211}`),
	})

	d, _ := runSecurity(t, sock)

	if d.SSHLogins.Window == "unavailable" {
		t.Fatal("window is unavailable; a truncated file must fall back to the journal")
	}
	if d.SSHLogins.FailedRecent == nil || d.SSHLogins.AcceptedRecent == nil {
		t.Fatal("counts are null on a truncated auth.log; the journal has the answer")
	}
	if *d.SSHLogins.FailedRecent != 4211 {
		t.Errorf("failed_recent: got %d, want 4211 (from the journal)", *d.SSHLogins.FailedRecent)
	}
	if d.SSHLogins.Window != "last_24h" {
		t.Errorf("window: got %q, want last_24h — the count must say what it spans",
			d.SSHLogins.Window)
	}
}

// The counts must not be labelled since_log_rotation when they came
// from a partial read or from the journal. That discriminator exists so
// a count is never ambiguous about the period it covers.
func TestATruncatedAuthLogNeverClaimsSinceLogRotation(t *testing.T) {
	authLogOfSize(t, 90000)
	sock := journalHelper(t, proto.Response{
		Status: "ok",
		Data:   json.RawMessage(`{"present":true,"accepted_last_24h":1,"failed_last_24h":2}`),
	})

	d, warnings := runSecurity(t, sock)

	if d.SSHLogins.Window == "since_log_rotation" {
		t.Error("tail counts must not be labelled since_log_rotation")
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "read cap") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning naming the read cap, got %v", warnings)
	}
}

// When the journal is also unavailable there is genuinely no answer,
// and the tool must say so rather than invent one.
func TestNoFileAndNoJournalReportsUnavailable(t *testing.T) {
	authLogOfSize(t, 90000)
	sock := journalHelper(t, proto.Response{
		Status: "ok", Data: json.RawMessage(`{"present":false}`),
	})

	d, _ := runSecurity(t, sock)

	if d.SSHLogins.Window != "unavailable" {
		t.Errorf("window: got %q, want unavailable", d.SSHLogins.Window)
	}
	if d.SSHLogins.FailedRecent != nil {
		t.Error("counts must stay null when neither source can answer")
	}
}

// Negative: a normal-sized auth.log must still be counted from the file
// and labelled since_log_rotation. The fallback must not swallow the
// common path.
func TestASmallAuthLogIsStillCountedFromTheFile(t *testing.T) {
	authLogOfSize(t, 5)
	// The journal would answer differently, so the source is unambiguous.
	sock := journalHelper(t, proto.Response{
		Status: "ok",
		Data:   json.RawMessage(`{"present":true,"accepted_last_24h":999,"failed_last_24h":999}`),
	})

	d, _ := runSecurity(t, sock)

	if d.SSHLogins.Window != "since_log_rotation" {
		t.Fatalf("window: got %q, want since_log_rotation", d.SSHLogins.Window)
	}
	if d.SSHLogins.FailedRecent == nil || *d.SSHLogins.FailedRecent != 5 {
		t.Errorf("failed_recent: got %v, want 5 (from the file, not the journal)",
			d.SSHLogins.FailedRecent)
	}
}
