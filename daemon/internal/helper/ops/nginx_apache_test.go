package ops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectServer_Nginx(t *testing.T) {
	root := t.TempDir()
	mustWriteComm(t, root, "100", "nginx")
	mustWriteComm(t, root, "101", "nginx")
	mustWriteComm(t, root, "102", "nginx")
	mustWriteComm(t, root, "200", "bash")
	server, n, a := detectServer(root)
	if server != "nginx" {
		t.Fatalf("server = %q want nginx", server)
	}
	if n != 3 {
		t.Fatalf("nginx count = %d want 3", n)
	}
	if a != 0 {
		t.Fatalf("apache count = %d want 0", a)
	}
}

func TestDetectServer_Apache(t *testing.T) {
	root := t.TempDir()
	mustWriteComm(t, root, "300", "apache2")
	mustWriteComm(t, root, "301", "apache2")
	mustWriteComm(t, root, "302", "apache2")
	mustWriteComm(t, root, "303", "apache2")
	server, _, a := detectServer(root)
	if server != "apache" {
		t.Fatalf("server = %q want apache", server)
	}
	if a != 4 {
		t.Fatalf("apache count = %d want 4", a)
	}
}

func TestDetectServer_None(t *testing.T) {
	root := t.TempDir()
	mustWriteComm(t, root, "500", "bash")
	mustWriteComm(t, root, "501", "systemd")
	server, n, a := detectServer(root)
	if server != "none" || n != 0 || a != 0 {
		t.Fatalf("got (%q,%d,%d) want (none,0,0)", server, n, a)
	}
}

func TestParseAccessLogSummary_OK(t *testing.T) {
	in := []byte(`{"generated_at":"2026-06-01T12:00:00Z","window_minutes":60,"count_4xx":12,"count_5xx":3}`)
	x4, x5, err := parseAccessLogSummary(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if x4 != 12 || x5 != 3 {
		t.Fatalf("got (%d,%d) want (12,3)", x4, x5)
	}
}

func TestParseAccessLogSummary_Negative(t *testing.T) {
	in := []byte(`{"count_4xx":-1,"count_5xx":0}`)
	if _, _, err := parseAccessLogSummary(in); err == nil {
		t.Fatal("expected error on negative count, got nil")
	}
}

func TestParseAccessLogSummary_Malformed(t *testing.T) {
	if _, _, err := parseAccessLogSummary([]byte("not json")); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func mustWriteComm(t *testing.T, root, pid, comm string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
