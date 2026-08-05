package network

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
)

// newTool builds the tool with a helper client pointed at a socket that
// does not exist. The helper-backed part of the response fails into
// errors[]/warnings[], which is exactly the partial-results path these
// tests are about.
func newTool(t *testing.T) *Tool {
	t.Helper()
	return New(helperinvoke.NewClient(filepath.Join(t.TempDir(), "absent.sock"), 2, nil), "")
}

// handleData runs the tool and returns the decoded response body, which
// is what a client actually sees — the Go value can hold a nil slice
// that only becomes visible as `null` after marshalling.
func handleData(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	got, _, err := newTool(t).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

// schema-draft.yaml declares interfaces as required and typed array.
// When /sys/class/net cannot be listed, readInterfaces returns
// (nil, err); assigning that unconditionally published
// "interfaces": null — a shape no client is allowed to expect, and one
// that fails a schema-validating client outright.
func TestInterfacesIsAnArrayWhenTheEnumerationRootIsUnreadable(t *testing.T) {
	orig := sysClassNetPath
	sysClassNetPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { sysClassNetPath = orig })

	m := handleData(t)

	raw, present := m["interfaces"]
	if !present {
		t.Fatal("interfaces key is absent; the schema lists it as required")
	}
	if string(raw) == "null" {
		t.Fatal("interfaces serialised as null; the schema declares it a required array")
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("interfaces is not an array: %s", raw)
	}
	if len(arr) != 0 {
		t.Errorf("expected an empty array, got %d entries", len(arr))
	}
}

// The same guarantee for an enumeration root that lists cleanly but is
// empty: readInterfaces returns (nil, nil), which is not an error path
// at all and so was never guarded.
func TestInterfacesIsAnArrayWhenNoInterfacesExist(t *testing.T) {
	orig := sysClassNetPath
	sysClassNetPath = t.TempDir()
	t.Cleanup(func() { sysClassNetPath = orig })

	m := handleData(t)

	if string(m["interfaces"]) == "null" {
		t.Fatal("interfaces serialised as null on a host with no interfaces")
	}
}

// An unreadable enumeration root must still say so. Returning a clean
// empty array with no warning would report "this host has no network
// interfaces" as a fact.
func TestAnUnreadableEnumerationRootWarns(t *testing.T) {
	orig := sysClassNetPath
	sysClassNetPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { sysClassNetPath = orig })

	_, warnings, err := newTool(t).Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	found := false
	for _, w := range warnings {
		if len(w) > 0 && contains(w, "interface") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a warning naming the interface read failure, got %v", warnings)
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
