package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

// The defect that motivated this loader: these four spellings are one
// document to any YAML parser, and the shell scanner they replaced
// accepted only the first. The second aborted the package configure
// and the third produced an empty capability set in silence.
func TestEveryYAMLSpellingOfASequenceAgrees(t *testing.T) {
	want := []string{"storage", "workload"}
	for _, tc := range []struct{ name, body string }{
		{"block", "enabled_tools:\n  - storage\n  - workload\n"},
		{"flow", "enabled_tools: [storage, workload]\n"},
		{"flow quoted", `enabled_tools: ["storage", 'workload']` + "\n"},
		{"flow multiline", "enabled_tools: [\n  storage,\n  workload\n]\n"},
		{"block with comments", "enabled_tools:\n  - storage   # primary\n  - workload\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, warnings, err := LoadManifestLenient(writeTemp(t, "manifest.yml", tc.body))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(warnings) != 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
			if !reflect.DeepEqual(m.EnabledTools, want) {
				t.Errorf("got %v, want %v", m.EnabledTools, want)
			}
		})
	}
}

func TestUnknownKeyWarnsAndIsIgnored(t *testing.T) {
	body := "enabled_tools:\n  - storage\nenabled_tolls:\n  - security\n"
	m, warnings, err := LoadManifestLenient(writeTemp(t, "manifest.yml", body))
	if err != nil {
		t.Fatalf("an unknown key must not be fatal, got: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("want exactly one warning, got %v", warnings)
	}
	if !strings.Contains(warnings[0], "enabled_tolls") {
		t.Errorf("the warning must name the offending key, got %q", warnings[0])
	}
	// The operator has to be able to find it. yaml.v3 supplies the
	// line; the loader supplies the file.
	if !strings.Contains(warnings[0], "line 3") {
		t.Errorf("the warning must carry the line number, got %q", warnings[0])
	}
	if !strings.Contains(warnings[0], "manifest.yml") {
		t.Errorf("the warning must name the file, got %q", warnings[0])
	}
	// And the keys it did understand must still have been read.
	if !reflect.DeepEqual(m.EnabledTools, []string{"storage"}) {
		t.Errorf("known keys must still decode, got %v", m.EnabledTools)
	}
}

// An unrecognised name is an operator typo the generator can safely
// skip. A value of the wrong type is a value it cannot read, and a
// capability set derived from it would be wrong rather than merely
// incomplete.
func TestTypeErrorStaysFatal(t *testing.T) {
	body := "enabled_tools: 17\n"
	_, _, err := LoadManifestLenient(writeTemp(t, "manifest.yml", body))
	if err == nil {
		t.Fatal("a type error must remain fatal")
	}
}

func TestEmptyFileIsAnEmptyDocument(t *testing.T) {
	m, warnings, err := LoadManifestLenient(writeTemp(t, "manifest.yml", ""))
	if err != nil {
		t.Fatalf("an empty manifest must not be an error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(m.EnabledTools) != 0 {
		t.Errorf("want zero value, got %v", m.EnabledTools)
	}
}

func TestMissingFileReportsNotPresent(t *testing.T) {
	_, _, err := LoadManifestLenient(filepath.Join(t.TempDir(), "absent.yml"))
	if err == nil || !strings.Contains(err.Error(), "not present") {
		t.Errorf("want a not-present error, got %v", err)
	}
}

// LoadDaemon runs Validate, which requires bind_addr. The generator
// needs ip_filter_allow from a host that may not have finished being
// configured, so the lenient path must not inherit that.
func TestLoadDaemonLenientSkipsValidation(t *testing.T) {
	body := "ip_filter_allow:\n  - 192.0.2.0/24\n"
	d, warnings, err := LoadDaemonLenient(writeTemp(t, "daemon.yml", body))
	if err != nil {
		t.Fatalf("a daemon.yml without bind_addr must still yield ip_filter_allow, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if !reflect.DeepEqual(d.IPFilterAllow, []string{"192.0.2.0/24"}) {
		t.Errorf("got %v", d.IPFilterAllow)
	}
	// The strict loader is unchanged and still rejects it, because the
	// daemon remains the authority on validity.
	if _, err := LoadDaemon(writeTemp(t, "daemon2.yml", body)); err == nil {
		t.Error("LoadDaemon must still reject a config without bind_addr")
	}
}

// LoadManifest is the daemon's path and must keep refusing what it
// refused before: this change adds a lenient reader, it does not
// loosen the strict one.
func TestStrictLoaderStillRejectsUnknownKeys(t *testing.T) {
	body := "enabled_tools:\n  - storage\nenabled_tolls:\n  - security\n"
	if _, err := LoadManifest(writeTemp(t, "manifest.yml", body)); err == nil {
		t.Error("LoadManifest must still reject an unknown key")
	}
}

// decodeYAMLLenient separates "unknown key" from "wrong type" by
// matching a substring of yaml.v3's own error text. That is the one
// place this package depends on a dependency's phrasing, so assert it
// against the library directly: if a version bump changes the wording,
// this fails loudly rather than the warnings quietly ceasing to be
// emitted and every unknown key becoming fatal.
func TestUnknownFieldMarkerMatchesYAMLv3(t *testing.T) {
	var into struct {
		Known string `yaml:"known"`
	}
	dec := yaml.NewDecoder(bytes.NewReader([]byte("known: a\nunknown: b\n")))
	dec.KnownFields(true)
	err := dec.Decode(&into)

	var te *yaml.TypeError
	if !errors.As(err, &te) {
		t.Fatalf("yaml.v3 no longer reports an unknown field as *yaml.TypeError: %v", err)
	}
	if len(te.Errors) != 1 {
		t.Fatalf("want one field error, got %v", te.Errors)
	}
	if !strings.Contains(te.Errors[0], unknownFieldMarker) {
		t.Fatalf("unknownFieldMarker %q no longer appears in yaml.v3's message %q",
			unknownFieldMarker, te.Errors[0])
	}
}
