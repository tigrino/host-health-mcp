package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// The install-time capability generator reads the same two files the
// daemon does, and until 2.4.0 it read them with a line scanner that
// understood only block sequences. `enabled_tools: [storage]` and the
// block form are the same document to any YAML parser; the scanner
// rejected the first and aborted the package configure. Worse, a
// multi-line flow sequence slipped past its guard entirely and yielded
// an empty capability set in silence.
//
// The fix is not a better scanner. It is to give the generator the
// decoder the daemon already uses, so one grammar decides what a
// manifest means.
//
// What the generator must NOT inherit is the daemon's strictness. The
// daemon refuses to start on a key it does not recognise, which is
// right for the process serving requests. A maintainer script that
// aborts the install over an unrecognised key strands dpkg
// half-configured across a fleet, and the capability set it would have
// generated is unaffected by the key it did not understand. So the
// loaders below warn and continue where the daemon would refuse, and
// the daemon remains the authority on whether a config is valid.

// unknownFieldMarker is the substring yaml.v3 puts in the per-field
// entries of a *yaml.TypeError when KnownFields(true) meets a key the
// target struct does not declare. Matching it separates "the operator
// misspelled a key" (warn, ignore) from "the value has the wrong type"
// (still fatal): a bounding set generated from a value that could not
// be read would be wrong rather than merely incomplete.
//
// This is the one place the code depends on the phrasing of a
// dependency's error string. yaml.v3 is pinned and vendored so it
// cannot change under us unnoticed, and TestUnknownFieldMarkerMatches
// asserts the phrasing directly against the library — if a future
// bump changes it, that test fails loudly instead of the warnings
// silently ceasing to be emitted.
const unknownFieldMarker = "not found in type"

// decodeYAMLLenient decodes path into into, ignoring keys the target
// type does not declare and returning one warning per ignored key.
//
// One strict pass, not two. A KnownFields(true) decode does not stop
// at the first unrecognised key: it records the complaint and carries
// on, so every key the type does declare is populated by the time it
// returns. That makes the returned *yaml.TypeError a complete list of
// what the decoder objected to, and classifying it here is the single
// place tolerance is decided.
//
// An earlier version decoded twice — once leniently for the values,
// once strictly for the diagnostics. It looked more careful and was
// less so: the strict pass sees a superset of the lenient pass's
// errors, so the lenient pass always failed first on anything fatal
// and this function's own fatal branch could never be reached. Two
// mutation tests survived against it, which is what surfaced the dead
// code.
func decodeYAMLLenient(path string, into any) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config: %s: not present", path)
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	derr := dec.Decode(into)
	// An empty file is an empty document, not a failure: a host that
	// has created manifest.yml but not yet filled it in gets the
	// zero-value config and the conservative defaults that follow from
	// it. io.EOF is how yaml.v3 reports "no document here".
	if derr == nil || errors.Is(derr, io.EOF) {
		return nil, nil
	}

	var te *yaml.TypeError
	if !errors.As(derr, &te) {
		// Not a per-field complaint — a malformed document. Nothing
		// was decoded and nothing can be salvaged.
		return nil, fmt.Errorf("config: parse %s: %w", path, derr)
	}

	var warnings, fatal []string
	for _, e := range te.Errors {
		if strings.Contains(e, unknownFieldMarker) {
			warnings = append(warnings, fmt.Sprintf("%s: %s (ignored)", path, e))
			continue
		}
		fatal = append(fatal, e)
	}
	if len(fatal) > 0 {
		return warnings, fmt.Errorf("config: parse %s: %s", path, strings.Join(fatal, "; "))
	}
	return warnings, nil
}

// LoadManifestLenient reads manifest.yml for the install-time
// capability generator. Unlike LoadManifest it does not reject
// unrecognised keys and does not run ValidateUnitSelectors: the
// generator consumes three list-valued keys, and a unit selector it
// never looks at must not be able to stop a host's helper from being
// granted the capabilities it needs.
func LoadManifestLenient(path string) (Manifest, []string, error) {
	cfg := Manifest{}
	warnings, err := decodeYAMLLenient(path, &cfg)
	return cfg, warnings, err
}

// LoadDaemonLenient reads daemon.yml for the same caller and for the
// same reason, and additionally skips Validate(): the generator needs
// ip_filter_allow only, and a daemon.yml missing bind_addr — the
// normal state on a host being provisioned — must not prevent the
// helper's capability drop-in from being written.
func LoadDaemonLenient(path string) (Daemon, []string, error) {
	cfg := defaultDaemon()
	warnings, err := decodeYAMLLenient(path, &cfg)
	return cfg, warnings, err
}
