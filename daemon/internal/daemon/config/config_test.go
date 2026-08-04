package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateRejectsZeroZeroBucket covers M-9: a bucket configured
// with sustained_per_min=0 AND burst=0 must fail load unless the
// operator explicitly disables it.
func TestValidateRejectsZeroZeroBucket(t *testing.T) {
	d := Daemon{
		BindAddr:     "127.0.0.1:8443",
		TLSCertPath:  "/x/cert.pem",
		TLSKeyPath:   "/x/key.pem",
		ClientCAPath: "/x/ca.pem",
		// Not the field under test; Validate() requires it and
		// LoadDaemon supplies it from defaultDaemon().
		MaxConcurrentHandshakes: 16,
		ExpensiveToolBuckets: map[string]BucketLimit{
			"logs": {SustainedPerMin: 0, Burst: 0},
		},
	}
	if err := d.Validate(); err == nil {
		t.Fatal("Validate() accepted (0,0) bucket; expected error")
	}
}

// TestValidateAcceptsExplicitlyDisabledBucket covers the opt-out:
// `enabled: false` lets the bucket carry zeros legitimately.
func TestValidateAcceptsExplicitlyDisabledBucket(t *testing.T) {
	off := false
	d := Daemon{
		BindAddr:     "127.0.0.1:8443",
		TLSCertPath:  "/x/cert.pem",
		TLSKeyPath:   "/x/key.pem",
		ClientCAPath: "/x/ca.pem",
		// Not the field under test; Validate() requires it and
		// LoadDaemon supplies it from defaultDaemon().
		MaxConcurrentHandshakes: 16,
		ExpensiveToolBuckets: map[string]BucketLimit{
			"logs": {SustainedPerMin: 0, Burst: 0, Enabled: &off},
		},
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate() rejected explicit-disable bucket: %v", err)
	}
}

// TestValidateAcceptsPositiveBucket keeps the regular path covered.
func TestValidateAcceptsPositiveBucket(t *testing.T) {
	d := Daemon{
		BindAddr:     "127.0.0.1:8443",
		TLSCertPath:  "/x/cert.pem",
		TLSKeyPath:   "/x/key.pem",
		ClientCAPath: "/x/ca.pem",
		// Not the field under test; Validate() requires it and
		// LoadDaemon supplies it from defaultDaemon().
		MaxConcurrentHandshakes: 16,
		ExpensiveToolBuckets: map[string]BucketLimit{
			"logs": {SustainedPerMin: 30, Burst: 10},
		},
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate() rejected positive bucket: %v", err)
	}
}

// TestValidateIPFilterAllow covers the ip_filter_allow entries that
// become IPAddressAllow= lines in the daemon's systemd drop-in. The
// daemon never enforces them itself, but it validates them: an invalid
// entry produces a drop-in that stops the unit from starting, and
// failing at config load is far easier to diagnose than failing at the
// next systemctl restart.
func TestValidateIPFilterAllow(t *testing.T) {
	base := func(entries ...string) Daemon {
		return Daemon{
			BindAddr:     "127.0.0.1:8443",
			TLSCertPath:  "/x/cert.pem",
			TLSKeyPath:   "/x/key.pem",
			ClientCAPath: "/x/ca.pem",
			// Not the field under test; see above.
			MaxConcurrentHandshakes: 16,
			IPFilterAllow:           entries,
		}
	}
	accepted := [][]string{
		nil,
		{},
		{"localhost"},
		{"any", "link-local", "multicast"},
		{"10.0.0.0/8", "192.168.7.9", "fc00::/7", "2001:db8::1"},
	}
	for _, entries := range accepted {
		d := base(entries...)
		if err := d.Validate(); err != nil {
			t.Errorf("Validate() rejected %v: %v", entries, err)
		}
	}

	rejected := [][]string{
		{"loopback"},                  // not a systemd keyword
		{"10.0.0.0/33"},               // prefix out of range
		{"10.0.0.256"},                // not an address
		{"example.com"},               // hostnames are not resolved here
		{""},                          // empty entry
		{"10.0.0.0/8 192.168.0.0/16"}, // one line, two values
	}
	for _, entries := range rejected {
		d := base(entries...)
		if err := d.Validate(); err == nil {
			t.Errorf("Validate() accepted %q; expected an error", entries)
		}
	}
}

// TestValidateUnitSelectors covers the tool 4.2 selector split. A glob
// in whitelisted_units is rejected rather than passed to
// ListUnitsByNames, where it would come back as a synthesised
// not-found row and read as "the unit is missing".
func TestValidateUnitSelectors(t *testing.T) {
	accepted := []Manifest{
		{},
		{WhitelistedUnits: []string{"sshd.service", "cron.service"}},
		{WhitelistedUnitPatterns: []string{"nginx*", "php*-fpm.service", "systemd-*"}},
		{
			WhitelistedUnits:        []string{"sshd.service"},
			WhitelistedUnitPatterns: []string{"postfix*"},
		},
		// Escaped device unit names legitimately carry no metacharacter
		// but do carry backslashes; they must pass as exact names.
		{WhitelistedUnits: []string{`dev-disk-by\x2duuid-1234.device`}},
	}
	for i, m := range accepted {
		if err := m.ValidateUnitSelectors(); err != nil {
			t.Errorf("accepted[%d] rejected: %v", i, err)
		}
	}

	rejected := []struct {
		name string
		m    Manifest
	}{
		{"glob in the exact list", Manifest{WhitelistedUnits: []string{"nginx*"}}},
		{"bracket glob in the exact list", Manifest{WhitelistedUnits: []string{"sshd[1].service"}}},
		{"question mark in the exact list", Manifest{WhitelistedUnits: []string{"ssh?.service"}}},
		{"empty exact entry", Manifest{WhitelistedUnits: []string{""}}},
		{"blank exact entry", Manifest{WhitelistedUnits: []string{"   "}}},
		{"empty pattern entry", Manifest{WhitelistedUnitPatterns: []string{""}}},
		{"match-everything pattern", Manifest{WhitelistedUnitPatterns: []string{"*"}}},
		{"match-everything pattern, doubled", Manifest{WhitelistedUnitPatterns: []string{"**"}}},
		{"metacharacters only", Manifest{WhitelistedUnitPatterns: []string{"?*"}}},
		{"bracket only", Manifest{WhitelistedUnitPatterns: []string{"["}}},
		{"bracket pair only", Manifest{WhitelistedUnitPatterns: []string{"[]"}}},
		{"whitespace pattern", Manifest{WhitelistedUnitPatterns: []string{"  "}}},
	}
	for _, c := range rejected {
		if err := c.m.ValidateUnitSelectors(); err == nil {
			t.Errorf("%s: accepted, expected an error", c.name)
		}
	}
}

// TestLoadManifestValidatesSelectors pins that validation is part of the
// loader's contract, not something a caller must remember. 2.2.1 called
// ValidateUnitSelectors from main.go only, so LoadDaemon validated
// internally while LoadManifest did not — a future second caller would
// silently have skipped it.
func TestLoadManifestValidatesSelectors(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "manifest.yml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, err := LoadManifest(write(t, "whitelisted_units:\n  - nginx*\n")); err == nil {
		t.Error("LoadManifest accepted a glob in whitelisted_units")
	}
	if _, err := LoadManifest(write(t, "whitelisted_unit_patterns:\n  - \"*\"\n")); err == nil {
		t.Error("LoadManifest accepted a match-everything pattern")
	}

	good := "whitelisted_units:\n  - sshd.service\nwhitelisted_unit_patterns:\n  - nginx*\n"
	m, err := LoadManifest(write(t, good))
	if err != nil {
		t.Fatalf("LoadManifest rejected a valid manifest: %v", err)
	}
	if len(m.WhitelistedUnits) != 1 || len(m.WhitelistedUnitPatterns) != 1 {
		t.Errorf("selectors not decoded: %+v", m)
	}
}

// B-8: an explicit 0 or a negative value left the listener UNCAPPED,
// with no warning and no validation — the same fail-open class already
// closed for the rate-limit buckets, where opting out must be spelled
// `enabled: false`.
func TestValidateRejectsUncappedHandshakes(t *testing.T) {
	base := func(n int) Daemon {
		return Daemon{
			BindAddr:                "127.0.0.1:8443",
			TLSCertPath:             "/x/cert.pem",
			TLSKeyPath:              "/x/key.pem",
			ClientCAPath:            "/x/ca.pem",
			MaxConcurrentHandshakes: n,
		}
	}
	for _, n := range []int{0, -1, -100} {
		if err := base(n).Validate(); err == nil {
			t.Errorf("max_concurrent_handshakes=%d accepted; the listener would be uncapped", n)
		}
	}
	for _, n := range []int{1, 16, 1024} {
		if err := base(n).Validate(); err != nil {
			t.Errorf("max_concurrent_handshakes=%d rejected: %v", n, err)
		}
	}
	// The loader supplies the default, so an operator who never names
	// the key is unaffected.
	if got := defaultDaemon().MaxConcurrentHandshakes; got <= 0 {
		t.Errorf("defaultDaemon() gives %d; LoadDaemon would reject its own default", got)
	}
}

// B-9: a bucket that passes validation but leaves the tool permanently
// unreachable is a silent misconfiguration. burst=0 refuses every call;
// sustained=0 never refills, so the tool dies after `burst` calls.
func TestValidateRejectsPermanentlyBrokenBuckets(t *testing.T) {
	base := func(b BucketLimit) Daemon {
		return Daemon{
			BindAddr:                "127.0.0.1:8443",
			TLSCertPath:             "/x/cert.pem",
			TLSKeyPath:              "/x/key.pem",
			ClientCAPath:            "/x/ca.pem",
			MaxConcurrentHandshakes: 16,
			ExpensiveToolBuckets:    map[string]BucketLimit{"logs": b},
		}
	}
	broken := []BucketLimit{
		{SustainedPerMin: 30, Burst: 0},
		{SustainedPerMin: 0, Burst: 5},
		{SustainedPerMin: -1, Burst: 5},
		{SustainedPerMin: 30, Burst: -1},
	}
	for _, b := range broken {
		if err := base(b).Validate(); err == nil {
			t.Errorf("bucket %+v accepted; the tool would be permanently broken", b)
		}
	}
	// An explicit opt-out still carries zeros legitimately.
	off := false
	if err := base(BucketLimit{SustainedPerMin: 0, Burst: 0, Enabled: &off}).Validate(); err != nil {
		t.Errorf("explicit enabled:false rejected: %v", err)
	}
}

// B-9, second half: a typo in a tool-keyed config map used to be
// silent. `log:` for `logs:` dropped that tool to the global bucket
// with no diagnostic, while the same typo in enabled_tools is fatal.
func TestValidateToolNames(t *testing.T) {
	registered := map[string]bool{"logs": true, "storage": true, "manifest": true}

	ok := Daemon{
		ExpensiveToolBuckets: map[string]BucketLimit{"logs": {SustainedPerMin: 30, Burst: 10}},
		TimeoutOverrides:     map[string]int{"storage": 8},
		CacheTTLOverrides:    map[string]int{"logs": 60},
	}
	if err := ok.ValidateToolNames(registered); err != nil {
		t.Fatalf("valid names rejected: %v", err)
	}

	for name, d := range map[string]Daemon{
		"expensive_tool_buckets": {ExpensiveToolBuckets: map[string]BucketLimit{"log": {SustainedPerMin: 1, Burst: 1}}},
		"timeout_overrides":      {TimeoutOverrides: map[string]int{"storag": 8}},
		"cache_ttl_overrides":    {CacheTTLOverrides: map[string]int{"logz": 60}},
	} {
		err := d.ValidateToolNames(registered)
		if err == nil {
			t.Errorf("%s: typo accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%s: error %q does not name the offending key", name, err)
		}
	}
}
