package config

import "testing"

// TestValidateRejectsZeroZeroBucket covers M-9: a bucket configured
// with sustained_per_min=0 AND burst=0 must fail load unless the
// operator explicitly disables it.
func TestValidateRejectsZeroZeroBucket(t *testing.T) {
	d := Daemon{
		BindAddr:     "127.0.0.1:8443",
		TLSCertPath:  "/x/cert.pem",
		TLSKeyPath:   "/x/key.pem",
		ClientCAPath: "/x/ca.pem",
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
			BindAddr:      "127.0.0.1:8443",
			TLSCertPath:   "/x/cert.pem",
			TLSKeyPath:    "/x/key.pem",
			ClientCAPath:  "/x/ca.pem",
			IPFilterAllow: entries,
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
	}
	for _, c := range rejected {
		if err := c.m.ValidateUnitSelectors(); err == nil {
			t.Errorf("%s: accepted, expected an error", c.name)
		}
	}
}
