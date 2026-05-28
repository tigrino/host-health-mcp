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
