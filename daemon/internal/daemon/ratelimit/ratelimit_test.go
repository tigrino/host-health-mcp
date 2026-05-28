package ratelimit

import "testing"

func TestGlobalBurst(t *testing.T) {
	l := New(BucketCfg{SustainedPerMin: 60, Burst: 3}, nil)
	for i := 0; i < 3; i++ {
		ok, _ := l.Allow("alice", "system")
		if !ok {
			t.Fatalf("burst call %d denied", i)
		}
	}
	ok, reason := l.Allow("alice", "system")
	if ok {
		t.Fatal("4th call should be denied")
	}
	if reason != "global" {
		t.Errorf("reason: got %q want global", reason)
	}
}

func TestPerToolBucket(t *testing.T) {
	l := New(
		BucketCfg{SustainedPerMin: 600, Burst: 100},
		map[string]BucketCfg{"logs": {SustainedPerMin: 1, Burst: 1}},
	)
	if ok, _ := l.Allow("alice", "logs"); !ok {
		t.Fatal("first logs call should pass")
	}
	ok, reason := l.Allow("alice", "logs")
	if ok {
		t.Fatal("second logs call should be denied by per-tool bucket")
	}
	if reason != "tool" {
		t.Errorf("reason: got %q want tool", reason)
	}
	// Global must still have plenty of room for other tools.
	if ok, _ := l.Allow("alice", "system"); !ok {
		t.Error("system call should still pass when only logs is starved")
	}
}

// TestPerToolBucketExplicitDisable covers M-9: an operator-supplied
// Disabled=true short-circuits the per-tool bucket regardless of
// numeric values. Global bucket still applies.
func TestPerToolBucketExplicitDisable(t *testing.T) {
	l := New(
		BucketCfg{SustainedPerMin: 600, Burst: 100},
		map[string]BucketCfg{"logs": {Disabled: true}},
	)
	for i := 0; i < 50; i++ {
		if ok, _ := l.Allow("alice", "logs"); !ok {
			t.Fatalf("explicit-disable logs call %d should pass", i)
		}
	}
}

func TestPerCallerIsolation(t *testing.T) {
	l := New(BucketCfg{SustainedPerMin: 60, Burst: 1}, nil)
	if ok, _ := l.Allow("alice", "system"); !ok {
		t.Fatal("alice first call")
	}
	if ok, _ := l.Allow("alice", "system"); ok {
		t.Fatal("alice second call should be denied")
	}
	if ok, _ := l.Allow("bob", "system"); !ok {
		t.Fatal("bob first call should pass; buckets are per-caller")
	}
}
