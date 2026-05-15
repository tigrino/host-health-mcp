package cache

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStoreAndLookup(t *testing.T) {
	c := New()
	k := Key("system", []byte(`{}`))
	c.Store(k, Entry{
		Data:    json.RawMessage(`{"x":1}`),
		Builtat: time.Now(),
		TTL:     10 * time.Second,
	})
	got, ok := c.Lookup(k)
	if !ok {
		t.Fatalf("Lookup: not found")
	}
	if string(got.Data) != `{"x":1}` {
		t.Errorf("Data: got %q", string(got.Data))
	}
}

func TestLookupExpired(t *testing.T) {
	c := New()
	k := Key("system", []byte(`{}`))
	c.Store(k, Entry{
		Data:    json.RawMessage(`{}`),
		Builtat: time.Now().Add(-time.Hour),
		TTL:     time.Second,
	})
	if _, ok := c.Lookup(k); ok {
		t.Fatal("Lookup returned expired entry")
	}
}

func TestSweep(t *testing.T) {
	c := New()
	c.Store("fresh", Entry{Data: json.RawMessage(`1`), Builtat: time.Now(), TTL: time.Hour})
	c.Store("stale", Entry{Data: json.RawMessage(`1`), Builtat: time.Now().Add(-time.Hour), TTL: time.Minute})
	c.Sweep()
	if _, ok := c.Lookup("stale"); ok {
		t.Error("Sweep left stale entry")
	}
	if _, ok := c.Lookup("fresh"); !ok {
		t.Error("Sweep evicted fresh entry")
	}
}

func TestKeyStability(t *testing.T) {
	a := Key("system", []byte(`{"a":1}`))
	b := Key("system", []byte(`{"a":1}`))
	if a != b {
		t.Errorf("identical inputs produced different keys: %q vs %q", a, b)
	}
	c := Key("system", []byte(`{"a":2}`))
	if a == c {
		t.Error("different inputs collapsed to the same key")
	}
}

func TestDoSingleflight(t *testing.T) {
	c := New()
	var calls atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	work := func() (Entry, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return Entry{
			Data:     json.RawMessage(`"hi"`),
			Warnings: []string{"warn"},
		}, nil
	}

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := c.Do(context.Background(), "k", work)
			if err != nil || string(got.Data) != `"hi"` || len(got.Warnings) != 1 {
				t.Errorf("Do: data=%s warnings=%v err=%v", string(got.Data), got.Warnings, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Errorf("expected 1 underlying call, got %d", got)
	}
}
