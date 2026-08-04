package cache

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
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

// C-3: Do accepted a context and never read it. singleflight.Do has no
// cancellation, so the per-tool timeout only bit for tools whose
// Handle observed ctx itself. A tool blocking in an uninterruptible
// syscall (unix.Statfs on a stale NFS mount) hung its goroutine
// forever.
func TestDoReleasesTheCallerOnContextExpiry(t *testing.T) {
	c := New()
	release := make(chan struct{})
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.Do(ctx, "stuck", func() (Entry, error) {
		<-release // never returns within the test's deadline
		return Entry{}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("caller was held for %v; the ctx was never observed", elapsed)
	}
}

// Forget on timeout is what makes the wedge recoverable. Without it the
// next caller joins the still-running call and the tool stays dead for
// the process lifetime — a daemon restart was the only cure.
func TestDoRecoversAfterAStuckCall(t *testing.T) {
	c := New()
	release := make(chan struct{})
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := c.Do(ctx, "k", func() (Entry, error) {
		<-release
		return Entry{}, nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first call: err = %v, want DeadlineExceeded", err)
	}

	// A fresh caller must get a fresh invocation, not the wedged one.
	ran := false
	got, err := c.Do(context.Background(), "k", func() (Entry, error) {
		ran = true
		return Entry{Data: []byte(`{"ok":true}`)}, nil
	})
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !ran {
		t.Error("second call joined the stuck invocation instead of starting a new one")
	}
	if string(got.Data) != `{"ok":true}` {
		t.Errorf("Data = %s", got.Data)
	}
}

// Coalescing must still work: that is the whole point of the type.
func TestDoStillCoalescesConcurrentCallers(t *testing.T) {
	c := New()
	var calls int32
	proceed := make(chan struct{})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Do(context.Background(), "shared", func() (Entry, error) {
				atomic.AddInt32(&calls, 1)
				<-proceed
				return Entry{Data: []byte("{}")}, nil
			})
		}()
	}
	// Give the goroutines time to pile onto the same key.
	time.Sleep(50 * time.Millisecond)
	close(proceed)
	wg.Wait()

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("fn ran %d times, want 1 — callers were not coalesced", n)
	}
}

// An error from fn reaches the caller unchanged.
func TestDoPropagatesTheError(t *testing.T) {
	c := New()
	want := errors.New("boom")
	if _, err := c.Do(context.Background(), "k", func() (Entry, error) {
		return Entry{}, want
	}); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}

// H-1: singleflight's DoChan path re-throws a panicking call with
// `go panic(e)` in a bare goroutine — unrecoverable, and it terminates
// the process. The plain Do path used to run fn on the caller's
// goroutine, where net/http's per-connection recover contained it. So
// switching to DoChan silently converted "one tool panics, one request
// fails" into "one tool panics, the daemon dies and systemd parks the
// unit after five restarts". fn must be wrapped.
func TestDoContainsAPanicInFn(t *testing.T) {
	c := New()
	_, err := c.Do(context.Background(), "k", func() (Entry, error) {
		panic("tool blew up")
	})
	if err == nil {
		t.Fatal("a panicking tool must surface as an error, not a nil result")
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Errorf("err = %v, want it to name the panic", err)
	}

	// The group must remain usable afterwards.
	got, err := c.Do(context.Background(), "k", func() (Entry, error) {
		return Entry{Data: []byte(`{"ok":true}`)}, nil
	})
	if err != nil {
		t.Fatalf("cache unusable after a contained panic: %v", err)
	}
	if string(got.Data) != `{"ok":true}` {
		t.Errorf("Data = %s", got.Data)
	}
}

// H-2: ctx here derives from the HTTP request, and net/http cancels it
// when the client disconnects. Forgetting on cancel would let a caller
// that issues and aborts requests repeatedly drop the singleflight
// entry out from under a running leader, starting a fresh concurrent
// invocation of the same tool each time — a fork storm onto the
// helper, which is precisely what this package exists to prevent.
func TestCancelDoesNotForgetTheInFlightCall(t *testing.T) {
	c := New()
	var calls int32
	proceed := make(chan struct{})
	leaderDone := make(chan struct{})

	// Leader, with no deadline of its own.
	go func() {
		defer close(leaderDone)
		_, _ = c.Do(context.Background(), "k", func() (Entry, error) {
			atomic.AddInt32(&calls, 1)
			<-proceed
			return Entry{Data: []byte("{}")}, nil
		})
	}()

	// Wait for the leader to be in flight.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatal("leader did not start")
	}

	// A follower joins and is then cancelled, as on a client disconnect.
	followerCtx, cancelFollower := context.WithCancel(context.Background())
	followerErr := make(chan error, 1)
	go func() {
		_, err := c.Do(followerCtx, "k", func() (Entry, error) {
			atomic.AddInt32(&calls, 1)
			return Entry{}, nil
		})
		followerErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancelFollower()
	if err := <-followerErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("follower err = %v, want context.Canceled", err)
	}

	// The key must still be held by the running leader, so a newcomer
	// coalesces rather than starting a second invocation.
	newcomerDone := make(chan struct{})
	go func() {
		defer close(newcomerDone)
		_, _ = c.Do(context.Background(), "k", func() (Entry, error) {
			atomic.AddInt32(&calls, 1)
			return Entry{}, nil
		})
	}()
	time.Sleep(50 * time.Millisecond)

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("fn ran %d times; a cancelled follower forgot the key and "+
			"started a concurrent invocation", n)
	}

	close(proceed)
	<-leaderDone
	<-newcomerDone
}

// A deadline is different: the leader's own context has expired too, so
// forgetting is what lets the tool recover instead of staying wedged.
func TestDeadlineDoesForgetSoTheToolRecovers(t *testing.T) {
	c := New()
	release := make(chan struct{})
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := c.Do(ctx, "k", func() (Entry, error) {
		<-release
		return Entry{}, nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}

	ran := false
	if _, err := c.Do(context.Background(), "k", func() (Entry, error) {
		ran = true
		return Entry{Data: []byte("{}")}, nil
	}); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !ran {
		t.Error("after a deadline the next caller must start a fresh invocation")
	}
}

// B-13: the key includes the canonicalised ARGS, so a caller varying a
// tool argument produces a distinct entry every time, and entries only
// leave on Sweep after their TTL. The old note said singleflight plus
// TTL bounded growth; between sweeps it does not.
func TestStoreIsBounded(t *testing.T) {
	c := New()
	live := Entry{Data: []byte("{}"), Builtat: time.Now(), TTL: time.Hour}
	for i := 0; i < MaxEntries+500; i++ {
		c.Store(Key("logs", []byte(`{"n":`+strconv.Itoa(i)+`}`)), live)
	}
	if n := len(c.m); n > MaxEntries {
		t.Errorf("cache holds %d entries, over the %d cap", n, MaxEntries)
	}
}

// Hitting the cap must not stop expired entries being reclaimed: the
// cache has to recover once TTLs lapse, not wedge at the ceiling.
func TestStoreReclaimsExpiredAtTheCap(t *testing.T) {
	c := New()
	expired := Entry{Data: []byte("{}"), Builtat: time.Now().Add(-time.Hour), TTL: time.Second}
	for i := 0; i < MaxEntries; i++ {
		c.Store(Key("logs", []byte(`{"n":`+strconv.Itoa(i)+`}`)), expired)
	}
	live := Entry{Data: []byte(`{"fresh":true}`), Builtat: time.Now(), TTL: time.Hour}
	k := Key("logs", []byte(`{"new":1}`))
	c.Store(k, live)
	if _, ok := c.Lookup(k); !ok {
		t.Error("a fresh entry was refused while the map was full of expired ones")
	}
}

// Replacing an existing key must always work, cap or no cap —
// otherwise a hot tool stops refreshing once the map fills.
func TestStoreAlwaysReplacesAnExistingKey(t *testing.T) {
	c := New()
	live := Entry{Data: []byte("{}"), Builtat: time.Now(), TTL: time.Hour}
	for i := 0; i < MaxEntries; i++ {
		c.Store(Key("logs", []byte(`{"n":`+strconv.Itoa(i)+`}`)), live)
	}
	k := Key("logs", []byte(`{"n":0}`))
	c.Store(k, Entry{Data: []byte(`{"updated":true}`), Builtat: time.Now(), TTL: time.Hour})
	got, ok := c.Lookup(k)
	if !ok {
		t.Fatal("the existing key vanished")
	}
	if string(got.Data) != `{"updated":true}` {
		t.Errorf("Data = %s, want the replacement", got.Data)
	}
}
