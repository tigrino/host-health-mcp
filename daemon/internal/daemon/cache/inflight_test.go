package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blocker is an fn that never returns until released, counting how many
// times it was actually started. A tool blocked in an uninterruptible
// syscall — unix.Statfs on a stale NFS mount, the case the system tool
// exists to report on — behaves exactly like this.
type blocker struct {
	started atomic.Int32
	release chan struct{}
}

func newBlocker() *blocker { return &blocker{release: make(chan struct{})} }

func (b *blocker) fn() (Entry, error) {
	b.started.Add(1)
	<-b.release
	return Entry{TTL: time.Minute}, nil
}

func shortCall(t *testing.T, c *Cache, k string, fn func() (Entry, error)) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.Do(ctx, k, fn)
	return err
}

// Positive: a wedged tool does NOT accumulate one goroutine per poll.
// Before the bound, Forget-on-deadline made every arrival start a fresh
// invocation, so a 30 s poll against a stuck syscall left thousands of
// wedged goroutines a day. The comment claimed this self-healed; it
// did not.
func TestAWedgedToolStopsStartingNewInvocations(t *testing.T) {
	c := New()
	b := newBlocker()
	defer close(b.release)

	var refused int
	for i := 0; i < 12; i++ {
		if err := shortCall(t, c, "k", b.fn); errors.Is(err, ErrStalled) {
			refused++
		}
	}

	if got := int(b.started.Load()); got > MaxInFlightPerKey {
		t.Errorf("12 timed-out calls started %d invocations; the per-key "+
			"bound is %d — the leak is unbounded again", got, MaxInFlightPerKey)
	}
	if refused == 0 {
		t.Error("no call was refused; callers are still paying a full timeout " +
			"each on a tool known to be wedged")
	}
	if per, _ := c.InFlight("k"); per > MaxInFlightPerKey {
		t.Errorf("in-flight count %d exceeds the bound %d", per, MaxInFlightPerKey)
	}
}

// The refusal has to be distinguishable from a timeout: "wedged" and
// "slow" call for different operator action, and the unbounded version
// reported both as a deadline.
func TestAStalledToolReportsAStalledError(t *testing.T) {
	c := New()
	b := newBlocker()
	defer close(b.release)

	for i := 0; i < MaxInFlightPerKey; i++ {
		shortCall(t, c, "k", b.fn)
	}
	err := shortCall(t, c, "k", b.fn)

	if !errors.Is(err, ErrStalled) {
		t.Fatalf("expected ErrStalled once the tool is wedged, got %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("a wedged tool must not present as an ordinary timeout")
	}
}

// The refusal must be immediate. Making the caller wait out the full
// deadline for an answer already known would keep the availability
// cost the bound exists to remove.
func TestARefusalDoesNotWaitOutTheDeadline(t *testing.T) {
	c := New()
	b := newBlocker()
	defer close(b.release)

	for i := 0; i < MaxInFlightPerKey; i++ {
		shortCall(t, c, "k", b.fn)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := c.Do(ctx, "k", b.fn)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrStalled) {
		t.Fatalf("expected ErrStalled, got %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("refusal took %v; it must not wait out the deadline", elapsed)
	}
}

// Recovery is the property the bound must not cost. When the wedged
// call finally returns — the underlying cause clearing — the tool has
// to work again without a restart.
func TestTheToolRecoversWhenTheWedgedCallReturns(t *testing.T) {
	c := New()
	b := newBlocker()

	for i := 0; i < MaxInFlightPerKey+2; i++ {
		shortCall(t, c, "k", b.fn)
	}
	if err := shortCall(t, c, "k", b.fn); !errors.Is(err, ErrStalled) {
		t.Fatalf("precondition: expected the tool to be stalled, got %v", err)
	}

	close(b.release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if per, _ := c.InFlight("k"); per == 0 {
			break
		}
		if time.Now().After(deadline) {
			per, total := c.InFlight("k")
			t.Fatalf("in-flight count never drained: per-key %d, total %d", per, total)
		}
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.Do(ctx, "k", func() (Entry, error) {
		return Entry{TTL: time.Minute}, nil
	}); err != nil {
		t.Fatalf("tool did not recover after the wedged call returned: %v", err)
	}
}

// Negative: the bound must be invisible to a healthy tool. A limit that
// trips under ordinary load is worse than no limit — it converts a
// working daemon into a refusing one.
func TestAHealthyToolIsNeverRefused(t *testing.T) {
	c := New()
	for i := 0; i < 200; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := c.Do(ctx, "k", func() (Entry, error) {
			return Entry{TTL: time.Minute}, nil
		})
		cancel()
		if err != nil {
			t.Fatalf("healthy call %d refused: %v", i, err)
		}
	}
	if per, total := c.InFlight("k"); per != 0 || total != 0 {
		t.Fatalf("in-flight count leaked on the healthy path: per-key %d, total %d", per, total)
	}
}

// Negative: concurrent callers of a healthy tool coalesce, so the
// in-flight count stays at one and nobody is refused. This is the
// property the per-key limit of 2 is chosen to leave room for.
func TestConcurrentHealthyCallersAreNotRefused(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	errs := make([]error, 32)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, errs[i] = c.Do(ctx, "k", func() (Entry, error) {
				time.Sleep(5 * time.Millisecond)
				return Entry{TTL: time.Minute}, nil
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent healthy caller %d refused: %v", i, err)
		}
	}
}

// The per-key bound cannot bound the process on its own: the key
// includes the canonicalised args, so a caller varying one argument
// produces an unbounded number of distinct keys, each with its own
// per-key allowance. That is reachable by any caller holding a valid
// certificate and staying inside its rate limit.
func TestDistinctKeysCannotAccumulateWithoutLimit(t *testing.T) {
	c := New()
	b := newBlocker()
	defer close(b.release)

	for i := 0; i < MaxInFlightTotal*2; i++ {
		shortCall(t, c, fmt.Sprintf("k%d", i), b.fn)
	}

	if got := int(b.started.Load()); got > MaxInFlightTotal+1 {
		t.Errorf("%d distinct keys started %d invocations; the total bound is "+
			"%d — varying an argument still leaks without limit",
			MaxInFlightTotal*2, got, MaxInFlightTotal)
	}
	if _, total := c.InFlight("k0"); total > MaxInFlightTotal+1 {
		t.Errorf("total in-flight %d exceeds the bound %d", total, MaxInFlightTotal)
	}
}
