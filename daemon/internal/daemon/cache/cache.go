// Package cache implements the daemon's global in-process cache (REQ
// 5.1, design §6). Singleflight coalesces concurrent cache misses for
// the same (tool, args_hash) so a fork-storm cannot land on the
// helper.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Entry is one cached payload. Warnings is the tool's
// warnings[] slice as returned by Tool.Handle; it must travel
// alongside Data because warnings are properties of the tool run, not
// of the request, and must persist across cache hits.
type Entry struct {
	Data     json.RawMessage
	Warnings []string
	Builtat  time.Time
	TTL      time.Duration
}

// Age returns how long ago the entry was constructed.
func (e Entry) Age() time.Duration { return time.Since(e.Builtat) }

// Expired reports whether the entry has aged past its TTL.
func (e Entry) Expired() bool { return e.Age() > e.TTL }

// MaxEntries bounds the map. The previous note said a cap was
// unnecessary because singleflight plus TTL bounds growth in practice
// — but the key includes the canonicalised ARGS, so a caller varying
// a tool argument produces a distinct entry every time, and entries
// only leave on Sweep after their TTL. Between sweeps a caller within
// its rate limit can still accumulate them. This is the backstop.
const MaxEntries = 4096

// MaxInFlightPerKey bounds how many invocations of the same
// (tool, args) may be running at once. Singleflight holds this at one
// under normal operation; it rises above one only after a caller timed
// out and Forget let the next arrival start a fresh call while the
// previous one was still wedged. Two allows exactly one retry past a
// wedged call — enough to recover from a transient block, not enough
// to accumulate.
//
// MaxInFlightTotal is the same backstop across all keys, which the
// per-key limit cannot provide on its own: the key includes the
// canonicalised args, so a caller varying one argument produces an
// unbounded number of distinct keys, each entitled to its own
// per-key allowance. The daemon's own concurrency ceiling is the
// listener's connection cap, an order of magnitude below this.
const (
	MaxInFlightPerKey = 2
	MaxInFlightTotal  = 64
)

// ErrStalled is returned when a tool already has MaxInFlightPerKey
// invocations that have not returned, or the process is at
// MaxInFlightTotal overall. It is a distinct error because "this tool
// is wedged" and "this tool timed out" call for different operator
// action, and the unbounded version reported both as the latter.
var ErrStalled = errors.New("cache: tool has invocations that have not returned; not starting another")

// Cache is the global cache keyed by (tool, args_hash).
type Cache struct {
	mu sync.RWMutex
	m  map[string]Entry

	sf singleflight.Group

	// inFlight counts started-but-unreturned invocations of fn, per
	// key and in total. Maintained inside the singleflight closure, so
	// callers that JOIN an existing call are not counted — only calls
	// that actually start one.
	ifMu          sync.Mutex
	inFlight      map[string]int
	inFlightTotal int
	// stalled remembers which keys have already logged, so a wedged
	// tool on a polling path does not log once per poll. Bounded by
	// the number of keys that can reach the per-key cap, which is
	// itself bounded by MaxInFlightTotal.
	stalled map[string]bool
}

// New returns an empty Cache.
func New() *Cache {
	return &Cache{
		m:        make(map[string]Entry),
		inFlight: make(map[string]int),
		stalled:  make(map[string]bool),
	}
}

// admit reports whether a new invocation may start. The check is
// advisory: it runs before singleflight decides whether this caller
// leads or joins, so a race between two arrivals can let the count
// exceed a limit by one. That is acceptable for a backstop — the
// purpose is to stop unbounded accumulation, not to hold an exact
// ceiling — and singleflight coalescing means the common race
// produces one call, not two.
func (c *Cache) admit(k string) error {
	c.ifMu.Lock()
	defer c.ifMu.Unlock()
	if c.inFlight[k] >= MaxInFlightPerKey || c.inFlightTotal >= MaxInFlightTotal {
		return ErrStalled
	}
	return nil
}

func (c *Cache) enter(k string) {
	c.ifMu.Lock()
	defer c.ifMu.Unlock()
	c.inFlight[k]++
	c.inFlightTotal++
	if c.inFlight[k] >= MaxInFlightPerKey && !c.stalled[k] {
		c.stalled[k] = true
		log.Printf("cache: %s has %d invocations that have not returned; "+
			"further calls will be refused until one does", k, c.inFlight[k])
	}
}

func (c *Cache) leave(k string) {
	c.ifMu.Lock()
	defer c.ifMu.Unlock()
	c.inFlightTotal--
	if c.inFlight[k] <= 1 {
		delete(c.inFlight, k)
		delete(c.stalled, k)
		return
	}
	c.inFlight[k]--
}

// InFlight reports the number of started-but-unreturned invocations,
// per key and in total. For tests and for anything that wants to see
// the wedged-goroutine count without reading it out of a stack dump.
func (c *Cache) InFlight(k string) (perKey, total int) {
	c.ifMu.Lock()
	defer c.ifMu.Unlock()
	return c.inFlight[k], c.inFlightTotal
}

// Key constructs a stable cache key for a (tool, args) pair. args is
// the raw JSON request body; identical *semantic* bodies hash to the
// same key after canonicalisation (whitespace, key ordering). The
// request layer is responsible for rejecting non-JSON bodies before
// this function is called; canonicaliseJSON's invalid-input fallback
// is kept defensively but should be unreachable in production.
//
// The full SHA-256 (not a 16-byte truncation) is used: cache keys are
// short-lived strings in memory, the cost of 64 hex chars instead of
// 32 is trivial, and a 128-bit truncation gave a 2^64 birthday
// collision surface for a global cache shared across all callers.
func Key(tool string, args []byte) string {
	canon := canonicaliseJSON(args)
	h := sha256.New()
	h.Write([]byte(tool))
	h.Write([]byte{0})
	h.Write(canon)
	return tool + ":" + hex.EncodeToString(h.Sum(nil))
}

// canonicaliseJSON re-encodes the input through encoding/json so
// whitespace differences and (top-level) key ordering converge to a
// canonical form. json.Marshal sorts map keys lexicographically; for
// objects-of-objects this propagates. Arrays preserve order
// (semantically meaningful). Returns the original bytes when the
// input is not valid JSON.
func canonicaliseJSON(b []byte) []byte {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return b
	}
	out, err := json.Marshal(v)
	if err != nil {
		return b
	}
	return out
}

// Lookup returns the cached entry for key if it is present and not
// expired.
func (c *Cache) Lookup(key string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.m[key]
	if !ok || e.Expired() {
		return Entry{}, false
	}
	return e, true
}

// Store inserts or replaces an entry under key. At MaxEntries it
// first drops expired entries; if that frees nothing, the write is
// skipped rather than growing the map without bound. Skipping costs a
// cache miss on the next call, which is the correct way to fail here.
func (c *Cache) Store(key string, e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, replacing := c.m[key]; !replacing && len(c.m) >= MaxEntries {
		c.sweepLocked()
		if len(c.m) >= MaxEntries {
			return
		}
	}
	c.m[key] = e
}

// Do executes fn under singleflight keyed by k. Concurrent callers of
// Do with the same k will share one invocation of fn and one Entry.
// fn is expected to populate the cache itself on success.
//
// ctx bounds the CALLER's wait, not fn. singleflight.Do offers no
// cancellation, and this function used to accept ctx and never read
// it — so the per-tool timeout only bit for tools whose Handle
// observed ctx itself, i.e. the helper-backed ones. A tool that blocks
// in a syscall instead (unix.Statfs on a stale NFS mount, in D-state
// and uninterruptible) hung its handler goroutine forever, and because
// the call was in flight under singleflight every later caller for the
// same key joined the same stuck call. The tool was dead for the
// process lifetime and only a restart cleared it.
//
// Forget on DEADLINE is what makes that recoverable: the next caller
// starts a fresh call rather than joining the wedged one, so the tool
// works again as soon as the underlying cause clears.
//
// Forget is deliberately NOT called on plain cancellation. ctx here
// derives from the HTTP request, which net/http cancels when the
// client disconnects — so forgetting on cancel would let a caller that
// issues and aborts a request repeatedly drop the singleflight entry
// out from under a running leader, starting a second concurrent
// invocation of the same tool each time. That is a fork storm onto the
// helper, which is the exact thing this package exists to prevent (REQ
// 5.1).
//
// On a deadline a narrow overlap window does remain, and it is worth
// being exact about rather than claiming otherwise. Since the B-7 fix
// the work runs on its own context created INSIDE fn, so its deadline
// is strictly later than any caller's — by the scheduling delta
// between this call and the closure body, sub-millisecond in practice.
// A caller whose deadline fires in that gap calls Forget while the
// leader is still live, and the next arrival starts a second
// invocation. Bounded, rare, and preferable to the alternative:
// forgetting on cancel instead would hand that same overlap to any
// caller willing to disconnect on purpose.
//
// The residual cost is one abandoned goroutine per timed-out call
// against a genuinely stuck fn, and this does NOT self-heal — an
// earlier version of this comment claimed it did, which was wrong.
// Forget makes the next caller start a FRESH call, so a tool blocked
// in an uninterruptible syscall accumulates one wedged goroutine per
// poll, indefinitely, while every caller keeps paying the full
// timeout. A 30 s poll leaves 2880 wedged goroutines a day, each
// holding whatever the tool allocated.
//
// MaxInFlightPerKey and MaxInFlightTotal are what bound it. Past the
// per-key limit a caller is refused immediately instead of starting
// another doomed invocation, and the refusal names the condition
// rather than presenting as one more timeout.
//
// Recovery survives the bound: the count drops when the wedged call
// finally returns, so the tool works again as soon as the underlying
// cause clears — which is the same moment it would have under the
// unbounded version. What is given up is the case where the cause
// never clears, where this now reports a stalled tool instead of
// leaking a goroutine per poll forever. Callers that can block in an
// uninterruptible syscall should still avoid getting there; see
// readMounts in the system tool.
func (c *Cache) Do(ctx context.Context, k string, fn func() (Entry, error)) (Entry, error) {
	if err := c.admit(k); err != nil {
		return Entry{}, err
	}
	ch := c.sf.DoChan(k, func() (v any, err error) {
		c.enter(k)
		defer c.leave(k)

		// Contain panics inside fn. singleflight's DoChan path
		// re-throws a panicking call with `go panic(e)` in a bare
		// goroutine, which no recover can catch and which terminates
		// the process — where the plain Do path used to run fn on the
		// caller's goroutine and let net/http's per-connection recover
		// contain it. Without this, any nil-deref in any of the 19
		// tool handlers becomes a daemon outage reachable by a caller
		// holding a valid certificate, and systemd's StartLimitBurst
		// parks the unit after five hits.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("cache: tool panicked: %v\n%s", r, debug.Stack())
				err = fmt.Errorf("cache: tool panicked: %v", r)
			}
		}()
		return fn()
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return Entry{}, res.Err
		}
		return res.Val.(Entry), nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			c.sf.Forget(k)
		}
		return Entry{}, ctx.Err()
	}
}

// Sweep evicts entries whose age exceeds their TTL. Called by a
// background goroutine at min(TTL)/2.
func (c *Cache) Sweep() {
	c.mu.Lock()
	c.sweepLocked()
	c.mu.Unlock()
}

// sweepLocked evicts expired entries. Caller holds c.mu.
func (c *Cache) sweepLocked() {
	for k, e := range c.m {
		if e.Expired() {
			delete(c.m, k)
		}
	}
}
