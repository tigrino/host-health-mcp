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

// Cache is the global cache keyed by (tool, args_hash).
// Per-tool entry-count cap deliberately not enforced; on the deployment target the memory budget headroom is ample and the singleflight+TTL design bounds memory growth in practice.
type Cache struct {
	mu sync.RWMutex
	m  map[string]Entry

	sf singleflight.Group
}

// New returns an empty Cache.
func New() *Cache {
	return &Cache{m: make(map[string]Entry)}
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

// Store inserts or replaces an entry under key.
func (c *Cache) Store(key string, e Entry) {
	c.mu.Lock()
	c.m[key] = e
	c.mu.Unlock()
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
// against a genuinely stuck fn. That is the deliberate trade — a leak
// that is visible in the goroutine count and self-heals, over a tool
// that stays silently dead. Callers that can block in an
// uninterruptible syscall should still avoid getting there; see
// readMounts in the system tool.
func (c *Cache) Do(ctx context.Context, k string, fn func() (Entry, error)) (Entry, error) {
	ch := c.sf.DoChan(k, func() (v any, err error) {
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
	for k, e := range c.m {
		if e.Expired() {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}
