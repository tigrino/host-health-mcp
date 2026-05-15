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
func (c *Cache) Do(ctx context.Context, k string, fn func() (Entry, error)) (Entry, error) {
	v, err, _ := c.sf.Do(k, func() (any, error) {
		return fn()
	})
	if err != nil {
		return Entry{}, err
	}
	return v.(Entry), nil
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
