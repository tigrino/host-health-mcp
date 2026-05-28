// Package ratelimit implements the two-level token-bucket limiter
// described in design §8 and REQ 6.6. A per-caller global bucket plus
// optional per-(caller, tool) buckets for expensive tools. Both must
// permit a request for it to proceed. The limiter never sleeps a
// worker; exceeded buckets reject with an error.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// BucketCfg configures one token bucket. Disabled short-circuits
// Allow() for the per-tool case, which means "operator explicitly
// opted this tool out of per-tool bucketing" — distinct from
// "tool is not in the expensive set" (no per-tool config at all).
type BucketCfg struct {
	SustainedPerMin int
	Burst           int
	Disabled        bool
}

// Limiter is the two-level limiter.
type Limiter struct {
	global    BucketCfg
	perTool   map[string]BucketCfg
	expensive map[string]bool

	mu          sync.Mutex
	globalBkts  map[string]*bucket
	toolBkts    map[string]*bucket // keyed by caller+":"+tool
	lastSwept   time.Time
	sweepEvery  time.Duration
}

// New constructs a Limiter. global applies to every caller; perTool is
// the map of tool name to per-(caller, tool) bucket config for the
// expensive set.
func New(global BucketCfg, perTool map[string]BucketCfg) *Limiter {
	exp := make(map[string]bool, len(perTool))
	for k := range perTool {
		exp[k] = true
	}
	return &Limiter{
		global:     global,
		perTool:    perTool,
		expensive:  exp,
		globalBkts: make(map[string]*bucket),
		toolBkts:   make(map[string]*bucket),
		lastSwept:  time.Now(),
		sweepEvery: 5 * time.Minute,
	}
}

// RunSweeper starts a background goroutine that sweeps idle buckets
// at a fixed interval (1 min). Stops when ctx is cancelled. The
// Allow path's lazy sweep alone is not enough to bound map growth
// under a caller-CN flux; the goroutine guarantees forward progress.
func (l *Limiter) RunSweeper(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			l.mu.Lock()
			l.sweepLocked(now)
			l.lastSwept = now
			l.mu.Unlock()
		}
	}
}

// Allow reports whether the call should proceed. caller is the
// SO_PEERCRED-derived or cert-subject identity; tool is the tool name.
// Returns "global" or "tool" as reason when denied.
func (l *Limiter) Allow(caller, tool string) (ok bool, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.lastSwept) > l.sweepEvery {
		l.sweepLocked(now)
		l.lastSwept = now
	}

	gb := l.globalBkts[caller]
	if gb == nil {
		gb = newBucket(l.global, now)
		l.globalBkts[caller] = gb
	}
	if !gb.tryTake(now) {
		return false, "global"
	}

	if l.expensive[tool] {
		cfg := l.perTool[tool]
		if cfg.Disabled {
			// Operator explicitly opted out of per-tool bucketing for
			// this tool. The global bucket still applies above.
			return true, ""
		}
		key := caller + ":" + tool
		tb := l.toolBkts[key]
		if tb == nil {
			tb = newBucket(cfg, now)
			l.toolBkts[key] = tb
		}
		if !tb.tryTake(now) {
			// Refund the global token; conservative would be to charge it,
			// but charging on tool-bucket-reject conflates the two error
			// sources for the caller. Refund keeps the global meter
			// honest.
			gb.refund(now)
			return false, "tool"
		}
	}
	return true, ""
}

func (l *Limiter) sweepLocked(now time.Time) {
	const idle = 10 * time.Minute
	for k, b := range l.globalBkts {
		if now.Sub(b.lastTouched) > idle {
			delete(l.globalBkts, k)
		}
	}
	for k, b := range l.toolBkts {
		if now.Sub(b.lastTouched) > idle {
			delete(l.toolBkts, k)
		}
	}
}

// bucket is one token bucket. Tokens accrue continuously at
// SustainedPerMin/60 per second; tokens hold up to Burst.
type bucket struct {
	cfg         BucketCfg
	tokens      float64
	lastFill    time.Time
	lastTouched time.Time
}

func newBucket(cfg BucketCfg, now time.Time) *bucket {
	return &bucket{cfg: cfg, tokens: float64(cfg.Burst), lastFill: now, lastTouched: now}
}

func (b *bucket) tryTake(now time.Time) bool {
	if b.cfg.SustainedPerMin == 0 && b.cfg.Burst == 0 {
		return true
	}
	dt := now.Sub(b.lastFill).Seconds()
	rate := float64(b.cfg.SustainedPerMin) / 60
	b.tokens += dt * rate
	b.lastFill = now
	if b.tokens > float64(b.cfg.Burst) {
		b.tokens = float64(b.cfg.Burst)
	}
	b.lastTouched = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// refund returns a global-bucket token to a caller whose tool-bucket
// take then failed. Marking lastTouched here matters because the
// caller IS active — without it, a caller bursting against a
// tool-bucket cap could go indefinite-refund and still appear idle
// to the sweeper, getting evicted prematurely.
func (b *bucket) refund(now time.Time) {
	b.tokens++
	if b.tokens > float64(b.cfg.Burst) {
		b.tokens = float64(b.cfg.Burst)
	}
	b.lastTouched = now
}
