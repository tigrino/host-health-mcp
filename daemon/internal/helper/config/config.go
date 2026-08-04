// Package config parses /etc/host-health-mcp/helper.yml. The helper's
// own config is intentionally small: it carries the daemon's uid (for
// SO_PEERCRED enforcement), the socket path, and the per-op deadline
// overrides.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the typed shape of helper.yml.
type Config struct {
	// DaemonUser is the system user the daemon runs as. The helper
	// resolves the uid at startup and rejects any unix-socket peer
	// whose SO_PEERCRED reports a different uid.
	DaemonUser string `yaml:"daemon_user"`

	// DaemonGroup is the system group that owns the helper socket so
	// the daemon can connect. Defaults to DaemonUser when empty; on
	// Debian a system useradd creates a matching group.
	DaemonGroup string `yaml:"daemon_group"`

	// SocketPath is the absolute path of the unix-socket the helper
	// listens on. Default /run/host-health-mcp/helper.sock.
	SocketPath string `yaml:"socket_path"`

	// OpDeadlineMS overrides the per-op deadline in milliseconds.
	// Missing keys use DefaultOpDeadline. Values are clamped to
	// [MinOpDeadline, MaxOpDeadline] by OpDeadline.
	OpDeadlineMS map[string]int `yaml:"op_deadline_ms"`

	// AccessLogPrefixes constrains which paths nginx_apache_status will
	// read. The path arrives in the request from the daemon, so the
	// allow-list has to live on the privileged side. Empty keeps the
	// built-in default of /var/log/.
	AccessLogPrefixes []string `yaml:"access_log_prefixes"`
}

// Per-op deadline bounds.
//
// DefaultOpDeadline applies only when the request frame carries no
// budget. On a normal call the daemon sends its own remaining budget,
// which is 500 ms less than whatever per-tool timeout applies — room
// for the SIGTERM -> KillGrace -> SIGKILL chain in helper/exec to
// finish before the daemon stops waiting, which is the relationship
// exec.go documents. 9500 ms is that subtraction applied to the 10 s
// ceiling REQ 5.1 puts on any per-tool timeout, so the fallback is
// never longer than the longest real call.
//
// MaxOpDeadline bounds an operator typo in helper.yml, not an attack:
// the helper's peer is the daemon, checked by SO_PEERCRED. It is
// deliberately close to the daemon's own ceiling — a value far above
// it would let a typo reproduce the symptom this deadline was added to
// remove (a subprocess outliving the request that started it), just
// finitely.
const (
	DefaultOpDeadline = 9500 * time.Millisecond
	MinOpDeadline     = 250 * time.Millisecond
	MaxOpDeadline     = 15 * time.Second
)

// maxDeadlineMS is the largest millisecond count that survives
// conversion to a time.Duration. Beyond it the multiply overflows
// int64 nanoseconds and goes negative; the Min clamp below would
// rescue the result, but by accident rather than by construction, and
// the "a peer may only shorten" property would be one refactor from
// inverting.
const maxDeadlineMS = int64(math.MaxInt64) / int64(time.Millisecond)

// OpDeadline returns the deadline to apply to op. callerMS is the
// daemon's remaining budget from the request frame; it is honoured
// only when it is shorter than the locally configured deadline, so a
// peer can ask for less time but never for more.
//
// The result is always in [MinOpDeadline, MaxOpDeadline]. It is never
// zero — context.WithTimeout treats a zero duration as already
// expired, which would fail every op rather than bounding it.
func (c Config) OpDeadline(op string, callerMS int) time.Duration {
	d := DefaultOpDeadline
	if v, ok := c.OpDeadlineMS[op]; ok && v > 0 {
		d = msToDuration(int64(v), MaxOpDeadline)
	}
	if d > MaxOpDeadline {
		d = MaxOpDeadline
	}
	// Narrowing only. The Min clamp comes after, so a peer asking for
	// 1 ms gets MinOpDeadline rather than a deadline that has already
	// expired.
	if callerMS > 0 {
		if caller := msToDuration(int64(callerMS), MaxOpDeadline); caller < d {
			d = caller
		}
	}
	if d < MinOpDeadline {
		d = MinOpDeadline
	}
	return d
}

// msToDuration converts a millisecond count to a Duration, saturating
// at ceiling rather than overflowing.
func msToDuration(ms int64, ceiling time.Duration) time.Duration {
	if ms > maxDeadlineMS {
		return ceiling
	}
	d := time.Duration(ms) * time.Millisecond
	if d > ceiling {
		return ceiling
	}
	return d
}

// Defaults returns the conservative defaults applied when helper.yml is
// missing or partial.
func Defaults() Config {
	return Config{
		DaemonUser:   "host-health-mcp",
		DaemonGroup:  "host-health-mcp",
		SocketPath:   "/run/host-health-mcp/helper.sock",
		OpDeadlineMS: map[string]int{},
	}
}

// Load reads path and merges its contents over Defaults(). It returns
// an error if path is present but contains unknown keys; the yaml.v3
// decoder is set to strict so a typo in helper.yml fails fast at start
// rather than silently degrading.
func Load(path string) (Config, error) {
	cfg := Defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("helper config: read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("helper config: parse %s: %w", path, err)
	}
	return cfg, nil
}

// ResolveUID resolves the configured daemon user to a numeric uid.
func (c Config) ResolveUID() (uint32, error) {
	u, err := user.Lookup(c.DaemonUser)
	if err != nil {
		return 0, fmt.Errorf("helper config: lookup user %s: %w", c.DaemonUser, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("helper config: parse uid %s: %w", u.Uid, err)
	}
	return uint32(uid), nil
}

// ResolveGID resolves the configured daemon group to a numeric gid.
// Falls back to DaemonUser when DaemonGroup is empty.
func (c Config) ResolveGID() (uint32, error) {
	name := c.DaemonGroup
	if name == "" {
		name = c.DaemonUser
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("helper config: lookup group %s: %w", name, err)
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("helper config: parse gid %s: %w", g.Gid, err)
	}
	return uint32(gid), nil
}
