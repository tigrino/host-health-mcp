// Package config parses /etc/host-health-mcp/helper.yml. The helper's
// own config is intentionally small: it carries the daemon's uid (for
// SO_PEERCRED enforcement), the socket path, and the per-op deadline
// overrides.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config is the typed shape of helper.yml.
type Config struct {
	// DaemonUser is the system user the daemon runs as. The helper
	// resolves the uid at startup and rejects any unix-socket peer
	// whose SO_PEERCRED reports a different uid.
	DaemonUser string `yaml:"daemon_user"`

	// SocketPath is the absolute path of the unix-socket the helper
	// listens on. Default /run/host-health-mcp/helper.sock.
	SocketPath string `yaml:"socket_path"`

	// OpDeadlineMS overrides the per-op deadline in milliseconds.
	// Missing keys keep the daemon-supplied default (per-tool timeout
	// minus exec.KillGrace).
	OpDeadlineMS map[string]int `yaml:"op_deadline_ms"`
}

// Defaults returns the conservative defaults applied when helper.yml is
// missing or partial.
func Defaults() Config {
	return Config{
		DaemonUser:   "host-health-mcp",
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

