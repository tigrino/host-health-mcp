// Package redact implements the positive-list redaction filter
// described in REQ 6.3. Tokens that match the configured safe set pass
// through; anything else is replaced with "<redacted>". The filter is
// fed by sample messages from the logs tool (REQ 4.10), by the
// daemon's mail-failure-reason field, and by the daemon-side
// post-processing of forwarded helper subprocess stderr prefixes
// (helperinvoke.HelperError.AsOpError, threat-model §6.7).
package redact

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const placeholder = "<redacted>"

// Rules drives the filter. Anything not described as safe by Rules is
// replaced with placeholder.
type Rules struct {
	// IPv4Allow accepts addresses inside the operator-declared CIDRs.
	IPv4Allow []netip.Prefix
	// IPv6Allow accepts addresses inside the operator-declared CIDRs.
	IPv6Allow []netip.Prefix
	// SensitiveDirs are filesystem-path prefixes the operator marks as
	// sensitive in daemon.yml. Any token starting with one of these
	// prefixes is scrubbed.
	SensitiveDirs []string

	// ScrubPatterns are operator-supplied regexps loaded from the file
	// named by daemon.yml's log_redaction_rules. A token matching any
	// of them is scrubbed even when the positive list would keep it.
	//
	// This is the escape hatch for anything the built-in classes
	// deliberately pass — email addresses being the obvious one, since
	// safeToken keeps them by design. Before this existed the config
	// key was parsed, documented, shipped in the example, and read by
	// nothing at all: an operator writing custom rules got a silent
	// no-op, which is worse than not offering the knob.
	ScrubPatterns []*regexp.Regexp
}

// RuleFile is the shape of the file named by log_redaction_rules.
type RuleFile struct {
	// ScrubPatterns are Go regexps. A token matching any of them is
	// replaced with the placeholder. Matching is match-anywhere, so
	// anchor with ^...$ when a whole-token match is intended.
	ScrubPatterns []string `yaml:"scrub_patterns"`
}

// MaxRuleFileBytes bounds the rules file. tokenSafe walks every
// pattern for every token on the logs hot path, so pattern count is a
// direct per-token multiplier; this is a sanity bound, not a security
// boundary (the file is operator-supplied and read once at startup).
const MaxRuleFileBytes = 64 * 1024

// LoadRuleFile reads and compiles the operator's redaction rules.
//
// Error semantics are deliberately split, and the distinction matters
// enough to state plainly:
//
//   - Empty path: the key is optional. No rules, no error.
//   - Path set but the file is ABSENT: os.ErrNotExist is returned for
//     the caller to warn about and continue. The operator has not
//     written any rules, so there is nothing to fail closed over — and
//     making this fatal would have bricked every deployment that
//     copied the shipped daemon.yml, which names this path with no
//     corresponding file installed anywhere.
//   - File present but unparseable, or a regexp that does not compile:
//     FATAL. Here the operator did write rules and would otherwise get
//     silently weaker redaction than they asked for, which is the
//     failure mode this whole key exists to remove.
func LoadRuleFile(path string) ([]*regexp.Regexp, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		// Returned unwrapped-enough for errors.Is; the caller decides.
		return nil, err
	}
	if st.Size() > MaxRuleFileBytes {
		return nil, fmt.Errorf("redact: %s is %d bytes, over the %d-byte cap", path, st.Size(), MaxRuleFileBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("redact: read %s: %w", path, err)
	}
	var rf RuleFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&rf); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("redact: parse %s: %w", path, err)
	}
	out := make([]*regexp.Regexp, 0, len(rf.ScrubPatterns))
	for i, p := range rf.ScrubPatterns {
		// An empty or whitespace-only pattern matches every token and
		// would turn the whole of logs[] into <redacted> — fail-closed,
		// but silently, and almost certainly a stray list entry rather
		// than an intent to redact everything.
		if strings.TrimSpace(p) == "" {
			return nil, fmt.Errorf("redact: %s scrub_patterns[%d] is empty; it would match every token", path, i)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("redact: %s scrub_patterns[%d] %q: %w", path, i, p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Filter holds compiled state.
type Filter struct {
	rules Rules

	// Patterns we recognise as safe (in addition to allowlisted IPs).
	// safeToken covers bare service / unit names ("nginx",
	// "ssh@1234.service"), short ASCII identifiers, and well-shaped
	// emails. Runs AFTER the explicit scrub classes below.
	safeToken *regexp.Regexp

	// Pre-scrub classes. Each matches inside a token and forces the
	// whole token to <redacted> regardless of safeToken's verdict.
	awsKey  *regexp.Regexp
	jwt     *regexp.Regexp
	bigBlob *regexp.Regexp
	uuid    *regexp.Regexp
}

// New returns a Filter configured by rules.
func New(rules Rules) *Filter {
	return &Filter{
		rules: rules,
		// safeToken: alphanumeric + dot + @ + dash + underscore, length
		// up to 64. Keeps "albert@tigr.net" and "ssh@1234.service".
		// Excludes ':' (no legitimate use) and excludes raw colons that
		// previously slipped through (REQ 6.3).
		safeToken: regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._@-]{0,63}$`),
		// awsKey: AKIA/ASIA followed by 16 uppercase alphanumerics.
		awsKey: regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`),
		// jwt: three dot-separated base64url segments ≥8 chars each.
		// Email addresses have a single '@' and one or two dots, so
		// they cannot match (≥3 dotted ≥8-char segments).
		jwt: regexp.MustCompile(`[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		// bigBlob: 33+ base64-ish chars without '@' or '.' (so an
		// email or a dotted identifier is not caught here). UUIDs
		// pass the anchored exemption below before this check runs.
		bigBlob: regexp.MustCompile(`[A-Za-z0-9+/=_-]{33,}`),
		// uuid: full 8-4-4-4-12 form, anchored so a UUID-shaped
		// substring inside a larger blob does not exempt it.
		uuid: regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`),
	}
}

// Redact rewrites s by replacing every token whose shape is not on the
// positive list with placeholder. Tokenisation is whitespace-based.
func (f *Filter) Redact(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Fields(s)
	for i, t := range parts {
		if !f.tokenSafe(t) {
			parts[i] = placeholder
		}
	}
	return strings.Join(parts, " ")
}

func (f *Filter) tokenSafe(t string) bool {
	// Operator patterns run FIRST — ahead of every built-in rule,
	// including the IP allowlist below and the UUID exemption further
	// down. They exist to scrub what the defaults would keep, so any
	// rule that could pre-empt them defeats the purpose.
	//
	// The IP branch is the one that made this ordering load-bearing:
	// it returns early for anything ParseAddr accepts, so with the
	// loop placed after it, "scrub one host inside an otherwise
	// allowlisted range" — the second most obvious use of this knob
	// after email — was silently ignored.
	for _, re := range f.rules.ScrubPatterns {
		if re.MatchString(t) {
			return false
		}
	}

	// IP addresses run next; they are the cheapest discriminator and
	// the safe-token pattern cannot represent them.
	if addr, err := netip.ParseAddr(t); err == nil {
		return f.addrAllowed(addr)
	}

	// Sensitive-dir prefix: drop any token that starts with one of the
	// operator-marked sensitive paths. Defended against both bare
	// path tokens and key=value forms ("path=/etc/secret/...").
	for _, d := range f.rules.SensitiveDirs {
		if d == "" {
			continue
		}
		if strings.HasPrefix(t, d) {
			return false
		}
		if i := strings.IndexByte(t, '='); i >= 0 {
			if strings.HasPrefix(t[i+1:], d) {
				return false
			}
		}
	}

	// Pre-scrub: AWS key, JWT triple, big blob. Match-anywhere on the
	// token so a key embedded in a larger string still triggers.
	if f.awsKey.MatchString(t) {
		return false
	}
	if f.jwt.MatchString(t) {
		return false
	}

	// UUID exemption: anchored match against the canonical 8-4-4-4-12
	// shape. Runs ahead of the safe-token check because UUIDs start
	// with a digit and so would otherwise fail safeToken.
	if f.uuid.MatchString(t) {
		return true
	}

	// Big-blob class: 33+ base64-ish chars without '@' or '.' (so a
	// dotted identifier or an email never lands here). UUIDs are
	// already exempted above.
	if !strings.ContainsAny(t, "@.") && f.bigBlob.MatchString(t) {
		return false
	}

	return f.safeToken.MatchString(t)
}

func (f *Filter) addrAllowed(addr netip.Addr) bool {
	if addr.Is4() || addr.Is4In6() {
		for _, p := range f.rules.IPv4Allow {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, p := range f.rules.IPv6Allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
