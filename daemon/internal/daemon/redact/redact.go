// Package redact implements the positive-list redaction filter
// described in REQ 6.3. Tokens that match the configured safe set pass
// through; anything else is replaced with "<redacted>". The filter is
// fed exclusively by sample messages from the logs tool (REQ 4.10) and
// by the daemon's mail-failure-reason field; structural identifiers
// (REQ 6.2, threat-model R5) bypass it.
package redact

import (
	"net/netip"
	"regexp"
	"strings"
)

const placeholder = "<redacted>"

// Rules drives the filter. Anything not described as safe by Rules is
// replaced with placeholder.
type Rules struct {
	// IPv4Allow accepts addresses inside the operator-declared CIDRs.
	IPv4Allow []netip.Prefix
	// IPv6Allow accepts addresses inside the operator-declared CIDRs.
	IPv6Allow []netip.Prefix
}

// Filter holds compiled state.
type Filter struct {
	rules Rules

	// Patterns we recognise as safe (in addition to allowlisted IPs).
	// These cover bare service / unit names ("nginx", "ssh@1234.service"),
	// short ASCII identifiers, and well-shaped timestamps. Anything not
	// matched by one of these collapses to <redacted>.
	safeToken *regexp.Regexp
}

// New returns a Filter configured by rules.
func New(rules Rules) *Filter {
	return &Filter{
		rules:     rules,
		safeToken: regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._@:-]{0,63}$`),
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
	if addr, err := netip.ParseAddr(t); err == nil {
		return f.addrAllowed(addr)
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
