// Package dns implements tool 4.4: resolver in use, self-hostname
// resolution, external probe resolution, canary check for transparent
// filtering. Each probe is strictly time-bounded; a timeout reports
// false and adds an envelope warning (design §7.3.2 per-source
// reporting; REQ 4.4).
package dns

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

// Data is the response data for tool dns. Mirrors DnsData in
// doc/schema-draft.yaml.
type Data struct {
	ResolverInUse         string `json:"resolver_in_use"`
	ResolvesSelfHostname  bool   `json:"resolves_self_hostname"`
	ResolvesExternalProbe bool   `json:"resolves_external_probe"`
	FilterCanaryBlocked   bool   `json:"filter_canary_blocked"`
}

// Probes are operator-supplied per the manifest / daemon.yml. The
// daemon never accepts probe targets from the caller (REQ 4.4); this
// struct carries the values resolved at startup.
type Probes struct {
	ExternalProbe string // hostname expected to resolve under normal egress
	FilterCanary  string // hostname that should NOT resolve through an upstream filter
}

// Tool is the registered tool.
type Tool struct {
	probes Probes

	// perProbeTimeout caps each individual lookup. Total tool budget
	// is therefore bounded by len(probes) * perProbeTimeout plus a
	// little overhead.
	perProbeTimeout time.Duration
}

// New returns a new tool instance.
func New(probes Probes) *Tool {
	return &Tool{probes: probes, perProbeTimeout: 800 * time.Millisecond}
}

// Name returns the tool name.
func (*Tool) Name() string { return "dns" }

// DefaultTTL: DNS state is volatile, but the routine inspection
// cadence does not need sub-second freshness.
func (*Tool) DefaultTTL() time.Duration { return 30 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 3 * time.Second }

// Handle runs the four probes serially under tight per-probe deadlines.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{}
	var warnings []string

	d.ResolverInUse = firstResolver()

	host, err := os.Hostname()
	if err != nil {
		warnings = append(warnings, "dns: hostname unavailable: "+err.Error())
	} else {
		ok, ferr := lookup(ctx, host, t.perProbeTimeout)
		d.ResolvesSelfHostname = ok
		if ferr != nil {
			warnings = append(warnings, "dns: self_hostname: "+ferr.Error())
		}
	}

	if t.probes.ExternalProbe != "" {
		ok, ferr := lookup(ctx, t.probes.ExternalProbe, t.perProbeTimeout)
		d.ResolvesExternalProbe = ok
		if ferr != nil {
			warnings = append(warnings, "dns: external_probe: "+ferr.Error())
		}
	}

	if t.probes.FilterCanary != "" {
		// The canary is configured to be a name that does NOT resolve
		// under an honest resolver. If it DOES resolve, the upstream
		// is rewriting or NX-redirecting; report that as
		// filter_canary_blocked=true (i.e. filtering is in effect).
		ok, ferr := lookup(ctx, t.probes.FilterCanary, t.perProbeTimeout)
		d.FilterCanaryBlocked = ok
		if ferr != nil && !isNXDomain(ferr) {
			warnings = append(warnings, "dns: filter_canary: "+ferr.Error())
		}
	}

	return d, warnings, nil
}

func lookup(ctx context.Context, name string, deadline time.Duration) (bool, error) {
	probeCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(probeCtx, name)
	if err != nil {
		return false, err
	}
	return len(addrs) > 0, nil
}

// firstResolver returns the address of the first nameserver listed in
// /etc/resolv.conf. systemd-resolved typically reports 127.0.0.53 here
// rather than the upstream DNS; that is the address the daemon's
// libc resolver actually uses, which is what REQ 4.4 asks for.
func firstResolver() string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "nameserver ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "nameserver"))
		}
	}
	return ""
}

// isNXDomain reports whether err looks like a clean NXDOMAIN. We
// don't surface NXDOMAIN as a warning on the filter canary because
// "the canary did not resolve" is the expected honest-resolver outcome.
func isNXDomain(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}
	return strings.Contains(err.Error(), "no such host")
}
