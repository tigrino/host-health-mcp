// Command capstemplate generates the helper unit's
// CapabilityBoundingSet drop-in, and the daemon unit's optional
// IPAddressAllow drop-in, from the operator's configuration. It ships
// as /usr/sbin/host-health-mcp-caps-template, runs from the .deb's
// post-install scriptlet, and is re-run by the operator after editing
// manifest.yml. See design-overview.md section 7 (capability
// templating).
//
// It replaces a POSIX shell script that scanned the same YAML with
// grep and awk. That scanner understood only block sequences, so
// `enabled_tools: [storage]` — the same document to any YAML parser —
// aborted the package configure, and a multi-line flow sequence
// slipped past its guard to produce an empty capability set in
// silence. This binary uses the decoder the daemon itself uses, so
// there is one grammar for the file rather than two.
//
// It is a generator, not a validator. It warns about what it does not
// recognise and carries on; the daemon remains the authority on
// whether a configuration is valid, and refuses to start on one that
// is not.
//
// Usage: host-health-mcp-caps-template [--hint]
//
//	--hint  Print how to activate the generated drop-in. Off by
//	        default. The generator runs non-interactively from the
//	        postinst, and on a fleet upgraded by unattended-upgrades
//	        its output lands in an automated report with no human in
//	        it. A line phrased as a required manual step, in a channel
//	        where nobody can act on it, is indistinguishable from a
//	        genuine action-required notice and trains the reader to
//	        ignore the channel. Everything printed by default states a
//	        fact about what was done.
//
//	        A flag rather than a TTY check: explicit, testable, and the
//	        postinst simply does not pass it.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"host-health-mcp/daemon/internal/daemon/config"
	"host-health-mcp/daemon/internal/shared/capsplan"
)

// selfPath is the installed path, embedded in the generated headers so
// an operator reading a drop-in knows what produced it and what to
// re-run. A constant rather than os.Args[0] so the header does not
// change when the binary is exercised from a test or a build tree.
const selfPath = "/usr/sbin/host-health-mcp-caps-template"

const usage = `Generates the helper unit's CapabilityBoundingSet drop-in from the
operator's manifest.yml, and the daemon unit's IPAddressAllow drop-in
from daemon.yml. Run by the .deb's post-install scriptlet and re-run by
the operator after editing either file.

Usage: host-health-mcp-caps-template [--hint]

  --hint  Print how to activate the generated drop-in. Off by default;
          the postinst does not pass it.

Paths may be overridden for testing:
  MANIFEST, DROPIN_DIR, DAEMON_DROPIN_DIR, DAEMON_YML`

const prefix = "caps-template: "

func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, prefix+format+"\n", args...)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	hint := false
	for _, a := range args {
		switch a {
		case "--hint":
			hint = true
		case "-h", "--help":
			fmt.Println(usage)
			return 0
		default:
			warn("unknown argument %q", a)
			return 2
		}
	}

	manifestPath := env("MANIFEST", "/etc/host-health-mcp/manifest.yml")
	dropinDir := env("DROPIN_DIR", "/etc/systemd/system/host-health-mcp-helper.service.d")
	daemonDropinDir := env("DAEMON_DROPIN_DIR", "/etc/systemd/system/host-health-mcp.service.d")
	daemonYML := env("DAEMON_YML", "/etc/host-health-mcp/daemon.yml")

	// Retiring the <= 2.0.0 daemon drop-in happens before anything can
	// exit early: it denied inbound traffic and left the listener
	// unreachable, so it must go even on a host with no manifest.
	stale := filepath.Join(daemonDropinDir, "10-ip-egress.conf")
	if _, err := os.Stat(stale); err == nil {
		if err := os.Remove(stale); err != nil {
			warn("ERROR: could not remove obsolete %s: %v", stale, err)
			return 1
		}
		warn("removed obsolete %s (it also blocked inbound traffic)", stale)
	} else if !errors.Is(err, os.ErrNotExist) {
		warn("ERROR: could not check %s: %v", stale, err)
		return 1
	}

	if _, err := os.Stat(manifestPath); errors.Is(err, os.ErrNotExist) {
		warn("manifest.yml not present; leaving CapabilityBoundingSet empty")
		return 0
	} else if err != nil {
		warn("ERROR: could not check %s: %v", manifestPath, err)
		return 1
	}

	m, mWarnings, err := config.LoadManifestLenient(manifestPath)
	for _, w := range mWarnings {
		warn("warning: %s", w)
	}
	if err != nil {
		warn("ERROR: %v", err)
		warn("  the capability set cannot be derived from a file that will not parse;")
		warn("  fix %s and re-run %s", manifestPath, selfPath)
		return 1
	}

	p := capsplan.For(m.EnabledTools, m.WorkloadPlugins, m.StorageBackends)
	for _, n := range p.Notes {
		warn("%s", n)
	}
	for _, w := range p.Warnings {
		warn("warning: %s", w)
	}

	rc := 0

	// daemon.yml is optional here: a host may be configured before its
	// daemon.yml exists, and the helper's capabilities do not depend on
	// it. A daemon.yml that will not parse is reported and costs the
	// IP-filter drop-in, not the capability drop-in.
	filterPath := filepath.Join(daemonDropinDir, "10-ip-filter.conf")
	var allow []string
	if _, err := os.Stat(daemonYML); err == nil {
		d, dWarnings, derr := config.LoadDaemonLenient(daemonYML)
		for _, w := range dWarnings {
			warn("warning: %s", w)
		}
		if derr != nil {
			warn("ERROR: %v", derr)
			warn("  no IP filter drop-in written; %s is unchanged", filterPath)
			rc = 1
		} else {
			allow = d.IPFilterAllow
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		warn("ERROR: could not check %s: %v", daemonYML, err)
		rc = 1
	}

	if len(allow) > 0 {
		if err := writeFile(daemonDropinDir, filterPath, renderIPFilter(daemonYML, allow)); err != nil {
			warn("ERROR: %v", err)
			rc = 1
		} else {
			warn("wrote %s", filterPath)
		}
	} else if rc == 0 {
		warn("ip_filter_allow absent or empty; no IP filter drop-in written")
	}

	dropin := filepath.Join(dropinDir, "caps.conf")
	if err := writeFile(dropinDir, dropin, renderCaps(manifestPath, p)); err != nil {
		warn("ERROR: %v", err)
		return 1
	}
	warn("wrote %s", dropin)

	if hint {
		warn("run 'systemctl daemon-reload && systemctl restart host-health-mcp-helper.service' to apply")
	}
	return rc
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

// writeFile creates dir if needed and writes content to path.
//
// Not atomic by design. systemd reads these drop-ins only on
// daemon-reload, which the postinst issues after this program has
// exited, so there is no reader to observe a partial file; and a
// rename-into-place would leave a stray temporary behind under
// /etc/systemd/system/ on a crash, where systemd would parse it as a
// second drop-in.
func writeFile(dir, path, content string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// renderCaps produces the helper drop-in. The trailing space after
// each capability, and the bare `AmbientCapabilities=` when the set is
// empty, reproduce the shell generator's output byte for byte so an
// upgrade does not rewrite every host's drop-in with a cosmetic diff.
func renderCaps(manifestPath string, p capsplan.Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Auto-generated by %s\n", selfPath)
	fmt.Fprintf(&b, "# from %s.\n", manifestPath)
	fmt.Fprintf(&b, "# Edit %s and re-run the generator to refresh.\n", manifestPath)
	b.WriteString("[Service]\n")
	b.WriteString("CapabilityBoundingSet=")
	for _, c := range p.Bounding {
		b.WriteString(c)
		b.WriteString(" ")
	}
	b.WriteString("\n")
	b.WriteString("AmbientCapabilities=")
	for _, c := range p.Ambient {
		b.WriteString(c)
		b.WriteString(" ")
	}
	b.WriteString("\n")
	return b.String()
}

func renderIPFilter(daemonYML string, allow []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Auto-generated by %s\n", selfPath)
	fmt.Fprintf(&b, "# from %s (ip_filter_allow).\n", daemonYML)
	b.WriteString("# NOTE: these rules apply to inbound AND outbound packets.\n")
	b.WriteString("[Service]\n")
	b.WriteString("IPAddressDeny=any\n")
	for _, r := range allow {
		fmt.Fprintf(&b, "IPAddressAllow=%s\n", r)
	}
	return b.String()
}
