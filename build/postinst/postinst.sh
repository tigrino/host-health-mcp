#!/bin/sh
# Debian post-install scriptlet. Idempotent.
#
# SCOPE: this script ships in the .deb built by build/build.sh — the
# offline install path (doc/install.md 1.2). Packages built by a
# separate packaging pipeline carry their own maintainer scripts and
# never run this file. A change here does not reach a repository-
# installed host until the same change is made there, which is a
# release-note item, not an implementation detail.
#
# Runs as postinst; $1 is "configure" on install and upgrade.
set -eu

ME=$(basename "$0")
# Accumulates the worst outcome seen. Every failure path sets it; the
# script exits with it. A message on stderr that leaves the exit status
# at 0 hides the failure from dpkg just as effectively as discarding
# the message would.
rc=0
restart_rc=0
status_rc=0

[ "${1:-configure}" = "configure" ] || exit 0

USER=host-health-mcp
GROUP=host-health-mcp
HOME_DIR=/var/lib/host-health-mcp

# getent is a QUERY used as a predicate: exit 0 means the entry exists,
# 2 means it does not. Its stdout is the passwd/group record itself,
# which carries no diagnostic value here, and any real error still
# reaches stderr untouched. This is case 3 in the shell-error-handling
# rules — a non-zero exit that is an answer, not a failure.
if ! getent group "$GROUP" >/dev/null; then
    addgroup --system "$GROUP"
fi
if ! getent passwd "$USER" >/dev/null; then
    adduser --system --no-create-home --home "$HOME_DIR" \
            --shell /usr/sbin/nologin --ingroup "$GROUP" "$USER"
fi

install -d -m 0750 -o "$USER" -g "$GROUP" "$HOME_DIR"
install -d -m 0750 -o root    -g "$GROUP" /etc/host-health-mcp/tls

# Generate the helper's CapabilityBoundingSet drop-in. Not guarded:
# a helper that cannot have its capability set templated would run
# with an empty one, so a failure here must fail the install rather
# than install quietly and break at first start.
host-health-mcp-caps-template

# Tell systemd about the unit files and the drop-in just generated.
#
# This used to be absent, on the stated grounds that dh_installsystemd
# emits equivalents. It does — for a debhelper build. These artefacts
# are built with nfpm, which emits no maintainer-script fragments at
# all, so nothing anywhere reloaded systemd or restarted anything: an
# upgrade installed a new binary that the running units kept ignoring,
# and a caps drop-in regenerated from an edited manifest.yml never took
# effect. The only hint was a line of advice printed by
# caps-template, which nobody reads on a fleet upgraded by
# unattended-upgrades.
#
# ENABLEMENT is still deliberately absent. Whether these units start at
# boot is the operator's decision, and a package that enables a network
# listener on install is making it for them.
if [ -d /run/systemd/system ]; then
    if ! reload_out=$(systemctl --system daemon-reload 2>&1); then
        echo "$ME: ERROR: systemctl daemon-reload failed:" >&2
        echo "$reload_out" | sed "s/^/$ME:   /" >&2
        echo "$ME:   the units below will restart against their OLD definitions" >&2
        rc=1
    fi

    # Restart only what is already running. On a first install nothing
    # is active, so nothing starts — installing the package must not
    # bring up a listener on its own. On an upgrade this is what makes
    # the new binary and the regenerated drop-in take effect.
    #
    # deb-systemd-invoke honours policy-rc.d, which matters in chroots
    # and on build hosts; plain systemctl does not. Restart the helper
    # first: the daemon dials its socket per call and reconnects.
    for unit in host-health-mcp-helper.service host-health-mcp.service; do
        # A non-zero exit here is an ANSWER, not a failure: 3 means
        # inactive, 4 means no such unit. Neither is something to
        # restart, and neither is an error worth reporting.
        if ! systemctl is-active --quiet "$unit"; then
            continue
        fi

        # command -v is a predicate; its stdout is the resolved path.
        if command -v deb-systemd-invoke >/dev/null; then
            restart_out=$(deb-systemd-invoke restart "$unit" 2>&1) || restart_rc=$?
        else
            restart_out=$(systemctl restart "$unit" 2>&1) || restart_rc=$?
        fi
        if [ "${restart_rc:-0}" -ne 0 ]; then
            echo "$ME: ERROR: restart of $unit exited ${restart_rc}:" >&2
            if [ -n "$restart_out" ]; then
                echo "$restart_out" | sed "s/^/$ME:   /" >&2
            fi
            rc=1
        elif [ -n "$restart_out" ]; then
            echo "$restart_out" | sed "s/^/$ME:   /" >&2
        fi
        restart_rc=0

        # Report what happened, not what was attempted. A restart that
        # exits 0 has not necessarily produced a running service, and
        # this is the check that catches a daemon rejecting a config
        # the previous version tolerated.
        if systemctl is-active --quiet "$unit"; then
            echo "$ME: $unit is running" >&2
        else
            echo "$ME: ERROR: $unit is NOT running after restart." >&2
            echo "$ME:   systemctl status $unit" >&2
            echo "$ME:   journalctl -u $unit -n 50" >&2
            # `status` exits non-zero for an inactive unit — which is
            # precisely the case we are in, so the non-zero is expected
            # and its OUTPUT is the diagnostic we want. Captured either
            # way and printed; nothing is discarded.
            status_out=$(systemctl --no-pager --lines=0 status "$unit" 2>&1) || status_rc=$?
            if [ -n "$status_out" ]; then
                echo "$status_out" | sed "s/^/$ME:   /" >&2
            else
                echo "$ME:   (systemctl status produced no output, exit ${status_rc:-0})" >&2
            fi
            status_rc=0
            rc=1
        fi
    done
fi

# A service that did not come back is reported through the exit status,
# not only on stderr. dpkg records a failed configure, `apt` says so,
# and the host shows up in any fleet report that reads package state —
# instead of a clean upgrade over a dead listener, which is what the
# previous `|| true` produced. Nothing above has been left half-done:
# files are installed and the unit definitions are in place, so
# `dpkg --configure` after fixing the cause completes normally.
if [ "$rc" -ne 0 ]; then
    echo "$ME: configuration finished with errors; see above." >&2
    exit "$rc"
fi

echo "host-health-mcp-server: installed. Place TLS material under" \
     "/etc/host-health-mcp/tls/, copy the examples from" \
     "/usr/share/doc/host-health-mcp-server/examples/ into" \
     "/etc/host-health-mcp/ and customise them, then" \
     "'systemctl enable --now host-health-mcp'." >&2
