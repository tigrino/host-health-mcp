#!/bin/sh
# Debian post-removal scriptlet.
#
# SCOPE: this script ships in the .deb built by build/build.sh — the
# offline install path (doc/install.md 1.2). Packages built by a
# separate packaging pipeline carry their own maintainer scripts and
# never run this file. A change here does not reach a repository-
# installed host until the same change is made there, which is a
# release-note item, not an implementation detail.
#
# $1 is "remove", "purge", "upgrade", "failed-upgrade", "abort-install",
# "abort-upgrade" or "disappear".
#
# The unit files are gone by the time this runs, so systemd still holds
# the old definitions until it is told. Reload on the paths where
# something was actually removed. On upgrade the postinst reloads
# instead, after the replacements are in place.
set -eu

ME=$(basename "$0")
rc=0

case "${1:-}" in
    remove|purge)
        ;;
    *)
        exit 0
        ;;
esac

if [ -d /run/systemd/system ]; then
    # Disable BEFORE the reload. The package never enables these units,
    # so it has no business leaving an enablement symlink behind
    # either: after `apt remove` an operator's own `systemctl enable`
    # link dangles, systemd complains on every reload, and a later
    # reinstall comes back silently enabled — a network listener
    # starting at boot because of a decision nobody made this time.
    # dh_installsystemd disables on remove for exactly this reason.
    # `disable` exits non-zero when a unit has no enablement symlink,
    # which is the normal case for this package — it never enables
    # them. That is an answer, not a failure, and it is why the output
    # is inspected rather than the status alone.
    if ! disable_out=$(systemctl --system disable \
            host-health-mcp.service host-health-mcp-helper.service 2>&1); then
        case "$disable_out" in
            *"not loaded"*|*"No such file"*|*"does not exist"*|"")
                : ;;
            *)
                echo "$ME: WARNING: disabling the units reported:" >&2
                echo "$disable_out" | sed "s/^/$ME:   /" >&2
                rc=1
                ;;
        esac
    elif [ -n "$disable_out" ]; then
        echo "$disable_out" | sed "s/^/$ME:   /" >&2
    fi
    if ! reload_out=$(systemctl --system daemon-reload 2>&1); then
        echo "$ME: ERROR: systemctl daemon-reload failed:" >&2
        echo "$reload_out" | sed "s/^/$ME:   /" >&2
        echo "$ME:   systemd still holds the removed unit definitions" >&2
        rc=1
    fi
fi

# The generated drop-ins are not package files — caps-template writes
# them at install time — so dpkg does not know to remove them and they
# would outlive the package, applying a stale CapabilityBoundingSet to
# any later reinstall. Purge means purge.
if [ "${1:-}" = "purge" ]; then
    # rm -f already exits 0 for a path that does not exist; it needs no
    # tolerance bolted on. A genuine failure here — a read-only /etc, an
    # immutable attribute — leaves a stale CapabilityBoundingSet behind
    # for any later reinstall, so it is reported.
    for f in /etc/systemd/system/host-health-mcp-helper.service.d/caps.conf \
             /etc/systemd/system/host-health-mcp.service.d/10-ip-filter.conf \
             /etc/systemd/system/host-health-mcp.service.d/10-ip-egress.conf; do
        if ! rm_out=$(rm -f "$f" 2>&1); then
            echo "$ME: ERROR: could not remove $f:" >&2
            echo "$rm_out" | sed "s/^/$ME:   /" >&2
            rc=1
        fi
    done

    # --ignore-fail-on-non-empty encodes the tolerance in a flag, which
    # says what it means. A directory an operator has put their own
    # drop-in into is theirs to keep; anything else failing is real.
    for d in /etc/systemd/system/host-health-mcp-helper.service.d \
             /etc/systemd/system/host-health-mcp.service.d; do
        if [ ! -d "$d" ]; then
            continue
        fi
        if ! rmdir_out=$(rmdir --ignore-fail-on-non-empty "$d" 2>&1); then
            echo "$ME: WARNING: could not remove $d:" >&2
            echo "$rmdir_out" | sed "s/^/$ME:   /" >&2
            rc=1
        fi
    done

    if [ -d /run/systemd/system ]; then
        if ! reload_out=$(systemctl --system daemon-reload 2>&1); then
            echo "$ME: ERROR: systemctl daemon-reload after purge failed:" >&2
            echo "$reload_out" | sed "s/^/$ME:   /" >&2
            rc=1
        fi
    fi
fi

# dpkg treats a failed postrm on purge as a package left half-removed,
# which is visible and recoverable. Silently leaving a stale drop-in
# that a later reinstall picks up is neither.
if [ "$rc" -ne 0 ]; then
    echo "$ME: post-removal finished with errors; see above." >&2
    exit "$rc"
fi
