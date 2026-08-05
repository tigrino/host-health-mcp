#!/bin/sh
# Debian pre-removal scriptlet.
#
# SCOPE: this script ships in the .deb built by build/build.sh — the
# offline install path (doc/install.md 1.2). Packages built by a
# separate packaging pipeline carry their own maintainer scripts and
# never run this file. A change here does not reach a repository-
# installed host until the same change is made there, which is a
# release-note item, not an implementation detail.
#
# $1 is "remove" when the package is going away, "upgrade" when a new
# version is about to replace it, "deconfigure" on a dependency
# rearrangement.
#
# Stop the units on removal only. On upgrade the postinst restarts
# whatever was running, which keeps the service down for a moment
# rather than for the whole unpack.
#
# Without this the unit files were deleted from under two running
# services: systemd kept the old unit definitions in memory, the
# daemon carried on serving from a binary that no longer existed on
# disk, and the helper kept its root privileges and its socket. The
# package looked removed and was still listening.
set -eu

ME=$(basename "$0")
rc=0
stop_rc=0

case "${1:-}" in
    remove)
        ;;
    *)
        exit 0
        ;;
esac

if [ ! -d /run/systemd/system ]; then
    # systemd is not running — a chroot or a container image build.
    # There is nothing to stop, and that is a correct outcome rather
    # than a degraded one; the caller has no action to take.
    echo "$ME: systemd is not running; no units to stop" >&2
    exit 0
fi

# Daemon first: it is the network listener, and it is the half that
# should stop accepting before its privileged backend goes away.
for unit in host-health-mcp.service host-health-mcp-helper.service; do
    # Non-zero from is-active is an answer (3 inactive, 4 no such unit),
    # not a failure. Nothing to stop, nothing to report.
    if ! systemctl is-active --quiet "$unit"; then
        continue
    fi

    # deb-systemd-invoke honours policy-rc.d; plain systemctl does not.
    # command -v is a predicate; its stdout is the resolved path.
    if command -v deb-systemd-invoke >/dev/null; then
        stop_out=$(deb-systemd-invoke stop "$unit" 2>&1) || stop_rc=$?
    else
        stop_out=$(systemctl stop "$unit" 2>&1) || stop_rc=$?
    fi
    if [ "${stop_rc:-0}" -ne 0 ]; then
        echo "$ME: ERROR: stop of $unit exited ${stop_rc}:" >&2
        if [ -n "$stop_out" ]; then
            echo "$stop_out" | sed "s/^/$ME:   /" >&2
        fi
        rc=1
    elif [ -n "$stop_out" ]; then
        echo "$stop_out" | sed "s/^/$ME:   /" >&2
    fi
    stop_rc=0

    # Verify the effect. A stop that exits 0 has not necessarily
    # stopped anything, and a unit still running while its files are
    # removed underneath it is worth knowing about before dpkg
    # proceeds.
    if systemctl is-active --quiet "$unit"; then
        echo "$ME: ERROR: $unit is STILL running after stop." >&2
        echo "$ME:   systemctl status $unit" >&2
        rc=1
    else
        echo "$ME: $unit stopped" >&2
    fi
done

# Deliberately NOT fatal, and deliberately asymmetric with postinst.
#
# postinst exits non-zero when a unit fails to come back, because a
# dead daemon behind a successful `apt` run is a monitoring outage
# nobody is told about, and the failed configure is the only thing that
# surfaces it.
#
# Removal is the opposite case. A unit that will not stop is often
# exactly why an operator is removing the package, and failing here
# would leave it un-removable without hand intervention — turning a
# stuck service into a stuck service AND a stuck package. Everything
# above is still reported in full; only the exit status is withheld.
if [ "$rc" -ne 0 ]; then
    echo "$ME: pre-removal finished with errors (see above), but is not" >&2
    echo "$ME:   failing the removal: a unit that will not stop is often the" >&2
    echo "$ME:   reason for removing the package. Check the units afterwards:" >&2
    echo "$ME:   systemctl status host-health-mcp host-health-mcp-helper" >&2
fi

exit 0
