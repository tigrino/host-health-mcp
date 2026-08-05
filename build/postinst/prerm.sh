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

case "${1:-}" in
    remove)
        ;;
    *)
        exit 0
        ;;
esac

[ -d /run/systemd/system ] || exit 0

# Daemon first: it is the network listener, and it is the half that
# should stop accepting before its privileged backend goes away.
for unit in host-health-mcp.service host-health-mcp-helper.service; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        # deb-systemd-invoke honours policy-rc.d; plain systemctl does not.
        if command -v deb-systemd-invoke >/dev/null 2>&1; then
            deb-systemd-invoke stop "$unit" >/dev/null 2>&1 || true
        else
            systemctl stop "$unit" >/dev/null 2>&1 || true
        fi
    fi
done
