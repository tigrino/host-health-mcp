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
    systemctl --system disable \
        host-health-mcp.service host-health-mcp-helper.service >/dev/null 2>&1 || true
    systemctl --system daemon-reload >/dev/null 2>&1 || true
fi

# The generated drop-ins are not package files — caps-template writes
# them at install time — so dpkg does not know to remove them and they
# would outlive the package, applying a stale CapabilityBoundingSet to
# any later reinstall. Purge means purge.
if [ "${1:-}" = "purge" ]; then
    rm -f /etc/systemd/system/host-health-mcp-helper.service.d/caps.conf \
          /etc/systemd/system/host-health-mcp.service.d/10-ip-filter.conf \
          /etc/systemd/system/host-health-mcp.service.d/10-ip-egress.conf
    rmdir --ignore-fail-on-non-empty \
          /etc/systemd/system/host-health-mcp-helper.service.d \
          /etc/systemd/system/host-health-mcp.service.d 2>/dev/null || true
    if [ -d /run/systemd/system ]; then
        systemctl --system daemon-reload >/dev/null 2>&1 || true
    fi
fi
