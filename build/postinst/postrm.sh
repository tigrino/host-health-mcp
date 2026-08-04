#!/bin/sh
# Debian post-removal scriptlet.
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
