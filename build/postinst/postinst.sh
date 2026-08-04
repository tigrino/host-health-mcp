#!/bin/sh
# Debian post-install scriptlet. Idempotent.
#
# Runs as postinst; $1 is "configure" on install and upgrade.
set -eu

[ "${1:-configure}" = "configure" ] || exit 0

USER=host-health-mcp
GROUP=host-health-mcp
HOME_DIR=/var/lib/host-health-mcp

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
    systemctl --system daemon-reload >/dev/null 2>&1 || true

    # Restart only what is already running. On a first install nothing
    # is active, so nothing starts — installing the package must not
    # bring up a listener on its own. On an upgrade this is what makes
    # the new binary and the regenerated drop-in take effect.
    #
    # deb-systemd-invoke honours policy-rc.d, which matters in chroots
    # and on build hosts; plain systemctl does not. Restart the helper
    # first: the daemon dials its socket per call and reconnects.
    for unit in host-health-mcp-helper.service host-health-mcp.service; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            if command -v deb-systemd-invoke >/dev/null 2>&1; then
                deb-systemd-invoke restart "$unit" >/dev/null 2>&1 || true
            else
                systemctl restart "$unit" >/dev/null 2>&1 || true
            fi
            echo "host-health-mcp-server: restarted $unit" >&2
        fi
    done
fi

echo "host-health-mcp-server: installed. Place TLS material under" \
     "/etc/host-health-mcp/tls/, copy the examples from" \
     "/usr/share/doc/host-health-mcp-server/examples/ into" \
     "/etc/host-health-mcp/ and customise them, then" \
     "'systemctl enable --now host-health-mcp'." >&2
