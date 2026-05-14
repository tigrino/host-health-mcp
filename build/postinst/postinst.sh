#!/bin/sh
# Debian post-install scriptlet. Idempotent.
set -eu

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

# Generate the helper's CapabilityBoundingSet drop-in.
/usr/local/share/host-health-mcp/caps-template.sh || true

systemctl daemon-reload || true

# Enable but do not start; the operator places real configuration
# (TLS material, daemon.yml, manifest.yml) before first start.
systemctl enable host-health-mcp-helper.service || true
systemctl enable host-health-mcp.service || true

echo "host-health-mcp: installed. Place TLS material under" \
     "/etc/host-health-mcp/tls/, customise /etc/host-health-mcp/" \
     "{daemon,helper,manifest}.yml, then 'systemctl start host-health-mcp'." >&2
