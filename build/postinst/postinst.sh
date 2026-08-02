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

# Generate the helper's CapabilityBoundingSet drop-in. Not guarded:
# a helper that cannot have its capability set templated would run
# with an empty one, so a failure here must fail the install rather
# than install quietly and break at first start.
host-health-mcp-caps-template

# Unit reload and enablement are deliberately absent: dh_installsystemd
# generates equivalents that additionally honour policy-rc.d, --no-enable
# and chroot detection. Doing it here as well would enable twice.

echo "host-health-mcp-server: installed. Place TLS material under" \
     "/etc/host-health-mcp/tls/, copy the examples from" \
     "/usr/share/doc/host-health-mcp-server/examples/ into" \
     "/etc/host-health-mcp/ and customise them, then" \
     "'systemctl start host-health-mcp'." >&2
