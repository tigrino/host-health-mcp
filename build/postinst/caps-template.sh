#!/bin/sh
# Generates the helper unit's CapabilityBoundingSet drop-in from the
# operator's manifest.yml. Run by the .deb's post-install scriptlet
# and re-run by the operator after editing manifest.yml. See
# design-overview.md section 7 (capability templating).

set -eu

MANIFEST=${MANIFEST:-/etc/host-health-mcp/manifest.yml}
DROPIN_DIR=/etc/systemd/system/host-health-mcp-helper.service.d
DROPIN=${DROPIN_DIR}/caps.conf

# Retiring the <= 2.0.0 daemon drop-in happens before anything can exit
# early: it denied inbound traffic and left the listener unreachable, so
# it must go even on a host with no manifest.
DAEMON_DROPIN_DIR=/etc/systemd/system/host-health-mcp.service.d
DAEMON_STALE_DROPIN="$DAEMON_DROPIN_DIR/10-ip-egress.conf"
if [ -f "$DAEMON_STALE_DROPIN" ]; then
    rm -f "$DAEMON_STALE_DROPIN"
    echo "caps-template: removed obsolete $DAEMON_STALE_DROPIN (it also blocked inbound traffic)" >&2
fi

if [ ! -f "$MANIFEST" ]; then
    echo "caps-template: manifest.yml not present; leaving CapabilityBoundingSet empty" >&2
    exit 0
fi

# enabled_tools[] and workload_plugins[] in manifest.yml drive the cap
# union. The rules below mirror design 7.3 (Caps required column):
#
#   read_audit_status  -> CAP_AUDIT_CONTROL
#                          (AUDIT_GET shares audit_netlink_ok()'s
#                          CAP_AUDIT_CONTROL gate with the rule-
#                          modification opcodes; CAP_AUDIT_READ only
#                          gates audit_bind() for multicast event
#                          consumption — confirmed empirically on
#                          Debian 13 kernel 6.12.x.)
#   read_aide_summary  -> CAP_DAC_READ_SEARCH
#   read_reboot_marker -> (none)
#   smart_summary      -> CAP_SYS_RAWIO, CAP_DAC_READ_SEARCH
#   mdraid_detail      -> CAP_DAC_READ_SEARCH
#   lvm_report         -> CAP_DAC_READ_SEARCH
#   zpool_status       -> CAP_SYS_ADMIN
#   btrfs_scrub        -> CAP_DAC_READ_SEARCH
#   postqueue          -> (none)
#   wireguard_show     -> CAP_NET_ADMIN
#   apt_pending        -> (none)
#   needrestart        -> (none)
#   firewall           -> CAP_NET_ADMIN
#   firewall_lookup    -> CAP_NET_ADMIN
#                          (nft list ruleset reads kernel nftables
#                          state via netlink NFNL_SUBSYS_NFTABLES;
#                          unprivileged callers cannot enumerate
#                          tables/chains/sets on stock kernels.)
#   dovecot_status     -> (none)
#                          (systemctl is-active uses dbus; doveadm
#                          who connects to dovecot's master socket
#                          owned by root — uid=0 helper passes the
#                          DAC check via owner-mode.)
#   nginx_apache_status -> CAP_DAC_READ_SEARCH
#                          (Debian-default access logs are
#                          www-data:adm 0640; uid=0 helper without
#                          DAC_READ_SEARCH cannot read them since
#                          it matches neither owner nor group.)
#
# Tool-to-op mapping (REQ 4):
#   security        => read_audit_status, read_aide_summary
#   storage         => smart_summary, mdraid_detail, lvm_report,
#                      zpool_status, btrfs_scrub
#   mail            => postqueue
#   updates         => apt_pending, needrestart
#   workload+wg     => wireguard_show
#   system          => read_reboot_marker

caps=""
have() { echo "$enabled" | grep -qw "$1"; }
add()  { case " $caps " in *" $1 "*) ;; *) caps="$caps $1" ;; esac; }

# CAP_CHOWN is required regardless of which ops are enabled: the
# helper chowns its unix socket and runtime directory at startup so
# the daemon can connect. Keep it in the union always.
add CAP_CHOWN

# Crude YAML extraction: the lines we care about are flat arrays under
# enabled_tools: and workload_plugins:. python3 -c is an option if
# more rigour is needed; this script keeps to POSIX sh.
enabled=$(awk '
    /^enabled_tools:/ { in_tools=1; next }
    /^workload_plugins:/ { in_plug=1; next }
    /^[a-z_]+:/ { in_tools=0; in_plug=0; next }
    (in_tools || in_plug) && /^[[:space:]]*-/ {
        sub(/^[[:space:]]*-[[:space:]]*/, "")
        print
    }
' "$MANIFEST")

have security  && { add CAP_AUDIT_CONTROL; add CAP_DAC_READ_SEARCH; }
have storage   && { add CAP_SYS_RAWIO; add CAP_DAC_READ_SEARCH; add CAP_SYS_ADMIN; }
have mail      && true
have updates   && true
have workload  && have wireguard    && add CAP_NET_ADMIN
have workload  && have nginx_apache && add CAP_DAC_READ_SEARCH
have firewall        && add CAP_NET_ADMIN
have firewall_lookup && add CAP_NET_ADMIN

# Warn on names this script does not recognise. Bundles the operator-
# experience finding from the 2026-05-24 security audit (I-2). The list
# below mirrors the compiled-in tool surface (REQ 4.1-4.17) plus the
# workload plugins. Anything else means a typo in manifest.yml or a
# stale postinst script.
known_tools="manifest system pressure kernel sockets updates storage \
    systemd_units dns mail certs backup sensors network security \
    firewall firewall_lookup logs workload"
known_plugins="postfix nginx_apache wireguard dovecot"
for n in $enabled; do
    case " $known_tools $known_plugins " in
        *" $n "*) ;;
        *) echo "host-health-mcp: warning: enabled_tools contains unknown name '$n'" >&2 ;;
    esac
done

# IPAddressAllow/Deny drop-in for the daemon (REQ 6.8, audit L-5).
#
# systemd's IPAddressAllow=/IPAddressDeny= are BIDIRECTIONAL: they
# filter packets sent and received. There is no egress-only variant.
# Releases 1.17.0 through 2.0.0 emitted an unconditional
# "IPAddressDeny=any / IPAddressAllow=localhost" pair here, which also
# denied every inbound mTLS connection and made the listener
# unreachable on any non-loopback bind_addr.
#
# The filter is therefore opt-in and fully operator-enumerated. The
# daemon.yml key ip_filter_allow[] must name every network that has to
# reach the listener as well as every egress destination the daemon is
# permitted to contact. Absent or empty, no drop-in is written and no
# IP filtering is applied.
DAEMON_FILTER_DROPIN="$DAEMON_DROPIN_DIR/10-ip-filter.conf"
DAEMON_YML=${DAEMON_YML:-/etc/host-health-mcp/daemon.yml}

# Only block form is recognised below. YAML flow form is valid to the
# daemon's decoder, so accepting it silently here would generate an
# empty filter from a non-empty config — fail instead.
if [ -f "$DAEMON_YML" ] && grep -qE '^ip_filter_allow:[[:space:]]*\[' "$DAEMON_YML"; then
    echo "caps-template: ip_filter_allow must use YAML block form (one '- entry' per line), not [a, b]" >&2
    exit 1
fi

ip_filter_allow=""
if [ -f "$DAEMON_YML" ]; then
    ip_filter_allow=$(awk '
        /^ip_filter_allow:[[:space:]]*$/ { in_l=1; next }
        in_l && /^[[:space:]]*-/ {
            sub(/^[[:space:]]*-[[:space:]]*/, "")
            sub(/[[:space:]]*#.*$/, "")
            gsub(/^["'"'"']|["'"'"']$/, "")
            if (length($0)) print
            next
        }
        in_l && /^[^[:space:]#]/ { in_l=0 }
    ' "$DAEMON_YML")
fi

if [ -n "$ip_filter_allow" ]; then
    mkdir -p "$DAEMON_DROPIN_DIR"
    {
        echo "# Auto-generated by /usr/sbin/host-health-mcp-caps-template"
        echo "# from $DAEMON_YML (ip_filter_allow)."
        echo "# NOTE: these rules apply to inbound AND outbound packets."
        echo "[Service]"
        echo "IPAddressDeny=any"
        for r in $ip_filter_allow; do
            echo "IPAddressAllow=$r"
        done
    } > "$DAEMON_FILTER_DROPIN"
    echo "caps-template: wrote $DAEMON_FILTER_DROPIN" >&2
else
    echo "caps-template: ip_filter_allow absent or empty; no IP filter drop-in written" >&2
fi

mkdir -p "$DROPIN_DIR"
{
    echo "# Auto-generated by /usr/sbin/host-health-mcp-caps-template"
    echo "# from $MANIFEST."
    echo "# Edit $MANIFEST and re-run the generator to refresh."
    echo "[Service]"
    # Bounding set carries every cap the helper or its subprocesses
    # might need, including CAP_CHOWN which only the helper itself
    # uses (to chown the runtime dir + socket at startup).
    printf 'CapabilityBoundingSet='
    for c in $caps; do printf '%s ' "$c"; done
    printf '\n'
    # Ambient set carries the per-op caps EXCLUDING CAP_CHOWN.
    # Modern tools that introspect their effective set (auditctl
    # checks CAP_AUDIT_READ explicitly rather than falling back on
    # euid==0) need their caps inherited via the ambient set across
    # execve under NoNewPrivileges=yes; an empty ambient set means
    # they observe zero capabilities even though the parent process
    # is root.
    printf 'AmbientCapabilities='
    for c in $caps; do
        case "$c" in
            CAP_CHOWN) ;; # parent-only
            *) printf '%s ' "$c" ;;
        esac
    done
    printf '\n'
} > "$DROPIN"

echo "caps-template: wrote $DROPIN" >&2
echo "caps-template: run 'systemctl daemon-reload && systemctl restart host-health-mcp-helper.service' to apply" >&2
