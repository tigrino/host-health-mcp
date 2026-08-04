#!/bin/sh
# Generates the helper unit's CapabilityBoundingSet drop-in from the
# operator's manifest.yml. Run by the .deb's post-install scriptlet
# and re-run by the operator after editing manifest.yml. See
# design-overview.md section 7 (capability templating).
#
# Usage: host-health-mcp-caps-template [--hint]
#
#   --hint  Print how to activate the generated drop-in. Off by
#           default. The script is run non-interactively from the
#           postinst, and on a fleet upgraded by unattended-upgrades
#           its stdout lands in an automated report with no human in
#           it. A line phrased as a required manual step, in a channel
#           where nobody can act on it, is indistinguishable from a
#           genuine action-required notice and trains the reader to
#           ignore the channel. Everything this script prints by
#           default states a fact about what it did.
#
#           A flag rather than a TTY check: explicit, testable, and
#           the postinst simply does not pass it.

set -eu

HINT=0
for arg in "$@"; do
    case "$arg" in
        --hint) HINT=1 ;;
        -h|--help)
            # Print the header comment block: everything from line 2
            # until the first line that is not a comment. Deriving the
            # range beats hardcoding it, which silently truncates or
            # over-prints whenever the header changes length.
            awk 'NR==1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
            exit 0
            ;;
        *)
            echo "caps-template: unknown argument '$arg'" >&2
            exit 2
            ;;
    esac
done

MANIFEST=${MANIFEST:-/etc/host-health-mcp/manifest.yml}
# Overridable so the generator can be exercised without root; the
# postinst never sets it.
DROPIN_DIR=${DROPIN_DIR:-/etc/systemd/system/host-health-mcp-helper.service.d}
DROPIN=${DROPIN_DIR}/caps.conf

# Retiring the <= 2.0.0 daemon drop-in happens before anything can exit
# early: it denied inbound traffic and left the listener unreachable, so
# it must go even on a host with no manifest.
DAEMON_DROPIN_DIR=${DAEMON_DROPIN_DIR:-/etc/systemd/system/host-health-mcp.service.d}
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

# enabled_tools and workload_plugins drive the ENTIRE capability union,
# so the same flow-form trap applies to them and matters more: a
# `enabled_tools: [storage, security]` line parses fine for the daemon,
# yields nothing here, and the helper ends up with CAP_CHOWN only —
# every privileged op failing EPERM. Harmless while nothing applied the
# drop-in; the postinst now restarts on the spot.
for k in enabled_tools workload_plugins; do
    if grep -qE "^${k}:[[:space:]]*\[[[:space:]]*[^]][[:space:]]*" "$MANIFEST"; then
        echo "caps-template: $k must use YAML block form (one '- entry' per line), not [a, b]" >&2
        exit 1
    fi
done

# Crude YAML extraction: the lines we care about are flat arrays under
# enabled_tools: and workload_plugins:. python3 -c is an option if
# more rigour is needed; this script keeps to POSIX sh.
enabled=$(awk '
    /^enabled_tools:/ { in_tools=1; next }
    /^workload_plugins:/ { in_plug=1; next }
    /^[A-Za-z0-9_-]+:/ { in_tools=0; in_plug=0; next }
    (in_tools || in_plug) && /^[[:space:]]*-/ {
        sub(/^[[:space:]]*-[[:space:]]*/, "")
        print
    }
' "$MANIFEST")

# storage_backends[] declares which storage backends this host actually
# runs, so the two dangerous caps are granted only where needed. Absent
# or empty means the conservative default below — never "all", because
# defaulting an allow-list to everything is how CAP_SYS_ADMIN ended up
# on every storage host in the first place.
# Flow form is valid YAML to the daemon's decoder, so accepting it
# silently here would generate the DEFAULT cap set from a non-empty
# config — the same trap the ip_filter_allow guard below exists for,
# and worse, because the fallback message would then say "absent".
# Match a NON-EMPTY flow form only. `storage_backends: []` is the
# natural spelling for "none" — five neighbouring keys in the shipped
# example use it, the daemon's decoder accepts it, and this script's
# own comment tells operators that empty is fine. Rejecting it aborted
# the package configure, which on an unattended-upgrades fleet leaves
# dpkg half-configured and the old binary running from replaced disk.
# A maintainer script must not fail the install over the shape of a
# value it can safely treat as empty.
if grep -qE '^storage_backends:[[:space:]]*\[[[:space:]]*[^]][[:space:]]*' "$MANIFEST"; then
    echo "caps-template: storage_backends must use YAML block form (one '- entry' per line), not [a, b]" >&2
    exit 1
fi

storage_backends=$(awk '
    /^storage_backends:/ { in_b=1; next }
    /^[A-Za-z0-9_-]+:/ { in_b=0; next }
    in_b && /^[[:space:]]*-/ {
        sub(/^[[:space:]]*-[[:space:]]*/, "")
        sub(/[[:space:]]*#.*$/, "")
        if (length($0)) print
    }
' "$MANIFEST")
if [ -z "$storage_backends" ]; then
    storage_backends="smart lvm mdraid"
    # Only worth saying on a host that actually enables `storage`;
    # elsewhere none of these caps are granted either way and the line
    # is noise in an unattended-upgrade report.
    if have storage; then
        echo "caps-template: storage_backends absent; defaulting to '$storage_backends'" \
             "(declare 'zfs' to grant CAP_SYS_ADMIN)" >&2
    fi
fi
have_backend() { echo "$storage_backends" | grep -qw "$1"; }

known_backends="smart lvm mdraid zfs btrfs"
for b in ${storage_backends}; do
    case " $known_backends " in
        *" $b "*) ;;
        *) echo "caps-template: warning: storage_backends contains unknown name '$b'" >&2 ;;
    esac
done

have security  && { add CAP_AUDIT_CONTROL; add CAP_DAC_READ_SEARCH; }
# `storage` is one tool over five backends, and the caps they need are
# not the same. CAP_SYS_ADMIN is required only by zpool_status and
# CAP_SYS_RAWIO only by smart_summary, but granting both to every
# storage operator put them in the AMBIENT set too — inherited across
# execve by smartctl, lvs, mdadm and btrfs. CAP_SYS_ADMIN is broadly
# equivalent to root and CAP_SYS_RAWIO permits raw device I/O, so a
# memory-corruption bug in any of those parsers escalated from "root
# under a narrow bounding set" to "full CAP_SYS_ADMIN". install.md
# asserted the opposite: that operators not running ZFS do not pay
# CAP_SYS_ADMIN. They did.
#
# storage_backends[] in manifest.yml now gates them individually.
# Absent, it defaults to the conservative set (smart + lvm + mdraid):
# an operator who has not declared ZFS does not get CAP_SYS_ADMIN.
have storage && add CAP_DAC_READ_SEARCH
have storage && have_backend smart && add CAP_SYS_RAWIO
have storage && have_backend zfs   && add CAP_SYS_ADMIN
# btrfs also needs CAP_SYS_ADMIN, and only for one case: `btrfs scrub
# status` reads /var/lib/btrfs/scrub.status.<uuid> for a FINISHED scrub
# but issues BTRFS_IOC_SCRUB_PROGRESS for a RUNNING one, and that ioctl
# is capable(CAP_SYS_ADMIN)-gated in fs/btrfs/ioctl.c. Granting it to
# every storage host previously masked this. Kept conservative rather
# than dropped, because losing in-progress scrub reporting would be a
# silent monitoring gap on exactly the hosts that care; narrowing it
# further needs verification against a live btrfs scrub.
have storage && have_backend btrfs && add CAP_SYS_ADMIN
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
if [ "$HINT" -eq 1 ]; then
    echo "caps-template: run 'systemctl daemon-reload && systemctl restart host-health-mcp-helper.service' to apply" >&2
fi
