#!/bin/sh
# Run a Debian maintainer script against a throwaway root, so it cannot
# touch the machine you are sitting on.
#
#   sh build/postinst/tests/jail.sh <script> [arg]
#
# e.g.  sh build/postinst/tests/jail.sh build/postinst/postrm.sh purge
#
# Why this exists: postinst.sh, prerm.sh and postrm.sh have no
# testability seams. They hardcode /etc/systemd/system, systemctl,
# adduser and install -d, because that is correct for the host they are
# meant to run on. Executing one on a developer workstation to "check
# the exit code" stops that workstation's services and deletes its
# drop-ins — which is not hypothetical; it is why this file exists.
#
# What this gives the script:
#
#   - an unprivileged user namespace, so it believes it is root and the
#     kernel disagrees. No sudo, no real privilege, nothing to clean up.
#   - a mount namespace with /usr /bin /lib /sbin /dev bind-mounted
#     READ-ONLY from the host, so real coreutils are available
#   - tmpfs over /etc /run /var /tmp, pre-seeded with the paths the
#     scripts expect, so their rm/rmdir/install actually run and their
#     effects are observable — and vanish with the namespace
#   - a stubbed systemctl on PATH that records calls instead of making
#     them, printed at the end
#
# Everything the script does is real except the parts that would leave
# the sandbox. That is the point: a stub-everything harness proves the
# script called something, this proves what it did.
set -eu

usage() {
    echo "usage: $0 <maintainer-script> [dpkg-arg]" >&2
    echo "  e.g. $0 build/postinst/postrm.sh purge" >&2
    exit 2
}

[ $# -ge 1 ] || usage
SCRIPT=$1
ARG=${2:-}
# Optional: space-separated unit names that must fail to start.
JAIL_FAIL_UNIT=${JAIL_FAIL_UNIT:-}

[ -f "$SCRIPT" ] || { echo "$0: no such script: $SCRIPT" >&2; exit 2; }
SCRIPT=$(cd -- "$(dirname -- "$SCRIPT")" && pwd)/$(basename -- "$SCRIPT")

# command -v is a predicate; its stdout is the resolved path.
if ! command -v unshare >/dev/null; then
    echo "$0: unshare(1) is required (util-linux)" >&2
    exit 2
fi
# --map-auto maps the caller's /etc/subuid range, so chown/install to a
# non-zero uid works inside the jail. Without it only uid 0 exists and
# postinst's `install -o host-health-mcp` cannot succeed. Fall back to
# --map-root-user, which is enough for prerm/postrm.
# --map-auto brings in the caller's /etc/subuid range so chown to a
# non-zero uid works; --map-root-user makes us root inside so mount
# does. Both are needed: without the range, postinst's
# `install -o host-health-mcp` cannot succeed; without root, the tmpfs
# mounts fail. Fall back to root-only, which is enough for prerm/postrm.
MAPFLAGS="--map-auto --map-root-user"
# Probing which mapping this kernel and /etc/subuid allow. A failure is
# an ANSWER driving the fallback, not an error — but the message from
# the final attempt is kept and shown if both fail.
if ! probe=$(unshare --user $MAPFLAGS true 2>&1); then
    MAPFLAGS=--map-root-user
fi
if ! probe=$(unshare --user $MAPFLAGS true 2>&1); then
    echo "$0: user-namespace probe failed: $probe" >&2
    echo "$0: unprivileged user namespaces are unavailable on this kernel." >&2
    echo "  Do NOT fall back to running the script directly. Use a container" >&2
    echo "  or a disposable VM instead." >&2
    exit 2
fi

JAIL=$(mktemp -d)
trap 'rm -rf "$JAIL"' EXIT
mkdir -p "$JAIL"/usr "$JAIL"/bin "$JAIL"/lib "$JAIL"/lib64 "$JAIL"/sbin \
         "$JAIL"/dev "$JAIL"/etc "$JAIL"/run "$JAIL"/var "$JAIL"/tmp "$JAIL"/opt

cp "$SCRIPT" "$JAIL/opt/script.sh"

# The inner half runs with CAP_SYS_ADMIN inside the namespace only.
cat > "$JAIL/opt/inner.sh" <<'INNER'
set -eu
J=$1; ARG=${2:-}
JAIL_FAIL_UNIT=${JAIL_FAIL_UNIT:-}

for d in usr bin lib lib64 sbin dev; do
    if [ ! -d "/$d" ]; then
        continue
    fi
    if ! m=$(mount --bind -o ro "/$d" "$J/$d" 2>&1); then
        echo "jail: WARNING: could not bind-mount /$d read-only: $m" >&2
    fi
done
for d in etc run var tmp; do
    mount -t tmpfs tmpfs "$J/$d"
done

# Seed the paths a maintainer script expects to find on a real host.
mkdir -p "$J/etc/systemd/system/host-health-mcp.service.d" \
         "$J/etc/systemd/system/host-health-mcp-helper.service.d" \
         "$J/etc/host-health-mcp/tls" \
         "$J/run/systemd/system" \
         "$J/var/lib" "$J/opt/bin"
# A minimal passwd/group database, so `install -o host-health-mcp`
# resolves the name the postinst has just "created". Without it the
# script fails on the stub environment rather than on its own logic.
cat > "$J/etc/passwd" <<'PW'
root:x:0:0:root:/root:/bin/sh
host-health-mcp:x:999:999:host-health-mcp:/var/lib/host-health-mcp:/usr/sbin/nologin
PW
cat > "$J/etc/group" <<'GR'
root:x:0:
host-health-mcp:x:999:
GR

: > "$J/etc/systemd/system/host-health-mcp-helper.service.d/caps.conf"
: > "$J/etc/systemd/system/host-health-mcp.service.d/10-ip-filter.conf"
: > "$J/etc/systemd/system/host-health-mcp.service.d/10-ip-egress.conf"

# Record systemd calls rather than making them. `is-active` answers
# true so the restart/stop branches are actually exercised.
# A stateful stub. The scripts now VERIFY their effects rather than
# trusting an exit code, so a stub that always answers "active" makes
# every stop look like a failure and every restart look like a success.
# State lives in /opt/state/<unit>; "active" unless a stop cleared it.
cat > "$J/opt/bin/systemctl" <<'STUB'
#!/bin/sh
echo "systemctl $*" >> /opt/calls
mkdir -p /opt/state
verb=""
for a in "$@"; do
    case "$a" in
        --*) ;;
        *) if [ -z "$verb" ]; then verb=$a; else units="${units:-} $a"; fi ;;
    esac
done
case "$verb" in
    is-active)
        for u in ${units:-}; do
            [ -f "/opt/state/$u.stopped" ] && exit 3
        done
        exit 0 ;;
    stop)
        # A unit named in JAIL_FAIL_UNIT refuses to stop and stays
        # active, which is the case prerm must report without failing
        # the removal.
        for u in ${units:-}; do
            case " ${JAIL_FAIL_UNIT:-} " in
                *" $u "*)
                    echo "Job for $u failed: unit is stuck in stopping." >&2
                    exit 1 ;;
            esac
            : > "/opt/state/$u.stopped"
        done ;;
    start|restart)
        # Fault injection: a unit named in JAIL_FAIL_UNIT refuses to
        # come back, which is the case the scripts must detect and
        # report rather than assume away.
        for u in ${units:-}; do
            case " ${JAIL_FAIL_UNIT:-} " in
                *" $u "*)
                    echo "Job for $u failed because the control process exited with error code." >&2
                    : > "/opt/state/$u.stopped"
                    exit 1 ;;
            esac
            rm -f "/opt/state/$u.stopped"
        done ;;
    status)
        for u in ${units:-}; do
            if [ -f "/opt/state/$u.stopped" ]; then
                echo "* $u - stub unit"; echo "   Active: inactive (dead)"; exit 3
            fi
            echo "* $u - stub unit"; echo "   Active: active (running)"
        done ;;
esac
exit 0
STUB
# deb-systemd-invoke delegates to systemctl so unit state stays
# consistent whichever path a script takes.
cat > "$J/opt/bin/deb-systemd-invoke" <<'STUB'
#!/bin/sh
echo "deb-systemd-invoke $*" >> /opt/calls
exec /opt/bin/systemctl "$@"
STUB
# User creation would otherwise need a real passwd database. getent
# reports "not found" so the create branch is the one exercised; the
# create commands then succeed, so the script proceeds past them
# instead of aborting on the stub under `set -e`.
printf '#!/bin/sh\necho "getent $*" >> /opt/calls\nexit 2\n' > "$J/opt/bin/getent"
for c in adduser addgroup deluser; do
    printf '#!/bin/sh\necho "%s $*" >> /opt/calls\nexit 0\n' "$c" > "$J/opt/bin/$c"
done
# The capability generator is installed by the package, not present in
# a bare chroot; stub it so postinst reaches the systemd block behind it.
printf '#!/bin/sh\necho "host-health-mcp-caps-template $*" >> /opt/calls\nexit 0\n' \
    > "$J/opt/bin/host-health-mcp-caps-template"
chmod +x "$J/opt/bin/"*

chroot "$J" /bin/sh -c "
    PATH=/opt/bin:\$PATH
    export JAIL_FAIL_UNIT='$JAIL_FAIL_UNIT'
    sh /opt/script.sh $ARG
    rc=\$?
    echo
    echo '--- exit status ---'
    echo \"  \$rc\"
    echo '--- privileged calls attempted ---'
    if [ -s /opt/calls ]; then sed 's/^/  /' /opt/calls; else echo '  (none)'; fi
    echo '--- /etc/systemd/system afterwards ---'
    find /etc/systemd/system -mindepth 1 | sed 's/^/  /' || echo '  (nothing, or /etc/systemd/system is absent)'
    exit \$rc
"
INNER

echo "=== $(basename "$SCRIPT") ${ARG:-<no arg>} — in a throwaway root ==="
JAIL_FAIL_UNIT="$JAIL_FAIL_UNIT" unshare --user $MAPFLAGS --mount sh "$JAIL/opt/inner.sh" "$JAIL" "$ARG"
