#!/bin/sh
# Regression tests for host-health-mcp-caps-template.
#
# This generator writes the helper's CapabilityBoundingSet from
# manifest.yml, and it runs from the postinst under `set -eu` on every
# install and upgrade. Two properties matter and neither is checked by
# any compiler:
#
#   1. It must never exit non-zero on operator config it can safely
#      treat as empty. A maintainer script that aborts leaves dpkg
#      half-configured on an unattended-upgrades fleet, with the old
#      binary running from disk dpkg has already replaced.
#   2. It must grant CAP_SYS_ADMIN and CAP_SYS_RAWIO only where the
#      declared storage backends need them.
#
# Run: sh build/postinst/tests/caps-template-test.sh
set -eu

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
GEN="$HERE/../caps-template.sh"
WORK=$(mktemp -d)
# Guard BEFORE installing the cleanup trap. The trap is rm -rf "$WORK";
# if WORK ever points somewhere real, the trap alone is destructive the
# moment the script exits — before a single test body has run. Checking
# after the trap is installed is checking too late. (Learned the hard
# way: an early version of this guard sat below the trap, and testing
# it fired rm -rf at /etc/systemd/system.)
guard() {
    for v in "$WORK" "$WORK/d" "$WORK/dd"; do
        case "$v" in
            ''|/|/etc|/usr|/var|/run|/lib|/boot|/etc/*|/usr/*|/var/*|/run/*|/lib/*|/boot/*)
                echo "REFUSING: a test path points at a real system directory: $v" >&2
                exit 3 ;;
        esac
    done
}
guard

trap 'rm -rf "$WORK"' EXIT

fail=0
pass=0

# run <name> <expected-rc> <manifest-body>
run() {
    name=$1; want_rc=$2; body=$3
    rm -rf "$WORK/d" "$WORK/dd"; mkdir -p "$WORK/d" "$WORK/dd"
    printf '%b' "$body" > "$WORK/m.yml"
    set +e
    MANIFEST="$WORK/m.yml" DROPIN_DIR="$WORK/d" DAEMON_DROPIN_DIR="$WORK/dd" \
        DAEMON_YML="$WORK/absent.yml" sh "$GEN" >"$WORK/out" 2>&1
    rc=$?
    set -e
    if [ "$rc" != "$want_rc" ]; then
        echo "FAIL [$name] rc=$rc want=$want_rc"
        sed 's/^/       /' "$WORK/out"
        fail=$((fail+1))
        return 1
    fi
    pass=$((pass+1))
    return 0
}

# grep exiting 1 means "no such line", which is an answer; a missing
# drop-in is a different answer and is reported as such rather than
# collapsed into the same string by a discarded stderr.
caps() { field '^CapabilityBoundingSet='; }
ambient() { field '^AmbientCapabilities='; }
field() {
    if [ ! -f "$WORK/d/caps.conf" ]; then
        echo "<no drop-in>"
        return 0
    fi
    if ! out=$(grep "$1" "$WORK/d/caps.conf"); then
        echo "<no matching line>"
        return 0
    fi
    echo "$out"
}

has() {
    if ! caps | grep -q "$1"; then
        echo "FAIL [$2] expected $1 in: $(caps)"; fail=$((fail+1)); return 1
    fi
    pass=$((pass+1))
}
hasnt() {
    if caps | grep -q "$1"; then
        echo "FAIL [$2] did NOT expect $1 in: $(caps)"; fail=$((fail+1)); return 1
    fi
    pass=$((pass+1))
}

# --- POSITIVE: shapes that must configure cleanly ------------------

# The empty flow form is the natural spelling for "none" and is used by
# five neighbouring keys in the shipped example. Rejecting it aborted
# the package configure.
run "empty flow form storage_backends" 0 \
    'enabled_tools:\n  - storage\nstorage_backends: []\n'
run "empty flow form enabled_tools" 0 'enabled_tools: []\n'
run "absent storage_backends"        0 'enabled_tools:\n  - storage\n'
run "block form"                     0 'enabled_tools:\n  - storage\nstorage_backends:\n  - zfs\n'
run "empty manifest"                 0 '\n'
run "comments and blank lines"       0 '# c\nenabled_tools:\n\n  - storage   # spinning rust\n'
run "tabs in list"                   0 'enabled_tools:\n\t- storage\n'
run "quoted values"                  0 'enabled_tools:\n  - "storage"\n'

# --- NEGATIVE: shapes that must be refused loudly ------------------

# A non-empty flow form parses for the daemon but yields NOTHING here,
# so accepting it silently would generate the default cap set from a
# non-empty config.
run "non-empty flow form storage_backends" 1 \
    'enabled_tools:\n  - storage\nstorage_backends: [smart, zfs]\n'
run "non-empty flow form enabled_tools"    1 'enabled_tools: [storage, security]\n'
run "non-empty flow form workload_plugins" 1 \
    'enabled_tools:\n  - workload\nworkload_plugins: [wireguard]\n'

# Argument handling: --hint is opt-in, an unknown flag is a usage
# error, and neither may change the generated drop-in.
argcheck() {
    name=$1; want_rc=$2; shift 2
    rm -rf "$WORK/d" "$WORK/dd"; mkdir -p "$WORK/d" "$WORK/dd"
    printf 'enabled_tools:\n  - storage\n' > "$WORK/m.yml"
    set +e
    MANIFEST="$WORK/m.yml" DROPIN_DIR="$WORK/d" DAEMON_DROPIN_DIR="$WORK/dd" \
        DAEMON_YML="$WORK/absent.yml" sh "$GEN" "$@" >"$WORK/out" 2>&1
    rc=$?
    set -e
    if [ "$rc" != "$want_rc" ]; then
        echo "FAIL [$name] rc=$rc want=$want_rc"; sed 's/^/       /' "$WORK/out"; fail=$((fail+1)); return
    fi
    pass=$((pass+1))
}
argcheck "unknown argument rejected" 2 --bogus
argcheck "--hint accepted"           0 --hint
argcheck "--help accepted"           0 --help

# --hint adds the activation line; the default must not, because the
# postinst runs non-interactively into an automated upgrade report.
rm -rf "$WORK/d" "$WORK/dd"; mkdir -p "$WORK/d" "$WORK/dd"
printf 'enabled_tools:\n  - storage\n' > "$WORK/m.yml"
MANIFEST="$WORK/m.yml" DROPIN_DIR="$WORK/d" DAEMON_DROPIN_DIR="$WORK/dd" \
    DAEMON_YML="$WORK/absent.yml" sh "$GEN" 2>"$WORK/plain" >"$WORK/plain_out"
MANIFEST="$WORK/m.yml" DROPIN_DIR="$WORK/d" DAEMON_DROPIN_DIR="$WORK/dd" \
    DAEMON_YML="$WORK/absent.yml" sh "$GEN" --hint 2>"$WORK/hinted" >"$WORK/hinted_out"
if grep -q 'systemctl' "$WORK/plain"; then
    echo "FAIL [--hint default] activation advice printed without --hint"; fail=$((fail+1))
else
    pass=$((pass+1))
fi
if grep -q 'systemctl' "$WORK/hinted"; then
    pass=$((pass+1))
else
    echo "FAIL [--hint] activation advice missing with --hint"; fail=$((fail+1))
fi

# --- Capability gating (B-6) ---------------------------------------

run "default backends" 0 'enabled_tools:\n  - storage\n' && {
    has    CAP_SYS_RAWIO      "default grants smart"
    hasnt  CAP_SYS_ADMIN      "default must NOT grant zfs cap"
}
run "zfs declared" 0 'enabled_tools:\n  - storage\nstorage_backends:\n  - zfs\n' && {
    has    CAP_SYS_ADMIN      "zfs grants SYS_ADMIN"
    hasnt  CAP_SYS_RAWIO      "zfs alone must not grant RAWIO"
}
run "btrfs declared" 0 'enabled_tools:\n  - storage\nstorage_backends:\n  - btrfs\n' && {
    has    CAP_SYS_ADMIN      "btrfs needs SCRUB_PROGRESS ioctl"
}
run "lvm only" 0 'enabled_tools:\n  - storage\nstorage_backends:\n  - lvm\n' && {
    hasnt  CAP_SYS_ADMIN      "lvm must not grant SYS_ADMIN"
    hasnt  CAP_SYS_RAWIO      "lvm must not grant RAWIO"
}
run "storage not enabled" 0 'enabled_tools:\n  - system\n' && {
    hasnt  CAP_SYS_ADMIN      "no storage, no SYS_ADMIN"
    hasnt  CAP_SYS_RAWIO      "no storage, no RAWIO"
}

# CAP_CHOWN is unconditional: the helper chowns its own socket.
run "chown always present" 0 'enabled_tools:\n  - system\n' && has CAP_CHOWN "CAP_CHOWN unconditional"

# Ambient must never carry CAP_CHOWN (parent-only).
run "ambient excludes chown" 0 'enabled_tools:\n  - storage\n' && {
    if ambient | grep -q CAP_CHOWN; then
        echo "FAIL [ambient] CAP_CHOWN leaked into AmbientCapabilities: $(ambient)"; fail=$((fail+1))
    else
        pass=$((pass+1))
    fi
}

echo
echo "caps-template: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
