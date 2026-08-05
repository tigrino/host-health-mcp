#!/usr/bin/env bash
# Drives a release build per design-overview.md section 10.
# Inputs: a clean checkout and the Go toolchain pinned by GOTOOLCHAIN
# below. Outputs: versioned, checksummed .deb artefacts for amd64 and
# arm64, one package each for the server and the client.
#
# Build reproducibility is FUNCTIONAL, not byte-identical. See section
# 10.1 of design-overview.md for the trade-off.
#
# SCOPE. This script builds the offline-path artefacts (install.md
# section 1.2). Packages installed from a distribution repository are
# built by a separate packaging pipeline, from its own packaging
# sources, and never execute this file. Every gate below — the GOTOOLCHAIN pin, go vet,
# the os/exec linter, staticcheck, govulncheck, the maintainer-script
# suites — therefore protects the offline path and local development
# only. Do not cite a green run here as evidence about a package
# installed with apt; that path has to run its own equivalents.

set -euo pipefail

# The go.mod `go` directive is a floor, not a pin: with GOTOOLCHAIN=auto
# a release would be built against whatever Go the build host happens to
# carry, and its stdlib would vary between hosts with no signal. Pin it
# exactly here. Distribution packages built downstream deliberately do
# not use this script; they pin to the toolchain their suite ships.
export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.26.5}

# `cd` can print the target directory when CDPATH is set in the
# caller's environment; that stdout would corrupt the captured path.
# Errors still reach stderr and an unresolvable path fails the
# assignment under `set -e`.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
DIST="$SCRIPT_DIR/dist"

if [ -z "${VERSION:-}" ]; then
    if VERSION=$(cd "$REPO" && git describe --tags --dirty --always 2>&1); then
        :
    else
        echo "==> WARNING: git describe failed, versioning this build 0.0.0-dev:" >&2
        echo "$VERSION" | sed 's/^/      /' >&2
        VERSION=0.0.0-dev
    fi
fi
if ! GIT_SHA=$(cd "$REPO" && git rev-parse --short HEAD 2>&1); then
    echo "==> WARNING: git rev-parse failed, recording the commit as 'unknown':" >&2
    echo "$GIT_SHA" | sed 's/^/      /' >&2
    GIT_SHA=unknown
fi
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    if ! SOURCE_DATE_EPOCH=$(cd "$REPO" && git log -1 --pretty=%ct 2>&1); then
        echo "==> WARNING: no git commit timestamp available, using the wall clock;" >&2
        echo "      this build's timestamps are not reproducible:" >&2
        echo "$SOURCE_DATE_EPOCH" | sed 's/^/      /' >&2
        SOURCE_DATE_EPOCH=$(date +%s)
    fi
fi
export SOURCE_DATE_EPOCH

mkdir -p "$DIST"

echo "==> Build host-health-mcp $VERSION (git $GIT_SHA, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"

# Step 1-3: vet, test, linters. Both modules.
echo "==> go vet"
( cd "$REPO/daemon" && go vet ./... )
( cd "$REPO/plugin" && go vet ./... )
echo "==> go test"
( cd "$REPO/daemon" && go test ./... )
( cd "$REPO/plugin" && go test ./... )
# The linter is the mechanism enforcing the read-only property, so its
# own regression tests run in the release path too. Untested
# enforcement is indistinguishable from none.
( cd "$REPO/build/linter" && go test ./... )
# Same reasoning for the capability generator: it runs from the
# postinst under `set -eu` on every install, it decides what the root
# helper is allowed to do, and it is shell parsing YAML with awk. It
# gets a test suite and the suite runs here.
echo "==> caps-template tests"
sh "$REPO/build/postinst/tests/caps-template-test.sh"

# Custom forbidden-call linter (REQ 10.2). Required.
echo "==> forbidden-call linter"
LINTER_BIN=$(mktemp)
trap 'rm -f "$LINTER_BIN"' EXIT
( cd "$REPO/build/linter" && go build -o "$LINTER_BIN" ./forbidden )
( cd "$REPO" && "$LINTER_BIN" -root daemon )
# The plugin is a separate module and a separate root. It is clean
# today, but "clean today" and "enforced" are different properties.
( cd "$REPO" && "$LINTER_BIN" -root plugin )

# REQ 10.2 scanners. These are REQUIRED, not best-effort: running them
# only "if command -v" succeeds meant a release could be cut with zero
# vulnerability scanning and still print Done — the same silent-skip
# pattern that once produced a package-less build when nfpm was
# missing. Set ALLOW_MISSING_SCANNERS=1 to build without them
# deliberately; the build then says so, loudly, instead of implying a
# scan happened.
for scanner in staticcheck govulncheck; do
    # command -v is a predicate; its stdout is the resolved path.
    if command -v "$scanner" >/dev/null; then
        continue
    fi
    if [ "${ALLOW_MISSING_SCANNERS:-0}" = "1" ]; then
        echo "==> WARNING: $scanner not installed and ALLOW_MISSING_SCANNERS=1;" \
             "this build was NOT scanned" >&2
    else
        echo "build.sh: $scanner is required (REQ 10.2) but not installed." >&2
        echo "  install it, or set ALLOW_MISSING_SCANNERS=1 to build without scanning." >&2
        exit 1
    fi
done
if command -v staticcheck >/dev/null; then
    echo "==> staticcheck"
    ( cd "$REPO/daemon" && staticcheck ./... )
    ( cd "$REPO/plugin" && staticcheck ./... )
fi
if command -v govulncheck >/dev/null; then
    echo "==> govulncheck"
    ( cd "$REPO/daemon" && govulncheck ./... )
    ( cd "$REPO/plugin" && govulncheck ./... )
fi

# Step 4: build both binaries for each arch.
# WORKLOAD_TAGS: workload plugins enabled at build time per REQ 4.9 and
# design §8. Default includes all four named plugins; operators who
# want a minimal binary may override.
# Read from build/workload-tags rather than hardcoding here. That file
# is the interface downstream packaging consumes; keeping a second
# copy in this script is exactly the drift that made adding a plugin
# silently produce a downstream build without it.
WORKLOAD_TAGS=${WORKLOAD_TAGS:-$(grep -vE '^[[:space:]]*(#|$)' "$REPO/build/workload-tags" | tr '\n' ',' | sed 's/,$//')}
if [ -z "$WORKLOAD_TAGS" ]; then
    echo "build.sh: build/workload-tags is empty or unreadable" >&2
    exit 1
fi
LDFLAGS="-buildid= -X main.buildID=$VERSION"
for ARCH in amd64 arm64; do
    echo "==> Build $ARCH (workload tags: $WORKLOAD_TAGS)"
    mkdir -p "$DIST/$ARCH"
    ( cd "$REPO/daemon" && \
        CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH \
        go build -trimpath -tags="$WORKLOAD_TAGS" -ldflags="$LDFLAGS" \
        -o "$DIST/$ARCH/host-health-mcp-daemon" ./cmd/daemon )
    ( cd "$REPO/daemon" && \
        CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH \
        go build -trimpath -ldflags="$LDFLAGS" \
        -o "$DIST/$ARCH/host-health-mcp-helper" ./cmd/helper )
    ( cd "$REPO/plugin" && \
        CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH \
        go build -trimpath -ldflags="$LDFLAGS" \
        -o "$DIST/$ARCH/host-health-mcp-client" ./cmd/plugin )
done

# Step 4b: Debian changelog for the package doc directories. Native
# package, so the file is changelog.gz rather than changelog.Debian.gz.
# Generated rather than tracked because it carries the release version.
# GNU date understands -d @epoch; BSD date does not. The fallback is a
# real difference in output (wall clock instead of the commit time), so
# it is announced rather than silently substituted.
if ! CHANGELOG_DATE=$(date -u -R -d "@$SOURCE_DATE_EPOCH" 2>&1); then
    echo "==> WARNING: date(1) does not support -d @epoch; the changelog" >&2
    echo "      timestamp will be the wall clock, not SOURCE_DATE_EPOCH:" >&2
    echo "$CHANGELOG_DATE" | sed 's/^/      /' >&2
    CHANGELOG_DATE=$(date -u -R)
fi
{
    echo "host-health-mcp ($VERSION) unstable; urgency=medium"
    echo
    echo "  * Release $VERSION. See /usr/share/doc/host-health-mcp-server/"
    echo "    or doc/changelog.md in the source tree for the full entry."
    echo
    echo " -- Albert 'Tigr' Zenkoff <albert@tigr.net>  $CHANGELOG_DATE"
} | gzip -9n > "$DIST/changelog.gz"

# Step 5: nfpm per arch.
#
# Required, for the same reason the scanners above are. This block used
# to print "skipping .deb production" and continue to "Done." — a
# release run that produced no packages and reported success. The
# comment on the scanner gate cites that very failure; leaving it in
# place three blocks below would have been a joke at the reader's
# expense. ALLOW_MISSING_NFPM=1 opts out deliberately and says so.
if ! command -v nfpm >/dev/null; then
    if [ "${ALLOW_MISSING_NFPM:-0}" = "1" ]; then
        echo "==> WARNING: nfpm not installed and ALLOW_MISSING_NFPM=1;" \
             "this run produced NO packages" >&2
    else
        echo "build.sh: nfpm is required to produce packages but is not installed." >&2
        echo "  install from https://nfpm.goreleaser.com/, or set" >&2
        echo "  ALLOW_MISSING_NFPM=1 to build binaries only." >&2
        exit 1
    fi
else
    for ARCH in amd64 arm64; do
        for PKG in server client; do
            echo "==> Package host-health-mcp-$PKG $ARCH"
            ARCH=$ARCH VERSION=$VERSION envsubst \
                < "$SCRIPT_DIR/nfpm/nfpm-$PKG.yaml.tmpl" \
                > "$SCRIPT_DIR/nfpm/nfpm-$PKG-$ARCH.yaml"
            ( cd "$SCRIPT_DIR/nfpm" && nfpm package -f "nfpm-$PKG-$ARCH.yaml" -p deb -t "$DIST/" )
        done
    done
fi

# Step 6: SHA256SUMS for whatever artefacts landed.
echo "==> SHA256SUMS"
( cd "$DIST" && find . -maxdepth 2 -type f \( -name '*.deb' -o -name 'host-health-mcp-*' \) -print0 \
    | xargs -0 sha256sum | sort > SHA256SUMS )

echo "==> Done. Output in $DIST/"
