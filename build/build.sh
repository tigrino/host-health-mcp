#!/usr/bin/env bash
# Drives a release build per design-overview.md section 10.
# Inputs: a clean checkout and a pinned Go toolchain (from daemon/go.mod).
# Outputs: versioned, checksummed .deb artefacts for amd64 and arm64.
#
# Build reproducibility is FUNCTIONAL, not byte-identical. See section
# 10.1 of design-overview.md for the trade-off.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
DIST="$SCRIPT_DIR/dist"

VERSION=${VERSION:-$(cd "$REPO" && git describe --tags --dirty --always 2>/dev/null || echo "0.0.0-dev")}
GIT_SHA=$(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(cd "$REPO" && git log -1 --pretty=%ct 2>/dev/null || date +%s)}

mkdir -p "$DIST"

echo "==> Build host-health-mcp $VERSION (git $GIT_SHA, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"

# Step 1-3: vet, test, linters.
echo "==> go vet"
( cd "$REPO/daemon" && go vet ./... )
echo "==> go test"
( cd "$REPO/daemon" && go test ./... )

# Optional linters: only run if installed. Production CI should
# require these per REQ 10.2.
if command -v staticcheck >/dev/null 2>&1; then
    echo "==> staticcheck"
    ( cd "$REPO/daemon" && staticcheck ./... )
fi
if command -v govulncheck >/dev/null 2>&1; then
    echo "==> govulncheck"
    ( cd "$REPO/daemon" && govulncheck ./... )
fi

# Step 4: build both binaries for each arch.
LDFLAGS="-buildid= -X main.buildID=$GIT_SHA"
for ARCH in amd64 arm64; do
    echo "==> Build $ARCH"
    mkdir -p "$DIST/$ARCH"
    ( cd "$REPO/daemon" && \
        CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH \
        go build -trimpath -ldflags="$LDFLAGS" \
        -o "$DIST/$ARCH/host-health-mcp-daemon" ./cmd/daemon )
    ( cd "$REPO/daemon" && \
        CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH \
        go build -trimpath -ldflags="$LDFLAGS" \
        -o "$DIST/$ARCH/host-health-mcp-helper" ./cmd/helper )
done

# Step 5: nfpm per arch.
if ! command -v nfpm >/dev/null 2>&1; then
    echo "nfpm not installed; skipping .deb production." >&2
    echo "Install from https://nfpm.goreleaser.com/ to produce packages." >&2
else
    for ARCH in amd64 arm64; do
        echo "==> Package $ARCH"
        ARCH=$ARCH VERSION=$VERSION envsubst < "$SCRIPT_DIR/nfpm/nfpm.yaml.tmpl" \
            > "$DIST/$ARCH/nfpm.yaml"
        ( cd "$DIST/$ARCH" && nfpm package -f ./nfpm.yaml -p deb -t "$DIST/" )
    done
fi

# Step 6: SHA256SUMS for whatever artefacts landed.
echo "==> SHA256SUMS"
( cd "$DIST" && find . -maxdepth 2 -type f \( -name '*.deb' -o -name 'host-health-mcp-*' \) -print0 \
    | xargs -0 sha256sum | sort > SHA256SUMS )

echo "==> Done. Output in $DIST/"
