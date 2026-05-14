# build/

Orchestrates a release build. Inputs: a clean checkout and a pinned Go
toolchain (read from `daemon/go.mod`'s `toolchain` directive). Outputs:
versioned, checksummed `.deb` artefacts for `linux/amd64` and
`linux/arm64`.

The full build sequence is specified in `../doc/design-overview.md` §10.
Build reproducibility is **functional, not byte-identical**; the trade-
off is recorded in §10.1.

## Planned layout

```
build/
├── build.sh                       drives the full build
├── nfpm/
│   ├── nfpm-amd64.yaml            .deb packaging config, amd64
│   └── nfpm-arm64.yaml            .deb packaging config, arm64
├── systemd/
│   ├── host-health-mcp.service        daemon unit (REQ 3.4, 9.2)
│   └── host-health-mcp-helper.service helper unit (REQ 3.4, 9.2)
├── postinst/                      post-install scriptlet sources
│   └── caps-template.sh           generates /etc/systemd/system/
│                                  host-health-mcp-helper.service.d/
│                                  caps.conf from manifest.yml at install
│                                  (design §7 cap-bounding-set templating)
└── dist/                          build output; gitignored
```

## What `build.sh` does

Numbered list per design §10:

1. Reads the Go toolchain version from `../daemon/go.mod` `toolchain`
   directive and verifies the local toolchain matches.
2. Sets `SOURCE_DATE_EPOCH` from `HEAD`'s author timestamp. For hygiene
   only - not a byte-reproducibility guarantee.
3. Runs `go vet`, `go test ./...`, the custom forbidden-call linter,
   `staticcheck`, and `govulncheck` against `../daemon/` and
   `../plugin/`.
4. Builds both binaries from `../daemon/cmd/daemon` and
   `../daemon/cmd/helper` for `GOOS=linux GOARCH={amd64,arm64}` with
   `CGO_ENABLED=0 -trimpath -ldflags='-buildid= -X
   main.buildID=<git-sha>'`. Builds `../plugin/cmd/plugin` similarly.
5. Stages the per-architecture tree (binaries, unit files, postinst
   script, example configs, `../doc/`) and invokes `nfpm` to produce the
   `.deb`.
6. Writes `SHA256SUMS` into `dist/`.

## Hardening surfaces produced by the build

The systemd units written here implement REQ 3.4 hardening. Both units
set `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateTmp=yes`. The daemon unit additionally sets
`CapabilityBoundingSet=` and `AmbientCapabilities=` (both empty). The
helper unit's `CapabilityBoundingSet` is empty in the shipped unit file
and is overridden by the install-time-generated drop-in (see
`postinst/caps-template.sh`); the drop-in's set is the union of caps
required by the ops enabled in the operator's `manifest.yml`.

## What is **not** done here

- Toolchain provisioning. The build assumes the pinned Go toolchain is
  already on PATH. CI images and container builders are out of scope per
  the architect brief.
- Signing the `.deb`. Repository-level signing is the deployment
  integrator's concern; `build/dist/SHA256SUMS` is the canonical artefact
  identity (design §10.1).
- `diffoscope` verification. Byte-identical reproducibility is not a
  goal (design §10.1).
