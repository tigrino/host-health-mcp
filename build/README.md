# build/

Orchestrates a release build. Inputs: a clean checkout and a Go
toolchain pinned by the `GOTOOLCHAIN` export at the top of
`build.sh` (currently `go1.26.5`, overridable from the environment).
Outputs: versioned, checksummed `.deb` artefacts — one server and
one client package for each of `linux/amd64` and `linux/arm64`.

The full build sequence is specified in `../doc/design-overview.md` §10.
Build reproducibility is **functional, not byte-identical**; the trade-
off is recorded in §10.1.

## Planned layout

```
build/
├── build.sh                       drives the full build
├── nfpm/
│   ├── nfpm-server.yaml.tmpl      .deb packaging template, server
│   └── nfpm-client.yaml.tmpl      .deb packaging template, client
│                                  build.sh expands each through
│                                  envsubst per arch, producing
│                                  nfpm-{server,client}-{amd64,arm64}.yaml
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

1. Exports `GOTOOLCHAIN=${GOTOOLCHAIN:-go1.26.5}` to pin the toolchain.
   No `go.mod` in the tree carries a `toolchain` directive; the
   `go 1.22` directive in each is a floor, not a pin.
2. Sets `SOURCE_DATE_EPOCH` from `HEAD`'s author timestamp. For hygiene
   only - not a byte-reproducibility guarantee.
3. Runs `go vet` and `go test ./...` against both `../daemon/` and
   `../plugin/`. The custom forbidden-call linter runs with
   `-root daemon` only. `staticcheck` and `govulncheck` run against
   `../daemon/` only, and are skipped when not installed; CI should
   require them per REQ 10.2.
4. Builds both binaries from `../daemon/cmd/daemon` and
   `../daemon/cmd/helper` for `GOOS=linux GOARCH={amd64,arm64}` with
   `CGO_ENABLED=0 -trimpath -ldflags='-buildid= -X
   main.buildID=<git-sha>'`. Builds `../plugin/cmd/plugin` similarly.
5. Stages the per-architecture trees — the server tree (both binaries,
   the capability generator, both unit files, the postinst script,
   example configs, documentation from `../doc/`) and the client tree
   (the client binary and its environment example) — and invokes
   `nfpm` four times, once per (package, arch) pair, producing four
   `.deb` artefacts.
6. Writes `SHA256SUMS` into `dist/`.

## Hardening surfaces produced by the build

The systemd units written here implement REQ 3.4 hardening. Both units
set `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateTmp=yes`. The daemon unit additionally sets
`CapabilityBoundingSet=` and `AmbientCapabilities=` (both empty). The
helper unit's `CapabilityBoundingSet` is `CAP_CHOWN` in the shipped unit
file — enough to chown its socket and runtime directory at startup — and
is extended by the install-time-generated drop-in (see
`postinst/caps-template.sh`); the drop-in's set is `CAP_CHOWN` plus the
union of caps required by the ops enabled in the operator's
`manifest.yml`.

## What is **not** done here

- Toolchain provisioning. The build assumes the pinned Go toolchain is
  already on PATH. CI images and container builders are out of scope per
  the architect brief.
- Signing the `.deb`. Repository-level signing is the deployment
  integrator's concern; `build/dist/SHA256SUMS` is the canonical artefact
  identity (design §10.1).
- `diffoscope` verification. Byte-identical reproducibility is not a
  goal (design §10.1).
