# daemon/

Go module containing two binaries that ship together as one package:

- `cmd/daemon` → `/usr/local/sbin/host-health-mcp-daemon` (network-facing,
  unprivileged).
- `cmd/helper` → `/usr/local/sbin/host-health-mcp-helper` (root via its
  systemd unit, exposed only via unix socket).

Privilege separation, IPC framing, op surface, and the linter discipline
are specified in `../doc/design-overview.md` §7. Read that before adding
or changing anything in this tree.

## Planned package layout

```
daemon/
├── cmd/
│   ├── daemon/main.go         daemon entrypoint
│   └── helper/main.go         helper entrypoint
└── internal/
    ├── daemon/                daemon-only, no helper imports allowed
    │   ├── audit/             audit-log emission (REQ 6.5)
    │   ├── cache/             global in-process cache + singleflight
    │   ├── config/            daemon.yml + manifest.yml parsing
    │   ├── helperinvoke/      unix-socket client to the helper service
    │   │                      sole site for daemon-side exec-equivalent;
    │   │                      the custom linter exempts this package only
    │   ├── httpserver/        TLS listener and request routing
    │   ├── ratelimit/         two-level token-bucket limiter (REQ 6.6)
    │   ├── redact/            positive-list redaction filter (REQ 6.3)
    │   └── tools/             one sub-package per tool 4.1-4.17
    ├── helper/                helper-only, no daemon imports allowed
    │   ├── config/            helper.yml parsing
    │   ├── dispatch/          op dispatcher; closed compile-time enum
    │   ├── exec/              sole site for helper-side os/exec
    │   ├── ops/               one file per op (design §7.3)
    │   ├── parse/             per-tool output parsers
    │   └── server/            unix-socket listener; SO_PEERCRED check
    └── shared/                both binaries import these
        ├── proto/             helper-socket frame types
        └── schema/            generated from ../doc/schema-draft.yaml
```

## Hard rules specific to this tree

- The daemon never imports `helper/...` and vice versa. Go's `internal`
  rule does not enforce this on its own at this depth; we add a
  `go vet`-time check in the linter set.
- `os/exec`, `syscall.ForkExec`, and write-mode `os.OpenFile`/`os.Create`
  are forbidden everywhere except `internal/daemon/helperinvoke/` (daemon
  side) and `internal/helper/exec/` (helper side). The custom forbidden-
  call linter enforces this at build time.
- The helper never reads anything caller-supplied as a path, regex, or
  shell fragment. Op parameters are validated against per-op whitelists
  before any tool is invoked.
- Helper-socket frames are length-prefixed JSON with a 16 KiB cap on the
  declared length. Larger frames are rejected before the body is read.

## Tests

Each tool gets:

- Unit tests with fixture data for the subsystem it queries
  (REQ 10.1).
- An integration test that runs against a real subsystem in a container
  or VM (REQ 10.1).

The redaction filter has a fuzz target plus an exhaustive table-driven
test set (REQ 10.2). Static analysis: `go vet`, `staticcheck`,
`govulncheck`, plus the custom forbidden-call linter (REQ 10.2).
