# plugin/

Go module containing the MCP plugin that exposes the daemon's tool
surface to MCP-speaking clients. Distributed as a standard MCP server
package (REQ 9.4); deployable on the operator workstation, on the target
host, or on a designated relay.

Configurable via environment variables (REQ 9.4):

- `HOSTHEALTH_TLS_CERT`, `HOSTHEALTH_TLS_KEY` — operator client cert + key
  for mTLS to the daemon.
- `HOSTHEALTH_TLS_CA` — optional CA bundle for daemon verification
  (otherwise system roots).
- `HOSTHEALTH_TARGET_HOST` — optional default target. The `host` argument
  on each tool call overrides it.
- `HOSTHEALTH_TARGET_PORT` — default port appended to bare hosts.
- `HOSTHEALTH_DNS_SUFFIX` — appended to host arguments with no dot.
- `HOSTHEALTH_TOOL_PREFIX` — prefix on MCP tool names (default `host_`).

The plugin negotiates schema-version compatibility with the daemon
through the `manifest` envelope on first contact per host per session
and fails closed on a major-version mismatch (REQ 7.2; version-matrix
C4). The compatibility matrix is in `../doc/version-matrix.md`.

## Package layout

```
plugin/
├── cmd/plugin/main.go             MCP server entrypoint
└── internal/
    ├── mcp/                       MCP protocol handling over stdio;
    │                              lifecycle (initialize, ping,
    │                              tools/list, tools/call); schema-
    │                              version gate per host
    ├── client/                    HTTP/JSON client to the daemon's
    │                              listener; mTLS configuration;
    │                              per-call host
    └── schema/                    compile-time SchemaVersion the
                                   plugin was built against
```

## Hard rules specific to this tree

- The plugin **must** accept the target host as a first-class argument
  (`host`). No hard-coded host list. (REQ 7.2.)
- The plugin surfaces daemon-side `warnings[]` to the caller without
  flattening them into the data payload. (REQ 7.2.)
- The plugin fails closed on schema-version incompatibility. (REQ 7.2,
  version-matrix C4.)
- Tool descriptions in the MCP manifest explicitly state read-only nature
  and the hard timeout. (REQ 7.2.)
- The plugin treats `tool_disabled` and `schema_incompatible` errors from
  the daemon as distinct cases. `tool_disabled` is a config state, not a
  version mismatch (version-matrix §4).

## Tests

The plugin's tools render against fixture daemon responses produced from
the schema in `../doc/schema-draft.yaml`. Live integration tests run the
plugin against a real daemon instance in a container.
