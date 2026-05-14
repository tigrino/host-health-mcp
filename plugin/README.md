# plugin/

Go module containing the MCP plugin that exposes the daemon's tool
surface to MCP-speaking clients. Distributed as a standard MCP server
package (REQ 9.4); deployable on the operator workstation, on the target
host, or on a designated relay.

Configurable via environment variables (REQ 9.4):

- TLS material path (client cert + key for mTLS to the daemon).
- Bearer token path (unused in the current design; mTLS is the chosen
  authentication mechanism per design §5).
- Default target host (optional).
- Default target port.
- Optional DNS suffix appended to bare hostnames.

The plugin negotiates schema-version compatibility with the daemon via
the `manifest` tool on first contact per session and fails closed on
major mismatch (REQ 7.2). The full compatibility matrix is in
`../doc/version-matrix.md`.

## Planned package layout

```
plugin/
├── cmd/plugin/main.go             MCP server entrypoint
└── internal/
    ├── mcp/                       MCP protocol handling
    │                              one tool per daemon RPC; tool names
    │                              namespaced under a configurable
    │                              prefix (default "host_")
    └── client/                    HTTP/JSON client to the daemon's
                                   listener; mTLS configuration
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
