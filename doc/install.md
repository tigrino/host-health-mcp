---
title: Host Health MCP - Installation
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
date: 2026-05-14
---

This document covers a fresh installation of `host-health-mcp` on a
single Debian/Ubuntu host: package install, system user creation
(handled by the post-install scriptlet), PKI provisioning, config
authoring, first start, and the operational notes the architect
brief and the requirements call out.

# 1. Package install

The build pipeline produces two `.deb` artefacts under
`build/dist/`:

```
host-health-mcp_<version>_amd64.deb
host-health-mcp_<version>_arm64.deb
```

Install with `dpkg`:

```
sudo dpkg -i host-health-mcp_<version>_<arch>.deb
sudo apt-get install -f          # if dependencies need resolution
```

The post-install scriptlet creates the `host-health-mcp` system
user (no shell, no home other than the state directory), establishes
`/etc/host-health-mcp/tls` with mode `0750` owner `root:host-health-mcp`,
and **enables but does not start** the two systemd units. The
operator places real configuration before first start.

# 2. PKI provisioning

The daemon listens with mTLS only. Three files are required under
`/etc/host-health-mcp/tls/`:

  - `cert.pem` (the daemon's server certificate)
  - `key.pem`  (the matching private key)
  - `ca.pem`   (the bundle that issues client certificates)

Permissions and ownership:

```
sudo chown root:host-health-mcp /etc/host-health-mcp/tls/*.pem
sudo chmod 0640 /etc/host-health-mcp/tls/{cert,ca}.pem
sudo chmod 0640 /etc/host-health-mcp/tls/key.pem
```

The daemon does not implement CRL or OCSP (design §5; threat-model R3).
Revocation is operator policy — short-lived client certificates
rotated by the operator's PKI tooling are the recommended posture.
Each rotation requires a `systemctl restart host-health-mcp.service`;
the daemon does not support runtime TLS material reload.

## 2.2 Client-certificate template requirements (1.12.0+)

Daemon 1.12.0 verifies, in addition to chain-to-CA:

  - The presented leaf certificate is NOT a CA (`basicConstraints
    CA:FALSE`).
  - The leaf carries `extendedKeyUsage = clientAuth` explicitly.
    RFC 5280 §4.2.1.12 says "absent EKU = any purpose allowed";
    the daemon does not rely on that — operator CSRs must declare
    the EKU.
  - The leaf has a non-empty Subject CN or at least one DNS SAN
    (so the daemon can derive a caller identity for rate-limiting
    and audit).

Existing operator-side CSR templates that produced bare-CN certs
without an EKU stanza WILL be rejected after upgrading. Pre-flight
verification on the operator workstation:

```
openssl x509 -in client.pem -noout -ext extendedKeyUsage
```

A passing cert prints `TLS Web Client Authentication`. If the
output is empty or shows different EKUs, regenerate the CSR with
(openssl example):

```
openssl req -new -key client.key -addext "extendedKeyUsage = clientAuth" \
    -subj "/CN=ops-client" -out client.csr
```

…or the equivalent ansible / cfssl / step-ca / smallstep
configuration. The CA must preserve the EKU (e.g. `openssl x509
-copy_extensions copy` if signing through `openssl x509`, or
`-extfile` with `extendedKeyUsage = clientAuth`).

Rotate every operator and host client cert through one renewal
cycle before deploying daemon 1.12.0; otherwise the first request
after the daemon restart returns TLS `bad_certificate`.

## 2.1 ACME-style deploy hooks

For ACME / cert-manager-driven PKI, point the deploy hook at:

```
#!/bin/sh
install -o root -g host-health-mcp -m 0640 \
    "$RENEWED_LINEAGE/cert.pem" /etc/host-health-mcp/tls/cert.pem
install -o root -g host-health-mcp -m 0640 \
    "$RENEWED_LINEAGE/privkey.pem" /etc/host-health-mcp/tls/key.pem
systemctl restart host-health-mcp.service
```

Each restart resets per-caller rate-limit buckets and drains in-flight
audit state. Operators choosing sub-hourly cert rotation should expect
correspondingly frequent restart events in `journalctl -u
host-health-mcp`.

# 3. Configuration

Three files under `/etc/host-health-mcp/` drive runtime behaviour:

## 3.1 `daemon.yml` (mode 0640, root:host-health-mcp)

Authoritative example: `/etc/host-health-mcp/daemon.yml.example` shipped
with the package. Key fields:

  - `bind_addr` — listener address. `127.0.0.1:8443` for SSH-tunnelled
    operator access; an overlay address for inter-host pulls. A
    routable public address requires `public_bind_acknowledged: true`
    or the daemon emits a startup warning (REQ 6.4).
  - `tls_cert_path`, `tls_key_path`, `client_ca_path` — PKI material.
  - `manifest_path` — defaults to
    `/etc/host-health-mcp/manifest.yml`.
  - `helper_socket_path` — defaults to
    `/run/host-health-mcp/helper.sock`.
  - `cache_ttl_overrides`, `timeout_overrides` — per-tool tuning;
    timeouts are capped at 10 s per REQ 5.1.
  - `dns_probe_targets` — DNS tool's external and canary probes;
    operator-supplied, caller cannot influence.
  - `ipv4_allowlist_ranges`, `ipv6_allowlist_ranges` — CIDRs that
    pass through the log-sample redactor unredacted.
  - `expensive_tool_buckets` — per-(caller, tool) token buckets for
    `logs`, `workload`, `storage` etc.
  - `max_concurrent_handshakes` — TLS handshake-time cap, default 16.

The daemon refuses unknown keys at startup (REQ 8.1).

## 3.2 `manifest.yml` (mode 0644)

Per-host enablement plus tool-specific operator data. The most
operationally significant fields:

  - `enabled_tools` — subset of the 17 tools in REQ §4. The daemon
    enforces this list at HTTP routing: a tool not on the list
    returns 404/`unknown_tool` even when the binary is compiled in
    (REQ 8.2). Every name on the list must be compiled into the
    build, or the daemon refuses to start. An empty list emits a
    single startup warning and exposes every compiled-in tool
    (legacy behaviour for hosts that have not yet pinned the
    surface). The `caps-template.sh` post-install script emits a
    `host-health-mcp: warning: enabled_tools contains unknown name
    '<name>'` line on stderr for any name the script does not
    recognise — typically a typo or a script that pre-dates the
    name's introduction.
  - `whitelisted_units` — the systemd units the `systemd_units` tool
    is permitted to report on. The caller cannot supply unit names.
  - `workload_plugins` — must intersect the build's
    `WORKLOAD_TAGS=` set (default ships all four named plugins).
  - `btrfs_mountpoints` — paths the helper's `btrfs_scrub` op may
    operate against. The helper also verifies via `statfs(2)` that
    each path is a btrfs filesystem (BTRFS_SUPER_MAGIC) before
    invoking `btrfs(8)`.
  - `cert_paths`, `cert_renewal_units` — parallel lists for the
    `certs` tool.

## 3.3 `helper.yml` (mode 0600, root-owned)

Tiny by design:

  - `daemon_user` — the system user the daemon runs as; the helper
    rejects any unix-socket peer whose `SO_PEERCRED` reports a
    different uid.
  - `socket_path` — must match the daemon's `helper_socket_path`.
  - `op_deadline_ms` — per-op overrides if the defaults are tight on
    a particular host.

# 4. Capability templating

The helper unit's `CapabilityBoundingSet` is **not** set in the
shipped `host-health-mcp-helper.service` file. The post-install
scriptlet (and any subsequent manifest edit) regenerates a drop-in:

```
/etc/systemd/system/host-health-mcp-helper.service.d/caps.conf
```

The generator script is at
`/usr/local/share/host-health-mcp/caps-template.sh`. After editing
`manifest.yml`:

```
sudo /usr/local/share/host-health-mcp/caps-template.sh
sudo systemctl daemon-reload
sudo systemctl restart host-health-mcp-helper.service
sudo systemctl restart host-health-mcp.service
```

The drop-in adds caps only for ops the manifest enables. Operators
not running ZFS do not pay `CAP_SYS_ADMIN`; not running WireGuard
do not pay `CAP_NET_ADMIN`.

The same generator writes a second drop-in at
`/etc/systemd/system/host-health-mcp.service.d/10-ip-egress.conf`
with `IPAddressDeny=any` plus `IPAddressAllow=localhost` and one
`IPAddressAllow=<resolver>` line for each address listed under
`dns.resolvers[]` in `daemon.yml`. This implements REQ 6.8 (egress
enumerable from config) at the kernel layer. If an operator's
deployment legitimately needs to reach an additional destination
(e.g. a recursive resolver on a non-loopback IP), add a manual
drop-in with the extra `IPAddressAllow=` lines; the generated file
is overwritten on every re-run.

# 5. First start

```
sudo systemctl start host-health-mcp-helper.service
sudo systemctl start host-health-mcp.service
sudo systemctl status host-health-mcp.service
```

Verify the listener:

```
curl --cacert /path/to/ca.pem \
     --cert  /path/to/plugin-cert.pem \
     --key   /path/to/plugin-key.pem \
     --tlsv1.3 \
     -X POST -d '{}' \
     https://<host>:8443/v1/manifest
```

You should see a JSON envelope with `schema_version`, `host`, `as_of`,
and a `data` object listing the daemon's `enabled_tools`.

## 5.1 Plugin CA bundle (fail-closed)

The MCP plugin client refuses to start if `HOSTHEALTH_TLS_CA` (and the
corresponding `Config.CAPath`) is empty. The deployment model is an
internal operator PKI; falling back to the system root store would
let any publicly-trusted CA issue a certificate the plugin would
accept. An operator who genuinely needs the system root store — for
example, a one-off test against a host whose certificate is issued
by a public CA — can set `HOSTHEALTH_TRUST_SYSTEM_ROOTS=1` in the
plugin environment. The plugin logs a single warning at startup when
the override is active.

# 6. Audit-log consumption

Every accepted or rejected call produces one journald entry tagged
`host-health-mcp` (REQ 6.5). Operator pipelines that consume journald
events can filter with:

```
journalctl -u host-health-mcp -t host-health-mcp -o json --since "5 min ago"
```

Payload bodies are never logged. Each entry contains caller identity
(CN/SAN from the verified client cert), tool name, structured args,
response size, duration, and either `result=ok` or a reject reason.

# 7. systemd-analyze baseline

Re-run after install on a fresh canary to establish the security
baseline (REQ 9.5 ack item):

```
sudo systemd-analyze security host-health-mcp.service
sudo systemd-analyze security host-health-mcp-helper.service
```

The daemon unit ships with `NoNewPrivileges`, empty
`CapabilityBoundingSet`, empty `AmbientCapabilities`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`MemoryDenyWriteExecute`, `RestrictSUIDSGID`, and
`SystemCallFilter=@system-service ~@privileged ~@resources ~@mount
~@swap ~@reboot ~@module`. The helper unit applies all the same
hardening **except** the empty `CapabilityBoundingSet` — that is
filled in by the install-time `caps.conf` drop-in.

# 8. Uninstall

```
sudo systemctl stop host-health-mcp.service host-health-mcp-helper.service
sudo dpkg --remove host-health-mcp
sudo dpkg --purge host-health-mcp     # also wipes /etc/host-health-mcp
sudo deluser --system host-health-mcp
sudo rm -rf /var/lib/host-health-mcp
```

# 9. Troubleshooting

Symptoms and first-look commands:

  - `host-health-mcp.service` enters `failed` immediately:
    `journalctl -u host-health-mcp -n 50` — usually a missing TLS
    file, an unknown key in `daemon.yml`, or a manifest workload
    plugin not compiled in.
  - Tool returns `tool_failed` with helper-side code:
    `journalctl -u host-health-mcp-helper -n 50` — the helper-side
    error code (`tool_missing`, `tool_failed`, `deadline`,
    `output_truncated`, `parse_failed`) plus the
    `stderr_sha256` fingerprint identify what to investigate.
  - All calls return 401 `auth_required`: the client cert was not
    presented or did not verify against `client_ca_path`. Run
    `openssl s_client -connect <host>:8443 -cert ... -key ...` to
    confirm.
  - All calls return 429 `rate_limited`: the per-caller token bucket
    has been exhausted. Either drop the calling cadence or raise
    `expensive_tool_buckets` in `daemon.yml`.
