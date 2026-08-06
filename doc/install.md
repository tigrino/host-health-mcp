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

Two binary packages are published:

  - **`host-health-mcp-server`** — the daemon, the helper, both
    systemd units, the capability generator, and the package
    documentation. Install this on every monitored host.
  - **`host-health-mcp-client`** — the MCP client binary and a
    worked environment example. Install this on the operator
    workstation or on a designated relay. It ships no systemd unit,
    creates no system user, and has no package dependencies.

Both are built for `linux/amd64` and `linux/arm64`.

## 1.1 Supported path: apt from the fleet repository

On the monitored host:

```
sudo apt update
sudo apt install host-health-mcp-server
```

On the operator workstation or relay:

```
sudo apt install host-health-mcp-client
```

This is the supported installation path. Repository configuration —
sources list, signing key, pinning, and which hosts see which suite —
is fleet infrastructure and is not provisioned by this repository.

## 1.2 Offline path: direct `.deb` install

**Scope note.** Everything in this section — the artefacts under
`build/dist/`, the maintainer scripts under `build/postinst/`, and the
nfpm configuration that assembles them — belongs to this path only. It
is how a package gets onto a host with no repository access, and how
this repository's own packaging is tested.

Packages installed by section 1.1 are built by a separate packaging
pipeline from its own packaging sources. That packaging supplies its
own maintainer scripts and its own toolchain pin, so nothing under
`build/` runs on that path and no guarantee made there applies to it.
The two are kept in step by what both consume from this repository —
`build/systemd/*.service`, `daemon/cmd/capstemplate`,
`build/examples/*`, and `build/workload-tags` — not by sharing a build.

The `build/postinst/` scripts are therefore reference material as much
as they are shipped code: when a change here affects install-time
behaviour, downstream packaging needs the same change made in its own
scripts, and that only happens if the release note says so.

Where the fleet repository is not reachable, install the artefacts
produced under `build/dist/` directly:

```
host-health-mcp-server_<version>_<arch>.deb
host-health-mcp-client_<version>_<arch>.deb
```

```
sudo apt install ./host-health-mcp-server_<version>_<arch>.deb
```

Prefer `apt install ./<file>.deb` over `dpkg -i`: it resolves
dependencies in the same step. With `dpkg` the resolution is a
second command:

```
sudo dpkg -i host-health-mcp-server_<version>_<arch>.deb
sudo apt-get install -f          # if dependencies need resolution
```

## 1.3 What the server post-install does

The post-install scriptlet creates the `host-health-mcp` system group
and user (no shell, no home other than the state directory),
establishes `/etc/host-health-mcp/tls` with mode `0750` owner
`root:host-health-mcp`, runs the capability generator (section 4),
reloads systemd, and restarts whichever of the two units was already
running.

It does **not** enable or start anything. Restart-if-running makes an
upgrade take effect; it never brings up a listener that was stopped,
and whether these units start at boot stays an operator decision — see
section 5. Until you enable them the services do not come back after a
reboot.

From 2.3.0 the package also ships a `prerm` that stops both units on
removal and a `postrm` that reloads systemd, with `purge` additionally
removing the generated drop-ins. Before 2.3.0 no maintainer script
carried a `systemctl` call at all: an upgrade installed a new binary
that the running units went on ignoring, and a removal deleted the unit
files from under two running services.

Beyond that directory the package owns nothing under
`/etc/host-health-mcp/`. The example configurations ship as
documentation at `/usr/share/doc/host-health-mcp-server/examples/`
(mode `0644`) and are **not** conffiles. Copy them into place with
the modes each file requires:

```
sudo install -m 0640 -o root -g host-health-mcp \
    /usr/share/doc/host-health-mcp-server/examples/daemon.yml \
    /etc/host-health-mcp/daemon.yml
sudo install -m 0600 -o root -g root \
    /usr/share/doc/host-health-mcp-server/examples/helper.yml \
    /etc/host-health-mcp/helper.yml
sudo install -m 0644 -o root -g root \
    /usr/share/doc/host-health-mcp-server/examples/manifest.yml \
    /etc/host-health-mcp/manifest.yml
```

`redaction.yml` is optional and deliberately not copied above. It is
only read when `log_redaction_rules` in `daemon.yml` names it, and that
key ships commented out. To use operator redaction patterns, copy the
example and uncomment the key:

```
sudo install -m 0640 -o root -g host-health-mcp \
    /usr/share/doc/host-health-mcp-server/examples/redaction.yml \
    /etc/host-health-mcp/redaction.yml
```

If the key names a file that does not exist the daemon starts and logs
a warning; a file that is present but contains an invalid regexp is
fatal, because in that case rules were written and would otherwise be
silently weaker than asked for.

Because the live configuration is not package-owned, an upgrade
never overwrites it and `dpkg` never raises a conffile prompt. The
corollary is that configuration keys introduced by a new release do
not appear in the running configuration on their own: read
`doc/changelog.md` and diff against the refreshed examples after
each upgrade.

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

Authoritative example:
`/usr/share/doc/host-health-mcp-server/examples/daemon.yml` shipped
with the package. Key fields:

  - `bind_addr` — listener address. `127.0.0.1:8443` for SSH-tunnelled
    operator access; an overlay address for inter-host pulls. A
    routable public address requires `public_bind_acknowledged: true`;
    without it the daemon **refuses to start** and says so (REQ 6.4).
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
  - `ip_filter_allow` — optional list of networks for the systemd
    packet filter on the daemon unit. It is consumed at install time
    by the capability generator, which turns it into a drop-in; the
    daemon does not act on the key itself, but it does validate every
    entry when it loads its configuration, so a malformed entry fails
    the service at startup. Absent or empty means no filtering, which
    is the default. Section 4 covers the semantics and the required
    YAML form.

The daemon refuses unknown keys at startup (REQ 8.1).

## 3.2 `manifest.yml` (mode 0644)

Per-host enablement plus tool-specific operator data. The most
operationally significant fields:

  - `enabled_tools` — subset of the registered tool set (the 17
    tools in REQ §4 plus the additive `firewall` and
    `firewall_lookup` from 1.13.0 / 1.14.0). The daemon enforces
    this list at HTTP routing: a tool not on the list returns
    404/`unknown_tool` even when the binary is compiled in (REQ
    8.2). Every name on the list must be compiled into the build,
    or the daemon refuses to start. An empty list emits a single
    startup warning and exposes every compiled-in tool (legacy
    behaviour for hosts that have not yet pinned the surface). The
    capability generator (`/usr/sbin/host-health-mcp-caps-template`)
    emits a
    `host-health-mcp: warning: enabled_tools contains unknown name
    '<name>'` line on stderr for any name the script does not
    recognise — typically a typo or a script that pre-dates the
    name's introduction.
  - `whitelisted_units` — the systemd units the `systemd_units` tool
    is permitted to report on. The caller cannot supply unit names.
  - `workload_plugins` — must intersect the build's
    `WORKLOAD_TAGS=` set (default ships all four named plugins).
  - `workload_plugin_config` — a string-to-(string-to-string) map
    keyed by plugin name, carrying plugin-specific configuration.
    Today only the `nginx_apache` plugin consumes a config (see
    section 3.4 below).
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

## 3.4 `nginx_apache` workload plugin

The plugin reads the access log directly via a bounded tail-read
(default 256 KiB). No operator scripting is required — point
`access_log_path` at the existing access log file and the helper
does the rest.

`manifest.yml`:

```yaml
workload_plugin_config:
  nginx_apache:
    access_log_path: /var/log/nginx/access.log
    # optional knobs:
    # access_log_window_minutes: 60   (default; 1..1440)
    # access_log_tail_bytes: 262144   (default 256 KiB; max 4 MiB)
```

The access log must be in combined or common log format
(timestamp in `[DD/Mon/YYYY:HH:MM:SS +ZZZZ]` form, status code
following the quoted request field). Custom `log_format` values
that omit one or both will cause `recent_4xx` / `recent_5xx` to
come back null with `recent_coverage="unavailable"` and a plugin
warning.

If `access_log_path` is unset or unreadable, `recent_4xx` and
`recent_5xx` are null (NOT zero), `recent_coverage` is
`"unavailable"`, and the response carries an envelope warning. A
null value means "can't measure", not "no errors" — fleet sweeps
should treat the two cases distinctly.

The helper parses the tail inside its own process and returns
typed integer counts to the daemon. Raw log bytes never cross the
helper-to-daemon socket boundary (REQ 6.2).

# 4. Capability templating

The shipped `host-health-mcp-helper.service` sets
`CapabilityBoundingSet=CAP_CHOWN` — only enough for the helper to chown
its unix socket and runtime directory at startup. The post-install
scriptlet (and any subsequent manifest edit) regenerates a drop-in that
extends it:

```
/etc/systemd/system/host-health-mcp-helper.service.d/caps.conf
```

The generator is installed at
`/usr/sbin/host-health-mcp-caps-template`. After editing
`manifest.yml`:

```
sudo /usr/sbin/host-health-mcp-caps-template --hint
sudo systemctl daemon-reload
sudo systemctl restart host-health-mcp-helper.service
sudo systemctl restart host-health-mcp.service
```

`--hint` appends a reminder of the two `systemctl` lines above. It is
off by default because the postinst runs the generator
non-interactively, where an instruction nobody can act on is noise.
The flag changes nothing else: same exit status, same drop-in, same
informational output.

The drop-in adds caps only for ops the manifest enables. Operators not
running WireGuard do not pay `CAP_NET_ADMIN`.

For storage this became true only in 2.3.0. `storage` is one tool over
five backends, and until then enabling it granted `CAP_SYS_ADMIN` and
`CAP_SYS_RAWIO` together — to every storage operator, in the **ambient**
set, so both were inherited across `execve` by `smartctl`, `lvs`,
`mdadm` and `btrfs`. `CAP_SYS_ADMIN` is broadly equivalent to root and
`CAP_SYS_RAWIO` permits raw device I/O. This document asserted the
opposite for several releases; it was wrong.

`storage_backends[]` in `manifest.yml` now gates them individually:

| Backend  | Capability granted   |
|----------|----------------------|
| `smart`  | `CAP_SYS_RAWIO`      |
| `zfs`    | `CAP_SYS_ADMIN`      |
| `btrfs`  | `CAP_SYS_ADMIN`      |
| `lvm`, `mdraid` | `CAP_DAC_READ_SEARCH` only |

`btrfs` needs `CAP_SYS_ADMIN` because `btrfs scrub status` reads a
status file for a finished scrub but issues `BTRFS_IOC_SCRUB_PROGRESS`
for a running one, and that ioctl is capability-gated.

Absent or empty, it defaults to `smart lvm mdraid` — deliberately not
"all", since defaulting an allow-list to everything is what produced
the original problem. Declare `zfs` or `btrfs` explicitly if the host
runs them; the generator prints which default it applied when
`storage` is enabled. Any YAML spelling of the list is accepted —
block form, flow form, and a multi-line flow sequence are the same
document — and an empty `[]` means "the default". Before 2.4.0 the
generator scanned this file with `grep` and `awk` and rejected flow
form outright, which aborted the package configure on a valid
manifest; see the 2.4.0 changelog entry.

## 4.1 IP filtering

The same generator writes a second drop-in at

```
/etc/systemd/system/host-health-mcp.service.d/10-ip-filter.conf
```

but **only** when `ip_filter_allow` in `daemon.yml` is non-empty.
Absent or empty, no drop-in is written and no IP filtering is
applied. That is the default.

The generated file carries `IPAddressDeny=any` followed by one
`IPAddressAllow=` line per entry. systemd's `IPAddressAllow=` and
`IPAddressDeny=` filter packets in **both** directions, inbound as
well as outbound. The list must therefore name every network that
has to reach the mTLS listener as well as every egress destination
the daemon may contact. A list naming only resolvers makes the
daemon unreachable.

Each entry is a CIDR, a bare address, or one of the systemd
keywords `any`, `localhost`, `link-local`, `multicast`. Entries are
validated when the daemon loads its configuration, so a typo fails
at startup rather than at the next restart.

Any YAML spelling of the list is accepted; from 2.4.0 the generator
reads this file with the same decoder the daemon uses. Block form is
what the example shows because it is easier to comment and to diff,
not because it is required:

```yaml
ip_filter_allow:
  - 127.0.0.1/32
  - 10.0.0.0/8
  - 192.0.2.53/32
```

After editing the key, re-run the generator and restart the daemon:

```
sudo /usr/sbin/host-health-mcp-caps-template --hint
sudo systemctl daemon-reload
sudo systemctl restart host-health-mcp.service
```

Releases 1.17.0 through 2.0.0 wrote an unconditional
`10-ip-egress.conf` in the same directory. The generator removes
that file when it runs; no operator action is required.

# 5. First start

The postinst has already run `daemon-reload` (and restarted any unit
that was already running), so the reload below is a no-op on a fresh
install and harmless to repeat. Neither unit is ENABLED, though — the
package deliberately does not make that decision for you. Skipping the
`enable` step yields a host on which the service runs now but does not
return after a reboot.

```
sudo systemctl daemon-reload
sudo systemctl enable host-health-mcp-helper.service host-health-mcp.service
sudo systemctl start host-health-mcp-helper.service
sudo systemctl start host-health-mcp.service
sudo systemctl status host-health-mcp.service
```

Start the helper first: the daemon needs the helper's unix socket.

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

## 5.1 MCP client configuration

`host-health-mcp-client` is configured entirely by environment
variable. There is no client configuration file. Eight variables are
read at startup:

| Variable | Default | Meaning |
|---|---|---|
| `HOSTHEALTH_TARGET_HOST` | none | Default target host. When unset, every call must name its host explicitly. |
| `HOSTHEALTH_TARGET_PORT` | `8443` | Daemon listener port. |
| `HOSTHEALTH_TLS_CERT` | `/etc/host-health-mcp/plugin/cert.pem` | Client certificate presented to the daemon. |
| `HOSTHEALTH_TLS_KEY` | `/etc/host-health-mcp/plugin/key.pem` | Matching private key. |
| `HOSTHEALTH_TLS_CA` | none | CA bundle that issued the daemon's server certificate. The client refuses to start if this is empty — see below. |
| `HOSTHEALTH_DNS_SUFFIX` | none | Suffix appended to bare hostnames supplied per call. |
| `HOSTHEALTH_TOOL_PREFIX` | `host_` | Prefix applied to the tool names the client advertises to the MCP host. |
| `HOSTHEALTH_TRUST_SYSTEM_ROOTS` | unset | Set to `1` to fall back to the system root store instead of failing closed. |

A worked example ships with the client package at
`/usr/share/doc/host-health-mcp-client/examples/client.env`. Copy it
to a location the MCP host can read, edit it, and reference it from
the MCP host's server configuration (or source it into the client's
environment).

### CA bundle: fail-closed

The client refuses to start if `HOSTHEALTH_TLS_CA` (and the
corresponding `Config.CAPath`) is empty. The deployment model is an
internal operator PKI; falling back to the system root store would
let any publicly-trusted CA issue a certificate the client would
accept. An operator who genuinely needs the system root store — for
example, a one-off test against a host whose certificate is issued
by a public CA — can set `HOSTHEALTH_TRUST_SYSTEM_ROOTS=1` in the
client environment. The client logs a single warning at startup when
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

The daemon unit ships with `NoNewPrivileges=yes`, empty
`CapabilityBoundingSet`, empty `AmbientCapabilities`,
`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
`PrivateDevices=yes`, `ProtectKernelTunables=yes`,
`ProtectKernelModules=yes`, `ProtectControlGroups=yes`,
`ProtectClock=yes`, `ProtectKernelLogs=yes`, `ProtectHostname=yes`,
`RestrictNamespaces=yes`, `RestrictRealtime=yes`,
`LockPersonality=yes`, `MemoryDenyWriteExecute=yes`,
`RestrictSUIDSGID=yes`, `RemoveIPC=yes`, and
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`,
`UMask=0077`, and a two-directive syscall filter:

```
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @swap @reboot @module
```

Two directives, not one line: a leading `~` makes the whole value a
deny-list, but a `~` in the middle of a list is parsed as part of a
syscall *name*. Releases up to 2.2.2 carried the single-line form, so
systemd logged `System call ~@privileged is not known, ignoring` and
applied only `@system-service` — every explicit denial was inert. Do
not copy the single-line form into a drop-in.

`AF_NETLINK` is required, not an oversight: the `network` tool reads
per-interface addresses through `net.Interface.Addrs()`, which Go
implements over netlink. Omitting it makes every interface report
`addrs: []` with no error.

The helper unit applies the same set of filesystem, namespace, and
process directives, plus `TasksMax=512`, `MemoryHigh=768M`,
`MemoryMax=1G` and `LimitNOFILE=8192`. Two intentional deviations:

  - **Capability sets.** The shipped helper base unit keeps
    `CapabilityBoundingSet=CAP_CHOWN` so the helper can chown its
    unix socket and runtime directory at startup; the
    install-time `caps.conf` drop-in extends both
    `CapabilityBoundingSet=` and `AmbientCapabilities=` with the
    per-op union derived from `manifest.yml`. The ambient half is
    load-bearing because `NoNewPrivileges=yes` computes the
    helper's effective set from `ambient ∪ (file_caps & bounding)`
    and inherits ambient caps into subprocesses (smartctl, lvs,
    etc.) across `execve`.
  - **System-call filter.** The helper uses
    `SystemCallFilter=@system-service` (the broader baseline) so
    the privileged subprocesses it spawns retain the exec, mount-
    info, audit-netlink, and similar syscalls they need. The
    daemon's stricter filter does not apply.

# 8. Uninstall

```
sudo systemctl disable host-health-mcp.service host-health-mcp-helper.service
sudo apt purge host-health-mcp-server
sudo deluser --system host-health-mcp
sudo rm -rf /var/lib/host-health-mcp /etc/host-health-mcp
```

From 2.3.0 the package stops both units in its `prerm` and reloads
systemd in its `postrm`, and `purge` also removes the generated
drop-ins (`caps.conf`, `10-ip-filter.conf`, and the obsolete
`10-ip-egress.conf`) together with their `.d` directories. Before
2.3.0 the package shipped neither script: removal deleted the unit
files from under two running services, so the daemon carried on
serving from a binary no longer on disk and the helper kept its root
privileges and its socket.

A unit that refuses to stop does **not** block the removal. The
`prerm` reports the failure in full — the stop's own error output, and
that the unit is still running — and then lets dpkg proceed, because a
service that will not stop is frequently the reason for removing the
package in the first place, and failing here would leave the package
un-removable without hand intervention. Check the units afterwards:

```
systemctl status host-health-mcp host-health-mcp-helper
```

This is deliberately the opposite of install. The `postinst` **does**
exit non-zero when a unit fails to come back after an upgrade, because
a dead daemon behind a successful `apt` run is an outage nobody is
told about, and the failed configure is the only thing that surfaces
it. Removal is loud but permissive; installation is loud and strict.

The `systemctl disable` above is belt-and-braces: from 2.3.0 the
`postrm` disables both units itself before reloading. It was left to
the operator at first, on the reasoning that a package which never
enables should not disable — but the consequence was a dangling
enablement symlink after `apt remove`, a systemd complaint on every
reload, and a later reinstall coming back silently enabled. A network
listener starting at boot because of a decision nobody made this time
is worse than the asymmetry.

Removing rather than purging leaves the generated drop-ins in place,
which is the right behaviour for a reinstall — `caps.conf` matches the
`manifest.yml` still under `/etc/host-health-mcp/`. Use `purge` when
the host is done with the package.

`purge` does **not** remove `/etc/host-health-mcp/`: the live
configuration and the PKI material there are operator-created, not
package-owned, so nothing in the package's file list covers them.
Remove that directory explicitly, as above, and only once the
private key under `tls/` no longer needs to be retained or
destroyed under the operator's key-handling policy.

On the operator workstation or relay:

```
sudo apt purge host-health-mcp-client
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
