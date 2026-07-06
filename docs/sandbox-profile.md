# Sandbox Profile

The sandbox profile is the **stable, versioned policy contract** for isolating a
wrapped MCP server. Mechanisms (bubblewrap, Seatbelt, containers, WASM, microVM)
change over time; this schema is the durable interface every backend implements.

Enable it by adding a `sandbox` object to a server's config, or set
`MCP_SANDBOX=strict` to apply strict defaults to every stdio server.

## Pillars

1. **Process confinement** (local `stdio` servers) - the server runs inside the
   strongest available backend; sensitive paths are invisible, syscalls limited.
2. **Default-deny egress** (local + remote) - all traffic routes through a
   filtering proxy that blocks reserved/metadata ranges and enforces a domain
   allowlist.
3. **Credential broker** - the server never receives raw secrets; they are
   injected at the egress boundary or as scoped env only when a rule requests it.

## Fields

Omitted fields resolve to strict, fail-closed defaults.

| Field | Meaning | Default |
|-------|---------|---------|
| `schema_version` | Format version | `"1.0"` |
| `target.transport` | `stdio` \| `sse` \| `http` | `stdio` |
| `target.image` | Container image (container backend) | none |
| `assurance.required` | `process` \| `container` \| `microvm` | `process` |
| `assurance.on_unavailable` | `block` \| `warn` \| `downgrade` | `block` |
| `enforcement.mode` | `observe` \| `warn` \| `enforce` | `enforce` |
| `filesystem.workdir` | Read/write working dir | `./` |
| `filesystem.read` / `write` / `deny` | Extra path rules (globs) | strict denies |
| `network.default` | `deny` \| `allow` | `deny` |
| `network.allow[]` | `{host, ports[]}` allowlist (`*.x` ok) | empty |
| `network.block_reserved` | Block private/metadata ranges | `true` |
| `network.on_new_domain` | `ask` \| `deny` \| `allow_once` | `ask` |
| `network.endpoint` / `pin_cert` | Remote server pinning | none |
| `environment.allow[]` | Env var names passed through | minimal set |
| `environment.set{}` | Explicit env values | empty |
| `environment.scrub` | Strip secret-looking vars | `true` |
| `secrets[]` | `{ref, inject_as, name, template, to}` | empty |
| `resources` | `cpu, memory, wall_time, max_processes, max_open_files` | none |
| `syscalls.profile` | `strict` \| `default` \| `permissive` | `strict` |
| `tools{}` | Per-tool partial overrides | none |
| `learning.mode` | `off` \| `observe` \| `suggest` | `off` |
| `audit.log` / `audit.path` | Decision logging | `true` / none |

## Precedence

`tools.<name>` override > server profile > built-in strict default. Filesystem
and reserved-range denies always win over allows.

## Minimal example

```json
{
  "schema_version": "1.0",
  "name": "weather-server",
  "target": { "server_id": "io.example/weather", "transport": "stdio" },
  "network": { "allow": [{ "host": "api.weather.com", "ports": [443] }] },
  "secrets": [
    { "ref": "weather_api_key", "inject_as": "header",
      "name": "Authorization", "template": "Bearer {secret}", "to": "api.weather.com" }
  ]
}
```

## Backends

| Backend | Assurance | Platform | Isolation |
|---------|-----------|----------|-----------|
| `subprocess` | process | all | env scrub + egress only (proxy is advisory) |
| `bubblewrap` | process | Linux | filesystem + namespace confinement |
| `seatbelt` | process | macOS | deny-by-default filesystem via `sandbox-exec` |
| `wasm` | container | any w/ `wasmtime` | WASI capability isolation (preopened dirs only) |
| `container` | container | any w/ podman/docker + image | full container |
| `microvm` | microvm | via `MCP_SANDBOX_MICROVM_CMD` | hardware-virtualised VM |

`select_backend` picks the strongest available backend meeting
`assurance.required` and fails closed (`on_unavailable`) when none qualifies.

## Capability matrix (what each backend actually enforces)

| Backend | filesystem | enforced egress | resources | env scrub |
|---------|:---:|:---:|:---:|:---:|
| `subprocess` | ✗ | ✗ (advisory) | POSIX only | ✓ |
| `bubblewrap` | ✓ | ✓ no-egress only | POSIX | ✓ |
| `seatbelt` | ✓ | ✗ (advisory) | POSIX | ✓ |
| `wasm` | ✓ | ✓ no-egress only | ✗ | ✓ |
| `container` | ✓ | ✓ no-egress only | ✓ | ✓ |
| `microvm` | ✓ | depends on cmd | ✗ | ✓ |

Every control a profile requires but the backend cannot enforce is **surfaced,
never silently dropped**: `filesystem` and no-egress `egress` are fail-closed
(blocked per `assurance.on_unavailable`); `syscalls` and `resources` warn.

**Container backend needs a server-bearing image.** The `container` backend runs
`command` inside `target.image`, so that image must already contain the server
and its dependencies (e.g. a `python:3.11-slim` base will not have your package).
A global `MCP_SANDBOX_IMAGE` is rarely correct for this reason; prefer per-server
`target.image`. `filesystem.deny` entries are literal paths (globs are ignored by
the filesystem backends) and are masked only when they fall under a bound dir.

**Enforced vs advisory egress.** A "no-egress" policy (`network.default: deny`
with an empty `allow`) is genuinely enforced on `bubblewrap` (`--unshare-net`),
`wasm` (no sockets granted), and `container` (`--network none`). An *allowlisted*
egress policy is **advisory** in this release - enforced only for cooperative
servers via `HTTP(S)_PROXY`; a hostile binary can bypass it. Set
`network.enforcement: advisory` to acknowledge this, or use a no-egress policy
for untrusted servers. `subprocess` never enforces egress.

## Egress hardening

- Reserved/metadata ranges are blocked with encoding-resistant parsing (octal,
  hex, integer, short-form IPv4, IPv4-mapped IPv6, zone ids, trailing dots,
  non-ASCII digits).
- Connections are made only to a resolved address re-checked against the
  reserved ranges, defeating DNS rebinding.
- Request and response bodies are size-capped; brokered secrets are stripped of
  CR/LF to prevent header injection.

## Remote (sse/http) servers

A remote server cannot be process-sandboxed. For `transport: sse|http`, warden
verifies the connection before use: it refuses endpoints resolving to
reserved/metadata ranges, checks the URL host against `network.endpoint`, and
pins the TLS certificate against `network.pin_cert` (`sha256:<hex>`).

## Observe mode

Set `learning.mode` to `observe` or `suggest`. The server runs under the profile
while the proxy records the domains it actually reaches; on exit a tightened
profile is written to `<name>.suggested.json` for review. Nothing is
auto-enforced.

## Windows

Strong isolation backends are Linux (`bubblewrap`) and macOS (`seatbelt`); on
Windows use `container` (Docker/Podman, incl. WSL2) or `wasm`. With only the
`subprocess` backend, a strict profile fails closed rather than pretend to
isolate - set `assurance.on_unavailable: warn` to run degraded knowingly.

## Durability principles

1. Policy and mechanism are separate - swap backends, never rewrite policy.
2. Fail-closed with assurance levels.
3. Portability first - subprocess/container work everywhere; native primitives
   are upgrades behind the same contract.
4. `learning.observed` is warden-written, enabling auto-proposed tight profiles.
5. Aligned to the MCP security spec, NSA MCP CSI, and RFC 9728 / 8693.
