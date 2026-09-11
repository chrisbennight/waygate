# Deployment

For required settings, credential groups, and environment loading, start with
the [configuration guide](configuration.md). This page describes deployment
safety, build profiles, runtime configuration, and connection behavior.

## Deployment safety posture

The gateway runs in one of two postures, selected by
`GATEWAY_DEPLOYMENT_PROFILE`:

- `dev` (default) — the local-iteration profile. Boot accepts every
  combination that works locally, including `GATEWAY_AUTH_MODE=disabled`
  on a debug build, an unset `GATEWAY_DATABASE_URL` (audit goes to a
  `NullSink`), disabled dashboard auth, and stdio upstreams. Each
  unsafe-in-prod choice still logs a `WARN` at boot, but does not refuse
  to start. This is the posture `docker compose up --build` runs under.
- `prod` — boot refuses to start when any of the known-unsafe defaults
  is set:
  - `GATEWAY_AUTH_MODE=disabled` (synthetic admin principal)
  - `GATEWAY_ACCEPT_UPSTREAM_TOKENS=true` (OAuth token-passthrough
    anti-pattern; deprecated and slated for removal — the built-in AS
    via `GATEWAY_AS_ENABLED=true` is the supported path)
  - missing `GATEWAY_DATABASE_URL` (`NullSink` silently drops audit
    events — no compliance evidence)
  - missing dashboard auth (`GATEWAY_DASHBOARD_CLIENT_ID` /
    `_CLIENT_SECRET` / `_SESSION_KEY` unset → `/admin` is wide open)
  - any upstream manifest using `transport: stdio` (this gateway is a
    proxy, not a sandboxing runtime manager)

  Each refusal names the offending field plus the dev-profile escape
  (`GATEWAY_DEPLOYMENT_PROFILE=dev`) so the operator knows what to
  flip for local iteration without grepping the source.

In addition, the cargo release build refuses
`GATEWAY_AUTH_MODE=disabled` at config parse, independent of the
profile. The synthetic-admin principal that the `Disabled` middleware
arm would otherwise inject
(`crates/waygate-oidc/src/middleware.rs::dev_principal`) is itself
compiled into every binary, but
`crates/waygate-server/src/config.rs::Config::from_env` bails before
the middleware ever gets a chance to run when `auth_mode == Disabled`
on a release build (`!cfg!(debug_assertions)`). The security boundary
is "release binary refuses the mode at config parse" rather than "the
synthetic-principal code does not exist in release." Two layers of
defense: the release-build config gate is the belt, the prod profile
is the suspenders, so a debug binary that ends up in production by
accident still fails fast.

Production deployments must set
`GATEWAY_DEPLOYMENT_PROFILE=prod` explicitly. Default is `dev` to
preserve the documented local Compose workflow; making prod the
default would surprise local devs running `docker compose up`.

### Annotation-native upstream configuration

Set `classification_mode: mcp_annotations` for an upstream whose tools provide
MCP annotations and result trust labels. Review the live tools with the
`classify` CLI, set each accepted `approved_behavior_hash`, and configure the
catalog risk, roles, and approval requirements before reloading the manifest.
Confirm that the expected tools are published; missing or malformed metadata
must be corrected rather than bypassing quarantine.

The switch does not grant access and cannot lower catalog risk. Annotation mode
derives side effects and protected-data handling from reviewed claims; unknown
sensitivity classifiers remain protected. Successful results must carry
well-formed trust labels, and declared sensitive results remain available after
authorization. Existing rows default to `manifest`; unrelated servers retain
their old semantics.

An invocation approval binds the tool behavior hash and canonical arguments.
Changing either requires a new approval.

Roll back by restoring the reviewed `manifest` mode entry, never by calling the
upstream directly. See
[the classification authority contract](agents/upstreams.md#classification-authority-claims-are-not-policy).

## Build profiles

`Dockerfile` accepts these build arguments:

| Arg | Default | When to override |
|-----|---------|------------------|
| `CARGO_PROFILE` | `release` | `dev` for a debug build |
| `BINARY_SUBDIR` | `release` | `debug` to match `CARGO_PROFILE=dev` |
| `CARGO_BUILD_JOBS` | Cargo's automatic selection | Limit compilation parallelism inside build stages; `build-docker.sh` forwards this environment variable when set |

| Build path | `CARGO_PROFILE` | `BINARY_SUBDIR` | Used by |
|------------|----|----|----|
| Published image | `release` (default) | `release` (default) | `build-docker.sh` |
| Local Compose (`docker compose up --build`) | `dev` | `debug` | `docker-compose.yml`'s `build.args` |

The profile and binary-subdirectory arguments must be set together; cargo's profile-to-output-dir mapping
is asymmetric (`--profile release` → `target/release/`, `--profile dev`
→ `target/debug/`), so the Dockerfile takes both rather than trying to
derive one from the other.

`BINARY_SUBDIR` was originally named `CARGO_TARGET_DIR`, which collided
with cargo's actual `CARGO_TARGET_DIR` env var — buildkit propagates
every Dockerfile `ARG` into RUN-step environments, so cargo saw the
build-arg as a target-directory override and wrote the binary under
`/app/release/release/` while the runtime stage's `COPY` read from
`/app/target/release/`. That mismatch silently dropped the
`gateway-server` binary on every image build between PR #73 and the
rename, even though `cargo build` reported "Finished" successfully.

Local Compose builds debug to shorten development compilation. Its disposable
issuer still exercises bearer validation and Cedar enforcement; dashboard
login remains disabled and the listener is loopback-only. Production uses the
release image and an actual identity provider.

For installation, acceptance, backups, upgrades, and rollback, follow the
[operator runbook](operations.md) and [authenticated Compose example](../examples/deployment/README.md).

## Live configuration volumes

The gateway reads its active server manifests and default-tenant Cedar policies
from writable shared volumes:

| Env var | Production path | Role |
|---|---|---|
| `GATEWAY_SERVERS_DIR` | `/etc/mcp-gateway/servers` | Authoritative `servers/*.yaml` set. |
| `GATEWAY_POLICIES_DIR` | `/etc/mcp-gateway/policies` | Authoritative default-tenant `policies/*.cedar` set. |

The dashboard and governed change paths publish directly to these volumes. The
Postgres stores are version-history, rollback, coordination, and recovery
ledgers; they do not override a readable live file set. The published image
contains neither configuration set, and Git is not a delivery or recovery path.

At boot, a readable manifest directory is authoritative, including an
intentionally empty directory. If it is unreadable, the gateway recovers the
newest usable ledger snapshot and reports degraded configuration health. If no
snapshot is usable, boot fails loud. Policy boot follows the same file-first
recovery order and refuses to start when neither the live set nor its ledger is
usable.

Mount persistent shared manifest and policy directories at the paths above.
Both mounts must be writable by uid 65532 and visible to every gateway replica.
For a new deployment, create the mount points and seed configuration through a
governed dashboard publication or the supported one-time import commands; do
not silently fall back to replica-local storage when a shared mount is missing.

Doorbell notifications and the periodic poll cause every replica to reload an
accepted file generation. The gateway content-hashes each generation rather
than trusting filesystem mtimes, and catalog reconciliation follows the accepted
manifest generation.

### Verify after deploy

```sh
docker ps --filter name=^/mcp-gateway$ --format '{{.Status}}'
docker logs mcp-gateway 2>&1 | grep 'source of truth' | tail -1
# expect a healthy container and the configured server directory in the log
```

A `Config STALE` dashboard banner (or a `config-health: degraded` signal) means
the live volume was unreadable and the gateway is serving a ledger snapshot —
fix the volume and Reload.

### Rollback

Use the dashboard's ledger-backed rollback path for a normal rollback. During
recovery, restore the desired files on the shared volume and reload. The image
does not carry an older configuration to restore.

## SSE keepalive and intermediary idle timeouts

Between tool calls a streamable-HTTP session's only long-lived HTTP exchange
is the standalone GET (SSE) stream, and without keepalive traffic it is
byte-silent. Every intermediary on the path enforces some idle-read
timeout, and a reaped stream is worse than it sounds: several MCP clients
(Claude Code among them) do not auto-reconnect a dropped remote server —
the session sits dead until a human intervenes.

Typical idle timeouts to plan around:

| Hop | Knob | Common default |
|---|---|---|
| squid (forward proxy) | `read_timeout` | 300s |
| nginx (reverse proxy) | `proxy_read_timeout` | 60s |
| AWS ALB | idle timeout | 60s |
| Traefik | none for streaming responses | n/a |

The gateway ships two layers of defense, both on by default:

- **`GATEWAY_SSE_KEEPALIVE_SECONDS`** (default 120) — SSE comment frames
  (`:`) on every open stream. Pure server→client bytes; defeats idle-read
  timers on the response path.
- **`GATEWAY_MCP_PING_INTERVAL_SECONDS`** (default 120) — server-initiated
  MCP `ping` requests. The client's answer arrives as a new POST, so bytes
  flow in both directions and the `mcp_client_pings_total` counter reports
  whether each session's client is actually reachable.

**Pick intervals below the tightest hop.** The defaults survive squid's
300s; a 60s-idle hop (stock nginx, ALB) needs `GATEWAY_SSE_KEEPALIVE_SECONDS`
≤ 55. There is no benefit to going below ~15s on either knob.

Per-proxy notes:

- **Traefik** (the production edge) streams SSE unbuffered by default —
  nothing to configure.
- **nginx** buffers proxied responses by default, which strands keepalive
  frames (and real events) in the proxy buffer. An nginx hop in front of
  `/mcp` needs `proxy_buffering off;` (or an `X-Accel-Buffering: no`
  response header) and a raised `proxy_read_timeout`.
- **Forward proxies on the client side** (squid CONNECT tunnels) count the
  keepalive bytes as tunnel traffic, so the gateway-side heartbeat resets
  their idle timer too — but only while the client actually holds the GET
  stream open. A client with no open stream has an idle pooled TCP
  connection the server cannot keep warm; raising the forward proxy's
  `read_timeout` and giving the client's supervisor an MCP-liveness
  healthcheck are the remaining levers, and they live in the client's
  deployment, not here.

Verify through the real edge (expect a `:` comment line at the configured
cadence):

```sh
SID=$(curl -sD- -o /dev/null https://gateway.example.com/mcp \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  | tr -d '\r' | awk 'tolower($1)=="mcp-session-id:"{print $2}')
curl -sN --max-time 130 https://gateway.example.com/mcp \
  -H "Authorization: Bearer $TOKEN" -H 'Accept: text/event-stream' \
  -H "Mcp-Session-Id: $SID" | cat -A
```

## Client-side timeouts during a long tool call

The section above concerns intermediaries reaping a quiet stream. This one
concerns the timers that bound a single `tools/call` which legitimately runs for
minutes. They overlap rather than partition: a long call holds a POST response
stream open, `GATEWAY_SSE_KEEPALIVE_SECONDS` heartbeats that stream as well as
the standalone GET one, and an intermediary with a tighter idle-read timeout can
still reap it mid-call. So read the hop table above as part of this picture — if
a long call dies at a suspiciously round interval matching a proxy default,
start there rather than here.

Most of the timers involved belong to the client, and no gateway setting
overrides them — which is why they are documented here as an integration
contract rather than as configuration. Two belong to the gateway, and both are
covered below so that a diagnosis can rule this side out too.

The client variables named here are Claude Code's. Other clients enforce their
own timeout models, which this guide does not enumerate; where that matters it
is called out rather than papered over.

Three client timers interact, and the order they fire in is the whole story:

1. **Per-request timeout.** Bounds a single request, and on the HTTP/SSE path it
   is the one that fires first: it defaults to 60 seconds. A `timeout` field on
   the client's entry for this server, in milliseconds, overrides
   `MCP_TOOL_TIMEOUT` for that server alone. The generous default of an *unset*
   `MCP_TOOL_TIMEOUT` does not feed this timer, so reading that variable and
   finding a large value is not evidence the call has room. Not to be confused
   with `MCP_TIMEOUT`, which bounds server *startup*.
2. **Automatic backgrounding** (Claude Code v2.1.212 or later). A
   main-conversation call still running past the threshold becomes a background
   task and *keeps running*. `CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS` sets the
   threshold in milliseconds; `0` turns backgrounding off.
   `CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1` turns it off along with every other
   background-task feature.
3. **Idle window.** A call that sends no response and no progress notification
   for the window is aborted. For remote MCP tool calls this defaults to five
   minutes, per the Claude Code v2.1.187 release note.
   `CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT` sets it in milliseconds; `0` disables the
   check.

The upstream reference describes the second and third: these timeouts "bound how
long a call can run, not always how long it blocks the session: a
main-conversation call that runs past two minutes moves to a background task
first."

**Backgrounding is not a reprieve from the request timeout.** It changes whether
a call blocks your session, not whether it can be killed. The request timeout
bounds the whole call and keeps running after the hand-off, so a call
backgrounded at two minutes is still terminated when that timeout expires.

Two consequences, and they are the whole of the guidance:

- **Size the request timeout against the call's expected duration**, not against
  the backgrounding threshold. Set it explicitly, by either route — a per-server
  `timeout` or an explicitly set `MCP_TOOL_TIMEOUT`. What fails is relying on
  that variable's default, which does not feed this timer; an unconfigured call
  is cut off well before backgrounding would have applied, and inspecting
  `MCP_TOOL_TIMEOUT` will not reveal why.
- **The idle window applies independently**, whenever nothing is being emitted,
  and is not superseded by either of the above.

### The gateway's own limits

Satisfying every client timer is not sufficient, because this gateway applies
limits of its own. They matter here for one reason: if the client timers above
do not account for a failure, this side is the next place to look, not the last.

- **Code Mode executions** use `GATEWAY_CODEMODE_EXECUTION_LIMIT_SECONDS`,
  default 300 seconds (5 minutes), configurable up to 86,400 seconds (24 hours). This is an
  operator-configurable execution deadline, including deliberate program waits.
  Check the returned error and configured budget when diagnosing a timeout.
- **Forwarded upstream operations** are bounded by
  `GATEWAY_UPSTREAM_CALL_TIMEOUT_SECONDS`, a deployment environment setting
  applied to every forwarded `tools/call`, `resources/list` and `resources/read`
  with no per-tool or per-resource override. It exists so a wedged upstream
  stream cannot hold a connection slot indefinitely; how much one hang costs
  depends on that upstream's configured concurrency.

Deliberately, this section does not tell you which timer wins a given race.
Where a call spends its time — waiting for a pool lane, dialling, inside an
upstream operation, or inside a program — decides that, and stating a fixed
order here would produce a rule that is wrong for some supported configurations
and that drifts as the code changes. Read the configured values for this
deployment and the client, and treat the source as authoritative over any
ordering prose.

### Where the idle window still binds

Backgrounding covers main-conversation calls only. It does not apply to:

- **subagent calls**;
- **IDE servers**;
- **non-interactive sessions**, unless `CLAUDE_AUTO_BACKGROUND_TASKS=1` is set;
- **clients that do not implement it.**

Those paths get no backgrounding reprieve, so a long call survives them only if
the gateway answers inside whatever timers govern them, or emits progress
notifications.

For Claude Code those are the request timeout and the idle window described
above — both still apply here; backgrounding was never what kept the call alive.
For other clients they are that client's own, and this guide does not enumerate
those models. If you are diagnosing a non-Claude client, the portable claim here
is only that nothing defers the call on its behalf; establish that client's
governing timeouts from its own documentation before matching a failure to
anything on this page.

### The failure that is not a timeout

Surviving the timers is not the same as delivering the answer, and the
difference is where operator time gets lost. A backgrounded call returns its
result as a notification the agent may simply not act on, leaving completed work
unretrieved. Reports of this describe it as silent, and biased toward the
longest-running calls — the ones whose results are usually worth the most.

Operationally it presents as "the tool ran, the gateway logged a successful
response, and nothing happened." That looks like a gateway fault and is not one.
Before investigating the gateway, establish whether the call was backgrounded:
the client announces the hand-off in-session, lists the task under `/tasks`, and
a backgrounded task does not survive exiting the session.

`GATEWAY_SSE_KEEPALIVE_SECONDS` is worth separating into the part it does and
the part nobody here has tested. It heartbeats the in-call POST stream, so it is
genuinely the lever against an *intermediary* reaping that stream mid-call — see
the hop table above. What it is not known to do is satisfy the *client's*
per-call idle timer: its frames are SSE comments rather than protocol-level
progress notifications, uncorrelated to any in-flight request, and whether that
traffic feeds the client timer has not been tested here. Treat that half as
unverified rather than excluded.

### Treat these as observed client defaults

This applies to the *client* values above — the request timer, the backgrounding
threshold, and the idle window. Each belongs to the client and can change
without anything in this repository changing. At least one of them, the
backgrounding threshold, has been reported as gated by a server-pushed feature
flag, which means it can take effect on a pinned client version with no upgrade
and no release note. Read those numbers as a starting point for diagnosis,
confirm them against the client actually in use, and prefer detecting the
behaviour at runtime over asserting it from a version.

The gateway's Code Mode budget (`GATEWAY_CODEMODE_EXECUTION_LIMIT_SECONDS`),
upstream timeout (`GATEWAY_UPSTREAM_CALL_TIMEOUT_SECONDS`), and SSE heartbeat
(`GATEWAY_SSE_KEEPALIVE_SECONDS`) are deployment environment settings. Check
the process's configured values before assuming a default. Their supported
ranges and fallback defaults are defined by the gateway release.

### Sources

- Claude Code MCP reference — per-request timeout, idle window, backgrounding,
  and the per-server `timeout` field: <https://code.claude.com/docs/en/mcp>
- Claude Code environment variables — `CLAUDE_AUTO_BACKGROUND_TASKS` and the
  background-task switches: <https://code.claude.com/docs/en/env-vars>
- anthropics/claude-code issue 78566 — the report behind the orphaned-result
  behaviour, its bias toward the longest-running calls, and the server-pushed
  feature flag gating the backgrounding threshold:
  <https://github.com/anthropics/claude-code/issues/78566>
- anthropics/claude-code issue 52137 — records the 60-second default request
  timeout in the SDK path this client uses:
  <https://github.com/anthropics/claude-code/issues/52137>

## In the meantime

- **Env var shortlist:** the [configuration reference](configuration-reference.md).
- **Healthcheck pattern:**
  [`crates/waygate-server/src/healthcheck.rs`](../crates/waygate-server/src/healthcheck.rs).
- **Image build:** [`Dockerfile`](../Dockerfile) (distroless final stage) and
  [`build-docker.sh`](../build-docker.sh).
- **CI build and publication:**
  [`.github/workflows/image.yml`](../.github/workflows/image.yml) runs source
  checks, database tests, and image smoke before publishing to
  `ghcr.io/chrisbennight/waygate`. Main builds update `edge`; version tags
  publish releases, with `latest` reserved for stable releases. See the
  [release guide](source-release.md#github-publication). The publish job uses GitHub's short-lived
  `GITHUB_TOKEN` with `packages: write`; it carries no deployment credential.
  Configure private package visibility and consumer read access separately.
- **Helper artifacts:**
  [`.github/workflows/release-mcp-files.yml`](../.github/workflows/release-mcp-files.yml)
  verifies builds on PRs and manual dispatches. Explicit `mcp-files-v<version>`
  tags on merged main commits publish checksummed GitHub release assets. Private release
  downloads require authenticated repository access.
- **Deployment overlay:** keep reverse-proxy labels, networks, secret injection,
  served manifests, and orchestration wiring in a private deployment repository.
- **Migrations:** [`migrations/`](../migrations/) — applied automatically by
  `sqlx` at boot when `GATEWAY_DATABASE_URL` is set.

## See also

- [`AGENTS.md`](../AGENTS.md) — image-publish conventions and safe defaults.
