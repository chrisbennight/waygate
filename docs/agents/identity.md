# Identity at the gateway

## MCP authorization spec coverage

The gateway serves the MCP spec versions pinned in
`waygate_mcp::SUPPORTED_MCP_SPEC_VERSIONS` —
[`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/)
statelessly and
[`2025-11-25`](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
on sessions. Authorization coverage:

| Spec item | Behaviour | Code |
|---|---|---|
| RFC 9728 PRM at `/.well-known/oauth-protected-resource` | Always served when bearer is configured; advertises `authorization_servers`, `scopes_supported`, `bearer_methods_supported`. | [`crates/waygate-oidc/src/metadata.rs`](../../crates/waygate-oidc/src/metadata.rs) |
| `WWW-Authenticate: Bearer resource_metadata="..."` on 401 | Header includes the PRM URL so clients without prior discovery can bootstrap. | [`crates/waygate-oidc/src/middleware.rs::unauthorized`](../../crates/waygate-oidc/src/middleware.rs) |
| `WWW-Authenticate: ... scope="..."` on 401 (`2025-11-25` SHOULD) | Optional scope hint set via `BearerLayer::with_scope_hint`. The gateway's default is `"mcp:invoke mcp:read"` (configured in `crates/waygate-server/src/boot.rs`, `build_bearer_layer`). | `with_scope_hint` in `middleware.rs`; default in `boot.rs` |
| RFC 9207 `iss` on **authorization-response redirect** (§2) + **token response** (§3) + AS-metadata advertisement + canonical issuer everywhere | The callback redirect built by `build_redirect` always appends `&iss=<url-encoded canonical issuer>` (§2 MUST when the AS supports issuer identification). `TokenResponse` carries the same canonical `iss` on every shape (§3). AS metadata sets `authorization_response_iss_parameter_supported: true`. PRM `authorization_servers` and the access-token JWT `iss` claim both advertise the same canonical value. **Single source of truth:** `GATEWAY_PUBLIC_URL` is trimmed of its trailing slash exactly once at `Config::from_env`, so every downstream consumer (`IdentityIssuer`, `BearerValidator`, `AsConfig`, PRM, AS metadata, auth-redirect, token-response) reads the same canonical string. RFC 9207 §2.4's exact-string-match invariant holds across every issuer-bearing surface. | [`crates/waygate-server/src/config.rs::Config::from_env`](../../crates/waygate-server/src/config.rs), [`crates/waygate-as/src/config.rs::AsConfig::issuer`](../../crates/waygate-as/src/config.rs), [`crates/waygate-as/src/callback.rs::build_redirect`](../../crates/waygate-as/src/callback.rs), [`crates/waygate-as/src/token.rs::TokenResponse`](../../crates/waygate-as/src/token.rs), [`crates/waygate-as/src/metadata.rs`](../../crates/waygate-as/src/metadata.rs) |
| OAuth 2.1 §7.5.2 PKCE S256 | `code_challenge_methods_supported: ["S256"]` advertised; `/oauth/token` verifies `BASE64URL(SHA256(verifier)) == challenge` in constant time. | [`crates/waygate-as/src/token.rs::handle_auth_code`](../../crates/waygate-as/src/token.rs), `crates/waygate-as/src/metadata.rs` |
| CIMD client registration (`2025-11-25` SHOULD) | `client_id_metadata_document_supported: true` advertised; fetch path documented below. | [`crates/waygate-as/src/cimd.rs`](../../crates/waygate-as/src/cimd.rs) |
| CIMD doc fetch — SSRF guards | HTTPS-only, no redirects, DNS-pinned, blocks private/loopback/link-local/multicast/shared/reserved IPs (v4 + v6), 10 s timeout, 5 KiB body cap, optional host allowlist. `client_id == fetch_url` invariant validated. See `is_public_ip` and `fetch_with_ssrf_guard` in cimd.rs; entry-point gates unit-tested under `cimd::tests`. | `crates/waygate-as/src/cimd.rs` |
| RFC 8707 resource indicators | `BearerValidator` enforces audience binding via `set_audience()`. | [`crates/waygate-oidc/src/validator.rs`](../../crates/waygate-oidc/src/validator.rs) |
| DCR (RFC 7591) deferral | Spec demotes DCR to MAY in `2025-11-25` and CIMD is the preferred path; this gateway does not implement DCR. AS metadata omits `registration_endpoint`. | n/a |
| Step-up via insufficient_scope on 403 (`2025-11-25` MUST shape) | Cedar emits a `StepUpRequired` verdict that serializes as an MCP JSON-RPC error AND, via `crates/waygate-server/src/mcp_http_promote.rs::promote_mcp_errors`, gets promoted to a real HTTP 403 with `WWW-Authenticate: Bearer error="insufficient_scope", scope="...", resource_metadata="..."`. JSON-RPC body still carries the structured data envelope so existing rmcp clients see the same shape; the header is additive for clients that prefer to consume standard HTTP signals. | `crates/waygate-authz/src/gate.rs`, `crates/waygate-server/src/mcp_http_promote.rs` |
| DNS-rebinding guard on streamable HTTP | `StreamableHttpServerConfig.allowed_hosts` populated from `GATEWAY_MCP_ALLOWED_HOSTS` (or derived from `GATEWAY_PUBLIC_URL`). | `crates/waygate-server/src/boot.rs::resolve_mcp_allowed_hosts` |
| OAuth 2.1 §10.4 confused-deputy — per-client consent record | `/oauth/callback` UPSERTs an `oauth_consent` row keyed on `(tenant, principal_sub, client_id)` after upstream id-token validation, before the gateway mints its own authorization code. The admin API supplies an audit trail and revocation (`/api/v1/admin/oauth_consent` list/revoke). The interactive consent screen uses the gateway-wide `require_explicit_consent` flag on top of the same rows: when the flag is set and no consent row exists (or one was revoked), the gateway renders a consent page instead of minting the code; the user's "Allow" POST UPSERTs the row before the flow continues. | `migrations/0028_oauth_consent.sql`, `migrations/0030_oauth_consent_screen.sql`, `crates/waygate-as/src/consent.rs`, `crates/waygate-as/src/callback.rs`, `crates/waygate-admin/src/oauth_consent.rs` |

Four authentication paths reach the same `Principal` shape:

1. **OAuth 2.1 JWTs** validated by `BearerValidator` against the gateway's
   own AS or Authentik. This is the human / interactive path.
2. **RFC 7662 opaque tokens** validated by `OpaqueTokenValidator`
   (`crates/waygate-oidc/src/introspection.rs`) — enabled by setting
   `GATEWAY_INTROSPECTION_URL` + `_CLIENT_ID` + `_CLIENT_SECRET` together.
   For deployments where the IdP issues OPAQUE access tokens (Authentik
   `provider_type=oauth2` with no signing key), the gateway POSTs each
   non-JWT-shaped, non-`mcpgw_…`-shaped bearer to the IdP's introspection
   endpoint and trusts the `active=true/false` reply. Positive cache TTL
   is `min(exp - now, GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS)` (default
   ceiling 300s) — short-`exp` tokens evict on the IdP's schedule, not the
   ceiling. The validator is **gated on `accept_upstream_tokens`** (same
   posture as the upstream JWT validator): in `GATEWAY_AS_ENABLED=true` +
   `GATEWAY_ACCEPT_UPSTREAM_TOKENS=false` (the recommended prod combo) the
   validator is **not wired**, and a `WARN` boot log explains the opt-in
   path. The skip is deliberate — accepting Authentik opaque tokens
   directly is the same token-passthrough anti-pattern the JWT validator
   guards against. `Principal.raw_token` is `None` for these principals
   (opaque tokens can't be re-signed for RFC 8693 exchange, so Tier-A
   upstream chaining falls back to Tier-B).
3. **Static API keys** validated by `ApiKeyValidator` against the
   `api_keys` table. This is the headless / non-interactive path.
4. **Peer assertions** validated by `PeerJwtValidator` against the
   `federated_peers` registry + cached JWKS — the Tier-C federation
   path. A JWT whose `iss` matches a registered
   peer's issuer is verified against the cached JWKS and produces a
   `Principal` with `auth_method = PeerAssertion` and `tenant` taken
   from the peer record (NOT from the JWT). Peer principals carry
   `raw_token = None` deliberately (prevents the
   peer's JWT from becoming the subject of an outbound RFC 8693
   exchange), have `mcp:admin` and `scim:write` scopes stripped at
   validation, and refuse cross-tenant ambiguous
   attribution fail-closed when the same peer is registered in
   multiple tenants. Full operator model in
   [`docs/agents/federation.md`](federation.md).

All four validators implement the `HeaderValidator` trait
(`crates/waygate-oidc/src/header_validator.rs`) and live side by side in
the `BearerLayer::enforce_multi` chain. Chain order is AS-JWT →
Authentik-JWT → introspection → API-key → peer-assertion; structural
shape filters route each token to the right validator without
re-trying earlier ones. The first to accept a header wins; unrecognised
headers fall through to the next validator and ultimately to a 401.
Peer-assertion runs LAST so a peer-issued JWT only hits this leg if
no earlier validator accepted it — zero hot-path cost in the common
single-tenant case.

## External signing-key freshness

Network-backed `JwksProvider` snapshots are usable for five minutes after a
successful fetch. Once that age is reached, authentication must refresh the
issuer's keys before accepting a token, even when its key identifier is already
cached. A successful refresh replaces the entire snapshot, so withdrawn keys
stop being accepted. This bound applies to new validation attempts; it does not
retroactively cancel requests or dashboard sessions that already authenticated.

Refresh attempts are shared within each provider and separated by a
30-second minimum interval, including after failure or cancellation. A newly
published key may therefore need to wait for that interval before it can be
discovered. These intervals are fixed provider defaults, not environment settings.
During an issuer outage, known keys remain usable only until the existing
five-minute deadline. Expired or unavailable keys fail authentication until a
refresh succeeds; failures never extend that deadline. Recovery is driven by
subsequent authentication attempts, without requiring a restart.

Providers built with `from_preloaded` intentionally pin their key set. They
never expire or perform discovery, including during cache warming. Change the
pinned set through its existing deployment/key-rotation procedure. Peer
federation has its own refresh contract described in [federation](federation.md).

## Outbound identity HTTP policy

The composition root builds identity clients once through
`waygate_core::http_client` and injects them into the OIDC consumers:

- OIDC discovery uses the `Standard` 10-second total-timeout profile and
  preserves reqwest's existing redirect and platform-TLS behavior.
- Authorization-code exchange and upstream-session refresh share a `Standard`
  client with redirects disabled. A code or refresh token is never replayed to
  a redirect target.
- Per-invocation RFC 8693 token exchange uses the `Interactive` 5-second
  profile with redirects disabled; the invocation's outer deadline can still
  end it sooner.

The request paths never construct their own clients. A client-builder failure
is a boot error, before the gateway starts accepting traffic.

## MCP browser origins

All HTTP methods under `/mcp` validate a present `Origin` before authentication
and body processing. The default allows only the origin of `GATEWAY_PUBLIC_URL`.
Set `GATEWAY_MCP_ALLOWED_ORIGINS` to a comma-separated list to replace that
default, for example `https://gateway.example,https://client.example:8443`.
Include the gateway origin explicitly if both it and another browser origin
must be accepted. Origins contain only an HTTP(S) scheme, host, and optional
port; paths, credentials, wildcards, and `null` are invalid configuration.
An explicitly empty value permits only requests without `Origin`.

Origins match the scheme, normalized host, and effective port. An omitted
HTTPS port means 443, not every port on that host. Malformed, duplicate, opaque,
and unlisted origins receive HTTP 403, as required by the
[MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).
Clients that omit `Origin`, such as command-line MCP clients, remain supported.
Passing this check does not grant authentication or authorization; the Host
guard and existing bearer and policy checks still apply. Other HTTP surfaces
retain their own policies. This allowlist does not add CORS response headers.

## Distinguishing auth methods at policy time

The resulting `Principal` carries an `auth_method: AuthMethod` field
(`Oauth` / `ApiKey` / `PeerAssertion`) that surfaces into Cedar as a
string entity attribute. Policies can selectively gate sensitive
tools by method:

```cedar
// API-key callers can't reach PII tools outside the public namespace
forbid (
    principal,
    action == Action::"CallTool",
    resource
)
when { principal.auth_method == "api_key" }
unless { resource in Server::"public" };

// Peer-assertion callers can't reach destructive tools at all
forbid (
    principal,
    action == Action::"CallTool",
    resource
)
when {
    principal.auth_method == "peer_assertion" &&
    resource.side_effects
};
```

Default policies don't reference `auth_method`, so existing rules behave
identically for all three methods.

## API keys

### Authentication capacity

Each API-key validator admits at most four cold authentication attempts at a
time, including their database lookup, queued or running verification, and
profile resolution. It
does not queue additional attempts when full. Excess demand follows the existing
HTTP 503 `auth_infrastructure_unavailable` response; clients should retry with
backoff. Already cached, unexpired keys continue through the cache path without
consuming verification capacity. This is a fixed default with no environment
setting.

Argon2 verification and unknown-key dummy hashing run off the async request
workers, with the existing hashing strength and unknown-prefix timing protection.
Cancelling a request releases its place when its database lookup is cancelled,
or when any already submitted hashing actually finishes. Cancellation cannot
admit replacement work while that hashing still consumes resources. Other
authentication methods and unrelated async requests can continue making progress.

### When to use them

- **Codex** and other headless MCP clients that need a stable bearer in
  `~/.codex/config.toml` (`http_headers.Authorization = "Bearer mcpgw_…"`)
  and can't reliably refresh OAuth tokens themselves. Codex issues
  [#15122](https://github.com/openai/codex/issues/15122) /
  [#14144](https://github.com/openai/codex/issues/14144) /
  [#7318](https://github.com/openai/codex/issues/7318) document why DCR +
  refresh aren't viable in 2026.
- **CI jobs**, cron, webhooks — anything that runs unattended and would
  otherwise need to embed an OAuth client.

### When NOT to use them

- Interactive humans. Use OAuth — it gives you per-user identity,
  refresh-token rotation, audit trails tied to real IdP groups, and
  scope step-up. None of those work for static keys.
- Cross-tenant fan-out where individual revocation is critical. Static
  keys are revocable, but the revocation window is bounded by the
  validator's cache TTL (default 60s) — not zero.

### Operator-trust model

The gateway intentionally enforces no ceiling on what an operator can mint:

- **No max TTL.** `never` is a valid expiry — the operator owns the
  lifecycle. Choose a non-trivial expiry whenever you can; rotation
  discipline is yours to enforce.
- **No scope blocklist.** Minting an `mcp:admin` key is allowed. A key
  with `mcp:admin` can revoke other keys and reach every admin tool —
  treat the secret accordingly.
- **No mint-rate limit.** The mint surface is only reachable to a
  dashboard caller carrying `mcp:admin` on their OAuth principal, so an
  external attacker who can mint already had your admin session.

If you want a tighter posture, layer it in Cedar policies on top of
`principal.auth_method` rather than crippling the mint surface.

### Setup

1. Set `GATEWAY_API_KEYS_ENABLED=true` and ensure `GATEWAY_DATABASE_URL`
   is configured (the `api_keys` table lives in the same Postgres as
   the OAuth AS state — see `migrations/0004_api_keys.sql`).
2. Restart the gateway.
3. Log into the dashboard with an `mcp:admin` OAuth principal.
4. Navigate to **Identities** and use the **Mint a new key** form.
5. Copy the `mcpgw_…` secret on the reveal page — it's shown exactly
   once.

### Wiring into Codex

Paste the snippet the reveal page generates into `~/.codex/config.toml`:

```toml
[mcp_servers.<name>]
url = "https://<gateway-public-url>/mcp"
[mcp_servers.<name>.http_headers]
Authorization = "Bearer mcpgw_…"
```

Restart Codex (it does not hot-reload `config.toml` per
[#3860](https://github.com/openai/codex/issues/3860)). The bearer is used
unchanged on every request; refresh isn't needed because the key is
long-lived.

### Configuration

| Env var | Default | Notes |
|---|---|---|
| `GATEWAY_API_KEYS_ENABLED` | `false` | Master switch. |
| `GATEWAY_API_KEYS_CACHE_TTL_SECONDS` | `60` | Per-token cache lifetime. Bounds the revocation latency. Floor 5s. |

### Revocation, expiry, sweep

- **Revoke** from the dashboard sets `revoked_at = now()`. In-flight
  callers can still authenticate for up to `cache_ttl` after the
  revocation; new validations fail immediately.
- **Expiry** is checked against the wall clock on cache hits, in the database
  lookup, and after asynchronous verification and profile resolution. The cache
  lifetime does not extend a key's recorded expiry.
- **Sweep** lives in the periodic store loop (`ApiKeyStore::sweep_expired`).
  Only rows whose `revoked_at` OR `expires_at` is older than the
  configured retention (default 90 days) are deleted. NULL `expires_at`
  rows are never swept — operator chose "unlimited", we honour it.

### What the validator does on the hot path

1. Reject anything that doesn't start with `Bearer mcpgw_` with
   `ValidationError::Malformed` so the middleware falls through to the
   next validator (which is the JWT validator).
2. Look up the full token in the cache. A hit returns its `Principal` only if
   the key has not expired, and accrues usage for the shared background flush.
3. On a miss, validate the token's shape and obtain a verification slot before
   looking up active, unexpired rows by prefix. Exhausted capacity returns a
   retryable infrastructure response without queuing another lookup or hash.
4. Run Argon2id verification in a blocking worker that owns the slot until it
   exits, even if its caller is cancelled. An unknown prefix verifies against
   the dummy hash; a known prefix verifies its stored hashes.
5. On a match, resolve any profile restrictions and build the `Principal`.
   Recheck expiry before allowing the result to authenticate or enter the cache.
6. Cache the valid result and accrue usage for the same background flush. A
   mismatch or expired result does not authenticate.

The validator never logs the secret; the prefix is logged at
`tracing::info` level on first use per key per hour (sampled by the
usage-bucket update path).

## Upstream identity chaining — Tier A / B / C

When the gateway calls an upstream MCP server on behalf of a
caller, it has three independent ways to project the caller's
identity onto the outbound request. The manifest decides which
ones fire per upstream.

| Tier | Header | When it fires | Source |
|---|---|---|---|
| **B** (always on for HTTP/SSE) | `X-MCP-Identity: <gw-minted JWT>` | Every identity-forwarding call and the bounded catalog-discovery handshake. | `IdentityIssuer::mint(principal, audience=server_name)` |
| **A** (opt-in via `exchange:`) | `Authorization: Bearer <downscoped IdP token>` | When the manifest has `exchange:` AND the caller has a stored upstream session OR `principal.raw_token`. | RFC 8693 token exchange against the upstream IdP. |
| **C** (opt-in via `tier_c_peer:`) | `Authorization: Bearer <gw-minted peer JWT>` AND `X-MCP-Identity` copy | When the manifest has `tier_c_peer: <peer_id>` and the gateway has the peer's JWKS cached. | `IdentityIssuer::mint(principal, audience=peer.issuer)` — the SAME mint as Tier B, but audienced at the remote gateway. |

Tier A and Tier C both want to write `Authorization: Bearer`,
so they're mutually exclusive at manifest load time — and so is
Tier C + `auth.bearer_env` (static per-upstream bearer, same
header). `load_manifests` returns `UpstreamError::InvalidManifest`
on conflict; the `--import-manifests` path runs the same check.

The initial `initialize` and `tools/list` exchange has no end-user caller. For
Tier-B HTTP/SSE upstreams, the pool mints a dedicated
`mcp-tool-search-gateway:catalog-probe` identity with no email, scopes, or user
token. Its groups are empty by default. A manifest may set
`auth.catalog_probe_groups` when the upstream role-filters `tools/list` and the
gateway must index the full governed catalog. The identity cell is cleared as
soon as discovery finishes, including cancellation and failure paths, before
the connection can serve a caller. Later tool calls always carry the real
caller identity, so catalog groups reveal definitions but cannot grant a caller
the corresponding role. Gateway Cedar policy and the upstream both still
authorize each call. A non-empty group list fails the upstream dial before any
network request when the gateway identity signer is not configured; the field
is never silently ignored.
The setting also requires the default `session.isolation: per_call`. Reused
sessions are rejected even when their scope is explicitly shared because an
upstream may retain initialize-time authorization in MCP session state. Caller
sessions therefore never reuse the privileged catalog-discovery session.

### Tier C — outbound peer-assertion mint

The outbound side of federation. Configured per upstream:

```yaml
name: bob-llc-tools
transport: http
url: https://gw.bob-llc.example/mcp
tier_c_peer: 7f8a9c2e-...  # UUID of bob-llc-gateway in YOUR federated_peers
```

At call time the pool resolves the `tier_c_peer` id against
the in-memory `PeerJwksCache` (the same cache the inbound
`PeerJwtValidator` reads from). On hit, the cached entry's
`issuer` becomes the JWT's `aud` claim; on miss the call is
refused fail-closed BEFORE breaker acquire with a structured
`McpError` naming `gateway_peer_jwks_refresh_*` metrics.

The mint goes through `IdentityIssuer::mint(principal,
peer.issuer)`. The JWT is stamped as BOTH:

1. `Authorization: Bearer <jwt>` — the remote gateway's
   `PeerJwtValidator` reads this. Without this header the
   federation round-trip never works.
2. `X-MCP-Identity: <jwt>` — the legacy Tier-B header,
   emitted alongside so upstreams that consume it in mixed
   deployments still see it.

Both headers carry the SAME JWT; only the placement differs.

Tier C ALSO refuses dispatch fail-closed when
`!entry.forwards_identity` (no IdentityIssuer at boot) or
`principal.is_none()` (auth disabled) — same shape as the
existing `tier_a_required` enforcement.

Full operator model + setup runbook in
[`docs/agents/federation.md`](federation.md).

## OAuth sessions

### Dashboard approval assurance

The dashboard keeps approval assurance separate from the general
`Principal`. After validating the signed ID token, the callback captures
`auth_time`, `amr`, and `acr`, normalizes them to the approval vocabulary
(`mfa` and `passkey`), and stores only that normalized evidence in the
encrypted session cookie. Cookies minted before this field existed deserialize
with empty assurance and therefore cannot satisfy a factor-protected approval.

The `/admin/login?step_up_scope=…` flow sets `prompt=login` so the IdP performs
a fresh login before granting the requested scope. It does not send
`acr_values`, compare the returned ACR with an MFA class, or synthesize an
authentication time at callback. Authentication-method policy belongs to the
IdP; the gateway accepts any successfully validated OIDC login and uses only
the signed `auth_time` when evaluating optional factor freshness.

Factor normalization preserves the distinction between passkeys and MFA.
Signed `amr=webauthn` or `amr=passkey` records `passkey` only. Authentik's
passwordless WebAuthn shape (`acr=goauthentik.io/providers/oauth2/default`,
`amr` containing `user`) also records `passkey` only, even though Authentik
adds `mfa` for credentials stored in its MFA-device table. A standalone signed
`amr=mfa` records `mfa`; a passkey is never promoted into that factor by the
gateway.

This evidence is intentionally unavailable to API-key and bearer-only REST
approval. Such callers may approve ordinary rows, but a factor-protected row
must be decided through an assured dashboard session and fails closed
otherwise.

When `GATEWAY_AS_ENABLED=true`, every interactive CIMD login produces
one or more rows in `oauth_refresh_tokens`. The dashboard surfaces these
under **Identities → OAuth sessions** so operators can see who's logged
in and chain-revoke a session in one click.

### What the panel shows

One row per live `(client_id, sub)` pair. "Live" = `revoked_at IS NULL`
AND `expires_at > now()`. For each pair:

- **Client** — the CIMD URL (scheme stripped for readability), with the
  full URL in the cell's tooltip.
- **Subject** — `sub`, plus the cached `email` and `groups` for context.
- **Scopes** — what the session was granted at authorize time.
- **Chains** — count of live refresh-token rows. Usually 1; >1 means
  multiple distinct logins (different browsers / machines) or an
  in-flight rotation that hasn't flipped the predecessor yet.
- **First / Latest issued** — relative timestamps; absolute on hover.
- **Usage (7d)** — count of tool-call audit events authored by this
  `sub` in the last 7 days. Approximate when one user has multiple
  client_ids (the audit log keys on `sub`, not `client_id`); acceptable
  for the "is this session being used at all?" question.

### Revoke semantics

The revoke action calls `OauthStore::revoke_by_client_sub`, which flips
`revoked_at = now()` on every live row matching the `(client_id, sub)`
pair inside a transaction that takes a Postgres advisory lock on the
pair (`pg_advisory_xact_lock(hashtext(client_id), hashtext(sub))`). The
refresh-rotation path in `handle_refresh` takes the *same* lock when it
revokes the predecessor and inserts the successor, so an admin revoke
can't slip between the two halves of a rotation and miss the successor —
either the admin runs first and the in-flight refresh fails to rotate,
or the refresh runs first and the admin's UPDATE catches the just-
inserted successor.

The user's gateway-minted access token is a stateless JWT — it stays
valid until its `exp` claim (default 1h via
`GATEWAY_AS_ACCESS_TOKEN_TTL_SECONDS`). The gateway has no
token-revocation list and a restart does **not** kill issued tokens,
because validation is signature + issuer + audience + exp with no
process-local session state.

Killing an active access token before its TTL requires removing the
**kid that signed it** from `GATEWAY_IDENTITY_JWT_KEYS` and restarting. A normal active-key *flip*
(`GATEWAY_IDENTITY_JWT_ACTIVE=v2` while v1 is still in `KEYS`) does
**not** invalidate v1-signed tokens — that's the rotation goal, so live
sessions survive a key change. Dropping the kid from `KEYS` is the
emergency button: it invalidates **every** still-valid token signed
under that kid across all users in one step. Wait
`max(identity_ttl, access_token_ttl)` between the active flip and the
drop unless you mean to terminate live sessions.

After a revoke, the user's next refresh fails (predecessor is now
revoked and the lock-serialized rotation can't mint a successor). Tell
them to log in again. Codex's stale-token bug
([codex#14144](https://github.com/openai/codex/issues/14144)) means the
client typically can't recover from a refresh failure without a
kill-and-restart, so a user-visible "please re-login" message is needed.

### Visibility gating

Same posture as API keys: `mcp:admin` required. Non-admin callers see
"You need `mcp:admin`" instead of the session inventory. The list query
exposes `sub`, `email`, `groups`, and `scopes` for every active user,
so this is not data we surface to anyone with a session cookie.

## Operator setup — wiring `mcp:admin` in Authentik

The gateway dashboard gates `/admin/identities` (API keys, OAuth
sessions) on the OAuth principal carrying the literal `mcp:admin`
scope. Authentik is the source of truth for who gets that scope. This
section is the operator runbook for enabling it on a fresh IdP install
or a fresh provider.

Three changes, all required. Skipping any one of them leaves the
dashboard gate stuck on "You need `mcp:admin` … Re-authorize with the
admin scope" forever.

### 1. Create the `mcp:admin` scope mapping

In the Authentik admin UI → **Customization → Property Mappings →
Create → Scope Mapping**:

- **Name**: `mcp:admin`
- **Scope name**: `mcp:admin`
- **Description**: anything; recommend "Grants dashboard admin access.
  Gated on `mcp-admins` group membership."
- **Expression**:

  ```python
  # OIDC discovery (provider.py get_claims) evaluates every scope
  # mapping with guardian's synthetic AnonymousUser and only catches
  # PropertyMappingExpressionException; an uncaught SkipObjectException
  # 500s the .well-known endpoint and crashloops any client that
  # bootstraps via OIDC discovery. Skip the membership gate for that
  # synthetic user so the scope still appears in claims_supported. The
  # real gate runs at token issuance, when a logged-in user is supplied.
  if user.username == "AnonymousUser":
      return {}
  if not any(g.name == "mcp-admins" for g in user.groups.all()):
      raise SkipObject
  return {}
  ```

The `AnonymousUser` short-circuit is **load-bearing** — see "Why the
AnonymousUser short-circuit" below before deleting it.

The body returns an empty dict on purpose: the dashboard reads
`mcp:admin` from the OAuth `scope` claim, not from any custom claim
payload, so there is nothing to emit. `raise SkipObject` is what
prevents the scope from appearing in the granted `scope` claim for
non-members.

### 2. Attach the mapping to the `mcp-gateway` OAuth2 provider

Admin → Applications → Providers → `mcp-gateway` → edit → "Scopes" →
add the new mapping alongside the existing five (`openid`, `profile`,
`email`, `mcp-gateway groups`, `mcp:invoke:high`).

Verify with a direct OIDC-discovery probe — the new scope name must
appear and the endpoint must return 200:

```sh
$ curl -sS https://idp.example.com/application/o/mcp-gateway/.well-known/openid-configuration \
    | jq .scopes_supported
[ "openid", "groups", "email", "profile", "mcp:invoke:high", "mcp:admin" ]
```

If this returns 500, the expression is wrong (most likely the
AnonymousUser short-circuit is missing or misspelled) — detach the
mapping from the provider before doing anything else, because the
gateway crashloops when its upstream OIDC discovery fails at startup
(see `crates/waygate-server/src/main.rs`, AS-mode bootstrap).

### 3. (Optional) Override the dashboard step-up allowlist

The dashboard's "Re-authorize with the admin scope" link (rendered by
`crates/waygate-admin/templates/api_keys.html` and
`oauth_clients_section.html`) drives `/admin/login?step_up_scope=mcp:admin`.
`login_get` in `crates/waygate-admin/src/auth.rs` checks the requested
step-up scope against `DashboardOidcConfig.allowed_step_up_scopes` and
silently drops anything not on the list.

The compiled-in default for that list is `mcp:invoke:high` and `mcp:admin`
(see `crates/waygate-server/src/config.rs`,
the `allowed_step_up_scopes` fallback), so a fresh deploy with no env-var
override already accepts the Identity-page step-up link. Operators only
need to touch this if they want to:

- **narrow** the allowlist (e.g. drop `mcp:admin` from step-up entirely
  because the deployment grants admin via always-on
  `GATEWAY_DASHBOARD_SCOPES` instead), or
- **widen** it (e.g. add a future gated scope that isn't compiled in).

Either way, do it via:

```yaml
- GATEWAY_DASHBOARD_ALLOWED_STEP_UP_SCOPES=mcp:invoke:high mcp:admin
```

The allowlist is operator policy, not user policy — it only controls
which `?step_up_scope=…` query values the dashboard is willing to
forward to the IdP. The actual membership check still runs inside
Authentik's scope-mapping expression (`SkipObject` for non-members), so
widening this list does not grant anyone new admin rights; narrowing
it only forecloses on the step-up UX, it does not change who can
ultimately receive the scope through other flows.

The choice between always-on (`GATEWAY_DASHBOARD_SCOPES` includes
`mcp:admin`) and step-up (above) is an operator posture decision. Step-up keeps
the admin scope present only when an operator is actively about to use it,
which can make its presence in logs a useful signal that an admin action is
being performed.

### Why the AnonymousUser short-circuit

Authentik's OIDC metadata view evaluates every attached scope mapping
when serving `.well-known/openid-configuration`, to compute the
`claims_supported` list. The relevant code lives at
`authentik.providers.oauth2.views.provider.MetadataView.get_claims`:

```python
for scope in ScopeMapping.objects.filter(provider=provider).order_by("scope_name"):
    value = None
    try:
        value = scope.evaluate(
            user=get_anonymous_user(),
            request=self.request,
            provider=provider,
        )
    except PropertyMappingExpressionException:
        continue
    ...
```

Two facts make this matter:

1. `get_anonymous_user()` returns a **real** DB-backed `User` row
   (guardian's anonymous user, `username="AnonymousUser"`, `pk=1`, no
   group memberships) — not Django's in-memory `AnonymousUser`. So
   `user.groups.all()` works fine and returns an empty queryset.
2. The `try/except` clause **only catches
   `PropertyMappingExpressionException`** — `SkipObjectException`
   escapes uncaught, which 500s the entire metadata endpoint.

A naive gate expression —

```python
# BROKEN: 500s .well-known/openid-configuration
if not any(g.name == "mcp-admins" for g in user.groups.all()):
    raise SkipObject
return {}
```

— passes its own unit-tested behaviour fine (real members get the
scope, real non-members don't), but raises `SkipObject` against the
synthetic anonymous user during metadata generation. That bubbles up
into a 500, which the gateway hits at startup, which causes the
gateway to crashloop (`Error: OIDC discovery from issuer … status 500
Internal Server Error`). The whole MCP stack on that host stops
serving until the mapping is detached.

The `AnonymousUser` short-circuit prevents that by returning a clean
empty dict during discovery and only running the membership gate when
a real user is being evaluated at token-issuance time. The behavioural
contract is unchanged: real members get the scope, real non-members
don't.

This same pattern applies to **any** Authentik scope mapping that
gates on user attributes — group membership, custom attributes, MFA
state, anything that would raise during evaluation against a user who
has none of those. If you add a future scope mapping with `raise
SkipObject` in it, add the `AnonymousUser` short-circuit. The other
defensive option is to gate via a separate Authentik Policy binding
and keep the expression trivially returning a dict; that's heavier to
set up but avoids the trap entirely.

### Membership

`mcp-admins` is an ordinary Authentik group. Add/remove members via
Admin → Directory → Groups → `mcp-admins`. Membership changes take
effect on the user's next dashboard login (the gateway reads scopes
from the access token returned by the authorize flow, not from a
live group lookup).
