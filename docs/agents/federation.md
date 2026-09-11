# Tier-C gateway federation

Reach for this doc when changing anything under
`crates/waygate-federation/`, the `federated_peers*` migration,
`PeerJwtValidator` consumers in `waygate-oidc`, or the
`tier_c_peer:` manifest field in `waygate-manifest-types`
(re-exported by `waygate-upstream`).

## What Tier-C is, in one paragraph

Two MCP gateways can call each other on behalf of their users
without sharing an IdP. Each gateway registers the other as a
peer (`federated_peers` row: name, issuer URL, JWKS URL,
trust tier, tenant). When gateway A calls a gateway-B-hosted
upstream that's configured with `tier_c_peer: <peer-id-of-B>`,
A mints a short-lived JWT signed by A's own identity key,
audience-claim = B's issuer URL, and stamps it on the outbound
request as `Authorization: Bearer <jwt>`. B's bearer chain
runs `PeerJwtValidator`, looks up A's JWKS in its in-memory
cache, verifies the signature, and produces a `Principal`
with `auth_method = PeerAssertion` and the tenant attribution
B chose when it registered A.

No shared IdP. No long-lived static credential. No human in
the loop on every call. The two sides agree on each other's
public signing keys (JWKS) and that's the whole trust
boundary.

## Where the pieces live

| Concern | Location |
|---|---|
| `federated_peers` table + admin CRUD | `migrations/0033_federated_peers.sql`, `crates/waygate-admin/src/federated_peers.rs` |
| Background JWKS fetcher + cache | `crates/waygate-federation/src/jwks.rs` |
| Inbound peer-asserted JWT validator | `crates/waygate-federation/src/peer_jwt.rs` |
| Outbound `tier_c_peer:` identity selector | `crates/waygate-manifest-types/src/lib.rs` (field) + `crates/waygate-upstream/src/{pool/session_identity.rs,identity_client.rs}` |

## Operator model

```
┌──────────────────────┐                ┌──────────────────────┐
│ Gateway A            │                │ Gateway B            │
│ tenant: alice-corp   │                │ tenant: bob-llc      │
│                      │                │                      │
│ federated_peers:     │                │ federated_peers:     │
│   (B, B.issuer,      │                │   (A, A.issuer,      │
│    B/jwks.json, full)│                │    A/jwks.json, full)│
│                      │                │                      │
│ server manifest:     │   Tier-C       │ PeerJwtValidator     │
│  tier_c_peer: <B-id> ├──── JWT ──────►│  iss=A.url           │
│                      │  signed by A   │  aud=B.url           │
│                      │  aud=B.issuer  │  → Principal{        │
│                      │                │     tenant=bob-llc,  │
│                      │                │     auth_method=peer │
│                      │                │   }                  │
└──────────────────────┘                └──────────────────────┘
```

Each side registers the other independently. Tenant
attribution on either end is the local operator's choice —
gateway B decides which of *its* tenants gateway A's calls
project into. The remote operator can't pick on behalf of
the local one.

## Setup runbook

To federate gateway A with gateway B, both sides do the
following (mirrored, once each):

1. **Confirm the other gateway publishes a JWKS.** Browser-
   GET `https://<the-other>/.well-known/jwks.json` — must
   return a valid JWKS document with at least one
   RSA/EC/EdDSA key. (Every gateway running
   `GATEWAY_AS_ENABLED=true` publishes one automatically.)
2. **Register the other side as a peer.** Either use the
   `/admin/t/<tenant>/federation` dashboard page — admins get
   inline create / edit / delete forms there (PR-2) — or POST to
   `/api/v1/admin/federated_peers` directly. Both paths run the
   same validators, audit, and JWKS-cache invalidation (the
   dashboard handlers reuse the REST `*_peer_core` functions).
   The REST body shape:

   ```json
   {
     "peer_name": "alice-corp-gateway",
     "issuer": "https://gw.alice-corp.example",
     "jwks_url": "https://gw.alice-corp.example/.well-known/jwks.json",
     "trust_tier": "full"
   }
   ```

   `issuer` MUST be the EXACT byte sequence the peer
   publishes as their `iss` claim (no canonicalization, no
   trailing slash unless they emit one — see PR #188 r3 high
   AERB rationale in `validate_issuer`).

3. **Wait for the first refresh cycle.** The
   `PeerJwksRefresher` walks every registered peer on a
   `GATEWAY_PEER_JWKS_REFRESH_INTERVAL_SECONDS` cadence
   (default 600s, floor 30s) and warms the cache. The
   first cycle runs almost immediately at boot. An admin
   POST after boot waits for the next tick — there is
   no immediate-refresh mechanism today: restarting the
   gateway is the only way to force a fresh cycle right
   away. PATCH against an existing peer invalidates that
   peer's cached entry (cache goes cold) but still waits
   for the next tick to re-fetch, so don't PATCH unless
   you're prepared for a cache-cold window up to the
   refresh-interval long.

4. **Configure an upstream that uses Tier-C.** On the
   gateway whose users will *originate* the call, edit the
   relevant `servers/*.yaml`:

   ```yaml
   name: bob-llc-tools
   transport: http
   url: https://gw.bob-llc.example/mcp
   tier_c_peer: 7f8a9c2e-...  # the UUID of bob-llc-gateway in YOUR federated_peers
   tools:
     - name: lookup_customer
       risk: low
       side_effects: false
       pii: false
   ```

   `tier_c_peer:` and `exchange:` are mutually exclusive
   (both write `Authorization: Bearer` — see "Invariants"
   below). Same for `tier_c_peer:` and `auth.bearer_env`.

5. **Reload.** `SIGHUP` re-reads manifests; the
   `reload_manifests` path copies `tier_c_peer` through to
   the live entry (PR #194 r1 medium fix).

6. **Make a call.** Have a user on gateway A call
   `bob-llc-tools.lookup_customer`. Gateway A's
   `IdentityAugmenter` mints a JWT with `iss = A's URL`,
   `aud = B's issuer URL`, `sub = the calling user`, stamps
   it as `Authorization: Bearer …`, and ships the request.
   Gateway B's `PeerJwtValidator` resolves the cached JWKS
   for A's issuer, verifies the signature, and produces a
   PeerAssertion principal in B's tenant.

## Trust tiers

Two values today; the runtime distinction is currently
advisory.

- **`full`** — peer principals project into the local tenant
  with their original `sub`. Use when the two gateways are
  operationally a single trust domain (blue/green, same
  operator, internal mesh).
- **`restricted`** — same on-wire behaviour today (recorded
  in tracing fields, logged on accept). A future PR may wrap
  the principal under a `peer:<peer_id>`-style sub rewrite
  so Cedar can authorize per-peer instead of per-user. The
  storage shape is ready; the wrapper isn't.

If you need stricter handling today, gate in Cedar:

```cedar
forbid (
    principal,
    action == Action::"CallTool",
    resource
)
when { principal.auth_method == "peer_assertion" }
unless { resource in Tool::"<a known-safe FQN>" };
```

## Invariants

These are the rules the code enforces; they exist because
each one was a real AERB finding during PR #193 / #194 review.

### Scope strip on peer principals

`PeerJwtValidator` strips `mcp:admin` and `scim:write`
scopes from the JWT's `scope` claim before producing the
Principal. A peer can attest ANY scope on their token; we
MUST not honour admin / SCIM-write scopes from a peer
because the local admin / SCIM surfaces are gated by
`principal.has_scope(...)`. Federated peers are NOT
operators of this gateway — that's the operator's job on
the OTHER end. Belt-and-suspenders: `waygate-admin::scope::require_scope`
and `require_admin_extension` also refuse `AuthMethod::PeerAssertion`
for `Scope::McpAdmin` / `Scope::ScimWrite` before the scope
check runs. PR #193 r2 high.

### Ambiguous tenant attribution refused

The migration's `UNIQUE(tenant_id, issuer)` permits the
same peer-issuer to be registered in multiple tenants
(operator A and operator B both federate with peer C, where
A and B are different tenants on the SAME gateway). If a
single JWT verifies against more than one of those cached
entries (same key shared across tenants), the validator
collects every accepted candidate, builds a
`BTreeSet<tenant_id>`, and fails-closed with
`PeerValidationError::Ambiguous` when the set has > 1
member. Operators have to pick a single tenant
registration. PR #193 r2 high.

### Cache fence vs in-flight refresh

The admin `PATCH` / `DELETE` handlers call
`cache.invalidate(peer_id)`. The refresher walks rows on
its own clock — it could be mid-fetch when the admin
mutates. To prevent a stale fetch from re-inserting the
OLD keys after invalidation, the cache has a per-peer
monotonic generation counter:

- `forget(peer_id)` removes the entry AND bumps `generations[peer_id]`.
- `try_upsert_at_gen(entry, snapshot)` only lands the upsert
  if `current == snapshot`. Returns `false` otherwise.
- The refresher snapshots `cache.generation(peer.id)` BEFORE
  its async `fetcher.fetch(...)` and passes the snapshot to
  `try_upsert_at_gen` on the way back.

A stale fetch is silently discarded (counted as a failure in
`RefreshSummary`); the next cycle starts clean against the
new metadata. PR #193 r4 high.

### URL userinfo rejected + sanitized on emit

`validate_issuer` and `validate_jwks_url` reject
`https://user:pass@host/...` shapes via
`reject_url_userinfo`. The audit reason strings for
`FederatedPeerCreated` / `FederatedPeerUpdated` also pass
the URL through `sanitize_url_for_audit` before formatting,
so a pre-existing row created before the input-side reject
(or written by migration / direct SQL) still doesn't leak
credentials into evidence. PR #193 r3 high + r4 medium.

### Body-cap is streaming, not after-the-fact

`PeerJwksFetcher::fetch` enforces `max_bytes` (default 1
MiB) TWO ways: pre-stream via `Content-Length`, post-stream
via per-chunk accumulator on `bytes_stream()`. A peer that
lies about Content-Length (or chunks indefinitely) gets cut
off at ~one chunk past the cap, never the full body. PR
#193 r3 high.

### Peer principals carry no raw_token

PeerAssertion `Principal.raw_token = None`. The upstream
pool's RFC 8693 exchange path uses `principal.raw_token`
as the subject token when no stored OAuth session exists;
allowing a peer JWT to flow through that path would let a
peer assertion turn into an outbound IdP exchange request,
expanding scope past inbound verification. PR #193 r4
medium.

### Outbound `tier_c_peer` fail-closed

`UpstreamPool::call_tool` refuses dispatch BEFORE breaker
acquire when `tier_c_peer:` is set but the gateway can't
mint the peer JWT:

- `!entry.forwards_identity` (no identity issuer at boot,
  or stdio transport) → refuse with operator error
  naming `GATEWAY_IDENTITY_*`.
- `principal.is_none()` (auth disabled) → refuse with
  "Tier-C needs authenticated caller".

Same shape as the existing `tier_a_required` enforcement.
PR #194 r2 high.

### `tier_c_peer:` is mutually exclusive with anything else that writes Authorization

Refused at `load_manifests` time:

- `tier_c_peer:` + `exchange:` (Tier-A) — both write
  Authorization.
- `tier_c_peer:` + `auth.bearer_env` — both write
  Authorization.

The import path (`waygate-server::import_cmd`) calls the
same `validate_manifest_invariants` so `--import-manifests`
can't persist a manifest that normal boot would refuse.
PR #194 r1 high + r2 medium.

### `tier_c_peer:` round-trips on reload + import

- `pool::reload_manifests` copies `new_manifest.tier_c_peer`
  to the live entry (SIGHUP edits land without restart).
- `import_cmd::to_import_server` writes `tier_c_peer` into
  the catalog `runtime_target` JSONB alongside `auth` /
  `exchange` / `mtls`. Without this, DB-backed boot would
  silently downgrade a Tier-C upstream to Tier-B until
  manual catalog edit.

PR #194 r1 medium.

## Operational notes

- **Forcing a refresh after rotation.** Admin `PATCH` /
  `DELETE` evict the cache entry immediately. The next
  refresh tick re-fetches. If the new `jwks_url` is
  unreachable the cache STAYS empty (the refresher
  deliberately retains the previous entry on fetch failure,
  but `forget` cleared it first); peer-asserted requests
  fail until the new endpoint is reachable. That's the
  intended fail-closed posture.
- **Cache miss vs unknown issuer.** `PeerJwtValidator`
  reports `NoPeer` when `iss` matches no cached entry, and
  `NoKey` when `iss` matches but the `kid` doesn't. Both
  surface to the bearer middleware as JWT client errors —
  the chain falls through to the next validator. A token
  with no peer match is just "not for me," not an outright
  reject.
- **Same kid, different keys across tenants.** Permitted by
  PR #193 r1 medium fix: the validator iterates all
  candidates that own the kid, tries each key, and accepts
  the first that verifies. Combined with the ambiguity
  check above, multi-tenant kid collisions still
  deterministically resolve to a single tenant.

## What's NOT in scope yet

- **Restricted-tier principal wrapping.** Today
  `trust_tier: restricted` is logged but doesn't change the
  Principal. A future PR may wrap the sub.
- **Per-upstream JWKS endpoint for the receiving side.**
  Today the gateway publishes one global JWKS at
  `/.well-known/jwks.json`. A multi-key federation deployment
  with per-peer key isolation is future work.
- **Scope propagation on Tier-C mint.** AERB PR #194 r3
  medium flagged that the gateway-minted Tier-C JWT carries
  no `scope` claim; the receiving gateway's `Principal.scopes`
  is therefore empty, so high-risk step-up policies will
  refuse. Fail-closed by design, but a broader scope-
  propagation design (deciding what subset of the caller's
  scopes to forward) is deferred.
- **Two-gateway end-to-end smoke test in CI.** The unit +
  integration tests in `crates/waygate-federation/tests/`
  cover the contracts on each side independently. A real
  two-gateway loop test belongs in `waygate-test-client` or a
  docker-compose harness; not shipped.

## See also

- [`docs/agents/identity.md`](identity.md) — the
  `AuthMethod::PeerAssertion` variant + bearer chain
  ordering.
- [`docs/compliance.md`](../compliance.md) — federation
  cells for CC6 / CC7 once the smoke test ships.
- `migrations/0033_federated_peers.sql` — schema.
- `crates/waygate-federation/src/peer_jwt.rs` — `PEER_FORBIDDEN_SCOPE_PREFIXES`
  and the validator's iteration loop are the most
  security-sensitive code in the crate.
