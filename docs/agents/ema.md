# Enterprise-Managed Authorization (EMA) at the gateway

Implementation guide for the MCP **Enterprise-Managed Authorization**
extension (`io.modelcontextprotocol/enterprise-managed-authorization`,
[SEP-990](https://modelcontextprotocol.io/seps/990-enable-enterprise-idp-policy-controls-during-mcp-o),
spec stable; built on IETF
[draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant),
May 2026).

Load this doc when changing `crates/waygate-as/src/token.rs`,
`crates/waygate-oidc/src/identity_jwt.rs`, the `waygate-scim` provisioning
surface, the `GrantCrossAppAccess` Cedar action / `crates/waygate-authz/tests/fixtures/policies/40-cross-app-access.cedar`,
or anything that mints or redeems ID-JAGs.

## Overview

The gateway plays **both** EMA authorization-server roles — it **mints**
ID-JAGs (the *IdP Authorization Server* role) and **redeems** them for
access tokens (the *Resource Authorization Server* role) — with **Cedar** as
the policy decision point and the existing **SCIM-provisioned directory** as
the authoritative attribute source. **Authentik keeps only authentication
(SSO) and provisioning (outbound SCIM).**

EMA is strictly **additive and opt-in**: the OAuth code-flow + CIMD and the
static API-key paths remain first-class and required-capable. EMA only adds
two grant types at `/oauth/token` plus one config-gated capability advert.

## The authentication / authorization split

| EMA role | Owner |
|---|---|
| Authentication (login, MFA) | Authentik |
| Directory / provisioning source | Authentik → `waygate-scim` |
| Policy decision (mint gate) | Gateway / Cedar (`GrantCrossAppAccess`) |
| ID-JAG issuance (IdP-AS) | `waygate-as` token-exchange grant |
| ID-JAG → access token (Resource-AS) | `waygate-as` jwt-bearer grant |

The gateway is NOT a full IdP — it does not own credentials/MFA. It is the
*policy decision point + token issuer*; Authentik remains the authentication
authority and the directory master.

## EMA flow (single-gateway deployment)

1. Client SSO's once via the gateway's CIMD login flow (which proxies
   Authentik). Authentik authenticates; the client holds a gateway access token.
2. Continuously, out of band: Authentik's SCIM provider pushes
   user/group/active changes into `waygate-scim`.
3. Client token-exchanges at `/oauth/token` for an **ID-JAG**. The gateway
   resolves the subject token to a `Principal`, **enriches groups/active from
   SCIM (not token claims)**, runs Cedar `GrantCrossAppAccess`, and mints the
   ID-JAG signed by the gateway identity key.
4. Client redeems the ID-JAG at `/oauth/token` (jwt-bearer grant) for an
   **audience-restricted** access token (`aud = resource`) and calls the
   upstream.

The same `/oauth/token` endpoint serves both AS roles (mint via
token-exchange, redeem via jwt-bearer). In a single gateway `iss == aud ==`
the gateway's canonical issuer; the split becomes meaningful across Tier-C
federation.

## Confirmed wire constants (id-jag-04 + MCP EMA profile)

| Thing | Exact value |
|---|---|
| Discovery field | `authorization_grant_profiles_supported` contains `urn:ietf:params:oauth:grant-profile:id-jag` |
| ID-JAG token type (requested + issued) | `urn:ietf:params:oauth:token-type:id-jag` |
| Mint grant (token-exchange at IdP-AS) | `urn:ietf:params:oauth:grant-type:token-exchange` |
| Redeem grant (jwt-bearer at Resource-AS) | `urn:ietf:params:oauth:grant-type:jwt-bearer` |
| JWT header | `typ: oauth-id-jag+jwt` |
| Required claims | `iss, sub, aud, client_id, jti, exp, iat` |
| Optional claims | `resource, scope, email, act, tenant, sub_id, acr, amr, …` |

**Audience restriction:** the base IETF draft leaves audience binding to local
policy, but the **MCP EMA profile tightens it to a MUST** — the issued access
token MUST be audience-restricted to the MCP server identified by the
ID-JAG `resource` claim. The profile governs us → **MUST**.

**Redeem MUST (IETF §4.4.1):** verify `typ == oauth-id-jag+jwt` (manual —
`jsonwebtoken::decode` does not check `typ`), validate `aud`, signature, `exp`,
and **`client_id` equals the authenticated client** at the token endpoint;
check `jti` for replay.

## Invariants (non-negotiable)

1. **Additive, never required.** OAuth code-flow + CIMD and static API keys
   remain first-class. EMA adds grant types + a config-gated advert only. The
   redeemed token is an ordinary gateway access token validated by the existing
   `BearerValidator`; inbound auth requirements are unchanged. No
   "enterprise-managed required" marker is ever emitted. Extension negotiation
   is mutual (both client + server declare it in `initialize`), so advertising
   is inert for clients that don't negotiate it.
2. **SCIM is the authoritative attribute source at mint.** Groups/active read
   from the enriched principal (SCIM), not token claims; **mint refuses without
   a present + active SCIM row** (`GATEWAY_AS_IDJAG_REQUIRE_SCIM`, default true).
3. **Audience-restricted tokens** (`aud = resource`) — MUST.
4. **Client-independent + self-testable** — the gateway mints and redeems its
   own ID-JAGs; no dependency on a specific MCP client.

## SCIM deprovisioning

SCIM DELETE sets `active=false,
deleted_at=now()` instead of hard-deleting. SCIM read endpoints filter
`deleted_at IS NULL` (so DELETE still 404s to Authentik, RFC 7644 compliant);
the **resolver's primary lookup filters `deleted_at IS NULL` and, on a live
miss, a tombstone-fallback resolves the matching tombstone as `active=false`**,
so `scim_blocks_request()` blocks the deprovisioned user on every gateway
surface. The SCIM user DELETE handler also evicts the shared bearer enricher
cache (`PgScimEnricher::invalidate` for both `(tenant, externalId)` and
`(tenant, userName)`) so the block takes effect on the next request rather
than after the 60s cache TTL. Re-`POST` of the same `userName`/`externalId`
re-provisions a fresh live row (the live-only partial unique indexes make the
tombstone invisible to the uniqueness constraint — **no revive**). A sweep
removes tombstones past retention. Never-provisioned principals (service
accounts, API keys, dev) still have `scim == None` → treated active,
while EMA mint requires a present, active SCIM row by default.

### SCIM soft-delete tombstone

- Migration `0058_scim_users_soft_delete.sql`: add `deleted_at TIMESTAMPTZ`
  to the `scim_users` table (mig 0019); swap the two full `UNIQUE`
  constraints on `(tenant, user_name)` / `(tenant, external_id)` for
  live-only partial unique indexes (`WHERE deleted_at IS NULL`); index the
  tombstones.
- `waygate-scim` store: `delete` → soft-delete (`active = false,
  deleted_at = now()`); SCIM reads (get/list/replace) and the group-member
  join filter `deleted_at IS NULL`. **No revive** — re-provisioning the
  same `userName`/`externalId` creates a fresh live row, because the
  live-only partial unique indexes make the tombstone invisible to the
  uniqueness constraint. `sweep_scim_tombstones` GCs old tombstones.
- Resolver: the primary lookup filters `deleted_at IS NULL` (live rows;
  the ambiguity guard is unchanged) and, on a live miss, a tombstone
  fallback resolves a matching tombstone as `active = false` so the
  request is blocked. A never-provisioned `sub` (no live row, no
  tombstone) stays a clean miss → treated active.
- `crates/waygate-admin/src/scim_users.rs` DELETE handler calls the
  soft-delete path; GET/LIST/PUT 404 / omit tombstoned rows.
- No change to `Principal::scim_blocks_request()` — it already blocks on
  `!active`, which the tombstone-fallback sets.
- Tests: provision → DELETE → resolver resolves `active = false` (blocks)
  but `GET /Users/{id}` 404s; re-`POST` re-provisions a fresh active row;
  never-provisioned `sub` is a clean miss; tombstoned user drops out of
  group members; sweep reclaims only old tombstones.

### ID-JAG mint (IdP-AS)

- `waygate-oidc/identity_jwt.rs`: `IdJagClaims { jti, iss, sub, email?, aud,
  resource, client_id, iat, exp, scope }`; `IdentityIssuer::mint_id_jag(...)`
  — same as `mint_access_token` but `header.typ = Some("oauth-id-jag+jwt")`,
  `jti = new_random_token()`.
- `waygate-as/token.rs`: dispatch arm
  `Some("urn:ietf:params:oauth:grant-type:token-exchange")`; extend
  `TokenRequest` (`subject_token`, `subject_token_type`, `requested_token_type`,
  `audience`, `resource`, `scope`); add `TokenExchangeResponse {
  issued_token_type: "urn:ietf:params:oauth:token-type:id-jag", access_token,
  token_type: "N_A", scope, expires_in }`.
- Handler order (validate-before-mint): require `requested_token_type ==
  …:id-jag` → resolve `subject_token` → `Principal` (`SubjectTokenResolver`) →
  `enrich()` (SCIM + RBAC) → require present + active SCIM row +
  `!scim_blocks_request()` → `CrossAppPolicy.authorize(principal, client_id,
  resource)` (Cedar) → validate `audience ∈ {self issuer, peer issuers}`,
  `resource ∈ known upstreams`, `scope ⊆ allowed_scopes ∩ principal-derived`
  → `mint_id_jag` → audit `OAuthIdJagIssued`.
- New traits in `waygate-as` (concrete impls in `waygate-server`):
  `SubjectTokenResolver` (wraps AS `BearerValidator` + `IdTokenValidator`),
  `CrossAppPolicy` (wraps `CedarGate`). `AsState` gains these +
  `enricher`, `idjag_enabled`, `idjag_ttl`, `idjag_require_scim`,
  `known_resources`.
- `waygate-authz`: `Action::"GrantCrossAppAccess"` + Facts variant
  `(principal, client_id, resource)`.
- `crates/waygate-authz/tests/fixtures/policies/40-cross-app-access.cedar`: permit gated on a provisioned group;
  `00-deny-by-default` + `16-scim-active` cover negatives.
- config: `GATEWAY_AS_IDJAG_ENABLED` (false), `GATEWAY_AS_IDJAG_TTL_SECONDS`
  (300), `GATEWAY_AS_IDJAG_REQUIRE_SCIM` (true).

### ID-JAG redeem (Resource-AS)

- Migration `0060_id_jag_jti.sql`: `id_jag_jti(jti PK, expires_at)`; replay
  defense = `INSERT … ON CONFLICT DO NOTHING` + rows-affected (race-safe).
- `waygate-oidc`: `verify_id_jag(token, key, expected_aud, trusted_issuers)`
  — `decode_header` → assert `typ == "oauth-id-jag+jwt"`, then `Validation`
  (aud + iss + exp).
- `waygate-as/token.rs`: arm
  `Some("urn:ietf:params:oauth:grant-type:jwt-bearer")`; `TokenRequest +=
  assertion`. Order: CIMD-auth client → resolve key (self keyring for local issuance;
  peer/external via trusted-IdP registry) → `verify_id_jag(expected_aud =
  cfg.issuer())` → assert `id_jag.client_id == authenticated client_id` →
  **assert `id_jag.resource ∈ idjag_known_resources`** (fail closed with
  `invalid_target`, BEFORE the jti write; otherwise a trusted/peer issuer could
  set `resource` to the estate audience and redeem an unrestricted estate token
  instead of a one-upstream token) → atomic jti insert (reject replay) →
  `scope = id_jag.scope ∩ allowed_scopes`, strip `mcp:admin`/`scim:write` on
  cross-org/peer → `mint_access_token(aud = id_jag.resource, …)` → respond
  (no refresh token) → audit `OAuthJwtBearerRedeemed`.
- config: `GATEWAY_AS_TRUSTED_IDP_ISSUERS` (default = own issuer).
- Tests: mint→redeem→`aud==resource`; replay rejected; typ-confusion rejected;
  `client_id` mismatch rejected; wrong aud/expired/untrusted iss rejected.

### SCIM PATCH support (optional)

`ServiceProviderConfig` now advertises `"patch": {"supported": true}`, and
RFC 7644 §3.5.2 `PATCH` is implemented at the `waygate-admin` handler layer
(no new store method — both reuse the existing `get` + `replace` ops):

- **Users** (`scim_users::patch_user`): `op:replace` of `active` only — both
  `{op:replace, path:"active", value:<bool>}` and the no-path
  `{op:replace, value:{"active":<bool>}}` shapes Authentik emits (string
  booleans coerced). Any other op/path → 400 `invalidValue`. Fetch→merge→replace
  so only `active` changes; idempotent when unchanged.
- **Groups** (`scim_groups::patch_group`): membership delta over the current
  set — `op:add`/`op:remove`/`op:replace` on `members` (value array of
  `{value:<uuid>}`), plus the `members[value eq "<uuid>"]` filter-path remove
  form. A non-empty `value` is required so a malformed body can't silently wipe
  the group; any other op/path → 400 `invalidValue`.

Tightly scoped to the ops Authentik emits, fail-closed on anything else.
Interop/efficiency only — **not** a security fix, and does NOT remove the need
for tombstones: scope-exit remains a DELETE (soft-delete tombstone), and a PATCH
`active=false` is just a state flip. Pure parse/apply logic is unit-tested
(`scim_users`/`scim_groups` `mod tests`).

### capability advert + discovery

- `waygate-mcp/server.rs`: `get_info` populates `ServerCapabilities.extensions`
  (rmcp SEP-1724 field) with `EMA_EXTENSION_ID`
  (`"io.modelcontextprotocol/enterprise-managed-authorization"`) → `{}` (empty
  settings object) **only when advertisement is enabled**, via the
  `GatewayServer::with_ema_capability_advert(bool)` builder. Off by default until
  a client is verified — protects the working OAuth/API-key discovery path.
- `waygate-as/metadata.rs`: `AuthorizationServerMetadata::build(public_url,
  advertise_ema)` adds `authorization_grant_profiles_supported:
  ["urn:ietf:params:oauth:grant-profile:id-jag"]` (`ID_JAG_GRANT_PROFILE`,
  omitted from JSON when empty) + both grant URNs (`token-exchange` mint,
  `jwt-bearer` redeem) to `grant_types_supported` — only when `advertise_ema`.
  Because the `jwt-bearer` redeem grant needs confidential-client auth, the same
  gate also adds `client_secret_basic` / `client_secret_post` / `private_key_jwt`
  to `token_endpoint_auth_methods_supported` (mirroring
  `client_auth::ClientCredentials::extract`) so the advertised grant is fully
  serviceable from discovery; the public CIMD `none` method stays for the
  `authorization_code` flow.
- Gate (`GATEWAY_AS_IDJAG_ADVERTISE`, default false) folded with EMA actually
  being wired so the gateway never advertises a grant `/oauth/token` can't
  service: the capability extension uses
  `cfg.as_server.is_some() && GATEWAY_AS_IDJAG_ENABLED && GATEWAY_AS_IDJAG_ADVERTISE`
  (`main.rs`), and the metadata handler uses
  `state.config.idjag_advertise && state.ema.is_some()`. New config field
  `AsConfig.idjag_advertise`.
- Tests: `waygate-mcp` `ema_capability_advertised_only_when_opted_in`;
  `waygate-as::metadata` `ema_grants_are_advertised_when_enabled` /
  `ema_grants_are_omitted_when_not_advertised`.

### per-upstream resource ids + audience binding

Per-upstream RFC 9728 resource id (`{public_url}/servers/<name>`), derived from
the loaded manifests at boot. **Implemented:**

- `waygate-server` computes the resource-id → server map from the manifests and
  feeds it to (a) the `/mcp` gateway-JWT `BearerValidator`
  (`with_resource_audiences`) — its accepted-audience set becomes
  `{estate audience} ∪ {resource ids}`, additive — and (b) the ID-JAG mint
  resource allowlist (unioned with `GATEWAY_AS_IDJAG_RESOURCES`), so mint +
  redeem agree on the canonical id format.
- When a validated token's `aud` is a resource id, the validator records a
  single-server **call restriction** via `Principal.api_key_profile_restrictions`
  (`allowed_servers = [the bound upstream]`). That reuses the existing general
  per-principal server/tool allow-list the invocation gate (`check_profile_restrictions`)
  AND the `tools/list` filter already enforce — so a resource-scoped (EMA-redeemed)
  token is confined to its one upstream for both dispatch and discovery.
- **Namespace-scoped gateway-local built-ins are confined too.**
  `gateway-admin.*`, `gateway-observe.*`, and `gateway-control.*` are dispatched
  (and listed) by `GatewayServer` *before* the upstream `InvocationService`
  where the allow-list is otherwise enforced, and they self-gate only on
  scope. So `dispatch_tool_call` and `list_visible_tools` apply the *same*
  profile allow-list to these namespaces — both the namespace
  (`profile_blocks_server`) AND the concrete tool (`profile_blocks_tool`),
  exactly as the upstream `evaluate_profile_restrictions` does: a token bound
  to one upstream (whose allow-list names only that upstream) cannot list or
  call these built-ins, and a profile whose `allowed_tools` names one built-in
  cannot reach its siblings in that namespace. A confined dispatch returns the
  hermetic `unknown tool` shape, never leaking that the built-in exists.

- **Delegated data-plane facades preserve the restriction internally.**
  `codemode.*` remains visible to a resource-bound token so the caller can use
  the common search/describe contract, but every returned upstream is filtered
  through that token's `allowed_servers` / `allowed_tools` profile plus the
  normal Cedar discovery gates. The outer facade carries no independent
  upstream or control-plane authority. A future execution tool must likewise
  send every nested call through the ordinary invocation pipeline with the
  original principal.
- Estate-wide tokens (`aud == cfg.audience`) stay unrestricted. An `aud` that is
  neither the estate audience nor a registered resource id is rejected.
- **Multi-valued `aud` is resolved fail-closed.** The audience-membership gate
  (`set_audience`) admits a token if *any* `aud` entry matches, so an `aud` array
  is too coarse to trust on its own. `resolve_resource_binding` re-derives the
  binding from every registered resource id present in the claim (deduplicated):
  **0** → unrestricted estate (the gate already proved the estate audience
  matched); **1** → confine to that one upstream (even if the estate audience is
  *also* present — the resource binding is strictly more restrictive); **≥2** →
  reject (`AmbiguousResourceAudience`, a 401), never fall back to unrestricted.


Per-resource PRM documents (RFC 9728
`.well-known/oauth-protected-resource/...`) are not served. Resource restrictions
are enforced independently of that discovery surface.

### Tier-C federation on ID-JAG

A mints ID-JAG (`aud = B.issuer`, `resource = <B upstream>`) → B redeems. The redeem path routes on the assertion's `iss`: a self-issued ID-JAG
(`iss == our issuer`) verifies against our own keyring; a **peer-minted** one
verifies against that peer's cached JWKS via the shared `PeerJwksCache`.

- `waygate-oidc::peek_unverified_issuer` — routing-only iss peek (the signature
  still decides; a forged iss routes to a keyset that won't verify it).
- `waygate-federation::peer_jwt::verify_peer_id_jag(cache, token, expected_aud,
  trusted_issuers)` → `PeerIdJag { claims, tenant, peer_id }`. Mirrors
  `PeerJwtValidator`: iss-route → per-candidate kid/key → `verify_id_jag` (typ +
  aud + iss-allowlist + exp + sig) → **fail-closed if more than one tenant
  verifies**. The peer's `iss` must be in BOTH `federated_peers` (cached) AND
  `idjag_trusted_issuers` (defense in depth). Peer ID-JAGs are **EdDSA-only**,
  matching the gateway's own ID-JAGs (`verify_id_jag` pins `Algorithm::EdDSA`);
  `peer_decoding_key` rejects RSA/EC/oct peer keys for the ID-JAG path (the
  general inbound peer-bearer path still accepts RSA/EC). Broadening ID-JAG to
  RSA/EC would be a deliberate change to `verify_id_jag`'s algorithm allow-list.
- `waygate-as` redeem (`EmaDeps.peer_jwks`): for a peer-minted ID-JAG the minted
  token's **tenant comes from the peer's `federated_peers` record, never the
  assertion's `tenant` claim** — the receiving gateway decides which of its
  tenants a peer's calls land in. `peer_jwks = None` ⇒ only self-issued ID-JAGs
  are redeemable. Scope strip (`mcp:admin`/`scim:write`) already fires on the
  cross-org path (`claims.iss != our issuer`); target validation (resource ∈
  known resources, not estate) and single-use jti are unchanged.
- Wiring: `main()` threads the same shared `peer_jwks_cache` (the inbound
  `PeerJwtValidator` + outbound pool already share it) into `boot.rs`'s
  `build_as_router` →
  `EmaDeps.peer_jwks`.
- Tests: `waygate-federation::peer_id_jag_verify` (happy path returns the
  peer-record tenant, not the claim; unregistered issuer; untrusted issuer;
  wrong audience; non-ID-JAG typ; tampered sig; multi-tenant ambiguity →
  fail-closed). `waygate-as::idjag_redeem_pg` e2e:
  `peer_minted_id_jag_redeems_with_tenant_from_peer_record` and
  `peer_minted_id_jag_rejected_when_peer_redemption_not_configured`.

## Deployment example

**Prerequisite:** Authentik → outbound SCIM provider, base URL
`https://gateway.example.com/scim/v2`, single static bearer = an `mcpgw_*` key
with both `scim:read` + `scim:write` (the gateway's `ServiceProviderConfig`
documents the single-bearer requirement). Map `mcp-*` groups + users. Store
the key in the deployment's secret manager. The gateway advertises
`patch.supported:true` and implements RFC 7644 §3.5.2 `PATCH` for Users
(`replace active`) and Groups (`add`/`remove`/`replace` on `members`), so
Authentik can sync membership and deactivation via PATCH; `PUT /scim/v2/Groups/{id}`
(full replace) remains available as the fallback.

Set these environment variables in the deployment configuration:

```yaml
- GATEWAY_AS_IDJAG_ENABLED=true
- GATEWAY_AS_IDJAG_TTL_SECONDS=300
- GATEWAY_AS_IDJAG_REQUIRE_SCIM=true
# Optional: the mint resource allowlist is auto-derived from the
# per-upstream resource ids ({public_url}/servers/<name>) in the loaded
# manifests, and the /mcp validator binds those same ids. Set this only to allow
# resources OUTSIDE the manifest set (unioned in). Comma/space-separated.
# - GATEWAY_AS_IDJAG_RESOURCES=https://gateway.example.com/servers/extra
# Resource-AS audiences an ID-JAG may be aud-bound to. Defaults to the gateway's
# own issuer (Tier-A/B self-redemption); list peer Resource-AS issuers here for
# cross-gateway. Optional — omit for a single-gateway deployment.
- GATEWAY_AS_IDJAG_AUDIENCES=https://gateway.example.com
- GATEWAY_AS_TRUSTED_IDP_ISSUERS=https://gateway.example.com # self; add trusted cross-org issuers
- GATEWAY_AS_IDJAG_ADVERTISE=false                            # flip on only after client verification
- GATEWAY_DEPLOYMENT_PROFILE=prod
```

The mint resource allowlist auto-derives from the manifests, so with
upstreams loaded the grant works without `GATEWAY_AS_IDJAG_RESOURCES`. A
resource-scoped (EMA-redeemed) token is bound to its one upstream at `/mcp` (the
gateway-JWT validator accepts the per-upstream resource id as an audience and
records the server restriction). A request whose `resource`/`aud` names no known
upstream is rejected at every stage: `invalid_target` at **mint** AND at
**redeem** (jwt-bearer), and `401` at `/mcp`. Redeem validation is essential —
without it a trusted/peer ID-JAG issuer could set `resource` to the estate
audience and obtain an unrestricted token.

No new mint secret — ID-JAG signing reuses `GATEWAY_IDENTITY_SIGNING_KEY_PEM`.
Publish `40-cross-app-access.cedar` into `GATEWAY_POLICIES_DIR`; SIGHUP
reload (preserve the broken-policy-doesn't-lock-out invariant).

**Register the redeeming confidential clients** before enabling redeem
(draft §4.4/§9.1 — confidential clients only). Each app that redeems an ID-JAG
authenticates with its own credential, registered via the admin API:

```sh
# client_secret (returned once) — or pass {"jwks": {...}} for private_key_jwt
curl -XPOST $GW/api/v1/admin/confidential-clients -H "authorization: Bearer $ADMIN" \
  -d '{"client_id":"https://app.example/c.json","generate_secret":true}'
```

`GET`/`DELETE /api/v1/admin/confidential-clients` list/remove them. The client's
`client_id` MUST equal the ID-JAG's `client_id` claim at redeem.

## Security invariants (AERB checklist)

- `typ == oauth-id-jag+jwt` checked manually on redeem (token-confusion guard) — MUST.
- jti replay = conditional INSERT + rows-affected, never read-then-write — MUST.
- Issued access token `aud == ID-JAG.resource` — MUST.
- `client_id` matches the authenticated client at redeem — MUST.
- `scope ⊆ allowed_scopes`; strip `mcp:admin`/`scim:write` on cross-org/peer ID-JAGs.
- Mint requires present + active SCIM row; deprovisioned (tombstoned) users blocked everywhere.
- All validation (resolve → enrich → SCIM gate → Cedar → scope/resource) before the mint side-effect + audit.
- No secrets/assertions in logs; `tracing` carries `sub`/`client_id`/`resource`/`jti`, never the token.
- Migrations: new files only, next free number re-checked vs `main`.
- Capability advert config-gated; EMA never required.
- Audit every mint and redeem (this is EMA's centralized audit trail).

## Client validation

Before enabling advertisement, verify that the client negotiates the EMA
extension and supports the gateway issuer. Exercise SCIM deactivation and
scope removal against the deployment's provisioning configuration.

## Primary sources

- [EMA spec page](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)
  · [stable .mdx](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx)
- [Official blog: Zero-touch OAuth for MCP](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)
- [Aaron Parecki: Nov 2025 MCP authorization spec update](https://aaronparecki.com/2025/11/25/1/mcp-authorization-spec-update)
- [IETF draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant)
- [MCP authorization core spec 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Client extension support matrix](https://modelcontextprotocol.io/extensions/client-matrix)
