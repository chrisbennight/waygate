# Compliance mapping

> **Scope.** This document maps SOC 2 (Common Criteria, 2017 TSC) and
> the NIST AI Risk Management Framework (AI RMF 1.0,
> GOVERN/MAP/MEASURE/MANAGE) to **concrete gateway features**: audit
> columns, Cedar policies, deployment settings, code paths, registered
> Prometheus metrics. Validate these controls against the deployed version.
>
> **What this is NOT.** Not a certification claim, not a SOC 2
> attestation, not a SOC 2 system description (AT-C 205). The gateway
> alone doesn't make any deployment compliant; the *deployment* does,
> with the gateway as a contributing control.
>
> Items marked **Partial** describe what's shipped today plus an
> explicit limitation. Items marked **Out of scope** belong to layers outside the
> gateway (HR, physical security, encryption-at-rest on the Postgres
> host, etc.) — listed so a reader can see they were intentionally
> excluded rather than forgotten.

## Reading the tables

Each row has four columns:

- **Criterion** — the spec ID + a short paraphrase.
- **Gateway control** — the concrete code path, table column, env var,
  or policy that contributes.
- **Evidence** — where an auditor would look to verify the control is
  working in a deployment (audit-log query, config inspection, metric
  name).
- **Status** — `Yes` (implemented), `Partial` (implemented with a
  named gap), `Out of scope` (deliberately outside the gateway's
  surface).

Spec citations are anchors only — the AICPA Trust Services Criteria
and NIST publications are the authoritative sources.

## Audit-log column glossary

Each `Yes` / `Partial` row that cites an audit query uses the column
names actually defined in `migrations/0002_audit_log.sql` +
`migrations/0006_audit_category.sql`:

- `category` — `EvidenceCategory::as_str()` snake_case discriminator
  (e.g. `invocation`, `admin_mutation`, `auth_attempt`,
  `policy_reload`, `manifest_reload`, `api_key_lifecycle`,
  `oauth_event`, `upstream_health`, `approval_lifecycle`,
  `catalog_drift`, `data_inspection`).
- `action` — free-form verb the recorder picks (e.g. `CallTool`,
  `ApiKeyMinted`, `tenants.delete`).
- `outcome` — lowercase `AuditOutcome::as_str()`: `success`, `denied`,
  `step_up_required`, `execution_error`.
- `principal_sub`, `principal_email`, `tenant_id` — actor identity.
- `policy_ids` — `TEXT[]` of fired Cedar policy IDs (deny path).
- `reason` — single text field (`NULL` when not set).
- `prev_hash`, `row_hash` — SHA-256 audit hash chain
  (`migrations/0015_audit_hashchain.sql`).

A query that searches for `action='AdminMutation'` returns no rows —
the discriminator is the `category` column, with `admin_mutation`
(lowercase). Audit consumers go through `crates/waygate-storage/src/
audit.rs::PgAuditSink` or the bundle export
(`crates/waygate-storage/src/bundle.rs`).

## Prometheus metrics

See the [telemetry reference](agents/telemetry.md#prometheus-metrics) for metric
semantics and labels. Definitions are in
[`metrics.rs`](../crates/waygate-telemetry/src/metrics.rs); individual criteria
below cite the measurements relevant to that control.

Rate-limit denials and break-glass token minting have no dedicated Prometheus
counters. Use their audit events for those alerts; break-glass token use is
counted by `mcp_break_glass_total`.

---

## SOC 2 Common Criteria (2017 TSC)

### CC1 — Control Environment

| Criterion | Gateway control | Evidence | Status |
|-----------|-----------------|----------|--------|
| CC1.1 Commitment to integrity & ethics | n/a (organizational) | — | Out of scope |
| CC1.2 Board independence | n/a (organizational) | — | Out of scope |
| CC1.3 Management establishes structures | n/a (organizational) | — | Out of scope |
| CC1.4 Commitment to attract / develop competence | n/a (organizational) | — | Out of scope |
| CC1.5 Accountability for internal control | `audit_log` row for every admin mutation carries `principal_sub`, `principal_email`, `tenant_id`, `action`, `reason` | `SELECT principal_sub, principal_email, action, reason, ts FROM audit_log WHERE category='admin_mutation' ORDER BY ts DESC` | Yes |

### CC2 — Communication & Information

| Criterion | Gateway control | Evidence | Status |
|-----------|-----------------|----------|--------|
| CC2.1 Quality information to support controls | `audit_log` schema (`ts`, `action`, `outcome`, `principal_sub`, `server`, `tool`, `risk_level`, `pii`, `policy_ids`, `reason`, `latency_ms`, `tenant_id`, `category`, hash chain) | `migrations/0002_audit_log.sql`, `0005_audit_pii.sql`, `0006_audit_category.sql`, `0015_audit_hashchain.sql`; writer at `crates/waygate-storage/src/audit.rs::PgAuditSink` | Yes |
| CC2.2 Internal communication of policies | Cedar policy bundle published via `/api/v1/policy_bundles`; `@reason("…")` annotations surface in denial responses via `data.reasons` | `crates/waygate-authz/tests/fixtures/policies/*.cedar`; `crates/waygate-authz/src/cedar.rs::evaluate_raw_facts` populates `AuthzResult.reasons` from per-policy annotations | Yes |
| CC2.3 External communication w/ users & vendors | OpenAPI document at `/api/v1/openapi.json` (utoipa-generated); MCP error envelopes include `data.error` discriminators (`insufficient_scope`, `profile_restricts_server`, `forbidden`) | `crates/waygate-admin/src/openapi.rs`; structured-error mappings in `crates/waygate-mcp/src/server.rs` (see arms around line 250) | Yes |

### CC3 — Risk Assessment

| Criterion | Gateway control | Evidence | Status |
|-----------|-----------------|----------|--------|
| CC3.1 Specifies objectives | Per-tool `risk` classification (`low`/`medium`/`high`) declared in upstream manifests + persisted in catalog | `servers/*.yaml` → `ToolClassification.risk`; catalog `tool_classifications.risk` column (migration `0011_catalog.sql`) | Yes |
| CC3.2 Identifies risks | catalog-owned risk plus legacy classification or reviewed MCP behavior/data claims; per-tool `risk_level` audited on every call; auto-quarantine on schema or security-metadata drift when the tool's risk tier or side-effect behavior meets the threshold (also emits a chained-best-effort `CatalogDrift` audit row) | `servers/*.yaml`; approved tool versions; `audit_log.risk_level` + `audit_log.pii`; `GATEWAY_QUARANTINE_ON_DRIFT_RISK=high\|medium\|all` (`crates/waygate-upstream/src/pool/`, see the `quarantine_threshold_covers_risk_correctly` + `emit_drift_audit_records_catalog_drift_rows` tests) | Yes |
| CC3.3 Considers fraud | Tier-A token exchange + RFC 8693 actor claim preserves the original principal across the upstream hop; per-upstream identity JWT carries `act` claim and `original_issuer` | `crates/waygate-upstream/src/identity_client.rs`; identity JWT `IdentityClaims` in `crates/waygate-oidc/src/identity_jwt.rs` | Yes |
| CC3.4 Identifies & assesses changes | Per-tool approved behavior identity tracked in `mcp_tool_versions`; runtime drift detection covers name, description, input/output schemas, standard annotations, and action metadata, then fires `tracing::warn!` + `mcp_tool_drift_total{server}` and optional in-process quarantine via `GATEWAY_QUARANTINE_ON_DRIFT_RISK` (`crates/waygate-upstream/src/pool/`). `GATEWAY_CATALOG_STRICT_PENDING_APPROVAL=true` separately makes the dispatch path refuse a catalog `PendingApproval` result (`crates/waygate-upstream/src/pool/mod.rs` strict-pending gate) | `mcp_tool_drift_total{server}` from `/metrics`; quarantine reflected in tool-list response | Partial — drift detection and the strict-pending-approval flag are two unconnected mechanisms today: drift is in-process (warn + metric + risk-or-`side_effects` quarantine + a chained-best-effort `CatalogDrift` audit row), and `STRICT_PENDING_APPROVAL` only changes how an already-existing catalog `PendingApproval` row dispatches. There is no production caller of `CatalogStore::record_drift`, so observed drift does not yet open a re-approval gate in the durable catalog |

### CC4 — Monitoring Activities

| Criterion | Gateway control | Evidence | Status |
|-----------|-----------------|----------|--------|
| CC4.1 Selects, develops, performs monitoring | OTel spans on every `tools/call` that reaches the MCP handler (semconv `mcp.method.name`, `gen_ai.tool.name`, `otel.kind`, `error.type`; plus gateway-specific `mcp.server`, `upstream.outcome`); calls refused by the pre-parse routing-header gate are terminated before the handler exists and are evidenced instead by their `CallTool`/`Denied` audit row (trace-id stamped) and the `mcp_authz_decisions_total` sample the gate records; Prometheus counters `mcp_authz_decisions_total`, `mcp_authz_latency_seconds`, `mcp_upstream_calls_total`, `mcp_server_operation_duration_seconds` (semconv `mcp.server.operation.duration`), `mcp_identity_cell_wait_seconds`, `mcp_tool_drift_total`, `mcp_bearer_validations_total` | `/metrics` Prometheus endpoint; registrations in `crates/waygate-telemetry/src/metrics.rs`; Grafana dashboard described in `docs/agents/telemetry.md` | Yes |
| CC4.2 Communicates deficiencies | Operator-facing deny reasons (`data.reasons`) on the MCP wire; admin "Activity" view (`/admin/activity`) paginates `audit_log` rows filtered by outcome / risk / server / principal | Activity handlers in `crates/waygate-admin/src/dashboard_activity_page.rs` (activity routes + templates around lines 765–1007) | Partial — no built-in alerting bus for repeated-deny / rate-limit-storm patterns; operator wires their own Prometheus alert rules off `mcp_authz_decisions_total{decision="deny"}` |

### CC5 — Control Activities

| Criterion | Gateway control | Evidence | Status |
|-----------|-----------------|----------|--------|
| CC5.1 Selects & develops control activities | Cedar policy bundle is the canonical access-decision artifact; `forbid` overrides `permit` (deny-wins) | `crates/waygate-authz/tests/fixtures/policies/*.cedar`; gate logic in `crates/waygate-authz/src/cedar.rs` and `crates/waygate-authz/src/gate.rs` | Yes |
| CC5.2 Selects & develops technology controls | OAuth 2.1 resource server + optional built-in AS (CIMD); SCIM 2.0 user/group ingestion; RBAC; per-tenant rate limits | `crates/waygate-as/`, `crates/waygate-scim/`, `crates/waygate-rbac/`, `crates/waygate-quota/` | Yes |
| CC5.3 Deploys through policies | `GATEWAY_DEPLOYMENT_PROFILE=prod` refuses boot with known-unsafe defaults (`AUTH_MODE=disabled`, `ACCEPT_UPSTREAM_TOKENS=true`, missing audit DB, missing dashboard auth, stdio upstreams) | `Config::enforce_prod_safety` in `crates/waygate-server/src/config.rs` | Yes |

### CC6 — Logical & Physical Access

| Criterion | Gateway control | Evidence | Status |
|-----------|-----------------|----------|--------|
| CC6.1 Restricts logical access | Bearer middleware validates OAuth tokens (JWT via preloaded JWKS); Cedar enforces per-call authorization; per-tenant `tenant_id` substrate gates every catalog / policy / audit row | `crates/waygate-oidc/src/middleware.rs`; `Principal.tenant` populated at bearer-validate time; `audit_log.tenant_id` column | Yes |
| CC6.2 Registers / authorizes users | SCIM 2.0 `/scim/v2/Users` + `/Groups` ingestion (writes `audit_log` rows with `category='admin_mutation'`); role assignments via admin REST `/api/v1/admin/rbac/*`; API-key mint optionally references a profile (`profile_id`) that bounds scopes/TTL and (when the profile sets `requires_reason`/`requires_owner=true`) forces those fields at mint time | `crates/waygate-scim/`, `crates/waygate-admin/src/rbac.rs`, `crates/waygate-admin/src/api_keys.rs`; `api_keys.owner`, `api_keys.reason`, `api_keys.profile_id` columns (migration `0026_api_key_profiles.sql`); `api_key_profiles.requires_owner`/`requires_reason` flags | Partial — `profile_id` is optional (`MintForm::profile_id` and `mint_core` in `crates/waygate-admin/src/api_keys.rs`); the legacy mint path still allows blank `profile_id` (and therefore blank `owner`/`reason`). To make accountability mandatory, an operator must mint every key against a profile with `requires_owner=true` and `requires_reason=true`. Forcing profile use globally is on the open work list |
| CC6.3 Authorizes & manages access | `api_key_profiles` bound `allowed_servers` / `allowed_tools` at mint AND enforced at call-time (`DefaultInvocationService::check_profile_restrictions`); native MCP resources fail closed for profiles with a populated exact-tool allowlist; BEFORE-DELETE trigger refuses profile deletion while live keys reference it | `crates/waygate-mcp/src/invocation/mod.rs` (`check_profile_restrictions`); `crates/waygate-mcp/src/authz.rs` (`profile_blocks_resources`); migration `0027_api_key_profiles_block_delete_if_referenced.sql` | Yes |
| CC6.4 Restricts physical access | n/a (deployer's data center / cloud) | — | Out of scope |
| CC6.5 Protects against unauthorized access | Step-up promotion: MCP JSON-RPC `insufficient_scope` error → HTTP 403 with `WWW-Authenticate: Bearer error="insufficient_scope" scope=…`; `forbid` policy default for PII tools under API-key auth (`crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar`) | `crates/waygate-server/src/mcp_http_promote.rs::promote_mcp_errors`; `data.reasons` denial annotation | Yes |
| CC6.6 Implements logical access controls | Cedar entity model exposes (flat attrs, no nested records — Cedar can't formally type those without a schema): `principal.scim_present`, `principal.scim_active`, `principal.scim_groups`, `principal.scim_user_name`, `principal.scim_attrs`, `principal.roles`, `principal.scopes`, `principal.auth_method`, `principal.tenant`, `resource.server`, `resource.name`, `resource.uri`, `resource.risk`, `resource.pii`, `resource.side_effects` | `crates/waygate-authz/src/cedar.rs::build_entities` (each attr name appears in a `*_attrs.insert(...)` call); URI-specific resource authorization is pinned by `waygate-authz::gate::tests::resource_operations_use_their_dedicated_cedar_actions`; tool attributes are used by `crates/waygate-authz/tests/fixtures/policies/16-scim-active.cedar` (`!principal.scim_active`), `crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar` (`resource.pii`), etc. | Yes |
| CC6.7 Restricts movement of information | Per-upstream identity-chain (Tier A via RFC 8693 token exchange, Tier B via gateway-minted JWT with `act` claim, Tier C via per-upstream `tier_c_peer:` selector that mints a peer-audienced JWT on `Authorization: Bearer`) so upstream calls carry the original principal rather than a synthetic service account; per-upstream mTLS via `manifest.mtls.{cert_path, key_path, ca_path}`; output inspection at the dispatch boundary (opt-in built-in PiiInspector, SecretsInspector, and PoisoningInspector) | `docs/agents/identity.md`; `docs/agents/federation.md`; `crates/waygate-upstream/src/identity_client.rs`; `crates/waygate-manifest-types/src/lib.rs` (`UpstreamManifest::auth.bearer_env`, `mtls`, `tier_c_peer`); `crates/waygate-mcp/src/inspection.rs` | Yes |
| CC6.8 Prevents / detects unauthorized software | Per-tool behavior-contract change detection in `crates/waygate-upstream/src/pool/`; drift covers schemas and security metadata, fires `tracing::warn!` + `mcp_tool_drift_total{server}`, and auto-quarantines high-risk or side-effecting tools under `GATEWAY_QUARANTINE_ON_DRIFT_RISK=high\|medium\|all` | `mcp_tool_drift_total{server}` from `/metrics`; quarantine flag visible in tool-list response | Partial — drift emits a chained-best-effort `CatalogDrift` audit row (`outcome=Denied` on quarantine, `Success` informational) in addition to the warn + metric; `mcp_servers.signing_pubkey` column exists (migration `0011_catalog.sql`) but no verification code path is wired |

### CC7 — System Operations

| Criterion | Gateway control | Evidence | Status |
|-----------|-----------------|----------|--------|
| CC7.1 Detects security events | Per-call audit row with `outcome` (`success`/`denied`/`step_up_required`/`execution_error` per `AuditOutcome::as_str()` in `crates/waygate-evidence/src/audit.rs`); auth failures recorded as `category='auth_attempt'`; rate-limit denials returned as `data.error="rate_limited"` and audited | `SELECT * FROM audit_log WHERE category='auth_attempt' AND outcome IN ('denied','execution_error')`; quota path in `crates/waygate-quota/src/lib.rs` (token-bucket) | Yes |
| CC7.2 Monitors security events | OTel spans + Prometheus counters; admin "Activity" view paginates `audit_log` filtered by outcome / risk / server / principal | `/metrics`; activity handlers in `crates/waygate-admin/src/dashboard_activity_page.rs` | Yes |
| CC7.3 Evaluates security events | `record_required` rows and successfully inserted `record_chained_best_effort` rows carry a per-tenant hash chain (`prev_hash`, `row_hash`) that operators can verify via `crates/waygate-storage/src/chain_verify.rs`; the append-only trigger also covers unchained best-effort rows. Signed evidence bundles authenticate the exported bytes. | `crates/waygate-storage/src/audit.rs`; `crates/waygate-storage/src/chain_verify.rs`; bundle format and limitations in `crates/waygate-storage/src/bundle.rs`; admin endpoint in `crates/waygate-admin/src/audit_bundle.rs` | Partial — `record_best_effort` rows have null chain hashes, and bundle format version 1 contains neither chain-coverage metadata nor a database-completeness proof. A valid bundle signature proves only that its signed export bytes were not altered. |
| CC7.4 Responds to identified events | Tenant `status` field (`active`/`suspended`); `PgTenantEnricher` resolves at bearer-validate time and blocks suspended tenants via `Principal.enrichment_blocked` (60s cache, invalidated on PATCH so the next request sees the change) | `crates/waygate-tenants/src/enforce.rs`; admin `PATCH /api/v1/admin/tenants/{id}` in `crates/waygate-admin/src/tenants.rs` | Yes |
| CC7.5 Recovers from incidents | Graceful drain on SIGTERM bounded by `GATEWAY_DRAIN_TIMEOUT_SECONDS` (default 20s) so a rolling restart never strands in-flight requests beyond the orchestrator grace; SIGHUP reload of policies / manifests | Shutdown path in `crates/waygate-server/src/main.rs` (search for `drain_timeout`) | Yes |

### CC8 — Change Management

| Criterion | Gateway control | Evidence | Status |
|-----------|-----------------|----------|--------|
| CC8.1 Authorizes / develops / implements changes | Optional two-approver mode for direct catalog server promotion (`GATEWAY_REQUIRE_TWO_APPROVALS=true`); durable unquarantine requires a version-bound `catalog.server.unquarantine` change approved by a distinct operator; lifecycle transitions write `catalog_approvals` rows; policy bundles are versioned in `policy_bundles` with explicit `publish` / `rollback` API | `crates/waygate-admin/src/catalog.rs`; `crates/waygate-admin/src/change_executor/operations.rs`; `crates/waygate-admin/src/policy_bundles.rs`; `crates/waygate-admin/src/policies.rs` | Yes |

### CC9 — Risk Mitigation

| Criterion | Gateway control | Evidence | Status |
|-----------|-----------------|----------|--------|
| CC9.1 Identifies / selects / develops risk mitigation | Per-tenant retention policy (`evidence_retention_policy`) bounds audit-log lifetime per category; per-tenant rate-limit policy bounds blast radius | `crates/waygate-admin/src/audit_retention.rs`; `crates/waygate-quota/src/store.rs::RateLimitPolicyStore` | Yes |
| CC9.2 Vendor management | Per-upstream manifest declares ownership (`runtime_target`), risk tier, PII handling; `mcp_servers.signing_pubkey` schema column reserved for future per-vendor signing | `servers/*.yaml`; `mcp_servers.signing_pubkey` column (migration `0011_catalog.sql`) | Partial — signing-verify path not yet wired (see MEASURE 2.11); vendor SOC 2 reports / DPAs are organizational and out of scope |

---

## NIST AI Risk Management Framework (AI RMF 1.0)

The AI RMF organizes controls under four functions: **GOVERN**
(policies), **MAP** (context), **MEASURE** (analysis), **MANAGE**
(response). The gateway primarily contributes to **MEASURE** and
**MANAGE** for the tool-invocation surface — agents are AI systems,
tool calls are their externalized actions, and the gateway is the
observability + access-control choke point.

### GOVERN

| Subcategory | Gateway control | Evidence | Status |
|-------------|-----------------|----------|--------|
| GOVERN 1.1 (legal & regulatory documented) | `tenants` table records per-tenant retention windows + audit routing via `tenant_evidence_routing`; per-tenant retention policies via `evidence_retention_policy` | `crates/waygate-storage/src/routing.rs`; `crates/waygate-storage/src/retention.rs` | Partial — operator layers their own jurisdiction record-keeping; gateway provides the substrate |
| GOVERN 1.4 (risk management processes operationalized) | Per-tool risk classification + step-up for `risk=high` (`crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar`); HITL approval grants for tools flagged `requires_approval` | `crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar`; `approval_grants` table; sweep job tracked by `mcp_grant_sweep_total` | Yes |
| GOVERN 1.5 (oversight & accountability) | Per-action audit row with `principal_sub`, `policy_ids`, `reason` — operator can trace every denied or step-up call back to the human + the policy that fired | `SELECT principal_sub, policy_ids, reason, ts FROM audit_log WHERE action='CallTool' AND outcome IN ('denied','step_up_required') ORDER BY ts DESC` | Yes |
| GOVERN 2 (accountability structures) | Two-approver mode for catalog promotion (`GATEWAY_REQUIRE_TWO_APPROVALS=true`); `api_key_profiles.requires_reason` + `requires_owner` flags force those fields at mint time WHEN the operator mints against a profile with the flags set | `GATEWAY_REQUIRE_TWO_APPROVALS=true`; `api_keys.owner` / `api_keys.reason` / `api_keys.profile_id` columns (migration `0026_api_key_profiles.sql`); `api_key_profiles.requires_owner` / `requires_reason` columns | Partial — same legacy-mint gap as CC6.2: an operator using the legacy (no-profile) mint path can leave `owner`/`reason` blank; accountability for long-lived credentials is only enforced when every mint references a profile with the flags set |
| GOVERN 4 (workforce trained) | n/a (organizational) | — | Out of scope |
| GOVERN 5 (engaging with AI actors) | Tier-A identity chaining preserves the original IdP principal across hops; upstream MCP servers see the human `sub` + `act` (gateway) claim, not a synthetic service account | `crates/waygate-upstream/src/identity_client.rs`; identity JWT `act` claim in `crates/waygate-oidc/src/identity_jwt.rs::IdentityClaims` | Yes |
| GOVERN 6 (third-party AI components) | Per-upstream manifest declares `transport`, `risk` per tool, `pii` per tool; classification CLI bulk-tags new manifests | `crates/waygate-upstream/src/bin/classify.rs` | Yes |

### MAP

| Subcategory | Gateway control | Evidence | Status |
|-------------|-----------------|----------|--------|
| MAP 1 (context established) | Per-tenant `tenant_id` substrate threads through every catalog / policy / audit row; per-tool `risk`, `pii`, `side_effects` classifications on `tool_classifications` | `tenants` table; `mcp_tool_versions` + `tool_classifications` columns (migration `0011_catalog.sql`) | Yes |
| MAP 2.1 (AI system task understood) | OTel span on every `tools/call` captures semconv `mcp.method.name` / `gen_ai.tool.name` / `otel.kind` / `error.type` plus gateway-specific `mcp.server`, `upstream.outcome`, latency; `audit_log` row records `latency_ms` + `principal_sub` + `trace_id` (trace↔audit correlation) | Span attributes in `crates/waygate-mcp/src/server.rs` (inbound, kind=server) and `crates/waygate-upstream/src/pool/` (upstream leg, kind=client); `audit_log.latency_ms` / `audit_log.trace_id` columns | Yes |
| MAP 2.2 (risks / benefits documented) | Per-tool `description` + `risk` + `pii` flags in manifest; admin REST surfaces them via `/api/v1/catalog/*` | `servers/*.yaml`; `crates/waygate-admin/src/catalog.rs` (admin REST handlers + the manifest-importer test fixtures) | Yes |
| MAP 3 (categorization of AI systems) | Tools classified into `low`/`medium`/`high` risk + `pii=true/false` + `side_effects=true/false` | `tool_classifications` table | Yes |
| MAP 4 (AI system impact assessed) | Approval grants required for tools flagged `requires_approval=true`; admin REST `/api/v1/admin/approval_grants` lists already-issued grants (operator authors a grant in advance against a `(principal, tool, argument_hash)` tuple so the caller's matching invocation passes the gate); on a miss the invocation pipeline returns `ApprovalRequired` to the caller without persisting a pending-request row | `approval_grants` table; `crates/waygate-admin/src/approval_grants.rs` (REST handlers); `crates/waygate-mcp/src/invocation/mod.rs` (`check_approval`'s `ApprovalRequired` return) | Partial — no durable "pending request" queue today: a caller hits a `requires_approval` tool, gets an `ApprovalRequired` MCP error, and either (a) the operator independently authors a grant + caller retries, or (b) the call fails. Building a request-driven queue (caller-initiated → operator approves) is the open gap; the current grant surface only supports operator-initiated pre-authorization |
| MAP 5 (impacts to individuals characterized) | `resource.pii` Cedar attribute drives per-tool PII policy: API-key auth blocked by default for PII tools (`crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar`) | `crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar`; pinned by `crates/waygate-authz/tests/golden/01_api_key_blocked_from_pii_tool.json` | Yes |

### MEASURE

| Subcategory | Gateway control | Evidence | Status |
|-------------|-----------------|----------|--------|
| MEASURE 1 (identify & implement appropriate metrics) | Prometheus counters, histograms, and gauges measure authorization, upstream health, evidence delivery, and invocation behavior. | `/metrics`; [metric semantics and labels](agents/telemetry.md#prometheus-metrics) | Yes |
| MEASURE 2.1 (trustworthy AI characteristics evaluated) | Per-call audit row records outcome + reason; admin "Activity" view filters by deny / step-up | Activity handlers in `crates/waygate-admin/src/dashboard_activity_page.rs` (search `activity` for routes + templates) | Yes |
| MEASURE 2.7 (security & resilience) | Required writes and successfully inserted chained-best-effort writes are hash chained and can be checked by the chain walker; every row is protected from ordinary update/delete by the append-only trigger. Best-effort admission is bounded and exposes saturation, shutdown loss, pending work, and payload truncation. A signed bundle protects the bytes selected for export. | Bundle contract: `crates/waygate-storage/src/bundle.rs`; chain reader: `crates/waygate-storage/src/chain_verify.rs`; bounded submission contract: `crates/waygate-evidence/src/audit.rs`; write-path split: `crates/waygate-storage/src/audit.rs`; hash columns: migration `0015_audit_hashchain.sql` | Partial — unchained `record_best_effort` rows are outside the hash chain. Chained-best-effort events may be dropped when their bounded queue is full/closed, on tenant-lock contention, or on another known pre-commit failure or deadline. Only a commit error or commit deadline produces an unknown outcome because the worker cannot prove whether PostgreSQL committed. Bundle format version 1 does not attest chain coverage or prove that the exported slice represents every database row outside its query contract. |
| MEASURE 2.8 (validity & reliability of AI) | Per-tool behavior drift detection in `crates/waygate-upstream/src/pool/` covers schemas and security metadata, fires `tracing::warn!` + `mcp_tool_drift_total{server}`, and optionally auto-quarantines high-risk or side-effecting tools | `mcp_tool_drift_total{server}` from `/metrics`; quarantine surfaced via tool-list response | Partial — drift emits a chained-best-effort `CatalogDrift` audit row (`EvidenceCategory::CatalogDrift`) in addition to the log + metric; the durable catalog re-approval gate (`CatalogStore::record_drift`) still has no production caller — see CC3.4 |
| MEASURE 2.11 (third-party AI components valid) | `mcp_servers.signing_pubkey` schema column reserved for per-upstream Ed25519 public-key registration | Migration `migrations/0011_catalog.sql` defines the column | Partial — column-only today; no verification or quarantine code path is wired yet. Behavior drift detection across schemas and security metadata is the only third-party-validity signal in use. |
| MEASURE 3 (mechanisms for tracking risks) | OTel + Prometheus + per-call audit row; per-tenant audit routing (`tenant_evidence_routing`) sends rows to `webhook` / `ocsf` / `ecs` / `syslog` sinks via the outbox drain (registered in `crates/waygate-server/src/main.rs`) | routing in `crates/waygate-storage/src/routing.rs`; exporters at `crates/waygate-storage/src/{ocsf,ecs,syslog}.rs` + webhook wiring in `main.rs` | Yes — the configured sink must be one of these four supported types |
| MEASURE 4 (feedback from end-users / operators) | Cedar policies carry `@reason("…")` annotations surfaced in MCP `forbidden` envelope as `data.reasons` so a denied user sees *why* and the operator sees *which rule fired* | `data.reasons` in MCP error JSON; pinned by `crates/waygate-authz/tests/policy_golden.rs` with `reason_contains` assertions on the prod forbid policies | Yes |

### MANAGE

| Subcategory | Gateway control | Evidence | Status |
|-------------|-----------------|----------|--------|
| MANAGE 1.2 (treatment plans) | Per-tenant retention + audit routing let an incident-response team pull the affected tenant's evidence without disturbing other tenants | `evidence_retention_policy` + `tenant_evidence_routing` tables | Yes |
| MANAGE 2.3 (mechanisms for incident response) | Tenant `status='suspended'` cuts off all calls for a tenant on the next request (60s cache TTL, invalidated on PATCH); profile DELETE blocked by BEFORE-DELETE trigger when live keys reference it (migration 0027) so an operator can't accidentally widen blast radius mid-incident | `PATCH /api/v1/admin/tenants/{id}` in `crates/waygate-admin/src/tenants.rs`; migration `0027_api_key_profiles_block_delete_if_referenced.sql`; tenant enforcement in `crates/waygate-tenants/src/enforce.rs` | Yes |
| MANAGE 2.4 (continuous monitoring) | Prometheus metrics exported at `/metrics`; OTel spans on hot paths | `crates/waygate-telemetry/src/metrics.rs` | Partial — alert rules and notification webhooks are operator-supplied and belong in the private deployment overlay, not this repository. |
| MANAGE 3.2 (third-party risks treated) | Per-upstream rate-limit policies (`rate_limit_policies` scope=`server`) isolate a misbehaving upstream from starving others | `crates/waygate-quota/src/store.rs` + `crates/waygate-quota/src/lib.rs` (token-bucket); `rate_limit_policies` table (migration `0025_rate_limits.sql`) | Yes |
| MANAGE 4 (documented response to identified risks) | Admin dashboard records every mutation as a `category='admin_mutation'` audit row with the actor's `principal_sub`, `principal_email`, `tenant_id` | `SELECT principal_sub, principal_email, action, reason, ts FROM audit_log WHERE category='admin_mutation' ORDER BY ts DESC` | Yes |
