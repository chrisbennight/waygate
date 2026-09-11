//! The read-side twin of `change_executor`'s proposable-action registry.
//!
//! `change_executor` answers "what can I *mutate*, and what params does each
//! mutation take?" (served over MCP by `gateway-admin.describe_action` +
//! `propose_change`). This module answers the symmetric read question: "what
//! can I *list*, and what does each row look like?" — served over MCP by
//! `gateway-observe.describe_resource` + `read_resource`.
//!
//! It exists to close an asymmetry: nearly every `propose_change` action needs
//! an identifier (`policy_id`, `api_key_id`, peer `id`, …) the agent had no MCP
//! way to obtain. [`read`] lists the same resources those actions mutate, so an
//! agent can discover the id before proposing the change.
//!
//! ## Shape, mirroring `change_executor`
//!
//! - `descriptors()` is the single registry: one
//!   `ResourceDescriptor` per resource carries the catalog metadata (scope
//!   tier, tenancy, schemars-derived filter/row schemas) AND the type-erased
//!   list fn. [`resource_catalog`] and [`read`] are both projections of it,
//!   so the advertised set can't drift from what dispatch serves (previously
//!   an entries list and an 11-arm `match` agreed only by convention). It is
//!   the analogue of `change_executor`'s `ExecutorRegistry`.
//! - Each `list_*` fn dispatches to the **existing** store list method the
//!   REST handler already calls (no new SQL), maps the store DTO to a local
//!   schemars view (the [`crate::dashboard`]-free, rmcp-free row), and
//!   returns a page. Tenant scoping comes from the caller's principal, never
//!   from `filters` — exactly like the REST handlers.
//!
//! ## Access tiers
//!
//! Each entry carries a [`AccessTier`]: low-sensitivity resources read under
//! `mcp:observe`; sensitive ones under `mcp:admin`. The MCP layer
//! (`gateway-observe.read_resource`) enforces the tier per resource — the
//! namespace's `mcp:observe` gate is only the floor.
//!
//! These observe-tier resources are deliberately `mcp:observe`, even though
//! their REST *CRUD* endpoints are `mcp:admin`-gated: they are non-secret
//! config, and the existing observe plane already surfaces comparably- or
//! more-sensitive operator visibility at `mcp:observe` — `query_audit`
//! returns principals and deny reasons, `triage_digest` surfaces active
//! break-glass `issued_to` / `reason`, and `simulate_authorization` reveals
//! RBAC-derived authority. The read plane is the lighter visibility tier;
//! `mcp:admin` is reserved for the admin-tier sensitive rows (api keys,
//! sessions, OAuth consents, …) whose row views redact secrets.
//!
//! `api_key` is tenant-scoped via a dedicated `ApiKeyStore::list_for_tenant`
//! query (its general `list` is operator-global), and is additionally gated on
//! the `api_keys_enabled` feature flag — mirroring the dashboard / REST
//! surfaces, which hide API-key metadata when `GATEWAY_API_KEYS_ENABLED=false`.
//! The two operator-global resources (`upstream_session`, `confidential_client`)
//! are `tenant_scoped: false`: their stores list across tenants by design, and
//! their row views expose metadata / `has_*` booleans only.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_dashboard_stores::agent_config::MAX_LIST_LIMIT as AGENT_MAX_LIMIT;
use waygate_dashboard_stores::inspection_rules::{
    InspectorKind, RuleFilter, MAX_LIST_LIMIT as RULE_MAX_LIMIT,
};
use waygate_federation::{PeerFilter, TrustTier, MAX_LIST_LIMIT as PEER_MAX_LIMIT};
use waygate_oidc::Scope;

use crate::state::AdminState;
use waygate_core::fmt::format_ts_rfc3339;

/// Hard cap on a single page, matching `query_audit`'s 200-row cap. (The
/// default page size when `limit` is omitted is applied at the MCP boundary,
/// like the other observe tools.)
const MAX_LIMIT: u32 = 200;

/// Which scope a resource type reads under. The MCP `read_resource` tool
/// enforces this per resource; `describe_resource` advertises it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTier {
    /// Low-sensitivity config the read plane (`mcp:observe`) may list.
    Observe,
    /// Sensitive rows that require `mcp:admin` (api keys, sessions, …).
    Admin,
}

impl AccessTier {
    /// The scope string a caller must hold to read this tier.
    pub fn scope(self) -> &'static str {
        match self {
            AccessTier::Observe => Scope::McpObserve.as_str(),
            AccessTier::Admin => Scope::McpAdmin.as_str(),
        }
    }
}

/// One entry of the readable-resource catalog: a `resource_type`, the scope it
/// reads under, whether it is tenant-scoped, and the JSON Schemas of its
/// `filters` and its row. The analogue of
/// [`crate::change_executor::ActionCatalogEntry`].
#[derive(Clone, Debug, Serialize)]
pub struct ResourceCatalogEntry {
    /// Key to pass as `read_resource.resource_type` (e.g. `rate_limit_policy`).
    pub resource_type: &'static str,
    /// The scope required to read this resource (`mcp:observe` / `mcp:admin`).
    pub min_scope: &'static str,
    /// `false` for operator-global resources whose list crosses tenants
    /// (none among observe-tier resources; admin-tier's `upstream_session` /
    /// `confidential_client`).
    pub tenant_scoped: bool,
    /// JSON Schema of the `filters` object this resource accepts.
    pub filter_schema: Value,
    /// JSON Schema of one row this resource returns.
    pub row_schema: Value,
}

/// Failure modes of [`read`], mapped to MCP errors by the `read_resource` tool.
#[derive(Debug)]
pub enum ReadError {
    /// `resource_type` is not in the catalog. Carries the valid set so the
    /// caller can be taught (errors-teach, per the SOP).
    UnknownResource(Vec<&'static str>),
    /// The backing store is not configured (no DB) — same posture as the REST
    /// surface's 503.
    Unavailable(&'static str),
    /// The `filters` object didn't match the resource's filter schema.
    BadFilter(String),
    /// A store read failed; the underlying (column-naming) error is logged in
    /// [`read`], never returned.
    Store(String),
}

/// One page of [`read`] output: serialized rows plus the applied window.
#[derive(Debug)]
pub struct ReadPage {
    pub rows: Vec<Value>,
    pub limit: u32,
    pub offset: u32,
}

/// One page-listing implementation, type-erased for the registry. Takes
/// `(state, tenant, filters, clamped_limit, offset)`; returns the page (the
/// natively-paginated stores may return a smaller effective `limit`).
type ListFn = for<'a> fn(
    &'a AdminState,
    &'a str,
    &'a Map<String, Value>,
    u32,
    u32,
) -> Pin<Box<dyn Future<Output = Result<ReadPage, ReadError>> + Send + 'a>>;

/// One readable resource: the catalog metadata AND the list implementation in
/// a single record, so `describe_resource` and `read_resource` can never
/// disagree about what exists — the registry is the single source both derive
/// from (previously an entries list and an 11-arm `match` agreed only by
/// convention). The read-side analogue of `change_executor`'s
/// `ExecutorRegistry`.
struct ResourceDescriptor {
    resource_type: &'static str,
    tier: AccessTier,
    tenant_scoped: bool,
    filter_schema: fn() -> Value,
    row_schema: fn() -> Value,
    list: ListFn,
}

/// The descriptor registry, sorted by `resource_type`, built once on first
/// use — `api_router` touches it at construction, so in every real
/// composition the duplicate-key assert below fires at boot, not on the
/// first request. Adding a resource = adding one `descriptor::<Filter,
/// Row>(...)` line plus its `list_*` fn — the catalog entry and the dispatch
/// arm come with it.
fn descriptors() -> &'static [ResourceDescriptor] {
    static REG: OnceLock<Vec<ResourceDescriptor>> = OnceLock::new();
    REG.get_or_init(|| {
        let mut v = vec![
            descriptor::<EmptyFilter, AgentConfigRow>(
                "agent_config",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_agent_config(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, ApiKeyProfileRow>(
                "api_key_profile",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_api_key_profile(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, ServerRow>(
                "server",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_server(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, RateLimitPolicyRow>(
                "rate_limit_policy",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_rate_limit_policy(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, RbacRoleRow>(
                "rbac_role",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_rbac_role(s, t, f, l, o)),
            ),
            descriptor::<RbacAssignmentFilter, RbacAssignmentRow>(
                "rbac_assignment",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_rbac_assignment(s, t, f, l, o)),
            ),
            descriptor::<RbacGroupMappingFilter, RbacGroupMappingRow>(
                "rbac_group_mapping",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_rbac_group_mapping(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, GroupRow>(
                "group",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_group(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, ScopeRow>(
                "scope",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_scope(s, t, f, l, o)),
            ),
            descriptor::<InspectionRuleFilter, InspectionRuleRow>(
                "inspection_rule",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_inspection_rule(s, t, f, l, o)),
            ),
            descriptor::<PeerFilterArgs, PeerRow>(
                "peer",
                AccessTier::Observe,
                true,
                |s, t, f, l, o| Box::pin(list_peer(s, t, f, l, o)),
            ),
            // Admin-tier — sensitive resources under mcp:admin. The last two
            // are operator-global (their store lists cross tenants by
            // design), so `tenant_scoped: false`.
            descriptor::<EmptyFilter, ApiKeyRowView>(
                "api_key",
                AccessTier::Admin,
                true,
                |s, t, f, l, o| Box::pin(list_api_key(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, SkillReviewRow>(
                "skill_review",
                AccessTier::Admin,
                true,
                |s, t, f, l, o| Box::pin(list_skill_reviews(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, BreakGlassTokenRow>(
                "break_glass_token",
                AccessTier::Admin,
                true,
                |s, t, f, l, o| Box::pin(list_break_glass_token(s, t, f, l, o)),
            ),
            descriptor::<OAuthConsentFilter, OAuthConsentRow>(
                "oauth_consent",
                AccessTier::Admin,
                true,
                |s, t, f, l, o| Box::pin(list_oauth_consent(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, UpstreamSessionRow>(
                "upstream_session",
                AccessTier::Admin,
                false,
                |s, t, f, l, o| Box::pin(list_upstream_session(s, t, f, l, o)),
            ),
            descriptor::<EmptyFilter, ConfidentialClientRow>(
                "confidential_client",
                AccessTier::Admin,
                false,
                |s, t, f, l, o| Box::pin(list_confidential_client(s, t, f, l, o)),
            ),
        ];
        v.sort_by_key(|d| d.resource_type);
        // A duplicate key would make one descriptor unreachable through the
        // sorted lookup — refuse at registry init (boot, via api_router's
        // eager touch) rather than serve half a resource. The
        // registry_keys_are_sorted_and_unique test catches this in CI too.
        for w in v.windows(2) {
            assert_ne!(
                w[0].resource_type, w[1].resource_type,
                "duplicate resource_type in the catalog registry"
            );
        }
        v
    })
}

/// The readable-resource catalog, sorted by `resource_type` — a projection of
/// [`descriptors`], so it cannot drift from what [`read`] dispatches. The
/// schemas are schemars-derived from the same row/filter view structs.
pub fn resource_catalog() -> Vec<ResourceCatalogEntry> {
    descriptors()
        .iter()
        .map(|d| ResourceCatalogEntry {
            resource_type: d.resource_type,
            min_scope: d.tier.scope(),
            tenant_scoped: d.tenant_scoped,
            filter_schema: (d.filter_schema)(),
            row_schema: (d.row_schema)(),
        })
        .collect()
}

/// Every readable `resource_type`, sorted — the teach-list for an unknown key.
pub fn resource_types() -> Vec<&'static str> {
    descriptors().iter().map(|d| d.resource_type).collect()
}

fn descriptor<F: schemars::JsonSchema, R: schemars::JsonSchema>(
    resource_type: &'static str,
    tier: AccessTier,
    tenant_scoped: bool,
    list: ListFn,
) -> ResourceDescriptor {
    ResourceDescriptor {
        resource_type,
        tier,
        tenant_scoped,
        filter_schema: schema_of::<F>,
        row_schema: schema_of::<R>,
        list,
    }
}

/// JSON Schema of a view/filter type — mirrors
/// [`crate::change_executor`]'s `params_schema_of`.
fn schema_of<T: schemars::JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("schemars schema serializes to JSON")
}

/// The catalog-read analogue of [`Capability::require`]: the handle, or a
/// [`ReadError::Unavailable`] carrying the capability's canonical message —
/// the same string the REST 503 uses, so the two surfaces can't drift.
fn cap<T>(c: &crate::capability::Capability<T>) -> Result<&T, ReadError> {
    c.get().ok_or(ReadError::Unavailable(c.unavailable_msg()))
}

/// List one resource type, tenant-scoped to `tenant` — except the two
/// operator-global resources (`upstream_session`, `confidential_client`), whose
/// stores list across tenants by design. Reuses the same store method the REST
/// handler calls; maps the store DTO to a schemars row view.
///
/// `filters` keys are resource-specific (see each entry's `filter_schema`);
/// resources with no filters ignore the object. `limit` is clamped to
/// `[1, MAX_LIMIT]`. Natively-paginated stores get the window pushed down; the
/// rest are paged over the returned vec.
pub async fn read(
    state: &AdminState,
    resource_type: &str,
    tenant: &str,
    filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let limit = limit.clamp(1, MAX_LIMIT);
    let d = descriptors()
        .iter()
        .find(|d| d.resource_type == resource_type)
        .ok_or_else(|| ReadError::UnknownResource(resource_types()))?;
    (d.list)(state, tenant, filters, limit, offset).await
}

#[derive(Serialize, schemars::JsonSchema)]
struct SkillReviewRow {
    /// Exact root URI accepted by the skill decision actions.
    skill_uri: String,
    /// Current decision generation; changes require a fresh review.
    generation: i64,
    /// Candidate digest accepted by skill.approve, skill.reject and skill.quarantine.
    content_digest: String,
    /// Candidate review state, independent of the serving version.
    #[schemars(with = "String")]
    candidate_status: waygate_skills::review::CandidateStatus,
    /// True when distribution of every version is blocked.
    quarantined: bool,
    /// Last approved content identity, which quarantine may still block.
    serving_digest: Option<String>,
    /// Tenant-relative dashboard path for reviewing exact content before approval.
    review_path: String,
}

async fn list_skill_reviews(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    cap(&state.hitl.reviewed_skills)?;
    let all = crate::dashboard_skills::current_reviews(state, tenant)
        .await
        .map_err(|error| store_err("skill_reviews", error.detail()))?;
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|review| {
            to_value(SkillReviewRow {
                review_path: crate::dashboard_skills::review_url(&review.skill_uri),
                generation: review.generation,
                content_digest: review.candidate.content_digest().into(),
                candidate_status: review.candidate_status,
                quarantined: review.quarantined,
                serving_digest: review
                    .serving
                    .map(|candidate| candidate.content_digest().into()),
                skill_uri: review.skill_uri,
            })
        })
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_server(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.servers.catalog)?;
    let all = store
        .list_servers(tenant)
        .await
        .map_err(|e| store_err("catalog", e))?;
    // Join runtime only onto catalog rows already visible to this tenant. The
    // pool is gateway-wide; iterating it directly here would disclose server
    // names the tenant-scoped catalog did not authorize this caller to see.
    let runtime: BTreeMap<String, waygate_upstream::UpstreamHealth> = state
        .upstreams
        .health_snapshot()
        .await
        .into_iter()
        .map(|health| (health.name.clone(), health))
        .collect();
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|s| {
            let health = runtime.get(&s.name);
            to_value(server_row(s, health))
        })
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_rate_limit_policy(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.policy.rate_limit_policies)?;
    let all = store
        .list(tenant)
        .await
        .map_err(|e| store_err("rate_limit_policies", e))?;
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|p| to_value(RateLimitPolicyRow::from(p)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_rbac_role(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.identity.rbac)?;
    let all = store
        .list_roles(tenant)
        .await
        .map_err(|e| store_err("rbac_roles", e))?;
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|r| to_value(RbacRoleRow::from(r)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_rbac_assignment(
    state: &AdminState,
    tenant: &str,
    filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let f: RbacAssignmentFilter = parse_filters("rbac_assignment", filters)?;
    let role_id = parse_optional_uuid_filter("role_id", f.role_id.as_deref())?;
    let store = cap(&state.identity.rbac)?;
    let all = store
        .list_assignments(tenant, role_id, f.subject_sub.as_deref())
        .await
        .map_err(|e| store_err("rbac_assignments", e))?;
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|a| to_value(RbacAssignmentRow::from(a)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_rbac_group_mapping(
    state: &AdminState,
    tenant: &str,
    filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let f: RbacGroupMappingFilter = parse_filters("rbac_group_mapping", filters)?;
    let role_id = parse_optional_uuid_filter("role_id", f.role_id.as_deref())?;
    let group_id = parse_optional_uuid_filter("group_id", f.group_id.as_deref())?;
    let store = cap(&state.identity.rbac)?;
    let all = store
        .list_group_mappings(tenant, role_id, group_id)
        .await
        .map_err(|e| store_err("rbac_group_mappings", e))?;
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|mapping| to_value(RbacGroupMappingRow::from(mapping)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_group(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.identity.groups)?;
    let all = store
        .list_with_usage(tenant)
        .await
        .map_err(|e| store_err("groups", e))?;
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|group| to_value(GroupRow::from(group)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_scope(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.identity.scopes)?;
    let all = store
        .list_with_usage(tenant)
        .await
        .map_err(|e| store_err("scopes", e))?;
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|scope| to_value(ScopeRow::from(scope)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_agent_config(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.agent.agent_configs)?;
    let eff = limit.min(AGENT_MAX_LIMIT);
    let rows = store
        .list(tenant, eff, offset)
        .await
        .map_err(|e| store_err("agent_configs", e))?
        .into_iter()
        .map(|agent| to_value(AgentConfigRow::from(agent)))
        .collect();
    Ok(ReadPage {
        rows,
        limit: eff,
        offset,
    })
}

async fn list_api_key_profile(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.identity.api_key_profiles)?;
    let all = store
        .list(tenant)
        .await
        .map_err(|e| store_err("api_key_profiles", e))?;
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|profile| to_value(ApiKeyProfileRow::from(profile)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_inspection_rule(
    state: &AdminState,
    tenant: &str,
    filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let f: InspectionRuleFilter = parse_filters("inspection_rule", filters)?;
    let store = cap(&state.policy.inspection_rules)?;
    // This store paginates natively; clamp to ITS cap and push the
    // window down rather than slicing client-side.
    let eff = limit.min(RULE_MAX_LIMIT);
    let filter = RuleFilter {
        inspector: f.inspector.as_deref().and_then(InspectorKind::parse),
        name: f.name.as_deref(),
        enabled: f.enabled,
    };
    let rules = store
        .list(tenant, filter, eff, offset)
        .await
        .map_err(|e| store_err("inspection_rules", e))?;
    let rows = rules
        .into_iter()
        .map(|r| to_value(InspectionRuleRow::from(r)))
        .collect();
    Ok(ReadPage {
        rows,
        limit: eff,
        offset,
    })
}

async fn list_peer(
    state: &AdminState,
    tenant: &str,
    filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let f: PeerFilterArgs = parse_filters("peer", filters)?;
    let store = cap(&state.federation.federated_peers)?;
    let eff = limit.min(PEER_MAX_LIMIT);
    let filter = PeerFilter {
        peer_name: f.peer_name.as_deref(),
        issuer: f.issuer.as_deref(),
        trust_tier: f.trust_tier.as_deref().and_then(TrustTier::parse),
    };
    let peers = store
        .list(tenant, filter, eff, offset)
        .await
        .map_err(|e| store_err("federated_peers", e))?;
    let rows = peers
        .into_iter()
        .map(|p| to_value(PeerRow::from(p)))
        .collect();
    Ok(ReadPage {
        rows,
        limit: eff,
        offset,
    })
}

async fn list_api_key(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    // The api-key admin surface is hidden when the feature is disabled
    // (the store can still be present for tenant-DELETE cleanup), so the
    // MCP read mirrors that gate — same posture as the dashboard/REST
    // (`api_keys_feature`).
    if !state.identity.api_keys_feature.enabled() {
        return Err(ReadError::Unavailable(
            state.identity.api_keys_feature.unavailable_msg(),
        ));
    }
    let store = cap(&state.identity.api_keys)?;
    // Tenant-scoped + paged in SQL: the store's global `list` would cap
    // the pre-filter scan and hide a tenant's rows beyond it at scale,
    // so use the tenant-scoped query instead.
    let rows = store
        .list_for_tenant(tenant, i64::from(limit), i64::from(offset))
        .await
        .map_err(|e| store_err("api_keys", e))?
        .into_iter()
        .map(|r| to_value(ApiKeyRowView::from(r)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_break_glass_token(
    state: &AdminState,
    tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.policy.break_glass)?;
    let rows = store
        .list(tenant, None, limit, offset)
        .await
        .map_err(|e| store_err("break_glass", e))?
        .into_iter()
        .map(|t| to_value(BreakGlassTokenRow::from(t)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_oauth_consent(
    state: &AdminState,
    tenant: &str,
    filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let f: OAuthConsentFilter = parse_filters("oauth_consent", filters)?;
    let store = cap(&state.identity.consent)?;
    let rows = store
        .list(tenant, f.principal_sub.as_deref(), limit, offset)
        .await
        .map_err(|e| store_err("oauth_consent", e))?
        .into_iter()
        .map(|g| to_value(OAuthConsentRow::from(g)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_upstream_session(
    state: &AdminState,
    _tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.identity.upstream_sessions)?;
    // Operator-global by design (tenant is intentionally NOT applied) —
    // the catalog entry is `tenant_scoped: false`. Metadata only; the
    // encrypted access/refresh tokens are never in `SessionMetadata`.
    let rows = store
        .list_all(limit, offset)
        .await
        .map_err(|e| store_err("upstream_sessions", e))?
        .into_iter()
        .map(|s| to_value(UpstreamSessionRow::from(s)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

async fn list_confidential_client(
    state: &AdminState,
    _tenant: &str,
    _filters: &Map<String, Value>,
    limit: u32,
    offset: u32,
) -> Result<ReadPage, ReadError> {
    let store = cap(&state.identity.confidential_clients)?;
    // Operator-global, no pagination at the store — page client-side.
    // Redacted to has_secret/has_jwks booleans (never the hash or JWKS).
    let all = store
        .list()
        .await
        .map_err(|e| store_err("confidential_clients", e))?;
    let rows = page(all, offset, limit)
        .into_iter()
        .map(|c| to_value(ConfidentialClientRow::from(c)))
        .collect();
    Ok(ReadPage {
        rows,
        limit,
        offset,
    })
}

/// Deserialize the `filters` object into a typed per-resource filter, rejecting
/// unknown keys (the filter structs are `deny_unknown_fields`) so a typo is a
/// teach-able error rather than a silently-ignored filter. An empty object
/// yields all-`None` (every field is `Option`).
fn parse_filters<T: serde::de::DeserializeOwned>(
    resource_type: &str,
    filters: &Map<String, Value>,
) -> Result<T, ReadError> {
    serde_json::from_value(Value::Object(filters.clone()))
        .map_err(|e| ReadError::BadFilter(format!("invalid filters for `{resource_type}`: {e}")))
}

fn parse_optional_uuid_filter(field: &str, value: Option<&str>) -> Result<Option<Uuid>, ReadError> {
    value
        .map(|raw| {
            Uuid::parse_str(raw.trim())
                .map_err(|_| ReadError::BadFilter(format!("`{field}` is not a valid uuid: {raw}")))
        })
        .transpose()
}

/// Apply a `[offset, offset+limit)` window to an already-fetched vec (for the
/// stores that don't paginate natively).
fn page<T>(items: Vec<T>, offset: u32, limit: u32) -> Vec<T> {
    items
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect()
}

/// Log a store read failure (the raw error can name columns/SQL) and return a
/// generic message. Generic over `Display` so this module needn't name the
/// per-store error types.
fn store_err<E: std::fmt::Display>(what: &str, e: E) -> ReadError {
    tracing::warn!(error = %e, "resource_catalog {what} list failed");
    ReadError::Store(format!("{what} list failed"))
}

/// Serialize a row view to JSON. Infallible for these plain structs (same
/// assumption `structured()` makes on the MCP side).
fn to_value<T: Serialize>(v: T) -> Value {
    serde_json::to_value(v).expect("resource row serializes to JSON")
}

/// Serialize an enum (snake_case via serde) to its wire string — uniform for
/// every store enum so the views needn't depend on per-enum `as_str()`.
fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// RFC 3339 string for an optional timestamp column.
fn ts_opt(t: Option<OffsetDateTime>) -> Option<String> {
    t.map(format_ts_rfc3339)
}

/// Strip any `user:pass@` userinfo from a URL before returning it on the read
/// surface. Belt-and-suspenders: the federated-peers write path already rejects
/// userinfo (`federated_peers::reject_url_userinfo`), but a row written before
/// that guard (or by direct SQL) could still carry credentials — and this read
/// tool surfaces peers at the lighter `mcp:observe` tier. Mirrors
/// `federated_peers::sanitize_url_for_audit`.
///
/// Only rewrites when userinfo is actually present; a clean URL (or a value the
/// `url` crate can't parse — which the validated write path never stores) is
/// returned byte-for-byte, preserving the byte-exact issuer the OIDC `iss`
/// match depends on.
fn sanitize_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) if !u.username().is_empty() || u.password().is_some() => {
            let _ = u.set_password(None);
            let _ = u.set_username("");
            u.to_string()
        }
        _ => raw.to_owned(),
    }
}

// --- Filter views (schemars-derived `filter_schema`) -------------------------

/// A resource that takes no filters. Used only for its schema (never parsed).
#[derive(schemars::JsonSchema)]
struct EmptyFilter {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RbacAssignmentFilter {
    /// Only assignments of this role (UUID).
    role_id: Option<String>,
    /// Only assignments for this exact subject `sub`.
    subject_sub: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RbacGroupMappingFilter {
    /// Only mappings that grant this role (UUID).
    role_id: Option<String>,
    /// Only mappings sourced from this group (UUID).
    group_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct InspectionRuleFilter {
    /// Inspector kind: `pii` | `secrets` | `poisoning` | `custom`. Unknown
    /// values are ignored (no filter).
    inspector: Option<String>,
    /// Exact rule name (within tenant + inspector).
    name: Option<String>,
    /// `true` ⇒ only enabled rules, `false` ⇒ only disabled. Unset ⇒ both.
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PeerFilterArgs {
    /// Exact peer name (within tenant).
    peer_name: Option<String>,
    /// Exact peer issuer URL.
    issuer: Option<String>,
    /// Trust tier: `full` | `restricted`. Unknown values are ignored.
    trust_tier: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct OAuthConsentFilter {
    /// Only consents for this exact subject `sub`.
    principal_sub: Option<String>,
}

// --- Row views (schemars-derived `row_schema`) -------------------------------
//
// Local views rather than the store DTOs so schemars stays inside this crate
// (the store DTOs live in crates that don't depend on it), and so enum columns
// surface as plain strings. The `AuditRowView` precedent in `mcp_observe`.

#[derive(Serialize, schemars::JsonSchema)]
struct AgentConfigRow {
    /// Pass as `agent_id` to `agent_config.update` / `agent_config.delete`.
    id: String,
    tenant_id: String,
    name: String,
    /// `chat` | `policy_review` | `classification`.
    kind: String,
    model_alias: String,
    instructions: Option<String>,
    /// Complete tool allowlist. Empty means the agent can call no tools.
    allowed_tools: Vec<String>,
    max_steps: i32,
    max_tool_calls: i32,
    token_budget: Option<i32>,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

impl From<waygate_dashboard_stores::agent_config::AgentConfig> for AgentConfigRow {
    fn from(agent: waygate_dashboard_stores::agent_config::AgentConfig) -> Self {
        Self {
            id: agent.id.to_string(),
            tenant_id: agent.tenant_id,
            name: agent.name,
            kind: enum_str(&agent.kind),
            model_alias: agent.model_alias,
            instructions: agent.instructions,
            allowed_tools: agent.allowed_tools,
            max_steps: agent.max_steps,
            max_tool_calls: agent.max_tool_calls,
            token_budget: agent.token_budget,
            enabled: agent.enabled,
            created_at: format_ts_rfc3339(agent.created_at),
            updated_at: format_ts_rfc3339(agent.updated_at),
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct ApiKeyProfileRow {
    /// Pass as `profile_id` to `api_key_profile.delete` or `api_key.mint`.
    id: String,
    tenant_id: String,
    name: String,
    description: Option<String>,
    max_ttl_seconds: i32,
    allowed_scopes: Vec<String>,
    /// `null` or an empty list means any server.
    allowed_servers: Option<Vec<String>>,
    /// `null` or an empty list means any tool within the server ceiling.
    allowed_tools: Option<Vec<String>>,
    requires_reason: bool,
    requires_owner: bool,
    created_at: String,
    updated_at: String,
}

impl From<waygate_apikeys::Profile> for ApiKeyProfileRow {
    fn from(profile: waygate_apikeys::Profile) -> Self {
        Self {
            id: profile.id.to_string(),
            tenant_id: profile.tenant_id,
            name: profile.name,
            description: profile.description,
            max_ttl_seconds: profile.max_ttl_seconds,
            allowed_scopes: profile.allowed_scopes,
            allowed_servers: profile.allowed_servers,
            allowed_tools: profile.allowed_tools,
            requires_reason: profile.requires_reason,
            requires_owner: profile.requires_owner,
            created_at: format_ts_rfc3339(profile.created_at),
            updated_at: format_ts_rfc3339(profile.updated_at),
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct ServerRow {
    id: String,
    tenant_id: String,
    name: String,
    transport: String,
    /// Compatibility alias for `catalog_status`. This is durable catalog
    /// lifecycle, not runtime availability.
    status: String,
    /// Durable catalog lifecycle, e.g. `live` | `quarantined` | `approved` |
    /// `proposed`.
    catalog_status: String,
    /// Current pool availability: `connected` | `degraded` | `disconnected`.
    /// Null when this catalog row has no loaded runtime manifest on this
    /// replica; that absence is distinct from a known disconnected runtime.
    runtime_status: Option<String>,
    /// RFC 3339 last successful runtime probe; null with no runtime entry.
    last_success_at: Option<String>,
    /// Bounded/redacted runtime failure classification.
    last_error_class: Option<String>,
    /// RFC 3339 next scheduled runtime reprobe.
    next_retry_at: Option<String>,
    /// Number of transport lanes currently connected; null with no runtime entry.
    connected_lanes: Option<usize>,
    /// Number of transport lanes configured for this runtime; null with no runtime entry.
    configured_lanes: Option<usize>,
    /// `closed` | `open` | `half_open`; null with no runtime entry.
    breaker: Option<String>,
    /// Tools currently published by the loaded runtime; null with no runtime entry.
    published_tool_count: Option<usize>,
    /// Runtime tools withheld because drift policy quarantined them; null with
    /// no runtime entry.
    drift_quarantined_tool_count: Option<usize>,
    /// `global` | `tenant_only`.
    visibility: String,
    owner: Option<String>,
}

fn server_row(
    s: waygate_catalog::CatalogServerSummary,
    runtime: Option<&waygate_upstream::UpstreamHealth>,
) -> ServerRow {
    let catalog_status = enum_str(&s.status);
    ServerRow {
        id: s.id.to_string(),
        tenant_id: s.tenant_id,
        name: s.name,
        transport: s.transport,
        status: catalog_status.clone(),
        catalog_status,
        runtime_status: runtime.map(|h| h.runtime_state.as_str().to_owned()),
        last_success_at: runtime.and_then(|h| h.last_success_at.map(format_ts_rfc3339)),
        last_error_class: runtime
            .and_then(|h| h.last_error_class.map(|class| class.as_str().to_owned())),
        next_retry_at: runtime.and_then(|h| h.next_retry_at.map(format_ts_rfc3339)),
        connected_lanes: runtime.map(|h| h.connected_lanes),
        configured_lanes: runtime.map(|h| h.total_lanes),
        breaker: runtime.map(|h| h.breaker.as_str().to_owned()),
        published_tool_count: runtime.map(|h| h.published_tool_count),
        drift_quarantined_tool_count: runtime.map(|h| h.quarantined_tool_count),
        visibility: enum_str(&s.visibility),
        owner: s.owner,
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct RateLimitPolicyRow {
    /// Pass as `policy_id` to `rate_limit.update` / `rate_limit.delete`.
    id: String,
    tenant_id: String,
    name: String,
    /// `tenant` | `principal` | `client` | `server` | `tool`.
    scope: String,
    scope_value: Option<String>,
    bucket_capacity: i32,
    refill_per_second: f64,
    /// `call` | `high_risk_call` | `cost_bearing` | `discovery`.
    action: String,
    created_at: String,
    updated_at: String,
}

impl From<waygate_quota::RateLimitPolicy> for RateLimitPolicyRow {
    fn from(p: waygate_quota::RateLimitPolicy) -> Self {
        Self {
            id: p.id.to_string(),
            tenant_id: p.tenant_id,
            name: p.name,
            scope: enum_str(&p.scope),
            scope_value: p.scope_value,
            bucket_capacity: p.bucket_capacity,
            refill_per_second: p.refill_per_second,
            action: enum_str(&p.action),
            created_at: format_ts_rfc3339(p.created_at),
            updated_at: format_ts_rfc3339(p.updated_at),
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct RbacRoleRow {
    /// Pass as `id` to `rbac.role.update` / `rbac.role.delete`.
    id: String,
    tenant_id: String,
    name: String,
    description: Option<String>,
    scopes: Vec<String>,
    created_at: String,
    updated_at: String,
}

impl From<waygate_rbac::Role> for RbacRoleRow {
    fn from(r: waygate_rbac::Role) -> Self {
        Self {
            id: r.id.to_string(),
            tenant_id: r.tenant_id,
            name: r.name,
            description: r.description,
            scopes: r.scopes,
            created_at: format_ts_rfc3339(r.created_at),
            updated_at: format_ts_rfc3339(r.updated_at),
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct RbacAssignmentRow {
    /// Pass as `id` to `rbac.assignment.revoke` or
    /// `rbac.assignment.revoke_privileged`, according to the role's scopes.
    id: String,
    tenant_id: String,
    role_id: String,
    subject_sub: String,
    created_at: String,
}

#[derive(Serialize, schemars::JsonSchema)]
struct RbacGroupMappingRow {
    tenant_id: String,
    /// Pass with `role_id` to `rbac.group_mapping.revoke` or
    /// `rbac.group_mapping.revoke_privileged`.
    group_id: String,
    role_id: String,
    created_at: String,
}

impl From<waygate_rbac::GroupRoleMapping> for RbacGroupMappingRow {
    fn from(mapping: waygate_rbac::GroupRoleMapping) -> Self {
        Self {
            tenant_id: mapping.tenant_id,
            group_id: mapping.group_id.to_string(),
            role_id: mapping.role_id.to_string(),
            created_at: format_ts_rfc3339(mapping.created_at),
        }
    }
}

impl From<waygate_rbac::RoleAssignment> for RbacAssignmentRow {
    fn from(a: waygate_rbac::RoleAssignment) -> Self {
        Self {
            id: a.id.to_string(),
            tenant_id: a.tenant_id,
            role_id: a.role_id.to_string(),
            subject_sub: a.subject_sub,
            created_at: format_ts_rfc3339(a.created_at),
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct GroupRow {
    /// Pass as a group reference to actions that manage group membership or
    /// group-to-role mappings.
    id: String,
    tenant_id: String,
    display_name: String,
    /// `scim` for IdP-provisioned groups or `local` for operator-defined
    /// groups.
    source: String,
    external_id: Option<String>,
    created_at: String,
    /// Mutable row version captured when `group.delete_local` is proposed and
    /// rechecked after approval.
    updated_at: String,
    /// Active SCIM-user memberships that block local-group deletion.
    user_member_count: i64,
    /// Live API-key labels that block local-group deletion.
    key_member_count: i64,
    /// RBAC group-to-role mappings that block local-group deletion.
    role_mapping_count: i64,
}

impl From<waygate_apikeys::GroupView> for GroupRow {
    fn from(group: waygate_apikeys::GroupView) -> Self {
        Self {
            id: group.id.to_string(),
            tenant_id: group.tenant_id,
            display_name: group.display_name,
            source: group.source,
            external_id: group.external_id,
            created_at: format_ts_rfc3339(group.created_at),
            updated_at: format_ts_rfc3339(group.updated_at),
            user_member_count: group.user_member_count,
            key_member_count: group.key_member_count,
            role_mapping_count: group.role_mapping_count,
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct ScopeRow {
    /// Catalog row identifier.
    id: String,
    /// `null` identifies a global built-in or policy-discovered scope;
    /// otherwise this is the tenant that owns the local scope.
    tenant_id: Option<String>,
    name: String,
    /// `builtin` | `policy` | `local`.
    source: String,
    description: Option<String>,
    created_at: String,
    updated_at: String,
    key_refs: i64,
    role_refs: i64,
}

impl From<waygate_apikeys::ScopeView> for ScopeRow {
    fn from(scope: waygate_apikeys::ScopeView) -> Self {
        Self {
            id: scope.id.to_string(),
            tenant_id: scope.tenant_id,
            name: scope.name,
            source: scope.source,
            description: scope.description,
            created_at: format_ts_rfc3339(scope.created_at),
            updated_at: format_ts_rfc3339(scope.updated_at),
            key_refs: scope.key_refs,
            role_refs: scope.role_refs,
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct InspectionRuleRow {
    /// Pass as `id` to `inspection_rule.update` / `inspection_rule.delete`.
    id: String,
    tenant_id: String,
    /// `pii` | `secrets` | `poisoning` | `custom`.
    inspector: String,
    name: String,
    config: Value,
    applies_to: Value,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

impl From<waygate_dashboard_stores::inspection_rules::InspectionRule> for InspectionRuleRow {
    fn from(r: waygate_dashboard_stores::inspection_rules::InspectionRule) -> Self {
        Self {
            id: r.id.to_string(),
            tenant_id: r.tenant_id,
            inspector: enum_str(&r.inspector),
            name: r.name,
            config: r.config,
            applies_to: r.applies_to,
            enabled: r.enabled,
            created_at: format_ts_rfc3339(r.created_at),
            updated_at: format_ts_rfc3339(r.updated_at),
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct PeerRow {
    /// Pass as `id` to `peer.update` / `peer.delete`.
    id: String,
    tenant_id: String,
    peer_name: String,
    issuer: String,
    jwks_url: String,
    /// `full` | `restricted`.
    trust_tier: String,
    created_at: String,
    updated_at: String,
}

impl From<waygate_federation::FederatedPeer> for PeerRow {
    fn from(p: waygate_federation::FederatedPeer) -> Self {
        Self {
            id: p.id.to_string(),
            tenant_id: p.tenant_id,
            peer_name: p.peer_name,
            issuer: sanitize_url(&p.issuer),
            jwks_url: sanitize_url(&p.jwks_url),
            trust_tier: enum_str(&p.trust_tier),
            created_at: format_ts_rfc3339(p.created_at),
            updated_at: format_ts_rfc3339(p.updated_at),
        }
    }
}

// --- Admin-tier sensitive row views (mcp:admin) ------------------------------

/// Redacted api-key row: it **never** carries `key_hash` (or any secret) — only
/// the `key_prefix` (first chars, the same the dashboard shows). The hard
/// redaction invariant for this surface; pinned by
/// `sensitive_row_views_redact_secrets`.
#[derive(Serialize, schemars::JsonSchema)]
struct ApiKeyRowView {
    /// Pass as `api_key_id` to `api_key.revoke` / `api_key.update_grants`.
    id: String,
    tenant_id: String,
    /// First chars of the token only — NOT the hash.
    key_prefix: String,
    name: String,
    sub: String,
    email: Option<String>,
    groups: Vec<String>,
    scopes: Vec<String>,
    created_by: String,
    created_at: String,
    last_used_at: Option<String>,
    expires_at: Option<String>,
    revoked_at: Option<String>,
    owner: Option<String>,
    reason: Option<String>,
}

impl From<waygate_apikeys::ApiKeyRow> for ApiKeyRowView {
    fn from(r: waygate_apikeys::ApiKeyRow) -> Self {
        // key_hash (the argon2id secret) MUST never reach the wire; profile_id
        // and rotation_due_at are dropped as low-value for this surface.
        Self {
            id: r.id.to_string(),
            tenant_id: r.tenant_id,
            key_prefix: r.key_prefix,
            name: r.name,
            sub: r.sub,
            email: r.email,
            groups: r.groups,
            scopes: r.scopes,
            created_by: r.created_by,
            created_at: format_ts_rfc3339(r.created_at),
            last_used_at: ts_opt(r.last_used_at),
            expires_at: ts_opt(r.expires_at),
            revoked_at: ts_opt(r.revoked_at),
            owner: r.owner,
            reason: r.reason,
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct BreakGlassTokenRow {
    /// Pass as `token_id` to `break_glass.revoke`.
    id: String,
    tenant_id: String,
    issued_to: String,
    issued_by: String,
    reason: String,
    scope_pattern: String,
    requires_amr: Vec<String>,
    expires_at: String,
    used_at: Option<String>,
    created_at: String,
}

impl From<waygate_authz::BreakGlassToken> for BreakGlassTokenRow {
    fn from(t: waygate_authz::BreakGlassToken) -> Self {
        Self {
            id: t.id.to_string(),
            tenant_id: t.tenant_id,
            issued_to: t.issued_to,
            issued_by: t.issued_by,
            reason: t.reason,
            scope_pattern: t.scope_pattern,
            requires_amr: t.requires_amr,
            expires_at: format_ts_rfc3339(t.expires_at),
            used_at: ts_opt(t.used_at),
            created_at: format_ts_rfc3339(t.created_at),
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct OAuthConsentRow {
    id: String,
    tenant_id: String,
    /// `(principal_sub, client_id)` are the args to `oauth_consent.revoke`.
    principal_sub: String,
    client_id: String,
    scopes: Vec<String>,
    granted_at: String,
    expires_at: Option<String>,
    revoked_at: Option<String>,
}

impl From<waygate_as::consent::ConsentGrant> for OAuthConsentRow {
    fn from(g: waygate_as::consent::ConsentGrant) -> Self {
        Self {
            id: g.id.to_string(),
            tenant_id: g.tenant_id,
            principal_sub: g.principal_sub,
            client_id: g.client_id,
            scopes: g.scopes,
            granted_at: format_ts_rfc3339(g.granted_at),
            expires_at: ts_opt(g.expires_at),
            revoked_at: ts_opt(g.revoked_at),
        }
    }
}

/// Global (cross-tenant) Tier-A session metadata — no tokens, only the
/// `(sub, upstream_issuer)` key plus rotation/expiry timestamps.
#[derive(Serialize, schemars::JsonSchema)]
struct UpstreamSessionRow {
    /// `(sub, upstream_issuer)` are the args to `upstream_session.revoke`.
    sub: String,
    upstream_issuer: String,
    key_id: String,
    access_expires_at: String,
    refreshed_at: String,
    created_at: String,
}

impl From<waygate_as::sessions::SessionMetadata> for UpstreamSessionRow {
    fn from(s: waygate_as::sessions::SessionMetadata) -> Self {
        Self {
            sub: s.sub,
            upstream_issuer: s.upstream_issuer,
            key_id: s.key_id,
            access_expires_at: format_ts_rfc3339(s.access_expires_at),
            refreshed_at: format_ts_rfc3339(s.refreshed_at),
            created_at: format_ts_rfc3339(s.created_at),
        }
    }
}

/// Redacted confidential-client row: the secret hash and private JWKS reduce to
/// `has_*` booleans and are NEVER serialized. Mirrors the REST `ClientSummary`.
#[derive(Serialize, schemars::JsonSchema)]
struct ConfidentialClientRow {
    client_id: String,
    has_secret: bool,
    has_jwks: bool,
    created_at: String,
}

impl From<waygate_as::clients::ConfidentialClient> for ConfidentialClientRow {
    fn from(c: waygate_as::clients::ConfidentialClient) -> Self {
        Self {
            client_id: c.client_id,
            has_secret: c.secret_hash.is_some(),
            has_jwks: c.jwks.is_some(),
            created_at: format_ts_rfc3339(c.created_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use waygate_dashboard_stores::agent_config::{
        AgentConfigFields, AgentConfigStore, AgentKind, InMemoryAgentConfigStore,
    };

    #[test]
    fn registry_keys_are_sorted_and_unique() {
        // The registry is the single source for both the catalog and read()
        // dispatch; a duplicate key would shadow a descriptor and a
        // non-sorted list would break the documented catalog ordering.
        let types = resource_types();
        let mut sorted = types.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(types, sorted, "descriptor keys must be sorted and unique");
    }

    #[test]
    fn catalog_has_expected_resources() {
        let cat = resource_catalog();
        let types: Vec<&str> = cat.iter().map(|e| e.resource_type).collect();
        assert_eq!(
            types,
            vec![
                "agent_config",
                "api_key",
                "api_key_profile",
                "break_glass_token",
                "confidential_client",
                "group",
                "inspection_rule",
                "oauth_consent",
                "peer",
                "rate_limit_policy",
                "rbac_assignment",
                "rbac_group_mapping",
                "rbac_role",
                "scope",
                "server",
                "skill_review",
                "upstream_session",
            ],
            "catalog must be sorted and list exactly the observe-tier + admin-tier resources",
        );
        // Admin-tier sensitive resources read under mcp:admin; the rest
        // under mcp:observe. The two operator-global resources cross
        // tenants by design; everything else is tenant-scoped.
        let admin = [
            "api_key",
            "break_glass_token",
            "confidential_client",
            "oauth_consent",
            "skill_review",
            "upstream_session",
        ];
        let global = ["upstream_session", "confidential_client"];
        for e in &cat {
            let expected_scope = if admin.contains(&e.resource_type) {
                Scope::McpAdmin.as_str()
            } else {
                Scope::McpObserve.as_str()
            };
            assert_eq!(e.min_scope, expected_scope, "{} tier", e.resource_type);
            assert_eq!(
                e.tenant_scoped,
                !global.contains(&e.resource_type),
                "{} tenant scoping",
                e.resource_type,
            );
            assert!(
                e.filter_schema.is_object() && e.row_schema.is_object(),
                "{} schemas must be JSON Schema objects",
                e.resource_type,
            );
        }
    }

    #[test]
    fn row_schemas_are_valid_json_schema() {
        // Every advertised row schema must itself compile as a JSON Schema, so
        // a client can validate `read_resource` rows against it.
        for e in resource_catalog() {
            assert!(
                jsonschema::validator_for(&e.row_schema).is_ok(),
                "{} row_schema is not a valid JSON Schema",
                e.resource_type,
            );
            assert!(
                jsonschema::validator_for(&e.filter_schema).is_ok(),
                "{} filter_schema is not a valid JSON Schema",
                e.resource_type,
            );
        }
    }

    #[test]
    fn group_row_exposes_guarded_delete_inputs() {
        let updated_at = OffsetDateTime::UNIX_EPOCH;
        let row = GroupRow::from(waygate_apikeys::GroupView {
            id: uuid::Uuid::nil(),
            tenant_id: "default".into(),
            display_name: "incident-responders".into(),
            source: "local".into(),
            external_id: None,
            created_at: updated_at,
            updated_at,
            user_member_count: 0,
            key_member_count: 0,
            role_mapping_count: 3,
        });
        let value = serde_json::to_value(row).expect("serialize observable group row");

        assert_eq!(value["updated_at"], format_ts_rfc3339(updated_at));
        assert_eq!(value["role_mapping_count"], 3);
    }

    #[test]
    fn server_row_separates_catalog_lifecycle_from_runtime_health() {
        let catalog = waygate_catalog::CatalogServerSummary {
            id: Uuid::nil(),
            tenant_id: "default".into(),
            name: "search".into(),
            transport: "http".into(),
            status: waygate_catalog::CatalogServerStatus::Live,
            visibility: waygate_catalog::CatalogVisibility::TenantOnly,
            owner: None,
        };
        let runtime = waygate_upstream::UpstreamHealth {
            name: "search".into(),
            runtime_state: waygate_upstream::UpstreamRuntimeState::Disconnected,
            last_success_at: None,
            last_error_class: Some(waygate_upstream::UpstreamErrorClass::Dns),
            next_retry_at: None,
            connected: false,
            breaker: waygate_upstream::BreakerState::Closed,
            connected_lanes: 0,
            total_lanes: 4,
            published_tool_count: 0,
            quarantined_tool_count: 2,
            rejected_output_schema_count: 0,
            protocol_versions: Vec::new(),
        };

        let row = serde_json::to_value(server_row(catalog, Some(&runtime)))
            .expect("serialize observable server row");
        assert_eq!(row["status"], "live", "legacy lifecycle alias remains");
        assert_eq!(row["catalog_status"], "live");
        assert_eq!(row["runtime_status"], "disconnected");
        assert_eq!(row["last_error_class"], "dns");
        assert_eq!(row["connected_lanes"], 0);
        assert_eq!(row["configured_lanes"], 4);
        assert_eq!(row["breaker"], "closed");
        assert_eq!(row["drift_quarantined_tool_count"], 2);
    }

    async fn empty_state() -> AdminState {
        // Every store left `None`: read() must report each resource as
        // Unavailable (not panic, not UnknownResource).
        let pool = Arc::new(waygate_upstream::UpstreamPool::connect(BTreeMap::new()).await);
        AdminState::new(
            pool,
            None,
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
    }

    #[tokio::test]
    async fn read_dispatch_covers_every_catalog_entry() {
        // Drift guard (the `action_catalog_keys_match_registry` analogue): every
        // catalog entry must be wired into read()'s dispatch. With no store
        // configured each known type returns Unavailable; a missing arm would
        // instead return UnknownResource — the failure this pins.
        let state = empty_state().await;
        for rt in resource_types() {
            let r = read(&state, rt, "default", &Map::new(), 50, 0).await;
            match r {
                Err(ReadError::Unavailable(_)) => {}
                Err(ReadError::UnknownResource(_)) => {
                    panic!("catalog lists `{rt}` but read() has no dispatch arm for it")
                }
                other => panic!("unexpected read({rt}) result with no store: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn agent_config_resource_exposes_the_reviewable_tool_allowlist() {
        let store = Arc::new(InMemoryAgentConfigStore::new());
        let tools = vec![
            "gateway-observe.query_audit".to_owned(),
            "example-security.list_alerts".to_owned(),
        ];
        let created = store
            .insert(
                "default",
                AgentConfigFields {
                    name: "triage",
                    kind: AgentKind::Classification,
                    model_alias: "reasoning-default",
                    instructions: Some("Summarize security findings."),
                    allowed_tools: &tools,
                    max_steps: 6,
                    max_tool_calls: 12,
                    token_budget: Some(4_000),
                    enabled: true,
                },
            )
            .await
            .expect("insert agent config");
        let state = empty_state().await.with_agent_configs(Some(store));

        let page = read(&state, "agent_config", "default", &Map::new(), 50, 0)
            .await
            .expect("read agent config resource");
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0]["id"], created.id.to_string());
        assert_eq!(page.rows[0]["allowed_tools"], serde_json::json!(tools));
        assert_eq!(page.rows[0]["kind"], "classification");
        assert_eq!(page.rows[0]["enabled"], true);
    }

    #[tokio::test]
    async fn unknown_resource_type_is_unknown_resource_error() {
        let state = empty_state().await;
        let r = read(&state, "not_a_resource", "default", &Map::new(), 50, 0).await;
        match r {
            Err(ReadError::UnknownResource(valid)) => {
                assert!(
                    valid.contains(&"peer"),
                    "teach-list must carry the valid set"
                );
            }
            other => panic!("expected UnknownResource, got {other:?}"),
        }
    }

    #[test]
    fn empty_filter_object_parses_to_all_none() {
        // The keystone for no-filter calls: `{}` deserializes to every field
        // None, and an unknown key is rejected (deny_unknown_fields).
        let empty = Map::new();
        let f: InspectionRuleFilter = parse_filters("inspection_rule", &empty).expect("empty ok");
        assert!(f.inspector.is_none() && f.name.is_none() && f.enabled.is_none());

        let mut bad = Map::new();
        bad.insert("bogus".into(), Value::Bool(true));
        let err = parse_filters::<InspectionRuleFilter>("inspection_rule", &bad)
            .expect_err("unknown key must be rejected");
        assert!(matches!(err, ReadError::BadFilter(_)), "got {err:?}");
    }

    #[test]
    fn peer_row_strips_url_userinfo_but_preserves_clean_urls() {
        // A `peer` row surfaces issuer/jwks_url at the mcp:observe tier, so any
        // `user:pass@` userinfo (from a pre-guard or direct-SQL row) must be
        // stripped before it reaches the agent. Clean URLs round-trip
        // byte-for-byte (the byte-exact OIDC `iss` contract).
        assert_eq!(
            sanitize_url("https://user:pass@peer.example/jwks"),
            "https://peer.example/jwks",
        );
        assert_eq!(
            sanitize_url("https://user@peer.example/"),
            "https://peer.example/"
        );
        // No userinfo ⇒ unchanged, including a bare-authority issuer with no
        // trailing slash (NOT canonicalized to add one).
        assert_eq!(
            sanitize_url("https://gw.acme.example"),
            "https://gw.acme.example"
        );
        assert_eq!(
            sanitize_url("https://gw.acme.example/.well-known/jwks.json"),
            "https://gw.acme.example/.well-known/jwks.json",
        );
    }

    #[test]
    fn sensitive_row_views_redact_secrets() {
        // Hard invariant for the admin tier: secret material must never
        // reach the serialized row. api_key drops `key_hash`; confidential_client
        // reduces secret_hash / jwks to `has_*` booleans.
        let key = ApiKeyRowView::from(waygate_apikeys::ApiKeyRow {
            id: Uuid::new_v4(),
            key_prefix: "mcpgw_abc".into(),
            key_hash: "ARGON2_SECRET_HASH_DO_NOT_LEAK".into(),
            name: "k".into(),
            sub: "u".into(),
            tenant_id: "default".into(),
            email: None,
            groups: vec![],
            scopes: vec!["mcp:invoke".into()],
            created_by: "admin".into(),
            created_at: OffsetDateTime::now_utc(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            profile_id: None,
            owner: None,
            reason: None,
            rotation_due_at: None,
        });
        let kv = serde_json::to_value(&key).expect("serializes");
        assert!(
            kv.get("key_hash").is_none(),
            "api_key row must not carry key_hash"
        );
        assert!(
            !kv.to_string().contains("ARGON2_SECRET_HASH_DO_NOT_LEAK"),
            "the key_hash secret leaked into the row",
        );
        assert_eq!(
            kv.get("key_prefix").and_then(|x| x.as_str()),
            Some("mcpgw_abc")
        );

        let client = ConfidentialClientRow::from(waygate_as::clients::ConfidentialClient {
            client_id: "https://app.example".into(),
            secret_hash: Some("ARGON2_CLIENT_SECRET".into()),
            jwks: Some(serde_json::json!({"keys": []})),
            created_at: OffsetDateTime::now_utc(),
        });
        let cv = serde_json::to_value(&client).expect("serializes");
        assert_eq!(cv.get("has_secret").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(cv.get("has_jwks").and_then(|x| x.as_bool()), Some(true));
        assert!(cv.get("secret_hash").is_none() && cv.get("jwks").is_none());
        assert!(
            !cv.to_string().contains("ARGON2_CLIENT_SECRET"),
            "the client secret_hash leaked into the row",
        );
    }
}
