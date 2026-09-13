//! `CatalogStore` trait + Postgres impl.
//!
//! The trait stays narrow: the per-call hot path uses
//! [`CatalogStore::resolve_tool`] only; admin endpoints use the
//! other methods. Anything that would need a join across many
//! tables (e.g. a "full catalog dump for backup") lives on the
//! Pg impl directly, not on the trait.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::types::{
    ApprovalAction, CatalogError, CatalogServerStatusChange, CatalogServerSummary,
    CatalogServerTransitionTarget, DriftEvent, DriftObservation, DriftSeverity, GrantLifecycle,
    ResolvedTool,
};

/// Decoupled store surface so callers don't reach for the
/// Postgres pool directly. Tests implement an in-memory variant;
/// production wires [`PgCatalogStore`].
#[async_trait]
pub trait CatalogStore: Send + Sync + 'static {
    /// List `live` servers visible to `principal_tenant`.
    /// Combines `mcp_servers.visibility = 'global'` with
    /// per-tenant rows. Used by the discovery surface (`tools/list` +
    /// admin `/api/v1/catalog/servers`).
    async fn approved_servers(
        &self,
        principal_tenant: &str,
    ) -> Result<Vec<CatalogServerSummary>, CatalogError>;

    /// All servers visible to `principal_tenant` (its own tenant
    /// rows plus `global` ones) across **every** lifecycle state
    /// — `proposed` / `approved` / `live` / `quarantined` /
    /// `retired` — ordered by `(tenant_id, name)`. Powers the
    /// admin governance/catalog view, which must surface the
    /// non-`live` rows that [`Self::approved_servers`]
    /// deliberately hides from the per-call discovery path.
    ///
    /// Defaults to empty for non-Postgres stores (test fakes that
    /// don't exercise server listing); [`PgCatalogStore`]
    /// overrides it with the real query.
    async fn list_servers(
        &self,
        principal_tenant: &str,
    ) -> Result<Vec<CatalogServerSummary>, CatalogError> {
        let _ = principal_tenant;
        Ok(Vec::new())
    }

    /// Durable fleet-wide generation for catalog state that can change an
    /// authorized discovery view. PostgreSQL-backed stores advance it in the
    /// same transaction as the catalog mutation. Stores without a durable
    /// catalog return `None`; their process-local catalog epoch remains the
    /// only applicable fence.
    async fn discovery_generation(&self) -> Result<Option<i64>, CatalogError> {
        Ok(None)
    }

    /// Resolve a `(tenant, "server.tool")` reference to a
    /// [`ResolvedTool`]. The per-call path branches on the
    /// returned variant (`Live` / `PendingApproval` / `NotFound`).
    /// Hot path; needs to be cheap (single indexed lookup).
    async fn resolve_tool(
        &self,
        principal_tenant: &str,
        fq_name: &str,
    ) -> Result<ResolvedTool, CatalogError>;

    /// Resolve one currently-live catalog tool by immutable id within the
    /// caller tenant's visibility. Used when a durable approval request already
    /// carries the tool identity and string selectors may contain dots.
    async fn resolve_live_tool_id(
        &self,
        principal_tenant: &str,
        tool_id: Uuid,
    ) -> Result<Option<crate::types::ToolDefinition>, CatalogError> {
        let _ = (principal_tenant, tool_id);
        Ok(None)
    }

    /// Record an observed drift. Idempotent at the SQL level
    /// (a fresh UUID per call; multiple observations of the
    /// same drift produce multiple rows so a long-running
    /// mismatch is visible as a stream, not a single event).
    async fn record_drift(&self, observation: DriftObservation<'_>) -> Result<(), CatalogError>;

    /// Append a row to `catalog_approvals`. The Pg impl
    /// validates `action` against the column CHECK constraint;
    /// callers that pass an unknown action get a wrapped sqlx
    /// error.
    ///
    /// `subject_id` is a soft reference (no FK — the audit trail
    /// must outlive the subject, see migration 0011). The CALLER
    /// is responsible for confirming the subject exists before
    /// recording an approval against it; this store does not
    /// re-check, because at the point of approval the caller has
    /// already loaded the subject to mutate it. The integrity
    /// guarantee is the write-boundary validation in the admin
    /// endpoints + ManifestImporter, deliberately not a DB foreign
    /// key.
    async fn record_approval(&self, action: ApprovalAction<'_>) -> Result<(), CatalogError>;

    /// Drift events for `tenant_id`, newest first, capped at
    /// `limit`. Used by the admin drift-feed endpoint
    /// (`GET /api/v1/catalog/drift_events`).
    async fn list_drift_events(
        &self,
        tenant_id: &str,
        since: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<DriftEvent>, CatalogError>;

    /// Transition a server's lifecycle `status` AND record the
    /// matching `catalog_approvals` audit row, atomically (one
    /// transaction). Used by immediate quarantine and legacy callers; delayed
    /// reviewed transitions use `transition_server_status_if_unchanged`.
    ///
    /// Scoped to `tenant_id`: an admin can only mutate servers in
    /// their own tenant (cross-tenant / global mutation is out of
    /// scope today). Returns `Ok(true)` when a row was
    /// updated, `Ok(false)` when no server matched
    /// `(tenant_id, server_id)` — the endpoint maps the latter to
    /// 404. The recorded approval action is derived from
    /// `new_status` (Live → "approved", Quarantined →
    /// "quarantined", Retired → "retired", etc.).
    async fn set_server_status(
        &self,
        tenant_id: &str,
        server_id: Uuid,
        new_status: crate::types::CatalogServerStatus,
        actor: &str,
        reason: Option<&str>,
    ) -> Result<bool, CatalogError>;

    /// Read one tenant-owned server together with the row version required for
    /// a governed lifecycle compare-and-swap. Implementations that do not
    /// support durable lifecycle transitions fail closed by returning `None`.
    async fn server_transition_target(
        &self,
        tenant_id: &str,
        server_id: Uuid,
    ) -> Result<Option<CatalogServerTransitionTarget>, CatalogError> {
        let _ = (tenant_id, server_id);
        Ok(None)
    }

    /// Atomically change a server status only when the tenant, immutable id,
    /// reviewed name, current status, and row version still match. The matching
    /// `catalog_approvals` row is committed in the same transaction. This is
    /// the mutation boundary for delayed HITL lifecycle changes: `Ok(false)`
    /// means the target changed after review and nothing was written.
    async fn transition_server_status_if_unchanged(
        &self,
        change: CatalogServerStatusChange<'_>,
    ) -> Result<bool, CatalogError> {
        let _ = change;
        Ok(false)
    }

    /// Actor on the most recent `approved` row for this
    /// server, scoped to `tenant_id`. Used by the admin two-approver
    /// mode to enforce that the same actor can't approve a server
    /// twice in a row. Returns `Ok(None)` when no prior `approved`
    /// row exists for this `(tenant_id, server_id)` — first-time
    /// approval is always allowed even under the two-approver rule.
    async fn last_approve_actor(
        &self,
        tenant_id: &str,
        server_id: Uuid,
    ) -> Result<Option<String>, CatalogError>;

    /// Look up an active (unexpired) approval grant
    /// matching the lookup tuple. Returns `Ok(None)` when no
    /// matching live grant exists; the per-call HITL gate
    /// (`DefaultInvocationService::check_approval`) refuses
    /// dispatch on `None`. `client_id` in the lookup
    /// matches a grant with `client_id IS NULL` (any-client) OR a
    /// grant whose `client_id` equals the caller's. Implementations
    /// MUST exclude expired rows.
    async fn find_grant<'a>(
        &self,
        lookup: crate::types::GrantLookup<'a>,
    ) -> Result<Option<crate::types::ApprovalGrant>, CatalogError>;

    /// Atomically claim (consume) a matching live grant.
    /// Locates the same row [`Self::find_grant`] would return AND sets
    /// `consumed_at = now()` in a single statement, preventing two
    /// concurrent dispatches from both consuming one grant. Returns
    /// `Ok(None)` when no live grant matches (caller refuses dispatch);
    /// returns `Ok(Some(grant))` with the now-consumed row.
    /// Implementations use `FOR UPDATE SKIP LOCKED` so a concurrent
    /// claimer sees `None` rather than blocking — the call gets refused
    /// and the operator can issue another grant.
    async fn claim_grant<'a>(
        &self,
        lookup: crate::types::GrantLookup<'a>,
    ) -> Result<Option<crate::types::ApprovalGrant>, CatalogError>;

    /// Mint a new approval grant. The admin "approve
    /// this caller for this exact call" endpoint inserts via this.
    /// Returns the persisted row so callers see the server-set
    /// `id` + `created_at`.
    async fn create_grant<'a>(
        &self,
        grant: crate::types::NewApprovalGrant<'a>,
    ) -> Result<crate::types::ApprovalGrant, CatalogError>;

    /// List grants for the admin "pending approvals"
    /// view. Tenant-scoped. `filter` narrows by principal / tool /
    /// server and toggles whether consumed-or-expired rows show up
    /// (defaults to live-only).
    async fn list_grants<'a>(
        &self,
        tenant_id: &'a str,
        filter: crate::types::GrantFilter<'a>,
    ) -> Result<Vec<crate::types::ApprovalGrant>, CatalogError>;

    /// Operator-driven revoke. Marks the grant
    /// consumed (`consumed_at = now()`) so the next `claim_grant`
    /// or `find_grant` won't return it. Tenant-scoped so an admin
    /// can't reach across tenants. Returns `Ok(true)` when a live
    /// row was revoked, `Ok(false)` when no live row matched the
    /// `(tenant_id, id)` pair — the latter maps to 404 at the
    /// admin handler (covers both "no such grant" and "already
    /// consumed").
    async fn revoke_grant(&self, tenant_id: &str, id: Uuid) -> Result<bool, CatalogError>;

    /// Revoke every live execution-bound grant for one durable Code Mode
    /// execution. Called when the execution's pending approval request is
    /// replaced, so an approval minted for an earlier request can never
    /// authorize a later, different effect: a bound grant stays claimable
    /// only while the exact request it was minted for remains the pending
    /// one. Returns the number of grants revoked. The default is a no-op for
    /// stores that never hold execution-bound grants; any store that mints
    /// them must override it.
    async fn revoke_execution_grants(
        &self,
        tenant_id: &str,
        execution_id: Uuid,
    ) -> Result<u64, CatalogError> {
        let _ = (tenant_id, execution_id);
        Ok(0)
    }

    /// Prune dead grant rows. Deletes rows that
    /// have either been consumed (`consumed_at IS NOT NULL`) or
    /// expired (`expires_at < now()`), AND whose `created_at` is
    /// older than `older_than` (the operator-tunable retention
    /// threshold — recent dead rows stay visible in the admin
    /// history view). Returns the count deleted.
    ///
    /// Not tenant-scoped: the sweeper is a global maintenance
    /// job. Tenant isolation is enforced on the caller-facing
    /// list/revoke paths, not on the sweep.
    async fn sweep_grants(&self, older_than: OffsetDateTime) -> Result<u64, CatalogError>;
}

/// Type-erased handle, matching the shape every other store in
/// this workspace uses (`SharedEvidence`,
/// `SharedUpstreamSessionStore`).
pub type SharedCatalogStore = Arc<dyn CatalogStore>;

/// Postgres-backed [`CatalogStore`]. One instance per gateway
/// boot; cheaply `Clone`-able because `PgPool` is internally an
/// `Arc`.
#[derive(Clone)]
pub struct PgCatalogStore {
    pub(crate) pool: PgPool,
}

impl PgCatalogStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }
}

#[async_trait]
impl CatalogStore for PgCatalogStore {
    async fn discovery_generation(&self) -> Result<Option<i64>, CatalogError> {
        let generation = sqlx::query_scalar(
            "SELECT generation FROM catalog_discovery_generation WHERE singleton = TRUE",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(CatalogError::Database)?;
        Ok(Some(generation))
    }

    async fn approved_servers(
        &self,
        principal_tenant: &str,
    ) -> Result<Vec<CatalogServerSummary>, CatalogError> {
        // `status = 'live'` is what the per-call hot path
        // actually consults — `approved` but not yet `live`
        // rows haven't been promoted to dispatchable yet and
        // shouldn't show up in discovery.
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, name, transport, status, visibility, owner
              FROM mcp_servers
             WHERE status = 'live'
               AND (visibility = 'global' OR tenant_id = $1)
             ORDER BY tenant_id, name
            "#,
        )
        .bind(principal_tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(CatalogError::Database)?;
        rows.into_iter()
            .map(|r| {
                let status_str: String = r.get("status");
                let vis_str: String = r.get("visibility");
                let status = parse_status(&status_str)?;
                let visibility = parse_visibility(&vis_str)?;
                Ok(CatalogServerSummary {
                    id: r.get("id"),
                    tenant_id: r.get("tenant_id"),
                    name: r.get("name"),
                    transport: r.get("transport"),
                    status,
                    visibility,
                    owner: r.get("owner"),
                })
            })
            .collect()
    }

    async fn list_servers(
        &self,
        principal_tenant: &str,
    ) -> Result<Vec<CatalogServerSummary>, CatalogError> {
        // Same tenant/visibility scoping as `approved_servers`,
        // but NO `status` filter — the governance view must show
        // proposed / approved / quarantined / retired rows, not
        // just `live`. Ordering matches `approved_servers`.
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, name, transport, status, visibility, owner
              FROM mcp_servers
             WHERE (visibility = 'global' OR tenant_id = $1)
             ORDER BY tenant_id, name
            "#,
        )
        .bind(principal_tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(CatalogError::Database)?;
        rows.into_iter()
            .map(|r| {
                let status_str: String = r.get("status");
                let vis_str: String = r.get("visibility");
                let status = parse_status(&status_str)?;
                let visibility = parse_visibility(&vis_str)?;
                Ok(CatalogServerSummary {
                    id: r.get("id"),
                    tenant_id: r.get("tenant_id"),
                    name: r.get("name"),
                    transport: r.get("transport"),
                    status,
                    visibility,
                    owner: r.get("owner"),
                })
            })
            .collect()
    }

    async fn resolve_tool(
        &self,
        principal_tenant: &str,
        fq_name: &str,
    ) -> Result<ResolvedTool, CatalogError> {
        // Split `server.tool`. Anything else is "not found" —
        // the per-call path renders that as an unknown-tool
        // error to the caller, same shape as today.
        let Some((server, tool)) = fq_name.split_once('.') else {
            return Ok(ResolvedTool::NotFound);
        };
        // Single roundtrip joining mcp_servers + mcp_tools +
        // mcp_tool_versions (latest approved) +
        // tool_classifications.
        //
        // ORDER BY precedence:
        // 1. `(s.tenant_id = $1) DESC` — a server owned by the
        //    principal's OWN tenant wins over a `global` server
        //    of the same name. `UNIQUE (tenant_id, name)` allows
        //    a global `example-messages` and an acme-tenant `example-messages` to
        //    coexist; the per-call path must deterministically
        //    pick the tenant's own override, not flip-flop.
        //    Deduping the shadowed global row out of the
        //    discovery surface's tool list isn't implemented yet.
        // 2. `v.approved_at DESC NULLS LAST` — among rows for the
        //    chosen server, the most-recently-*approved* schema
        //    (rollback-correct, not most-recently-observed).
        let row = sqlx::query(
            r#"
            SELECT
                t.id              AS tool_id,
                t.server_id       AS server_id,
                t.name            AS tool_name,
                s.name            AS server_name,
                s.status          AS server_status,
                s.classification_mode AS classification_mode,
                v.schema_hash     AS schema_hash,
                v.description     AS description,
                v.input_schema    AS input_schema,
                v.output_schema   AS output_schema,
                v.tool_annotations AS tool_annotations,
                v.action_metadata AS action_metadata,
                c.risk            AS risk,
                c.side_effects    AS side_effects,
                c.pii             AS pii,
                c.data_classification AS data_classification,
                c.cost_class      AS cost_class,
                c.requires_approval AS requires_approval,
                c.discriminator   AS discriminator,
                -- One row per classified operation, folded into the single
                -- round-trip this hot path is allowed. Ordered so a snapshot
                -- comparison is stable; `[]` when the tool names none.
                COALESCE(
                    (SELECT jsonb_agg(
                                jsonb_build_object(
                                    'value',        o.operation,
                                    'risk',         o.risk,
                                    'side_effects', o.side_effects,
                                    'pii',          o.pii
                                )
                                ORDER BY o.operation
                            )
                       FROM tool_operation_classifications o
                      WHERE o.tool_id = c.tool_id
                        -- A refinement may narrow what a call authorizes
                        -- under, so it takes an operator's review to apply.
                        -- An unreviewed row is not a decision yet; leaving it
                        -- out keeps the tool-level classification in force.
                        AND o.reviewed_at IS NOT NULL),
                    '[]'::jsonb
                )                 AS operations
              FROM mcp_servers s
         LEFT JOIN mcp_tools t
                ON t.server_id = s.id
               AND t.name = $3
         LEFT JOIN mcp_tool_versions v
                ON v.tool_id = t.id
               AND v.approved_at IS NOT NULL
         LEFT JOIN tool_classifications c
                ON c.tool_id = t.id
             WHERE (s.visibility = 'global' OR s.tenant_id = $1)
               AND s.name = $2
             ORDER BY (s.tenant_id = $1) DESC, v.approved_at DESC NULLS LAST
             LIMIT 1
            "#,
        )
        .bind(principal_tenant)
        .bind(server)
        .bind(tool)
        .fetch_optional(&self.pool)
        .await
        .map_err(CatalogError::Database)?;

        // No matching SERVER row at all (server name unknown to the
        // catalog in this tenant scope). NotFound lets the per-call
        // path fall back to the manifest during the dual-read
        // transition. NOTE: the `mcp_tools` join is a LEFT JOIN —
        // server status is checked BELOW independent of whether the
        // specific tool row exists, so a quarantined server with an
        // un-imported tool is still blocked.
        let Some(row) = row else {
            return Ok(ResolvedTool::NotFound);
        };

        let server_status: String = row.get("server_status");
        let server_name: String = row.get("server_name");
        // `tool_name` is NULL when the server matched but the tool row
        // is absent (LEFT JOIN miss); fall back to the requested name
        // so the returned variant still names the tool.
        let tool_name: String = row
            .get::<Option<String>, _>("tool_name")
            .unwrap_or_else(|| tool.to_owned());
        let tool_id: Option<Uuid> = row.get("tool_id");
        let schema_hash: Option<String> = row.get("schema_hash");
        let risk: Option<String> = row.get("risk");

        // The status-vs-tool-presence ordering lives in a pure helper
        // so it's unit-testable without a live Postgres: a
        // quarantined server with an un-imported tool must still
        // block, not fall through to NotFound → manifest fallback.
        match classify_row(
            &server_status,
            tool_id.is_some(),
            schema_hash.is_some(),
            risk.is_some(),
        ) {
            RowClass::Quarantined => {
                return Ok(ResolvedTool::Quarantined {
                    server_name,
                    tool_name,
                })
            }
            RowClass::NotFound => return Ok(ResolvedTool::NotFound),
            RowClass::PendingApproval => {
                return Ok(ResolvedTool::PendingApproval {
                    server_name,
                    tool_name,
                })
            }
            RowClass::Live => {}
        }

        Ok(ResolvedTool::Live(Box::new(live_tool_definition(&row))))
    }

    async fn resolve_live_tool_id(
        &self,
        principal_tenant: &str,
        tool_id: Uuid,
    ) -> Result<Option<crate::types::ToolDefinition>, CatalogError> {
        let row = sqlx::query(
            r#"
            SELECT
                t.id              AS tool_id,
                t.server_id       AS server_id,
                t.name            AS tool_name,
                s.name            AS server_name,
                v.schema_hash     AS schema_hash,
                v.description     AS description,
                v.input_schema    AS input_schema,
                v.output_schema   AS output_schema,
                v.tool_annotations AS tool_annotations,
                v.action_metadata AS action_metadata,
                s.classification_mode AS classification_mode,
                c.risk            AS risk,
                c.side_effects    AS side_effects,
                c.pii             AS pii,
                c.data_classification AS data_classification,
                c.cost_class      AS cost_class,
                c.requires_approval AS requires_approval,
                c.discriminator   AS discriminator,
                -- One row per classified operation, folded into the single
                -- round-trip this hot path is allowed. Ordered so a snapshot
                -- comparison is stable; `[]` when the tool names none.
                COALESCE(
                    (SELECT jsonb_agg(
                                jsonb_build_object(
                                    'value',        o.operation,
                                    'risk',         o.risk,
                                    'side_effects', o.side_effects,
                                    'pii',          o.pii
                                )
                                ORDER BY o.operation
                            )
                       FROM tool_operation_classifications o
                      WHERE o.tool_id = c.tool_id
                        -- A refinement may narrow what a call authorizes
                        -- under, so it takes an operator's review to apply.
                        -- An unreviewed row is not a decision yet; leaving it
                        -- out keeps the tool-level classification in force.
                        AND o.reviewed_at IS NOT NULL),
                    '[]'::jsonb
                )                 AS operations
              FROM mcp_tools t
              JOIN mcp_servers s
                ON s.id = t.server_id
               AND s.status = 'live'
               AND (s.visibility = 'global' OR s.tenant_id = $1)
              JOIN mcp_tool_versions v
                ON v.tool_id = t.id
               AND v.approved_at IS NOT NULL
              JOIN tool_classifications c
                ON c.tool_id = t.id
             WHERE t.id = $2
             ORDER BY v.approved_at DESC
             LIMIT 1
            "#,
        )
        .bind(principal_tenant)
        .bind(tool_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(CatalogError::Database)?;
        Ok(row.as_ref().map(live_tool_definition))
    }

    async fn record_drift(&self, observation: DriftObservation<'_>) -> Result<(), CatalogError> {
        sqlx::query(
            r#"
            INSERT INTO catalog_drift_events
                (id, tenant_id, tool_id, observed_hash, approved_hash, severity)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(observation.tenant_id)
        .bind(observation.tool_id)
        .bind(observation.observed_hash)
        .bind(observation.approved_hash)
        .bind(observation.severity.as_str())
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(CatalogError::Database)
    }

    async fn record_approval(&self, action: ApprovalAction<'_>) -> Result<(), CatalogError> {
        sqlx::query(
            r#"
            INSERT INTO catalog_approvals
                (id, tenant_id, subject_type, subject_id, subject_version_hash,
                 action, actor, reason)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(action.tenant_id)
        .bind(action.subject_type.as_str())
        .bind(action.subject_id)
        .bind(action.subject_version_hash)
        .bind(action.action)
        .bind(action.actor)
        .bind(action.reason)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(CatalogError::Database)
    }

    async fn list_drift_events(
        &self,
        tenant_id: &str,
        since: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<DriftEvent>, CatalogError> {
        // Cap at 500 mirroring the admin list endpoints' hard
        // ceiling. An operator paging through a noisy upstream
        // can still walk the full history page by page.
        let effective_limit = limit.min(500) as i64;
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, tool_id, observed_hash, approved_hash, severity, observed_at
              FROM catalog_drift_events
             WHERE tenant_id = $1
               AND observed_at >= $2
             ORDER BY observed_at DESC
             LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(since)
        .bind(effective_limit)
        .fetch_all(&self.pool)
        .await
        .map_err(CatalogError::Database)?;
        rows.into_iter()
            .map(|r| {
                let severity = parse_severity(r.get::<&str, _>("severity"))?;
                Ok(DriftEvent {
                    id: r.get("id"),
                    tenant_id: r.get("tenant_id"),
                    tool_id: r.get("tool_id"),
                    observed_hash: r.get("observed_hash"),
                    approved_hash: r.get("approved_hash"),
                    severity,
                    observed_at: r.get("observed_at"),
                })
            })
            .collect()
    }

    async fn set_server_status(
        &self,
        tenant_id: &str,
        server_id: Uuid,
        new_status: crate::types::CatalogServerStatus,
        actor: &str,
        reason: Option<&str>,
    ) -> Result<bool, CatalogError> {
        let mut tx = self.pool.begin().await.map_err(CatalogError::Database)?;
        // Scoped to the caller's tenant: an admin can only mutate
        // their own tenant's servers. The RETURNING tells us
        // whether the row existed (404 vs. updated).
        let updated = sqlx::query(
            r#"
            UPDATE mcp_servers
               SET status = $3, updated_at = now()
             WHERE id = $1 AND tenant_id = $2
            RETURNING id
            "#,
        )
        .bind(server_id)
        .bind(tenant_id)
        .bind(new_status.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(CatalogError::Database)?
        .is_some();

        if !updated {
            // No matching row — roll back (no-op) and report
            // not-found. Don't write an approval for a server
            // that doesn't exist in this tenant.
            tx.rollback().await.map_err(CatalogError::Database)?;
            return Ok(false);
        }

        // Audit the transition in the same transaction so the
        // status change and its approval row commit together.
        let action = status_to_action(new_status);
        sqlx::query(
            r#"
            INSERT INTO catalog_approvals
                (id, tenant_id, subject_type, subject_id, subject_version_hash,
                 action, actor, reason)
            VALUES ($1, $2, 'server', $3, NULL, $4, $5, $6)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(server_id)
        .bind(action)
        .bind(actor)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(CatalogError::Database)?;

        tx.commit().await.map_err(CatalogError::Database)?;
        Ok(true)
    }

    async fn server_transition_target(
        &self,
        tenant_id: &str,
        server_id: Uuid,
    ) -> Result<Option<CatalogServerTransitionTarget>, CatalogError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, name, status, updated_at
              FROM mcp_servers
             WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(server_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(CatalogError::Database)?;

        row.map(|r| {
            let status = parse_status(r.get::<&str, _>("status"))?;
            Ok(CatalogServerTransitionTarget {
                id: r.get("id"),
                tenant_id: r.get("tenant_id"),
                name: r.get("name"),
                status,
                updated_at: r.get("updated_at"),
            })
        })
        .transpose()
    }

    async fn transition_server_status_if_unchanged(
        &self,
        change: CatalogServerStatusChange<'_>,
    ) -> Result<bool, CatalogError> {
        let target = change.target;
        let mut tx = self.pool.begin().await.map_err(CatalogError::Database)?;
        let updated = sqlx::query(
            r#"
            UPDATE mcp_servers
               SET status = $6, updated_at = now()
             WHERE id = $1
               AND tenant_id = $2
               AND name = $3
               AND status = $4
               AND updated_at = $5
            RETURNING id
            "#,
        )
        .bind(target.id)
        .bind(&target.tenant_id)
        .bind(&target.name)
        .bind(target.status.as_str())
        .bind(target.updated_at)
        .bind(change.new_status.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(CatalogError::Database)?
        .is_some();

        if !updated {
            tx.rollback().await.map_err(CatalogError::Database)?;
            return Ok(false);
        }

        sqlx::query(
            r#"
            INSERT INTO catalog_approvals
                (id, tenant_id, subject_type, subject_id, subject_version_hash,
                 action, actor, reason)
            VALUES ($1, $2, 'server', $3, NULL, $4, $5, $6)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(&target.tenant_id)
        .bind(target.id)
        .bind(status_to_action(change.new_status))
        .bind(change.actor)
        .bind(change.reason)
        .execute(&mut *tx)
        .await
        .map_err(CatalogError::Database)?;

        tx.commit().await.map_err(CatalogError::Database)?;
        Ok(true)
    }

    async fn last_approve_actor(
        &self,
        tenant_id: &str,
        server_id: Uuid,
    ) -> Result<Option<String>, CatalogError> {
        // Newest `approved` action for this server in this tenant.
        // Reads the same append-only audit table that `set_server_status`
        // writes; no separate index needed in the v1 schema because
        // catalog_approvals is small (one row per transition, not per
        // call).
        let row = sqlx::query_scalar::<_, String>(
            r#"
            SELECT actor
              FROM catalog_approvals
             WHERE tenant_id = $1
               AND subject_type = 'server'
               AND subject_id = $2
               AND action = 'approved'
             ORDER BY created_at DESC
             LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(server_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(CatalogError::Database)?;
        Ok(row)
    }

    async fn find_grant<'a>(
        &self,
        lookup: crate::types::GrantLookup<'a>,
    ) -> Result<Option<crate::types::ApprovalGrant>, CatalogError> {
        // Equality on tenant_id + principal_sub + tool_id + argument_hash
        // (hot-path index), plus the unexpired + un-consumed filters,
        // plus the any-client / specific-client OR. The
        // `consumed_at IS NULL` filter enforces one-time-use HITL
        // semantics: a previously-consumed grant must not be
        // returned even when still unexpired.
        // ORDER BY created_at DESC so a freshly-issued grant wins over
        // a stale duplicate (operator re-issuing the same grant);
        // LIMIT 1 because callers only need a yes/no answer.
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, principal_sub, principal_issuer, client_id,
                   server_id, tool_id, argument_hash, execution_id,
                   source_digest, call_id, expires_at, consumed_at, approver,
                   reason, created_at
              FROM approval_grants
             WHERE tenant_id     = $1
               AND principal_sub = $2
               -- Exact issuer binding: a pre-upgrade NULL row matches
               -- nothing (fail closed) and ages out on its expiry clock.
               AND principal_issuer = $9
               AND tool_id       = $3
               AND argument_hash = $4
               AND expires_at    > now()
               AND consumed_at IS NULL
               AND (client_id IS NULL OR client_id = $5)
               AND (
                    ($6::uuid IS NULL
                        AND execution_id IS NULL
                        AND source_digest IS NULL
                        AND call_id IS NULL)
                    OR (
                        execution_id = $6
                        AND source_digest = $7
                        AND call_id = $8
                        -- An accepted cancellation on the bound execution
                        -- closes its grants before any authority is consumed.
                        AND NOT EXISTS (
                            SELECT 1
                              FROM codemode_executions e
                             WHERE e.tenant_id = approval_grants.tenant_id
                               AND e.id = approval_grants.execution_id
                               AND e.cancellation_requested_at IS NOT NULL
                        )
                    )
               )
             ORDER BY created_at DESC
             LIMIT 1
            "#,
        )
        .bind(lookup.tenant_id)
        .bind(lookup.principal_sub)
        .bind(lookup.tool_id)
        .bind(lookup.argument_hash)
        .bind(lookup.client_id)
        .bind(lookup.execution_binding.map(|binding| binding.execution_id))
        .bind(
            lookup
                .execution_binding
                .map(|binding| binding.source_digest),
        )
        .bind(lookup.execution_binding.map(|binding| binding.call_id))
        .bind(lookup.principal_issuer)
        .fetch_optional(&self.pool)
        .await
        .map_err(CatalogError::Database)?;

        Ok(row.as_ref().map(approval_grant_from_row))
    }

    async fn claim_grant<'a>(
        &self,
        lookup: crate::types::GrantLookup<'a>,
    ) -> Result<Option<crate::types::ApprovalGrant>, CatalogError> {
        // Atomic claim. The inner SELECT picks the same row find_grant
        // would (newest live unconsumed match) under FOR UPDATE SKIP
        // LOCKED so a concurrent claimer sees nothing rather than
        // blocking, and the outer UPDATE sets consumed_at = now() and
        // RETURNs the row — all in one statement, so SELECT and UPDATE
        // can't be raced between by another transaction.
        let mut tx = self.pool.begin().await.map_err(CatalogError::Database)?;
        if let Some(binding) = lookup.execution_binding {
            // Lock-ordered cancellation check for execution-bound claims: a
            // shared lock on the bound execution row conflicts with
            // request_cancellation's FOR UPDATE, so either this claim
            // commits first (the cancellation then lands mid-flight and the
            // effect outcome is journaled) or the cancellation commits first
            // and this check refuses — the NOT EXISTS predicate below alone
            // reads a statement snapshot and could miss a cancellation that
            // commits while the claim statement runs.
            let cancelled = sqlx::query_scalar::<_, bool>(
                r#"
                SELECT cancellation_requested_at IS NOT NULL
                  FROM codemode_executions
                 WHERE tenant_id = $1
                   AND id = $2
                   FOR SHARE
                "#,
            )
            .bind(lookup.tenant_id)
            .bind(binding.execution_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(CatalogError::Database)?;
            if cancelled == Some(true) {
                tx.rollback().await.map_err(CatalogError::Database)?;
                return Ok(None);
            }
        }
        let row = sqlx::query(
            r#"
            UPDATE approval_grants
               SET consumed_at = now()
             WHERE id = (
                 SELECT id
                   FROM approval_grants
                  WHERE tenant_id     = $1
                    AND principal_sub = $2
                    -- Exact issuer binding: a pre-upgrade NULL row matches
                    -- nothing (fail closed).
                    AND principal_issuer = $9
                    AND tool_id       = $3
                    AND argument_hash = $4
                    AND expires_at    > now()
                    AND consumed_at IS NULL
                    AND (client_id IS NULL OR client_id = $5)
                    AND (
                         ($6::uuid IS NULL
                             AND execution_id IS NULL
                             AND source_digest IS NULL
                             AND call_id IS NULL)
                         OR (
                             execution_id = $6
                             AND source_digest = $7
                             AND call_id = $8
                             -- Atomic with consumption: once cancellation is
                             -- requested on the bound execution, its one-time
                             -- grant can no longer be claimed, so no dispatch
                             -- follows an accepted cancellation.
                             AND NOT EXISTS (
                                 SELECT 1
                                   FROM codemode_executions e
                                  WHERE e.tenant_id = approval_grants.tenant_id
                                    AND e.id = approval_grants.execution_id
                                    AND e.cancellation_requested_at IS NOT NULL
                             )
                         )
                    )
                  ORDER BY created_at DESC
                  LIMIT 1
                  FOR UPDATE SKIP LOCKED
             )
            RETURNING id, tenant_id, principal_sub, principal_issuer,
                      client_id, server_id, tool_id, argument_hash,
                      execution_id, source_digest, call_id, expires_at,
                      consumed_at, approver, reason, created_at
            "#,
        )
        .bind(lookup.tenant_id)
        .bind(lookup.principal_sub)
        .bind(lookup.tool_id)
        .bind(lookup.argument_hash)
        .bind(lookup.client_id)
        .bind(lookup.execution_binding.map(|binding| binding.execution_id))
        .bind(
            lookup
                .execution_binding
                .map(|binding| binding.source_digest),
        )
        .bind(lookup.execution_binding.map(|binding| binding.call_id))
        .bind(lookup.principal_issuer)
        .fetch_optional(&mut *tx)
        .await
        .map_err(CatalogError::Database)?;
        tx.commit().await.map_err(CatalogError::Database)?;

        Ok(row.as_ref().map(approval_grant_from_row))
    }

    async fn create_grant<'a>(
        &self,
        grant: crate::types::NewApprovalGrant<'a>,
    ) -> Result<crate::types::ApprovalGrant, CatalogError> {
        // Server-set id + created_at; consumed_at starts NULL. The
        // admin handler validated tool_id / server_id correspond to a
        // Live catalog tool before calling; the table accepts both as
        // soft references (no FK, see migration 0013 + the parallel
        // catalog_approvals reasoning).
        let id = Uuid::now_v7();
        let row = sqlx::query(
            r#"
            INSERT INTO approval_grants
                (id, tenant_id, principal_sub, principal_issuer, client_id,
                 server_id, tool_id, argument_hash, execution_id,
                 source_digest, call_id, expires_at, approver, reason)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                    $14)
            RETURNING id, tenant_id, principal_sub, principal_issuer,
                      client_id, server_id, tool_id, argument_hash,
                      execution_id, source_digest, call_id, expires_at,
                      consumed_at, approver, reason, created_at
            "#,
        )
        .bind(id)
        .bind(grant.tenant_id)
        .bind(grant.principal_sub)
        .bind(grant.principal_issuer)
        .bind(grant.client_id)
        .bind(grant.server_id)
        .bind(grant.tool_id)
        .bind(grant.argument_hash)
        .bind(grant.execution_binding.map(|binding| binding.execution_id))
        .bind(grant.execution_binding.map(|binding| binding.source_digest))
        .bind(grant.execution_binding.map(|binding| binding.call_id))
        .bind(grant.expires_at)
        .bind(grant.approver)
        .bind(grant.reason)
        .fetch_one(&self.pool)
        .await
        .map_err(CatalogError::Database)?;

        Ok(approval_grant_from_row(&row))
    }

    async fn list_grants<'a>(
        &self,
        tenant_id: &'a str,
        filter: crate::types::GrantFilter<'a>,
    ) -> Result<Vec<crate::types::ApprovalGrant>, CatalogError> {
        // Build the predicates dynamically so the optional filters
        // become NULL-tolerant no-ops at the SQL level. Each `IS NULL
        // OR =` clause matches everything when the bind is NULL, so
        // a caller passing GrantFilter::default() gets all live
        // grants in the tenant.
        //
        // Lifecycle gate: two paths.
        //
        // 1. `filter.lifecycle = Some(...)` — precise
        //    bucket (`active`, `expired`, `consumed`). Lets the
        //    dashboard fetch each section in its own 200-row window
        //    so consumed rows can't crowd live rows out of view.
        //    Consumed also orders by `consumed_at DESC` so "recently
        //    consumed" is surface-true (created_at DESC would mean
        //    "consumed in the slice of recently-created" — not the
        //    operator's mental model).
        //
        // 2. `filter.lifecycle = None` (legacy) — `include_consumed`
        //    bool. `false` restricts to live grants (the public
        //    REST `/api/v1/admin/approval_grants` default — also
        //    filters out expired-unused rows so the "pending
        //    approvals" view doesn't show stale-but-still-NULL-
        //    consumed_at grants), `true` returns the unfiltered
        //    history view. Kept for backward-compat with the
        //    documented query param.
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, principal_sub, principal_issuer, client_id,
                   server_id, tool_id, argument_hash, execution_id,
                   source_digest, call_id, expires_at, consumed_at, approver,
                   reason, created_at
              FROM approval_grants
             WHERE tenant_id = $1
               AND ($2::text IS NULL OR principal_sub = $2)
               AND ($3::uuid IS NULL OR tool_id       = $3)
               AND ($4::uuid IS NULL OR server_id     = $4)
               AND CASE
                 WHEN $6::text = 'active'   THEN consumed_at IS NULL AND expires_at >  now()
                 WHEN $6::text = 'expired'  THEN consumed_at IS NULL AND expires_at <= now()
                 WHEN $6::text = 'consumed' THEN consumed_at IS NOT NULL
                 WHEN $5                    THEN TRUE
                 ELSE                            consumed_at IS NULL AND expires_at > now()
               END
             ORDER BY
               CASE WHEN $6::text = 'consumed' THEN consumed_at END DESC NULLS LAST,
               created_at DESC
             LIMIT 200
            "#,
        )
        .bind(tenant_id)
        .bind(filter.principal_sub)
        .bind(filter.tool_id)
        .bind(filter.server_id)
        .bind(filter.include_consumed)
        .bind(filter.lifecycle.map(GrantLifecycle::as_sql_str))
        .fetch_all(&self.pool)
        .await
        .map_err(CatalogError::Database)?;

        Ok(rows
            .into_iter()
            .map(|row| approval_grant_from_row(&row))
            .collect())
    }

    async fn revoke_grant(&self, tenant_id: &str, id: Uuid) -> Result<bool, CatalogError> {
        // Only revokes LIVE grants (`consumed_at IS NULL`). A second
        // revoke on the same id is a no-op and reports false →
        // handler 404s. The tenant_id predicate prevents
        // cross-tenant revoke even if an admin guessed an id from
        // another tenant.
        let updated = sqlx::query(
            r#"
            UPDATE approval_grants
               SET consumed_at = now()
             WHERE id = $1
               AND tenant_id = $2
               AND consumed_at IS NULL
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(CatalogError::Database)?
        .is_some();
        Ok(updated)
    }

    async fn revoke_execution_grants(
        &self,
        tenant_id: &str,
        execution_id: Uuid,
    ) -> Result<u64, CatalogError> {
        let result = sqlx::query(
            r#"
            UPDATE approval_grants
               SET consumed_at = now()
             WHERE tenant_id = $1
               AND execution_id = $2
               AND consumed_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(execution_id)
        .execute(&self.pool)
        .await
        .map_err(CatalogError::Database)?;
        Ok(result.rows_affected())
    }

    async fn sweep_grants(&self, older_than: OffsetDateTime) -> Result<u64, CatalogError> {
        // Caller (the periodic grant sweeper) computes the retention threshold in
        // Rust and passes it as a bind, so this query stays a clean
        // single-statement DELETE without server-side INTERVAL
        // arithmetic. Index hit profile: full scan filtered by the
        // two-clause predicate; at realistic grant volumes this is
        // sub-second and runs once per sweep tick.
        let rows = sqlx::query(
            r#"
            DELETE FROM approval_grants
             WHERE (consumed_at IS NOT NULL OR expires_at < now())
               AND created_at < $1
            "#,
        )
        .bind(older_than)
        .execute(&self.pool)
        .await
        .map_err(CatalogError::Database)?;
        Ok(rows.rows_affected())
    }
}

fn live_tool_definition(row: &PgRow) -> crate::types::ToolDefinition {
    crate::types::ToolDefinition {
        tool_id: row.get("tool_id"),
        server_id: row.get("server_id"),
        server_name: row.get("server_name"),
        tool_name: row.get("tool_name"),
        schema_hash: row.get("schema_hash"),
        description: row.get("description"),
        input_schema: row.get("input_schema"),
        output_schema: row.get("output_schema"),
        tool_annotations: row.get("tool_annotations"),
        action_metadata: row.get("action_metadata"),
        classification_mode: row.get("classification_mode"),
        risk: row.get("risk"),
        side_effects: row.get("side_effects"),
        pii: row.get("pii"),
        data_classification: row.get("data_classification"),
        cost_class: row.get("cost_class"),
        requires_approval: row.get("requires_approval"),
        discriminator: row.get("discriminator"),
        operations: operation_classifications(row),
    }
}

/// Decode the folded operation rows.
///
/// The aggregate is built by this module's own queries, so a shape it cannot
/// decode is a bug here rather than untrusted input. An empty list is the
/// correct reading either way: every value then falls back to the tool-level
/// classification, which is never weaker than a named one.
fn operation_classifications(row: &PgRow) -> Vec<crate::types::OperationClassification> {
    let raw: serde_json::Value = row.get("operations");
    serde_json::from_value(raw).unwrap_or_default()
}

fn approval_grant_from_row(row: &PgRow) -> crate::types::ApprovalGrant {
    let execution_id = row.get("execution_id");
    let source_digest = row.get("source_digest");
    let call_id = row.get("call_id");
    let execution_binding = match (execution_id, source_digest, call_id) {
        (Some(execution_id), Some(source_digest), Some(call_id)) => {
            Some(crate::types::ApprovalGrantExecutionBinding {
                execution_id,
                source_digest,
                call_id,
            })
        }
        (None, None, None) => None,
        _ => unreachable!("approval grant execution binding is constrained all-or-nothing"),
    };
    crate::types::ApprovalGrant {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        principal_sub: row.get("principal_sub"),
        principal_issuer: row.get("principal_issuer"),
        client_id: row.get("client_id"),
        server_id: row.get("server_id"),
        tool_id: row.get("tool_id"),
        argument_hash: row.get("argument_hash"),
        execution_binding,
        expires_at: row.get("expires_at"),
        consumed_at: row.get("consumed_at"),
        approver: row.get("approver"),
        reason: row.get("reason"),
        created_at: row.get("created_at"),
    }
}

/// Classification of a `resolve_tool` row, before mapping to the
/// public `ResolvedTool`. Pure decision logic, extracted from the
/// query path so the ordering can be unit-tested without Postgres.
#[derive(Debug, PartialEq, Eq)]
enum RowClass {
    Live,
    PendingApproval,
    Quarantined,
    NotFound,
}

/// Decide a `resolve_tool` outcome from a matched server row.
///
/// Ordering is load-bearing: the `quarantined` /
/// `retired` status is an *authoritative operator block* and is
/// checked BEFORE tool-presence. A quarantined server therefore stays
/// blocked even when its tool rows haven't been imported into the
/// catalog yet — otherwise the per-call path would see `NotFound` and
/// fall back to the manifest, silently re-enabling a server an
/// operator just pulled.
///
/// `tool_present` is whether the `mcp_tools` LEFT JOIN matched;
/// `has_approved_version` / `has_classification` whether the joined
/// version / classification rows exist.
fn classify_row(
    server_status: &str,
    tool_present: bool,
    has_approved_version: bool,
    has_classification: bool,
) -> RowClass {
    if server_status == "quarantined" || server_status == "retired" {
        return RowClass::Quarantined;
    }
    // Server exists and isn't blocked, but this tool isn't catalogued
    // yet → NotFound lets the per-call path use the manifest fallback
    // during the dual-read transition.
    if !tool_present {
        return RowClass::NotFound;
    }
    if server_status != "live" || !has_approved_version || !has_classification {
        return RowClass::PendingApproval;
    }
    RowClass::Live
}

/// Map a target server status to the `catalog_approvals.action`
/// vocabulary. The action records WHY the status changed for the
/// audit trail (a transition to Live is an "approved" event, to
/// Quarantined a "quarantined" event, etc.).
fn status_to_action(status: crate::types::CatalogServerStatus) -> &'static str {
    use crate::types::CatalogServerStatus::*;
    match status {
        Proposed => "proposed",
        Approved | Live => "approved",
        Quarantined => "quarantined",
        Retired => "retired",
    }
}

fn parse_status(s: &str) -> Result<crate::types::CatalogServerStatus, CatalogError> {
    use crate::types::CatalogServerStatus::*;
    Ok(match s {
        "proposed" => Proposed,
        "approved" => Approved,
        "live" => Live,
        "quarantined" => Quarantined,
        "retired" => Retired,
        // The CHECK constraint guards this, but we surface a
        // typed error rather than panic — a future DB migration
        // that adds a new status value would otherwise crash
        // every running gateway until they pick up the matching
        // binary.
        _ => return Err(CatalogError::Unknown("server status")),
    })
}

fn parse_visibility(s: &str) -> Result<crate::types::CatalogVisibility, CatalogError> {
    use crate::types::CatalogVisibility::*;
    Ok(match s {
        "global" => Global,
        "tenant_only" => TenantOnly,
        _ => return Err(CatalogError::Unknown("server visibility")),
    })
}

fn parse_severity(s: &str) -> Result<DriftSeverity, CatalogError> {
    Ok(match s {
        "info" => DriftSeverity::Info,
        "warn" => DriftSeverity::Warn,
        "critical" => DriftSeverity::Critical,
        _ => return Err(CatalogError::Unknown("drift severity")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CatalogServerStatus, CatalogVisibility, SubjectType};

    #[test]
    fn status_round_trip() {
        for s in [
            CatalogServerStatus::Proposed,
            CatalogServerStatus::Approved,
            CatalogServerStatus::Live,
            CatalogServerStatus::Quarantined,
            CatalogServerStatus::Retired,
        ] {
            assert_eq!(parse_status(s.as_str()).unwrap(), s);
        }
    }

    #[test]
    fn unknown_status_is_typed_error() {
        let err = parse_status("nonsense").unwrap_err();
        assert!(matches!(err, CatalogError::Unknown(_)));
    }

    #[test]
    fn visibility_round_trip() {
        for v in [CatalogVisibility::Global, CatalogVisibility::TenantOnly] {
            assert_eq!(parse_visibility(v.as_str()).unwrap(), v);
        }
    }

    #[test]
    fn severity_round_trip() {
        for s in [
            DriftSeverity::Info,
            DriftSeverity::Warn,
            DriftSeverity::Critical,
        ] {
            assert_eq!(parse_severity(s.as_str()).unwrap(), s);
        }
    }

    #[test]
    fn subject_type_strings_are_stable() {
        // CHECK constraint relies on these specific literals;
        // a rename here without a migration would silently
        // reject every approval insert.
        assert_eq!(SubjectType::Server.as_str(), "server");
        assert_eq!(SubjectType::Tool.as_str(), "tool");
        assert_eq!(SubjectType::ToolVersion.as_str(), "tool_version");
        assert_eq!(SubjectType::Classification.as_str(), "classification");
    }

    #[test]
    fn classify_row_quarantine_wins_even_when_tool_absent() {
        // Regression case: server quarantined, tool row not yet
        // imported (tool_present=false). Must be Quarantined, NOT
        // NotFound — a NotFound would let the per-call path fall back
        // to the manifest and re-enable the quarantined server.
        assert_eq!(
            classify_row("quarantined", false, false, false),
            RowClass::Quarantined,
        );
        assert_eq!(
            classify_row("retired", false, false, false),
            RowClass::Quarantined,
        );
        // Even fully-catalogued, quarantine still wins.
        assert_eq!(
            classify_row("quarantined", true, true, true),
            RowClass::Quarantined,
        );
    }

    #[test]
    fn classify_row_live_and_pending_and_notfound() {
        // Live server, tool fully approved → dispatchable.
        assert_eq!(classify_row("live", true, true, true), RowClass::Live);
        // Live server, tool present but missing approved version /
        // classification → awaiting approval.
        assert_eq!(
            classify_row("live", true, false, true),
            RowClass::PendingApproval,
        );
        assert_eq!(
            classify_row("live", true, true, false),
            RowClass::PendingApproval,
        );
        // Not-yet-live (proposed/approved) but tool present → pending.
        assert_eq!(
            classify_row("proposed", true, true, true),
            RowClass::PendingApproval,
        );
        // Live server, tool not catalogued yet → NotFound (manifest
        // fallback during the dual-read transition).
        assert_eq!(
            classify_row("live", false, false, false),
            RowClass::NotFound
        );
    }

    #[test]
    fn status_to_action_maps_to_approval_vocabulary() {
        use crate::types::CatalogServerStatus::*;
        // Each must be one of the catalog_approvals.action CHECK
        // values; a Live transition records as "approved".
        assert_eq!(status_to_action(Live), "approved");
        assert_eq!(status_to_action(Approved), "approved");
        assert_eq!(status_to_action(Quarantined), "quarantined");
        assert_eq!(status_to_action(Retired), "retired");
        assert_eq!(status_to_action(Proposed), "proposed");
    }

    /// Deserializing a `ToolDefinition` JSON that pre-dates
    /// the `requires_approval` field (a catalog row serialized
    /// before the migration, or a fixture in an older test)
    /// MUST default to `false` rather than failing serde — that's
    /// the safe default and matches the column DEFAULT in the
    /// migration. Without `#[serde(default)]` an old payload
    /// would error and the catalog would refuse to load.
    #[test]
    fn tool_definition_requires_approval_defaults_to_false_on_deserialize() {
        // A minimal JSON missing `requires_approval` (mirrors a
        // payload serialized before the `requires_approval` column
        // existed).
        let json = serde_json::json!({
            "tool_id": "00000000-0000-0000-0000-000000000000",
            "server_id": "00000000-0000-0000-0000-000000000000",
            "server_name": "example-messages",
            "tool_name": "send",
            "schema_hash": "deadbeef",
            "description": "send a message",
            "risk": "high",
            "side_effects": true,
            "pii": false
        });
        let td: crate::types::ToolDefinition = serde_json::from_value(json).unwrap();
        assert!(
            !td.requires_approval,
            "missing field must deserialize as false"
        );
    }
}
