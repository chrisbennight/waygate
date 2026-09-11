//! One-shot importer: `servers/*.yaml` manifests -> catalog tables.
//!
//! The operator runs
//! `gateway-server --import-manifests <dir>` once at cutover; this
//! module does the DB writes. It's deliberately decoupled from
//! `waygate-upstream`'s `UpstreamManifest` (which pulls rmcp) — the
//! caller maps the manifest into the neutral [`ImportServer`] /
//! [`ImportTool`] shapes so `waygate-catalog` stays dependency-light.
//!
//! ## Why imported tools are stamped approved
//!
//! `CatalogStore::resolve_tool` only returns `Live` when a tool has
//! an approved version AND a classification. The manifests an
//! operator reviewed and chose to import are the approval — importing them is
//! an explicit or governed operator action. Explicit imports stamp
//! `manifest-import`; automatic convergence stamps `manifest-reconcile` only
//! when it first sees a server or tool version, so a restart is not represented
//! as a fresh approval.
//! Without this, every imported tool would resolve as
//! `PendingApproval` and the per-call hot path couldn't dispatch it
//! until a durable live-schema observer exists. Imported rows still carry no
//! schema: invocation resolution completes their input contract from the
//! connected upstream's published `tools/list` snapshot and refuses dispatch
//! if neither source can provide one.
//!
//! ## schema_hash without schemas
//!
//! Legacy YAML manifests carry no input/output JSON schemas — only the
//! classification (name, risk, side_effects, pii). The importer hashes that
//! classification tuple as the version's `schema_hash`. Annotation-native
//! manifests instead carry the reviewed, schema-and-annotations-inclusive
//! `approved_behavior_hash`; the importer uses that exact value as the version
//! identity.
//! Re-importing an unchanged manifest produces the same hash
//! (idempotent UPSERT, no new version row); changing a
//! classification produces a new hash, hence a new version the
//! operator implicitly re-approves on the next import. If a
//! durable live-schema observer is added later, its richer schema-based hashes
//! would supersede these classification-only ones.
//!
//! ## Atomicity
//!
//! [`ManifestImporter::import`] imports each server inside its own
//! transaction: a partial write (server row inserted but a tool failed)
//! would leave the catalog inconsistent, so the whole
//! server+tools+versions+classifications set commits or rolls back
//! together. Servers are independent of each other — one bad server
//! doesn't abort the rest of the batch; its error is collected into
//! [`ImportStats::errors`].
//!
//! [`ManifestImporter::import_atomic`] imports the WHOLE batch in a single
//! transaction — all-or-nothing. A failure rolls back every server, so the
//! catalog is never left partially reclassified. Automatic full-set
//! reconciliation uses it because a partial catalog — where
//! `ResolvedTool::Live` facts outrank manifest facts in authz — is a
//! mixed-authorization hazard.

use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::types::CatalogError;

const AUTO_QUARANTINE_REASON: &str =
    "auto-quarantined: server absent from the reconciled manifest set";
const AUTO_RESTORE_REASON: &str = "auto-restored: server returned to the reconciled manifest set";

/// Neutral per-server import input. The caller (waygate-server)
/// maps `UpstreamManifest` into this so the catalog crate doesn't
/// depend on waygate-upstream.
#[derive(Debug, Clone)]
pub struct ImportServer {
    pub tenant_id: String,
    pub name: String,
    /// `"http"` | `"sse"` | `"stdio"` — matches the
    /// `mcp_servers.transport` CHECK constraint.
    pub transport: String,
    /// JSONB blob a future catalog-backed transport factory would
    /// consume. Shape mirrors the YAML manifest (`{"url": ...}` /
    /// `{"command": [...]}`).
    pub runtime_target: serde_json::Value,
    /// `"manifest"` for legacy classification or `"mcp_annotations"` for
    /// annotation-native behavior claims. Risk remains catalog-owned in both
    /// modes.
    pub classification_mode: String,
    pub tools: Vec<ImportTool>,
}

/// Neutral per-tool import input.
#[derive(Debug, Clone)]
pub struct ImportTool {
    pub name: String,
    /// Reviewed annotation-inclusive live behavior hash. When present this is
    /// the approved tool-version identity instead of the legacy manifest tuple.
    pub approved_behavior_hash: Option<String>,
    /// `"low"` | `"medium"` | `"high"` | `"critical"`.
    pub risk: String,
    pub side_effects: bool,
    pub pii: bool,
    /// Argument field whose value selects the operation a call performs.
    ///
    /// `None` classifies the tool by name alone, which is every tool whose
    /// operator has not opted into per-operation review.
    pub discriminator: Option<String>,
    /// Classifications for named discriminator values. A value with no entry
    /// is classified by the tool's own row, so an unrecognized operation is
    /// never weaker than the tool it arrived through.
    pub operations: Vec<ImportOperation>,
}

/// Neutral per-operation import input.
#[derive(Debug, Clone)]
pub struct ImportOperation {
    /// The discriminator value this classification applies to.
    pub value: String,
    /// `"low"` | `"medium"` | `"high"` | `"critical"`.
    pub risk: String,
    pub side_effects: bool,
    pub pii: bool,
}

/// The borrowed view the version identity hashes.
fn classified_operations(tool: &ImportTool) -> Vec<crate::ClassifiedOperation<'_>> {
    tool.operations
        .iter()
        .map(|operation| crate::ClassifiedOperation {
            value: &operation.value,
            risk: &operation.risk,
            side_effects: operation.side_effects,
            pii: operation.pii,
        })
        .collect()
}

/// Severity order, for the ceiling an operation may not exceed.
fn risk_rank(risk: &str) -> Option<u8> {
    match risk {
        "low" => Some(0),
        "medium" => Some(1),
        "high" => Some(2),
        "critical" => Some(3),
        _ => None,
    }
}

/// Aggregate outcome of an import run.
#[derive(Debug, Default, Clone)]
pub struct ImportStats {
    /// Servers successfully imported (inserted or updated).
    pub servers: u64,
    /// Tools successfully imported across all servers.
    pub tools: u64,
    /// Servers auto-quarantined because they are absent from the reconciled
    /// full set. Only nonzero when `quarantine_absent` is
    /// requested; status flips `live → quarantined` (never delete), so authz
    /// refuses them while an older pool generation or in-flight call still
    /// holds them.
    pub quarantined: u64,
    /// Per-server failures: `(server_name, error string)`. A
    /// failed server is rolled back whole; the rest of the batch
    /// proceeds. Non-empty means the operator should investigate
    /// before relying on the catalog.
    pub errors: Vec<(String, String)>,
}

/// One-shot importer over a `PgPool`.
pub struct ManifestImporter {
    pool: PgPool,
}

#[derive(Clone, Copy)]
enum ImportMode {
    Explicit,
    Reconcile,
}

impl ImportMode {
    fn preserve_status(self) -> bool {
        matches!(self, Self::Reconcile)
    }

    fn actor(self) -> &'static str {
        match self {
            Self::Explicit => "manifest-import",
            Self::Reconcile => "manifest-reconcile",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Explicit => "imported from servers/*.yaml",
            Self::Reconcile => "reconciled from an accepted manifest generation",
        }
    }

    fn deduplicate_evidence(self) -> bool {
        matches!(self, Self::Reconcile)
    }
}

impl ManifestImporter {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Import every server in `servers`. Each server commits in its
    /// own transaction; a failure is collected into
    /// [`ImportStats::errors`] and doesn't abort the rest.
    pub async fn import(&self, servers: &[ImportServer]) -> ImportStats {
        let mut stats = ImportStats::default();
        for server in servers {
            match self.import_one(server).await {
                Ok(tool_count) => {
                    stats.servers += 1;
                    stats.tools += tool_count;
                }
                Err(e) => {
                    tracing::warn!(
                        server = %server.name,
                        tenant = %server.tenant_id,
                        error = %e,
                        "manifest import: server failed; rolled back, continuing batch",
                    );
                    stats.errors.push((server.name.clone(), e.to_string()));
                }
            }
        }
        stats
    }

    /// Import one server + its tools inside its OWN transaction. Returns the
    /// number of tools imported. The per-server transaction boundary is what
    /// keeps the lenient batch [`import`](Self::import) resilient — one bad
    /// server rolls back alone and the rest of the batch continues.
    async fn import_one(&self, server: &ImportServer) -> Result<u64, CatalogError> {
        let mut tx = self.pool.begin().await.map_err(CatalogError::Database)?;
        // CLI / operator import: an explicit `--import-manifests` run is an
        // operator action that re-affirms the server as live (preserve_status =
        // false) — the pre-existing behavior.
        let tool_count = Self::import_one_in_tx(&mut tx, server, ImportMode::Explicit).await?;
        tx.commit().await.map_err(CatalogError::Database)?;
        Ok(tool_count)
    }

    /// Import every server in `servers` in a SINGLE transaction — all-or-nothing.
    /// Any failure returns early via `?`, dropping the transaction (rollback), so
    /// the catalog is NEVER left partially updated. Automatic full-set
    /// reconciliation uses this rather than [`import`](Self::import) because a
    /// partially-applied catalog — where `ResolvedTool::Live` facts outrank
    /// manifest facts in authz — is a mixed-authorization hazard (some tools
    /// reclassified, others not).
    ///
    /// Imports with `preserve_status = true` apply the accepted manifest
    /// generation without clearing an operator lifecycle block. A present server
    /// that an operator quarantined or retired keeps that status across the import
    /// while transport, runtime target, and classifications are refreshed. A
    /// server quarantined by this reconciler solely because it was absent returns
    /// to `live` when a later accepted full set contains it again.
    ///
    /// `tenant_id` names the tenant whose full set is being reconciled. Every
    /// input server must belong to it; the explicit tenant keeps an empty set
    /// meaningful without widening the quarantine to other tenants.
    ///
    /// When `quarantine_absent` is true, after importing the present set, flip
    /// any `live` server in this tenant that is absent from `servers` to
    /// `quarantined`. The supplied set is complete, so a removed server must stop
    /// being authorized even while an older in-memory generation or in-flight
    /// call still holds it. **Quarantine, not delete:** deleting the row would
    /// make `resolve_invocation_tool` fall through to the unknown-tool
    /// least-sensitive default (a permissive regression).
    /// Operator `quarantined`/`retired` (and `proposed`/`approved`) rows are left
    /// untouched — only `live` is flipped. Imports + absence-quarantine are ONE
    /// transaction (all-or-nothing). Callers MUST pass the FULL reconcile set.
    pub async fn import_atomic(
        &self,
        tenant_id: &str,
        servers: &[ImportServer],
        quarantine_absent: bool,
    ) -> Result<ImportStats, CatalogError> {
        if servers.iter().any(|server| server.tenant_id != tenant_id) {
            return Err(CatalogError::InvalidInput(format!(
                "atomic manifest reconcile for tenant {tenant_id} contains another tenant"
            )));
        }
        let mut tx = self.pool.begin().await.map_err(CatalogError::Database)?;
        // Fleet replicas may reconcile the same accepted generation at once.
        // Serialize this tenant's reconcile transactions so the idempotent
        // approval-evidence check below cannot race and append duplicates.
        sqlx::query(
            "SELECT pg_advisory_xact_lock(\
                hashtext('gateway-catalog-manifest-reconcile'), hashtext($1))",
        )
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(CatalogError::Database)?;
        let mut stats = ImportStats::default();
        for server in servers {
            let tool_count = Self::import_one_in_tx(&mut tx, server, ImportMode::Reconcile).await?;
            stats.servers += 1;
            stats.tools += tool_count;
        }
        if quarantine_absent {
            stats.quarantined = Self::quarantine_absent_in_tx(&mut tx, tenant_id, servers).await?;
        }
        tx.commit().await.map_err(CatalogError::Database)?;
        Ok(stats)
    }

    /// Flip `live` servers ABSENT from `servers` in `tenant_id` to
    /// `quarantined`, inside the caller's transaction. See [`import_atomic`]'s
    /// `quarantine_absent` for the rationale (authoritative full set; quarantine
    /// not delete; preserve operator/proposed states). An empty `servers` set
    /// quarantines every live row for this tenant and cannot affect any other
    /// tenant.
    async fn quarantine_absent_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: &str,
        servers: &[ImportServer],
    ) -> Result<u64, CatalogError> {
        let present: Vec<&str> = servers.iter().map(|server| server.name.as_str()).collect();
        // Only `live` rows are flipped: an operator `quarantined`/`retired`
        // block and `proposed`/`approved` lifecycle states are preserved.
        // RETURNING the affected ids so each transition gets an audit row.
        let flipped = sqlx::query(
            r#"
                UPDATE mcp_servers
                   SET status = 'quarantined', updated_at = now()
                 WHERE tenant_id = $1
                   AND status = 'live'
                   AND name <> ALL($2)
                RETURNING id
                "#,
        )
        .bind(tenant_id)
        .bind(&present)
        .fetch_all(&mut **tx)
        .await
        .map_err(CatalogError::Database)?;
        // Audit each auto-quarantine in the same transaction, mirroring the
        // operator status-transition path (`store.rs`) so an absence
        // quarantine is as traceable as an operator one.
        for row in &flipped {
            let server_id: Uuid = row.get("id");
            sqlx::query(
                r#"
                    INSERT INTO catalog_approvals
                        (id, tenant_id, subject_type, subject_id, subject_version_hash,
                         action, actor, reason)
                    VALUES ($1, $2, 'server', $3, NULL, 'quarantined', 'manifest-reconcile', $4)
                    "#,
            )
            .bind(Uuid::now_v7())
            .bind(tenant_id)
            .bind(server_id)
            .bind(AUTO_QUARANTINE_REASON)
            .execute(&mut **tx)
            .await
            .map_err(CatalogError::Database)?;
        }
        Ok(flipped.len() as u64)
    }

    /// Import one server + its tools into the caller's transaction (no
    /// begin/commit). Shared by [`import_one`](Self::import_one) (one tx per
    /// server, lenient batch) and [`import_atomic`](Self::import_atomic) (one tx
    /// for the whole batch, all-or-nothing).
    ///
    /// Explicit imports re-affirm approval and reset an existing server to
    /// `live`. Automatic reconciliation preserves an operator lifecycle block,
    /// records each server/tool-version approval once, and does not move
    /// approval timestamps merely because the process restarted. A new server
    /// always inserts as `live`.
    async fn import_one_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        server: &ImportServer,
        mode: ImportMode,
    ) -> Result<u64, CatalogError> {
        // A reconcile may clear only the exact quarantine previously created
        // by absence reconciliation. Lock the row while reading its latest
        // lifecycle evidence so a concurrent operator action cannot be
        // overwritten by this transaction.
        let restore_auto_quarantine = if matches!(mode, ImportMode::Reconcile) {
            sqlx::query_scalar::<_, bool>(
                r#"
                SELECT a.action = 'quarantined'
                       AND a.actor = 'manifest-reconcile'
                       AND a.reason = $3
                  FROM mcp_servers s
                  JOIN LATERAL (
                      SELECT action, actor, reason
                        FROM catalog_approvals
                       WHERE tenant_id = s.tenant_id
                         AND subject_type = 'server'
                         AND subject_id = s.id
                       ORDER BY created_at DESC, id DESC
                       LIMIT 1
                  ) a ON TRUE
                 WHERE s.tenant_id = $1
                   AND s.name = $2
                   AND s.status = 'quarantined'
                 FOR UPDATE OF s
                "#,
            )
            .bind(&server.tenant_id)
            .bind(&server.name)
            .bind(AUTO_QUARANTINE_REASON)
            .fetch_optional(&mut **tx)
            .await
            .map_err(CatalogError::Database)?
            .unwrap_or(false)
        } else {
            false
        };

        // UPSERT the server. A NEW row inserts as `status = 'live'` because the
        // manifest generation is approved by import. On CONFLICT, automatic
        // reconciliation preserves operator lifecycle state but restores a
        // reconcile-owned absence quarantine when the server returns. An
        // explicit CLI import continues to reset the row to `live`.
        let server_id: Uuid = sqlx::query(
            r#"
            INSERT INTO mcp_servers
                (id, tenant_id, name, transport, runtime_target, classification_mode, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'live')
            ON CONFLICT (tenant_id, name) DO UPDATE
                SET transport      = EXCLUDED.transport,
                    runtime_target = EXCLUDED.runtime_target,
                    classification_mode = EXCLUDED.classification_mode,
                    status         = CASE
                        WHEN NOT $7 OR $8 THEN 'live'
                        ELSE mcp_servers.status
                    END,
                    updated_at     = CASE
                        WHEN NOT $7 OR $8
                          OR (mcp_servers.transport,
                              mcp_servers.runtime_target,
                              mcp_servers.classification_mode)
                             IS DISTINCT FROM
                             (EXCLUDED.transport,
                              EXCLUDED.runtime_target,
                              EXCLUDED.classification_mode)
                        THEN GREATEST(
                            clock_timestamp(),
                            mcp_servers.updated_at + interval '1 microsecond'
                        )
                        ELSE mcp_servers.updated_at
                    END
            RETURNING id
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(&server.tenant_id)
        .bind(&server.name)
        .bind(&server.transport)
        .bind(&server.runtime_target)
        .bind(&server.classification_mode)
        .bind(mode.preserve_status())
        .bind(restore_auto_quarantine)
        .fetch_one(&mut **tx)
        .await
        .map_err(CatalogError::Database)?
        .get("id");

        if restore_auto_quarantine {
            sqlx::query(
                r#"
                INSERT INTO catalog_approvals
                    (id, tenant_id, subject_type, subject_id, subject_version_hash,
                     action, actor, reason)
                VALUES ($1, $2, 'server', $3, NULL, 'approved', 'manifest-reconcile', $4)
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(&server.tenant_id)
            .bind(server_id)
            .bind(AUTO_RESTORE_REASON)
            .execute(&mut **tx)
            .await
            .map_err(CatalogError::Database)?;
        }

        // Record the server approval: the importer is a write-boundary that
        // records approvals, so the audit trail must identify the explicit
        // import or automatic accepted-generation reconcile rather than only
        // showing the mutated catalog row.
        insert_approval(&mut *tx, &server.tenant_id, "server", server_id, None, mode).await?;

        let mut tool_count = 0u64;
        let mut authorization_facts_changed = false;
        for tool in &server.tools {
            // UPSERT the tool identity.
            let tool_id: Uuid = sqlx::query(
                r#"
                INSERT INTO mcp_tools (id, server_id, name)
                VALUES ($1, $2, $3)
                ON CONFLICT (server_id, name) DO UPDATE SET name = EXCLUDED.name
                RETURNING id
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(server_id)
            .bind(&tool.name)
            .fetch_one(&mut **tx)
            .await
            .map_err(CatalogError::Database)?
            .get("id");

            // The ceiling: a tool must be at least as severe as every
            // operation it names, or a value nobody listed would be treated
            // more leniently than one somebody already assessed as dangerous.
            // The manifest loader refuses this too; it is checked again here
            // because this is the only writer of these rows, and a ceiling
            // enforced at one of two doors is not enforced.
            let tool_rank = risk_rank(&tool.risk)
                .ok_or_else(|| CatalogError::InvalidInput(format!("risk {}", tool.risk)))?;
            for operation in &tool.operations {
                let rank = risk_rank(&operation.risk).ok_or_else(|| {
                    CatalogError::InvalidInput(format!("risk {}", operation.risk))
                })?;
                if rank > tool_rank
                    || (operation.side_effects && !tool.side_effects)
                    || (operation.pii && !tool.pii)
                {
                    return Err(CatalogError::InvalidInput(format!(
                        "operation {} of tool {} exceeds its tool classification",
                        operation.value, tool.name
                    )));
                }
            }

            // UPSERT the classification (one row per tool).
            let classification_result = sqlx::query(
                r#"
                INSERT INTO tool_classifications
                    (tool_id, risk, side_effects, pii, discriminator, reviewed_at, reviewer)
                VALUES ($1, $2, $3, $4, $5, now(), $6)
                ON CONFLICT (tool_id) DO UPDATE
                    SET risk          = EXCLUDED.risk,
                        side_effects  = EXCLUDED.side_effects,
                        pii           = EXCLUDED.pii,
                        discriminator = EXCLUDED.discriminator,
                        reviewed_at   = now(),
                        reviewer      = EXCLUDED.reviewer
                    WHERE $7 OR (tool_classifications.risk,
                                 tool_classifications.side_effects,
                                 tool_classifications.pii,
                                 tool_classifications.discriminator)
                                IS DISTINCT FROM
                                    (EXCLUDED.risk, EXCLUDED.side_effects,
                                     EXCLUDED.pii, EXCLUDED.discriminator)
                "#,
            )
            .bind(tool_id)
            .bind(&tool.risk)
            .bind(tool.side_effects)
            .bind(tool.pii)
            .bind(tool.discriminator.as_deref())
            .bind(mode.actor())
            .bind(matches!(mode, ImportMode::Explicit))
            .execute(&mut **tx)
            .await
            .map_err(CatalogError::Database)?;
            authorization_facts_changed |= classification_result.rows_affected() > 0;

            // The operation rows are replaced, not merged: the manifest is the
            // whole reviewed set for this tool, so a value it no longer names
            // must lose its refinement and fall back to the tool's row rather
            // than linger as a narrower grant nobody can see in the source.
            let removed = sqlx::query(
                "DELETE FROM tool_operation_classifications \
                  WHERE tool_id = $1 AND operation <> ALL($2)",
            )
            .bind(tool_id)
            .bind(
                tool.operations
                    .iter()
                    .map(|operation| operation.value.clone())
                    .collect::<Vec<_>>(),
            )
            .execute(&mut **tx)
            .await
            .map_err(CatalogError::Database)?;
            authorization_facts_changed |= removed.rows_affected() > 0;

            for operation in &tool.operations {
                // Marked reviewed on arrival, like the tool row beside it: the
                // manifest IS the operator's reviewed set, and a refinement
                // left unreviewed would be silently ignored by the read path.
                let operation_result = sqlx::query(
                    r#"
                    INSERT INTO tool_operation_classifications
                        (tool_id, operation, risk, side_effects, pii, reviewed_at, reviewer)
                    VALUES ($1, $2, $3, $4, $5, now(), $6)
                    ON CONFLICT (tool_id, operation) DO UPDATE
                        SET risk         = EXCLUDED.risk,
                            side_effects = EXCLUDED.side_effects,
                            pii          = EXCLUDED.pii,
                            reviewed_at  = now(),
                            reviewer     = EXCLUDED.reviewer
                        WHERE $7 OR (tool_operation_classifications.risk,
                                     tool_operation_classifications.side_effects,
                                     tool_operation_classifications.pii,
                                     tool_operation_classifications.reviewed_at IS NULL)
                                    IS DISTINCT FROM
                                        (EXCLUDED.risk, EXCLUDED.side_effects,
                                         EXCLUDED.pii, false)
                    "#,
                )
                .bind(tool_id)
                .bind(&operation.value)
                .bind(&operation.risk)
                .bind(operation.side_effects)
                .bind(operation.pii)
                .bind(mode.actor())
                .bind(matches!(mode, ImportMode::Explicit))
                .execute(&mut **tx)
                .await
                .map_err(CatalogError::Database)?;
                authorization_facts_changed |= operation_result.rows_affected() > 0;
            }

            // INSERT the approved version. schema_hash is derived from the
            // classification tuple (no real schema in YAML). An explicit
            // import always re-affirms an existing version. Automatic
            // convergence advances the timestamp only when it activates a
            // different version; this keeps routine restarts idempotent while
            // making A -> B -> A rollback select A again.
            let schema_hash = if server.classification_mode == "mcp_annotations" {
                tool.approved_behavior_hash
                    .clone()
                    .ok_or(CatalogError::Unknown("approved behavior hash"))?
            } else {
                crate::manifest_classification_hash(
                    &tool.name,
                    &tool.risk,
                    tool.side_effects,
                    tool.pii,
                    tool.discriminator.as_deref(),
                    &classified_operations(tool),
                )
            };
            let activate_version = if matches!(mode, ImportMode::Explicit) {
                true
            } else {
                let selected_hash = sqlx::query_scalar::<_, String>(
                    r#"
                    SELECT schema_hash
                      FROM mcp_tool_versions
                     WHERE tool_id = $1 AND approved_at IS NOT NULL
                     ORDER BY approved_at DESC
                     LIMIT 1
                    "#,
                )
                .bind(tool_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(CatalogError::Database)?;
                selected_hash.as_deref() != Some(schema_hash.as_str())
            };
            let version_result = sqlx::query(
                r#"
                WITH activation AS (
                    SELECT GREATEST(
                        clock_timestamp(),
                        COALESCE(
                            MAX(approved_at) + interval '1 microsecond',
                            clock_timestamp()
                        )
                    ) AS approved_at
                      FROM mcp_tool_versions
                     WHERE tool_id = $1
                )
                INSERT INTO mcp_tool_versions
                    (tool_id, schema_hash, description, input_schema, output_schema,
                     approved_at, approved_by)
                SELECT $1, $2, $3, NULL, NULL, activation.approved_at, $4
                  FROM activation
                ON CONFLICT (tool_id, schema_hash) DO UPDATE
                    SET approved_at = EXCLUDED.approved_at,
                        approved_by = EXCLUDED.approved_by
                    WHERE $5
                "#,
            )
            .bind(tool_id)
            .bind(&schema_hash)
            .bind(format!("imported from manifest: {}", tool.name))
            .bind(mode.actor())
            .bind(activate_version)
            .execute(&mut **tx)
            .await
            .map_err(CatalogError::Database)?;
            authorization_facts_changed |= version_result.rows_affected() > 0;

            // Record the tool_version approval, naming the
            // schema_hash (the composite-key discriminator that
            // disambiguates which version was approved — see
            // `mcp_tool_versions`'s composite PK). The
            // classification + tool identity are subordinate to
            // the version approval, so a single tool_version row
            // per tool is the meaningful audit entry.
            insert_approval(
                &mut *tx,
                &server.tenant_id,
                "tool_version",
                tool_id,
                Some(&schema_hash),
                mode,
            )
            .await?;

            tool_count += 1;
        }

        if matches!(mode, ImportMode::Reconcile) && authorization_facts_changed {
            // Governed lifecycle transitions use the parent timestamp as their
            // compare-and-swap witness. Advance it only when authorization-
            // bearing child facts changed, so a pending transition cannot
            // commit against a generation other than the one reviewed.
            sqlx::query(
                r#"
                UPDATE mcp_servers
                   SET updated_at = GREATEST(
                       clock_timestamp(),
                       updated_at + interval '1 microsecond'
                   )
                 WHERE id = $1
                "#,
            )
            .bind(server_id)
            .execute(&mut **tx)
            .await
            .map_err(CatalogError::Database)?;
        }

        Ok(tool_count)
    }
}

/// Insert a `catalog_approvals` row inside the importer's transaction. Automatic
/// convergence records a subject/version once; explicit imports deliberately
/// re-affirm approval on every invocation. `version_hash` is `Some` only for
/// `subject_type = "tool_version"` (the DB CHECK enforces the pairing).
async fn insert_approval(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    subject_type: &str,
    subject_id: Uuid,
    version_hash: Option<&str>,
    mode: ImportMode,
) -> Result<(), CatalogError> {
    sqlx::query(
        r#"
        INSERT INTO catalog_approvals
            (id, tenant_id, subject_type, subject_id, subject_version_hash,
             action, actor, reason)
        SELECT $1, $2, $3, $4, $5, 'approved', $6, $7
         WHERE NOT $8
            OR NOT EXISTS (
                SELECT 1
                  FROM catalog_approvals
                 WHERE tenant_id = $2
                   AND subject_type = $3
                   AND subject_id = $4
                   AND subject_version_hash IS NOT DISTINCT FROM $5
                   AND action = 'approved'
                   AND actor = $6
                   AND reason = $7
            )
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(subject_type)
    .bind(subject_id)
    .bind(version_hash)
    .bind(mode.actor())
    .bind(mode.reason())
    .bind(mode.deduplicate_evidence())
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(CatalogError::Database)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classification_hash(tool: &ImportTool) -> String {
        crate::manifest_classification_hash(
            &tool.name,
            &tool.risk,
            tool.side_effects,
            tool.pii,
            tool.discriminator.as_deref(),
            &classified_operations(tool),
        )
    }

    fn tool(name: &str, risk: &str, side_effects: bool, pii: bool) -> ImportTool {
        ImportTool {
            name: name.into(),
            approved_behavior_hash: None,
            risk: risk.into(),
            side_effects,
            pii,
            discriminator: None,
            operations: Vec::new(),
        }
    }

    #[test]
    fn classification_hash_is_stable() {
        let t = tool("send", "high", true, false);
        assert_eq!(classification_hash(&t), classification_hash(&t));
    }

    #[test]
    fn classification_hash_changes_with_each_field() {
        let base = tool("send", "high", true, false);
        let base_h = classification_hash(&base);
        assert_ne!(
            base_h,
            classification_hash(&tool("recv", "high", true, false))
        );
        assert_ne!(
            base_h,
            classification_hash(&tool("send", "low", true, false))
        );
        assert_ne!(
            base_h,
            classification_hash(&tool("send", "high", false, false))
        );
        assert_ne!(
            base_h,
            classification_hash(&tool("send", "high", true, true))
        );
    }

    #[test]
    fn classification_hash_no_separator_collision() {
        // ("a", "bc", ...) vs ("ab", "c", ...) must differ — the
        // \x00 separators prevent the concatenation collision.
        let a = tool("a", "bc", false, false);
        let b = tool("ab", "c", false, false);
        assert_ne!(classification_hash(&a), classification_hash(&b));
    }

    #[test]
    fn import_stats_default_is_empty() {
        let s = ImportStats::default();
        assert_eq!(s.servers, 0);
        assert_eq!(s.tools, 0);
        assert!(s.errors.is_empty());
    }

    #[tokio::test]
    async fn atomic_import_rejects_a_server_from_another_tenant_before_db_access() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy never dials");
        let importer = ManifestImporter::new(pool);
        let server = ImportServer {
            tenant_id: "neighbor".into(),
            name: "server".into(),
            transport: "http".into(),
            runtime_target: serde_json::json!({ "url": "http://x.test/mcp" }),
            classification_mode: "manifest".into(),
            tools: Vec::new(),
        };

        let error = importer
            .import_atomic("expected", &[server], true)
            .await
            .expect_err("cross-tenant input must be rejected");
        assert!(matches!(error, CatalogError::InvalidInput(_)));
    }
}
