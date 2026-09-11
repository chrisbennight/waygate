//! Shared builders, fakes, and request helpers — split from the monolithic
//! `dashboard_render.rs`; bodies verbatim, cut at the file's own
//! section markers.

//! Dashboard route tests: every page must render, critical fragments must
//! carry their htmx hooks, and the audit-aware routes must degrade cleanly
//! when no audit store is configured.
//!
//! We don't stand up a real Postgres here; we use a tiny in-memory
//! `AuditReader` fake to test filter logic and the drawer route without
//! dragging sqlx into the test runtime.

pub(crate) use std::collections::BTreeMap;
pub(crate) use std::sync::Arc;
pub(crate) use waygate_test_support::admin::{
    base_admin_state, base_admin_state_with_pool, example_messages_manifest,
};
pub(crate) use waygate_test_support::mocks::InMemoryManifestStore;

pub(crate) use async_trait::async_trait;
pub(crate) use axum::body::Body;
pub(crate) use axum::http::{Request, StatusCode};
pub(crate) use tower::util::ServiceExt;

pub(crate) use time::OffsetDateTime;
pub(crate) use uuid::Uuid;
pub(crate) use waygate_admin::{
    api_router, dashboard_router, AdminState, DashboardAuth, DashboardOidcConfig,
};
pub(crate) use waygate_authz::{CedarEngine, ReloadableCedar};
pub(crate) use waygate_changeset::ChangeRequestStore as _;
pub(crate) use waygate_oidc::{IdTokenValidator, JwksProvider, OidcEndpoints, SessionKey};
pub(crate) use waygate_storage::{
    AuditFacets, AuditQuery, AuditReader, AuditRow, HistogramBucket, ToolStat,
};
pub(crate) use waygate_upstream::pool::UpstreamPool;
pub(crate) use waygate_upstream::{Transport, UpstreamManifest};

// ---- test state builders --------------------------------------------------

pub(crate) async fn empty_state() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(base_admin_state_with_pool(pool))
}

pub(crate) async fn state_with_manifests() -> Arc<AdminState> {
    Arc::new(base_admin_state())
}

/// A state whose config-health signal is healthy or degraded, for the
/// Servers-page stale banner.
pub(crate) async fn state_with_config_health(degraded: bool) -> Arc<AdminState> {
    let health: waygate_upstream::SharedConfigHealth =
        Arc::new(waygate_upstream::ConfigHealth::default());
    if degraded {
        health.set_degraded("reload refused — serving the previous set: bad yaml");
    } else {
        health.set_healthy("1 upstream(s) loaded from servers/*.yaml");
    }
    Arc::new(base_admin_state().with_config_health(health))
}

#[tokio::test]
pub(crate) async fn servers_page_shows_stale_config_banner_when_degraded() {
    let app = dashboard_router(
        state_with_config_health(true).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/servers").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Config STALE"),
        "degraded config must render the stale banner: {body}"
    );
    assert!(
        body.contains("reload refused"),
        "the stale banner must carry the reason"
    );
    assert!(
        body.contains("role=\"alert\""),
        "the stale banner must be an alert region"
    );
}

#[tokio::test]
pub(crate) async fn servers_page_no_stale_banner_when_healthy() {
    let app = dashboard_router(
        state_with_config_health(false).await,
        DashboardAuth::Disabled,
    );
    let (_, body) = body_of(app, "/servers").await;
    assert!(
        !body.contains("Config STALE"),
        "a healthy config must not render the stale banner"
    );
}

/// Minimal deny-everyone policy set so the policies page + simulator have
/// something to chew on. Cedar's empty-policy-set semantics deny by default,
/// so an explicit forbid rule gives us a deterministic "deny" decision.
pub(crate) const DENY_ALL_POLICY: &str = r#"
// Test: forbid everything to keep the simulator response deterministic.
forbid(principal, action, resource);
"#;

// Two annotated policies in different layers — exercises the layered grouping,
// stable ids, descriptions, tags, and @reason surfaced by the Policies pane.
pub(crate) const LAYERED_POLICY: &str = r#"
@id("baseline-discovery")
@layer("baseline")
@description("Any authenticated principal may list and search tools.")
@tags("discovery, baseline")
permit (principal, action == Action::"SearchTools", resource);

@id("step-up-delete-dataset")
@layer("step-up-overlay")
@description("delete_dataset requires a fresh mcp:invoke:high step-up scope.")
@tags("step-up, high, security")
@reason("delete_dataset requires the mcp:invoke:high step-up scope")
forbid (principal, action == Action::"CallTool", resource is Tool)
when { resource.name == "delete_dataset" && !principal.scopes.contains("mcp:invoke:high") };
"#;

pub(crate) async fn state_with_cedar() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source(DENY_ALL_POLICY).unwrap(),
    ));
    Arc::new(AdminState::new(
        pool,
        Some(engine),
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

pub(crate) async fn state_with_layered_cedar() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source(LAYERED_POLICY).unwrap(),
    ));
    Arc::new(AdminState::new(
        pool,
        Some(engine),
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

// Baseline-style read-only grant: a low-risk tool is permitted only when it has
// no side effects. Lets a test prove the simulator's side_effects checkbox
// actually flows into the decision.
pub(crate) const READONLY_LOW_POLICY: &str = r#"
@id("ro-low-tools")
@layer("baseline")
permit (principal, action == Action::"CallTool", resource is Tool)
when { resource.risk == "low" && !resource.side_effects };
"#;

pub(crate) async fn state_with_readonly_low_policy() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source(READONLY_LOW_POLICY).unwrap(),
    ));
    Arc::new(AdminState::new(
        pool,
        Some(engine),
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

// ---- in-memory audit reader fake ------------------------------------------

pub(crate) struct MemoryAudit {
    pub(crate) rows: Vec<AuditRow>,
}

#[async_trait]
impl AuditReader for MemoryAudit {
    async fn recent_notable(
        &self,
        tenant: &str,
        since: time::OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        let mut rows: Vec<_> = self
            .rows
            .iter()
            .filter(|r| {
                r.tenant_id == tenant
                    && r.ts >= since
                    && r.outcome != "success"
                    && r.reason.as_deref() != Some("pre_call")
            })
            .cloned()
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse((r.ts, r.id)));
        rows.truncate(limit.clamp(1, 500) as usize);
        Ok(rows)
    }

    async fn recent_events(
        &self,
        limit: i64,
        after_id: Option<Uuid>,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        let limit = limit.clamp(1, 500) as usize;
        let out: Vec<AuditRow> = self
            .rows
            .iter()
            .filter(|r| match after_id {
                Some(a) => r.id < a,
                None => true,
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(out)
    }

    async fn query_events(
        &self,
        query: &AuditQuery,
        limit: i64,
        after_id: Option<Uuid>,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        // In-memory mirror of PgAuditSink::query_events: apply the keyset
        // cursor + every predicate (via AuditQuery::matches), then take the
        // page. This fake filters across ALL rows so a matching row beyond
        // the newest 50 is still found — the exact behaviour the SQL
        // pushdown gives.
        let limit = limit.clamp(1, 500) as usize;
        let out: Vec<AuditRow> = self
            .rows
            .iter()
            .filter(|r| match after_id {
                Some(a) => r.id < a,
                None => true,
            })
            .filter(|r| query.matches(r))
            .take(limit)
            .cloned()
            .collect();
        Ok(out)
    }

    async fn facet_counts(&self, query: &AuditQuery) -> Result<AuditFacets, sqlx::Error> {
        fn tally<I: IntoIterator<Item = String>>(it: I) -> Vec<(String, i64)> {
            let mut m: BTreeMap<String, i64> = BTreeMap::new();
            for v in it {
                *m.entry(v).or_insert(0) += 1;
            }
            m.into_iter().collect()
        }
        // Tenant scope (security) + time window only; categorical filters do
        // not narrow facets. Mirrors PgAuditSink::facet_counts.
        let win: Vec<&AuditRow> = self
            .rows
            .iter()
            .filter(|r| {
                query
                    .tenant_id
                    .as_deref()
                    .map(|t| r.tenant_id == t)
                    .unwrap_or(true)
                    && query.since.map(|lb| r.ts >= lb).unwrap_or(true)
                    && query.until.map(|ub| r.ts <= ub).unwrap_or(true)
            })
            .collect();
        Ok(AuditFacets {
            outcome: tally(win.iter().map(|r| r.outcome.clone())),
            risk: tally(win.iter().filter_map(|r| r.risk_level.clone())),
            category: tally(win.iter().map(|r| {
                r.category
                    .clone()
                    .unwrap_or_else(|| "invocation".to_owned())
            })),
            pii: tally(win.iter().filter_map(|r| {
                r.pii.map(|b| {
                    if b {
                        "true".to_owned()
                    } else {
                        "false".to_owned()
                    }
                })
            })),
            server: tally(win.iter().filter_map(|r| r.server.clone())),
        })
    }

    async fn tool_stats(
        &self,
        query: &AuditQuery,
        limit: i64,
    ) -> Result<Vec<ToolStat>, sqlx::Error> {
        use std::collections::BTreeMap;
        // percentile_cont(0.95) with linear interpolation over sorted,
        // non-null latencies — mirrors Postgres's ordered-set aggregate.
        fn p95(mut v: Vec<i64>) -> Option<f64> {
            if v.is_empty() {
                return None;
            }
            v.sort_unstable();
            if v.len() == 1 {
                return Some(v[0] as f64);
            }
            let rank = 0.95 * (v.len() - 1) as f64;
            let lo = rank.floor() as usize;
            let hi = rank.ceil() as usize;
            let frac = rank - lo as f64;
            Some(v[lo] as f64 + frac * (v[hi] as f64 - v[lo] as f64))
        }
        let limit = limit.clamp(1, 200) as usize;
        let mut groups: BTreeMap<(String, String), Vec<&AuditRow>> = BTreeMap::new();
        for r in self
            .rows
            .iter()
            .filter(|r| query.matches(r))
            // Exclude fail-closed pre-dispatch intent rows (reason='pre_call';
            // see PgAuditSink::tool_stats) — they pair with a later outcome row.
            .filter(|r| r.reason.as_deref() != Some("pre_call"))
        {
            if let (Some(s), Some(t)) = (r.server.as_deref(), r.tool.as_deref()) {
                groups
                    .entry((s.to_owned(), t.to_owned()))
                    .or_default()
                    .push(r);
            }
        }
        let mut stats: Vec<ToolStat> = groups
            .into_iter()
            .map(|((server, tool), rows)| {
                let total = rows.len() as i64;
                let errors = rows
                    .iter()
                    .filter(|r| r.outcome == "execution_error")
                    .count() as i64;
                let denied = rows.iter().filter(|r| r.outcome == "denied").count() as i64;
                let lat: Vec<i64> = rows.iter().filter_map(|r| r.latency_ms).collect();
                ToolStat {
                    server,
                    tool,
                    total,
                    errors,
                    denied,
                    p95_latency_ms: p95(lat),
                }
            })
            .collect();
        stats.sort_by(|a, b| {
            b.total
                .cmp(&a.total)
                .then_with(|| a.server.cmp(&b.server))
                .then_with(|| a.tool.cmp(&b.tool))
        });
        stats.truncate(limit);
        Ok(stats)
    }

    async fn histogram(
        &self,
        query: &AuditQuery,
        bucket_seconds: i64,
    ) -> Result<Vec<HistogramBucket>, sqlx::Error> {
        use std::collections::BTreeMap;
        let bucket_seconds = bucket_seconds.max(1);
        let mut counts: BTreeMap<(i64, String), i64> = BTreeMap::new();
        for r in self
            .rows
            .iter()
            .filter(|r| query.matches(r))
            .filter(|r| r.reason.as_deref() != Some("pre_call"))
        {
            let bucket = (r.ts.unix_timestamp() / bucket_seconds) * bucket_seconds;
            *counts.entry((bucket, r.outcome.clone())).or_insert(0) += 1;
        }
        Ok(counts
            .into_iter()
            .map(|((bucket_epoch, outcome), count)| HistogramBucket {
                bucket_epoch,
                outcome,
                count,
            })
            .collect())
    }

    async fn fetch_event(&self, id: Uuid) -> Result<Option<AuditRow>, sqlx::Error> {
        Ok(self.rows.iter().find(|r| r.id == id).cloned())
    }

    async fn count_events_by_sub_since(
        &self,
        sub: &str,
        since: time::OffsetDateTime,
        exclude_issuer: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        Ok(self
            .rows
            .iter()
            .filter(|r| r.principal_sub.as_deref() == Some(sub) && r.ts >= since)
            .filter(|r| match exclude_issuer {
                Some(excl) => r.issuer.as_deref() != Some(excl),
                None => true,
            })
            .count() as i64)
    }

    async fn verify_chain(
        &self,
        tenant_id: &str,
        from: Option<time::OffsetDateTime>,
        to: Option<time::OffsetDateTime>,
        _after_chain_seq: Option<i64>,
        _limit: i64,
    ) -> Result<waygate_storage::ChainVerifyReport, sqlx::Error> {
        // Dashboard-render tests don't exercise the chain
        // verifier (it has its own coverage); this fake just
        // returns the empty-window outcome so the trait
        // stays satisfied.
        Ok(waygate_storage::ChainVerifyReport {
            tenant_id: tenant_id.to_owned(),
            from,
            to,
            rows_walked: 0,
            status: waygate_storage::ChainVerifyStatus::Empty,
            first_mismatch: None,
            truncated: false,
            next_after_chain_seq: None,
            chain_head: None,
        })
    }

    async fn fetch_events_for_bundle(
        &self,
        _tenant_id: &str,
        _from: time::OffsetDateTime,
        _to: time::OffsetDateTime,
        _principal_sub: Option<&str>,
        _tool: Option<&str>,
        _limit: i64,
    ) -> Result<(Vec<AuditRow>, bool), sqlx::Error> {
        // Dashboard-render tests don't exercise the bundle
        // exporter; bundle is its own integration test path.
        Ok((Vec::new(), false))
    }
}

pub(crate) fn sample_row(outcome: &str, server: Option<&str>, risk: Option<&str>) -> AuditRow {
    AuditRow {
        operation: None,
        id: Uuid::now_v7(),
        ts: OffsetDateTime::now_utc(),
        category: Some("invocation".into()),
        tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
        action: "CallTool".into(),
        outcome: outcome.into(),
        principal_sub: Some("alice@example.com".into()),
        principal_email: Some("alice@example.com".into()),
        principal_groups: vec!["mcp-users".into()],
        issuer: Some("https://idp.example.com".into()),
        server: server.map(|s| s.into()),
        tool: Some("send_msg".into()),
        risk_level: risk.map(|r| r.into()),
        pii: None,
        policy_ids: vec!["policy0".into()],
        reason: Some("group not permitted".into()),
        trace_id: Some("00000000000000000000000000000001".into()),
        latency_ms: Some(42),
        scim_active: None,
        scim_groups: Vec::new(),
        target: None,
        req_scopes: Vec::new(),
        auth_method: None,
        req_roles: Vec::new(),
        side_effects: None,
        invocation_hierarchy: None,
    }
}

/// Tier-0: `recent_by_category` yields the most-recent rows of the EXACT
/// category, tenant-scoped. The Overview "what changed" feed relies on this,
/// and this exercises the trait's default body (delegating to `query_events`)
/// that every non-Postgres reader inherits — the Postgres impl overrides it
/// with a sargable `category = $` for speed, but must return the same rows.
#[tokio::test]
pub(crate) async fn recent_by_category_filters_to_exact_category() {
    let mk = |cat: &str| {
        let mut r = sample_row("success", Some("srv"), None);
        r.category = Some(cat.to_owned());
        r
    };
    let reader = MemoryAudit {
        rows: vec![
            mk("invocation"),
            mk("manifest_reload"),
            mk("invocation"),
            mk("manifest_reload"),
        ],
    };
    let got = reader
        .recent_by_category(waygate_core::TenantId::DEFAULT, "manifest_reload", 5)
        .await
        .expect("recent_by_category");
    assert_eq!(got.len(), 2, "only the manifest_reload rows are returned");
    assert!(got
        .iter()
        .all(|r| r.category.as_deref() == Some("manifest_reload")));
    // A category with no rows returns empty — the policy_reload=0 case that
    // previously full-scanned the table via the COALESCE filter.
    let empty = reader
        .recent_by_category(waygate_core::TenantId::DEFAULT, "policy_reload", 5)
        .await
        .expect("recent_by_category empty");
    assert!(empty.is_empty());
}

/// Admin state serving exactly the rows a test supplies.
pub(crate) async fn state_with_audit_reader(audit: Arc<dyn AuditReader>) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

pub(crate) async fn state_with_audit() -> (Arc<AdminState>, Uuid) {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // Outcome strings here match `AuditOutcome::as_str()` — the
    // canonical wire form persisted to `audit_log.outcome`. The UI
    // (dashboard counters + activity templates) reads the same strings.
    let rows = vec![
        sample_row("denied", Some("example-messages"), Some("high")),
        sample_row("success", Some("example-observability"), Some("low")),
        sample_row("step_up_required", Some("example-messages"), Some("high")),
    ];
    let deny_id = rows[0].id;
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
    (
        Arc::new(AdminState::new(
            pool,
            None,
            Some(audit),
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )),
        deny_id,
    )
}

// ---- helpers --------------------------------------------------------------

pub(crate) async fn body_of(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}
