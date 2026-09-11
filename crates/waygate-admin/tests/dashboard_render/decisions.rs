//! Decisions queue, decision log, changes preview — split from the
//! monolithic `dashboard_render.rs`; bodies verbatim, cut at the file's
//! own section markers.

use crate::common::*;
use crate::crud_pages::seed_bg_token;
use crate::crud_pages::FakeBreakGlassStore;
use crate::editors::seeded_bundle;
use crate::editors::InMemoryPolicyStore;
use crate::servers::{example_messages_bundle_content, servers_dir_from_content};

// ---- Merged Decisions queue ------------------------------------------

pub(crate) async fn state_with_decision_stores(
    cr: Arc<dyn waygate_changeset::ChangeRequestStore>,
    bg: Arc<dyn waygate_authz::BreakGlassStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    Arc::new(
        AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_break_glass_store(Some(bg))
        .with_change_request_store(Some(cr)),
    )
}

pub(crate) async fn seed_pending_cr(
    store: &waygate_changeset::InMemoryChangeRequestStore,
    tenant: &str,
    requested_by: &str,
) -> Uuid {
    store
        .propose(waygate_changeset::NewChangeRequest {
            tenant_id: tenant.into(),
            requested_by: requested_by.into(),
            client_id: None,
            action_type: "api_key.mint".into(),
            params: serde_json::json!({ "scopes": ["mcp:read"] }),
            preview: None,
            target_etag: None,
            justification: "nightly sync needs read-only catalog access".into(),
            requirement: waygate_changeset::ApprovalRequirement::single("dashboard-admins"),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        })
        .await
        .unwrap()
        .id
}

async fn state_with_manifest_impact_request(
    classification_mode: waygate_upstream::ClassificationMode,
) -> Arc<AdminState> {
    let mut candidate = example_messages_manifest();
    candidate.name = "grounded-docs".to_owned();
    candidate.url = Some("http://grounded-docs-mcp:6280/mcp".to_owned());
    let annotation_native = matches!(
        classification_mode,
        waygate_upstream::ClassificationMode::McpAnnotations
    );
    candidate.classification_mode = classification_mode;
    let exemplar = candidate.tools[0].clone();
    let operation_fixture = (!annotation_native).then(|| {
        let mut fixture = waygate_upstream::parse_manifest_set(
            "- name: operation-fixture\n  transport: http\n  url: http://fixture.local\n  tools:\n    - name: executor\n      risk: low\n      discriminator: operation\n      operations:\n        - value: search\n          risk: low\n",
        )
        .expect("operation manifest fixture parses");
        let mut manifest = fixture
            .remove("operation-fixture")
            .expect("operation fixture server exists");
        manifest.tools.remove(0).operations.remove(0)
    });
    candidate.tools = (0..10)
        .map(|index| {
            let mut tool = exemplar.clone();
            tool.name = format!("docs_tool_{index}");
            tool.approved_behavior_hash = annotation_native.then(|| "a".repeat(64));
            tool.side_effects = false;
            tool.pii = false;
            if !annotation_native {
                tool.discriminator = Some("operation".into());
                tool.operations = vec![operation_fixture
                    .clone()
                    .expect("manifest-mode fixture has an operation")];
            }
            tool
        })
        .collect();
    let candidate_content = waygate_upstream::serialize_manifest_set(&BTreeMap::from([(
        candidate.name.clone(),
        candidate,
    )]))
    .expect("serialize candidate manifest");

    let changes = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    changes
        .propose(waygate_changeset::NewChangeRequest {
            tenant_id: "default".into(),
            requested_by: "grounded-docs-enablement".into(),
            client_id: None,
            action_type: "manifest.upsert_servers".into(),
            params: serde_json::json!({ "content": candidate_content }),
            preview: None,
            target_etag: None,
            justification: "restore governed documentation access".into(),
            requirement: waygate_changeset::ApprovalRequirement::single("dashboard-admins"),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        })
        .await
        .expect("seed manifest upsert request");

    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    let shared_changes: Arc<dyn waygate_changeset::ChangeRequestStore> = changes;
    let cedar = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source("").expect("empty Cedar policy set"),
    ));
    let mut caller = sample_row("success", Some("example-messages"), Some("low"));
    caller.reason = None;
    caller.auth_method = Some("oauth".into());
    caller.req_scopes = vec!["mcp:invoke".into()];
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows: vec![caller] });
    let state = AdminState::new(
        pool,
        Some(cedar),
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    )
    .with_servers_dir(servers_dir_from_content(&example_messages_bundle_content()))
    .with_change_request_store(Some(shared_changes));

    Arc::new(state)
}

async fn state_with_executed_manifest_change(
    heartbeats: Vec<waygate_manifest_store::ReplicaHeartbeat>,
) -> Arc<AdminState> {
    let changes = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    let proposed = changes
        .propose(waygate_changeset::NewChangeRequest {
            tenant_id: "default".into(),
            requested_by: "grounded-docs-enablement".into(),
            client_id: None,
            action_type: "manifest.upsert_servers".into(),
            params: serde_json::json!({"content": "reviewed upstream fragment"}),
            preview: None,
            target_etag: None,
            justification: "restore governed documentation access".into(),
            requirement: waygate_changeset::ApprovalRequirement::single("dashboard-admins"),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        })
        .await
        .expect("seed executed manifest request");
    changes
        .try_approve("default", proposed.id, "operator")
        .await
        .expect("approve fixture request")
        .expect("fixture approval transitions");
    changes
        .try_begin_execution("default", proposed.id)
        .await
        .expect("claim fixture request")
        .expect("fixture execution claim transitions");
    changes
        .mark_executed(
            "default",
            proposed.id,
            serde_json::json!({
                "bundle_id": Uuid::new_v4(),
                "version": 7,
                "content_hash": "ledger-hash",
                "activation_hash": "activation-hash"
            }),
        )
        .await
        .expect("record fixture result")
        .expect("fixture execution completes");

    let manifests = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    manifests.set_heartbeats(heartbeats);
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    let shared_changes: Arc<dyn waygate_changeset::ChangeRequestStore> = changes;
    let shared_manifests: Arc<dyn waygate_manifest_store::ManifestStore> = manifests;
    Arc::new(
        AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_change_request_store(Some(shared_changes))
        .with_manifest_store(Some(shared_manifests)),
    )
}

/// The queue merges a pending change request and an active break-glass
/// token into one list, each carrying its inline action form that posts
/// to a queue-owned route (so the operator stays on the queue).
#[tokio::test]
pub(crate) async fn decisions_queue_merges_change_requests_and_break_glass() {
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    let cr_id = seed_pending_cr(&cr, "default", "example-agent").await;
    let bg = Arc::new(FakeBreakGlassStore::default());
    let bg_id = seed_bg_token(&bg);
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/decisions").await;
    assert_eq!(status, StatusCode::OK);
    // Both kinds present as chips.
    assert!(body.contains(">change request<"), "CR chip missing");
    assert!(body.contains(">break-glass<"), "break-glass chip missing");
    // Plain-language summaries.
    assert!(
        body.contains("example-agent · api_key.mint"),
        "CR summary missing"
    );
    assert!(
        body.contains("alice · example-messages.*"),
        "break-glass summary missing"
    );
    // Inline forms post to QUEUE-owned routes (stay on the queue), not the
    // per-surface pages' own routes.
    assert!(
        body.contains(&format!(
            r#"action="/admin/decisions/changes/{cr_id}/approve""#
        )),
        "CR approve form must post to the queue-owned approve route",
    );
    assert!(
        body.contains(&format!(
            r#"action="/admin/decisions/changes/{cr_id}/deny""#
        )),
        "CR deny form must post to the queue-owned deny route",
    );
    assert!(
        body.contains(&format!(
            r#"action="/admin/decisions/break_glass/{bg_id}/revoke""#
        )),
        "break-glass revoke form must post to the queue-owned revoke route",
    );
    // The approver must see the captured params, not just the
    // `requested_by · action_type` summary. The pending api_key.mint CR
    // proposed scopes=[mcp:read]; the queue must render them so a maker can't
    // hide a dangerous intent behind a benign justification.
    assert!(
        body.contains("mcp:read") && body.contains("scopes"),
        "the decisions queue must render the captured CR params for review",
    );
    // The params must render ABOVE the Approve control on the
    // queue too, not beside it — the reviewer reads the intent before acting.
    let params_at = body
        .find("Captured parameters")
        .expect("decisions params label present");
    let approve_at = body
        .find(&format!("/decisions/changes/{cr_id}/approve"))
        .expect("decisions approve form present");
    assert!(
        params_at < approve_at,
        "captured params must render before the Approve control on /decisions (params@{params_at} approve@{approve_at})",
    );
}

/// The /changes pending table must render the captured params
/// so the human approver sees the exact intent (subject / scope / TTL) they
/// authorize — review is hollow on action_type + justification alone.
#[tokio::test]
pub(crate) async fn changes_page_renders_captured_params_for_review() {
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    seed_pending_cr(&cr, "default", "example-agent").await;
    let bg = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/changes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Parameters being authorized"),
        "the pending table must label the captured params",
    );
    assert!(
        body.contains("mcp:read") && body.contains("scopes"),
        "the pending table must render the captured params (scopes=[mcp:read])",
    );
    // The params must render ABOVE the Approve control so the
    // reviewer reads the intent before acting — not after the button.
    let params_at = body
        .find("Parameters being authorized")
        .expect("params label present");
    let approve_at = body
        .find("/changes/")
        .and_then(|_| body.find(">Approve<"))
        .expect("approve button present");
    assert!(
        params_at < approve_at,
        "captured params must render before the Approve button (params@{params_at} approve@{approve_at})",
    );
}

#[tokio::test]
pub(crate) async fn manifest_impact_summary_precedes_controls_on_both_approval_surfaces() {
    let app = dashboard_router(
        state_with_manifest_impact_request(waygate_upstream::ClassificationMode::McpAnnotations)
            .await,
        DashboardAuth::Disabled,
    );

    for path in ["/changes", "/decisions"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "{path} must render");
        let outcome_at = body
            .find("Expands the configured capability surface")
            .unwrap_or_else(|| panic!("{path} must lead with the effective capability outcome"));
        let prospective_at = body
            .find("Prospective authorization sample")
            .unwrap_or_else(|| panic!("{path} must show candidate access evidence"));
        let evidence_at = body
            .find("Recent authorization evidence")
            .unwrap_or_else(|| {
                panic!("{path} must retain replay as separately-labelled supporting evidence")
            });
        let params_label = if path == "/changes" {
            "Parameters being authorized"
        } else {
            "Captured parameters"
        };
        let params_at = body
            .find(params_label)
            .unwrap_or_else(|| panic!("{path} must retain the captured parameters"));
        let approve_at = body
            .find(">Approve<")
            .unwrap_or_else(|| panic!("{path} must retain the approval control"));
        assert!(
            outcome_at < prospective_at
                && prospective_at < evidence_at
                && evidence_at < params_at
                && params_at < approve_at,
            "{path} must read service outcome → prospective sample → replay evidence → captured params → approval control"
        );
        assert!(
            body.contains("10 added · 0 removed · 0 reclassified"),
            "{path} must distinguish configured additions from reclassifications"
        );
        assert!(
            body.contains("Not applicable: this candidate changes capability membership"),
            "{path} must not present zero replay rows as evidence of zero service impact"
        );
        assert!(
            body.contains("10 context-target pair(s) were indeterminate")
                && body.contains("runtime side-effect and sensitivity facts derive from reviewed MCP annotations"),
            "{path} must identify annotation-native targets as indeterminate rather than inventing manifest facts"
        );
        assert!(
            body.contains("converges asynchronously across the gateway fleet"),
            "{path} must distinguish publication from fleet activation"
        );
        assert!(
            body.contains("Verify grounded-docs connects after publication"),
            "{path} must preserve connection verification alongside catalog recovery"
        );
        assert!(
            body.contains(
                "type=\"checkbox\" name=\"effect_preview_acknowledged\" value=\"true\" required"
            ) && body.contains("I reviewed the effect preview"),
            "{path} must require an explicit acknowledgement of the rendered effect"
        );
    }
}

#[tokio::test]
pub(crate) async fn decided_manifest_outcome_separates_publication_from_fleet_verification() {
    let now = time::OffsetDateTime::now_utc();
    let app = dashboard_router(
        state_with_executed_manifest_change(vec![
            waygate_manifest_store::ReplicaHeartbeat {
                replica_id: "gateway-a".into(),
                tenant_id: "default".into(),
                version: Some(7),
                content_hash: "activation-hash".into(),
                updated_at: now,
            },
            waygate_manifest_store::ReplicaHeartbeat {
                replica_id: "gateway-b".into(),
                tenant_id: "default".into(),
                version: Some(6),
                content_hash: "previous-hash".into(),
                updated_at: now,
            },
            waygate_manifest_store::ReplicaHeartbeat {
                replica_id: "gateway-c".into(),
                tenant_id: "default".into(),
                version: Some(7),
                content_hash: "activation-hash".into(),
                updated_at: now - time::Duration::minutes(2),
            },
        ])
        .await,
        DashboardAuth::Disabled,
    );

    let (status, body) = body_of(app, "/changes").await;
    assert_eq!(status, StatusCode::OK);
    let publication_at = body
        .find("Published manifest v7.")
        .expect("publication receipt rendered");
    let activation_at = body
        .find("fleet pending")
        .expect("fleet state rendered separately");
    assert!(
        publication_at < activation_at,
        "durable publication must precede observed activation state"
    );
    assert!(
        body.contains("1 of 2 fresh observed replica(s) loaded this version")
            && body.contains("1 stale replica(s) also remain unverified"),
        "mixed and stale observations must remain explicitly incomplete: {body}"
    );
    assert!(
        body.contains("Open fleet status") && body.contains("/admin/server_manifests"),
        "the receipt must hand the operator to the existing fleet evidence view"
    );
    assert!(
        !body.contains("all replicas loaded"),
        "partial evidence must never be promoted to whole-fleet certainty"
    );
}

#[tokio::test]
pub(crate) async fn manifest_operation_fallback_discloses_unbounded_policy_input() {
    let app = dashboard_router(
        state_with_manifest_impact_request(waygate_upstream::ClassificationMode::Manifest).await,
        DashboardAuth::Disabled,
    );

    for path in ["/changes", "/decisions"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "{path} must render");
        assert!(
            body.contains("10 context-target pair(s) were indeterminate"),
            "{path} must count operation-aware fallback pairs as indeterminate"
        );
        assert!(
            body.contains("undeclared operation values retain tool-level facts"),
            "{path} must explain why the fallback category is indeterminate"
        );
        assert!(
            body.contains("docs_tool_0") && body.contains("/ search"),
            "{path} must still show each evaluated declared operation"
        );
    }
}

/// An approval handoff selects the exact pending request even after newer
/// requests push it beyond the bounded first page.
#[tokio::test]
pub(crate) async fn changes_page_focuses_the_requested_pending_row() {
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    let target_id = seed_pending_cr(&cr, "default", "target-agent").await;
    // Deliberately overfill the bounded review page; the assertion below
    // verifies the target actually landed outside it.
    for index in 0..32 {
        seed_pending_cr(&cr, "default", &format!("newer-agent-{index}")).await;
    }
    let bg = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );

    let (status, first_page) = body_of(app.clone(), "/changes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !first_page.contains(&format!("change-{target_id}")),
        "fixture target must be outside the first pending page"
    );

    let (status, focused) = body_of(app, &format!("/changes?pending_id={target_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        focused.contains(&format!("change-{target_id}")) && focused.contains("target-agent"),
        "focused approval page must render the exact pending request"
    );
    assert!(
        !focused.contains("newer-agent-0"),
        "focused approval page must remain a single bounded pending payload"
    );
}

/// A focused id is still resolved through the viewer's tenant. An id from a
/// different tenant cannot select or reveal that request.
#[tokio::test]
pub(crate) async fn changes_page_focus_is_tenant_scoped() {
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    seed_pending_cr(&cr, "default", "local-agent").await;
    let foreign_id = seed_pending_cr(&cr, "other-tenant", "foreign-agent").await;
    let bg = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );

    let (status, body) = body_of(app, &format!("/changes?pending_id={foreign_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("local-agent"),
        "normal tenant page must render"
    );
    assert!(
        !body.contains("foreign-agent") && !body.contains(&format!("change-{foreign_id}")),
        "focused id must not disclose another tenant's request"
    );
}

/// The selector is an approval handoff, not a way to move a terminal request
/// back into the actionable pending table.
#[tokio::test]
pub(crate) async fn changes_page_focus_does_not_make_a_decided_row_actionable() {
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    seed_pending_cr(&cr, "default", "local-agent").await;
    let decided_id = seed_pending_cr(&cr, "default", "decided-agent").await;
    cr.try_deny("default", decided_id, "operator", "superseded")
        .await
        .unwrap()
        .expect("fixture denial");
    let bg = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );

    let (status, body) = body_of(app, &format!("/changes?pending_id={decided_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("local-agent"), "live pending row must render");
    assert!(
        !body.contains(&format!("/changes/{decided_id}/approve")),
        "a decided target must not gain an approval control"
    );
}

/// Security: the queue is scoped to the principal's tenant. A pending CR
/// and an active token under a DIFFERENT tenant must never appear
/// (`DashboardAuth::Disabled` is the default tenant).
#[tokio::test]
pub(crate) async fn decisions_queue_is_tenant_scoped() {
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    seed_pending_cr(&cr, "other-tenant", "foreign-agent").await;
    let bg = Arc::new(FakeBreakGlassStore::default());
    bg.tokens
        .lock()
        .unwrap()
        .push(waygate_authz::BreakGlassToken {
            id: Uuid::new_v4(),
            tenant_id: "other-tenant".into(),
            issued_to: "foreign-bg-user".into(),
            issued_by: "op".into(),
            reason: "incident".into(),
            scope_pattern: "secret.*".into(),
            requires_amr: vec![],
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            used_at: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        });
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/decisions").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("foreign-agent"),
        "another tenant's CR leaked"
    );
    assert!(
        !body.contains("foreign-bg-user"),
        "another tenant's token leaked"
    );
    assert!(
        body.contains("Nothing awaiting a decision"),
        "tenant-empty queue should show the empty state",
    );
}

/// Stores wired but nothing pending → the benign empty state, not the
/// "not configured" copy.
#[tokio::test]
pub(crate) async fn decisions_queue_empty_when_nothing_pending() {
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    let bg = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/decisions").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Nothing awaiting a decision"));
    assert!(
        !body.contains("not configured"),
        "stores ARE configured here"
    );
}

/// No decision stores (dev / no DB) → the distinct "not configured"
/// empty copy, never a 500.
#[tokio::test]
pub(crate) async fn decisions_queue_not_configured_without_stores() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/decisions").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Nothing awaiting a decision"));
    assert!(
        body.contains("aren't configured"),
        "should explain the stores are unwired"
    );
}

/// `/decisions` is the Decisions destination's landing, with the Queue
/// tab current and the three source tabs present.
#[tokio::test]
pub(crate) async fn decisions_is_destination_landing_with_queue_tab() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/decisions").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/decisions" aria-current="page""#),
        "Decisions destination + Queue tab should be current on /decisions",
    );
    for tab in ["/admin/approvals", "/admin/changes", "/admin/break_glass"] {
        assert!(
            body.contains(&format!(r#"href="{tab}""#)),
            "missing tab {tab}"
        );
    }
}

/// A queue-owned deny POST with no reason returns to the queue with an
/// error flash (the reason guard), exercising the new action route +
/// PRG-back-to-queue wiring end to end.
#[tokio::test]
pub(crate) async fn decisions_deny_without_reason_returns_to_queue_with_error() {
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    let cr_id = seed_pending_cr(&cr, "default", "example-agent").await;
    let bg = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/decisions/changes/{cr_id}/deny"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf=&reason="))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.starts_with("/admin/decisions?err="),
        "should PRG back to the queue: {loc}"
    );
}

/// A change-request store whose read methods error. Mutation tests use it to
/// pin the operator-visible failure state for both list and focused reads.
#[derive(Default)]
pub(crate) struct FailingChangeRequestStore;

#[async_trait]
impl waygate_changeset::ChangeRequestStore for FailingChangeRequestStore {
    async fn propose(
        &self,
        _new: waygate_changeset::NewChangeRequest,
    ) -> Result<waygate_changeset::ChangeRequest, waygate_changeset::ChangeRequestError> {
        unimplemented!("load-error fixture")
    }
    async fn get(
        &self,
        _tenant_id: &str,
        _id: Uuid,
    ) -> Result<Option<waygate_changeset::ChangeRequest>, waygate_changeset::ChangeRequestError>
    {
        Err(waygate_changeset::ChangeRequestError::Database(
            sqlx::Error::PoolClosed,
        ))
    }
    async fn list(
        &self,
        _tenant_id: &str,
        _lifecycle: Option<waygate_changeset::ChangeRequestLifecycle>,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<waygate_changeset::ChangeRequest>, waygate_changeset::ChangeRequestError> {
        // A configured store that fails to read — the case the queue must
        // NOT silently render as "nothing pending".
        Err(waygate_changeset::ChangeRequestError::Database(
            sqlx::Error::PoolClosed,
        ))
    }
    async fn list_summaries(
        &self,
        _tenant_id: &str,
        _lifecycle: Option<waygate_changeset::ChangeRequestLifecycle>,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<waygate_changeset::ChangeRequestSummary>, waygate_changeset::ChangeRequestError>
    {
        Err(waygate_changeset::ChangeRequestError::Database(
            sqlx::Error::PoolClosed,
        ))
    }
    async fn list_for_requester(
        &self,
        _tenant_id: &str,
        _requested_by: &str,
        _lifecycle: Option<waygate_changeset::ChangeRequestLifecycle>,
        _limit: u32,
        _offset: u32,
    ) -> Result<
        Vec<waygate_changeset::ChangeRequestStatusSummary>,
        waygate_changeset::ChangeRequestError,
    > {
        unimplemented!("load-error fixture")
    }
    async fn count_pending_up_to(
        &self,
        _tenant_id: &str,
        _limit: u32,
    ) -> Result<u32, waygate_changeset::ChangeRequestError> {
        Err(waygate_changeset::ChangeRequestError::Database(
            sqlx::Error::PoolClosed,
        ))
    }
    async fn try_approve(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _approver_sub: &str,
    ) -> Result<Option<waygate_changeset::ChangeRequest>, waygate_changeset::ChangeRequestError>
    {
        unimplemented!("load-error fixture")
    }
    async fn record_approval(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _approver_sub: &str,
    ) -> Result<waygate_changeset::ApprovalProgress, waygate_changeset::ChangeRequestError> {
        unimplemented!("load-error fixture")
    }
    async fn list_approvers(
        &self,
        _tenant_id: &str,
        _id: Uuid,
    ) -> Result<Vec<String>, waygate_changeset::ChangeRequestError> {
        unimplemented!("load-error fixture")
    }
    async fn try_deny(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _approver_sub: &str,
        _reason: &str,
    ) -> Result<Option<waygate_changeset::ChangeRequest>, waygate_changeset::ChangeRequestError>
    {
        unimplemented!("load-error fixture")
    }
    async fn try_begin_execution(
        &self,
        _tenant_id: &str,
        _id: Uuid,
    ) -> Result<Option<waygate_changeset::ChangeRequest>, waygate_changeset::ChangeRequestError>
    {
        unimplemented!("load-error fixture")
    }
    async fn mark_executed(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _result: serde_json::Value,
    ) -> Result<Option<waygate_changeset::ChangeRequest>, waygate_changeset::ChangeRequestError>
    {
        unimplemented!("load-error fixture")
    }
    async fn mark_failed(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _error: &str,
    ) -> Result<Option<waygate_changeset::ChangeRequest>, waygate_changeset::ChangeRequestError>
    {
        unimplemented!("load-error fixture")
    }
    async fn store_secret(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _ciphertext: &[u8],
        _key_id: &str,
    ) -> Result<(), waygate_changeset::ChangeRequestError> {
        unimplemented!("load-error fixture")
    }
    async fn try_burn_secret(
        &self,
        _tenant_id: &str,
        _id: Uuid,
    ) -> Result<Option<waygate_changeset::StoredSecret>, waygate_changeset::ChangeRequestError>
    {
        unimplemented!("load-error fixture")
    }
    async fn get_secret(
        &self,
        _tenant_id: &str,
        _id: Uuid,
    ) -> Result<Option<waygate_changeset::StoredSecret>, waygate_changeset::ChangeRequestError>
    {
        unimplemented!("load-error fixture")
    }
}

/// A store READ failure must surface loudly — never read as "nothing
/// awaiting a decision". A queue that swallows the error tells the
/// operator there's nothing to decide while a decision may be waiting.
#[tokio::test]
pub(crate) async fn decisions_queue_surfaces_store_read_error_not_empty() {
    let cr = Arc::new(FailingChangeRequestStore);
    let bg = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/decisions").await;
    // The handler degrades, it does not 500.
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Couldn't load part of the decision queue"),
        "a failed store read must surface the load-error callout",
    );
    assert!(
        !body.contains("Nothing awaiting a decision"),
        "a load error must NOT render as the benign empty state",
    );
}

/// The dedicated change-request page must also distinguish a failed pending
/// list from a genuinely empty queue.
#[tokio::test]
pub(crate) async fn changes_page_surfaces_pending_list_error_not_empty() {
    let cr = Arc::new(FailingChangeRequestStore);
    let bg = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/changes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Couldn't load change requests"),
        "a failed pending list must surface the load-error callout",
    );
    assert!(
        !body.contains("Nothing waiting"),
        "a pending-list error must not render as an empty queue",
    );
}

/// A failed exact-row lookup must fail visibly rather than silently falling
/// back to a benign queue page that might hide the requested approval.
#[tokio::test]
pub(crate) async fn changes_page_surfaces_focused_lookup_error() {
    let cr = Arc::new(FailingChangeRequestStore);
    let bg = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_decision_stores(cr, bg).await,
        DashboardAuth::Disabled,
    );
    let id = Uuid::new_v4();
    let (status, body) = body_of(app, &format!("/changes?pending_id={id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Couldn't load change requests"),
        "a failed focused lookup must surface the load-error callout",
    );
    assert!(
        !body.contains("Nothing waiting"),
        "a focused lookup error must not render as an empty queue",
    );
}

/// Decision Log endpoints (`/api/v1/audit/decisions`): the `policy_id`
/// reverse lookup is tenant-scoped, and per-decision detail refuses
/// cross-tenant reads with 404 (no existence leak).
#[tokio::test]
pub(crate) async fn decisions_api_filters_by_policy_and_scopes_by_tenant() {
    fn admin_principal() -> waygate_oidc::Principal {
        waygate_oidc::Principal {
            sub: "admin@example.com".into(),
            email: None,
            groups: vec![],
            issuer: "test".into(),
            scopes: vec!["mcp:admin".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }
    async fn get(app: axum::Router, uri: &str) -> (StatusCode, String) {
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        req.extensions_mut().insert(admin_principal());
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // One decision in the caller's (default) tenant, one in another tenant —
    // both fired the same policy.
    let mut mine = sample_row("denied", Some("example-messages"), Some("high"));
    mine.tenant_id = waygate_core::TenantId::default().as_str().to_owned();
    mine.policy_ids = vec!["step-up-delete-dataset".into()];
    let mine_id = mine.id;
    let mut other = sample_row("denied", Some("example-messages"), Some("high"));
    other.tenant_id = "other-tenant".into();
    other.policy_ids = vec!["step-up-delete-dataset".into()];
    let other_id = other.id;
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![mine, other],
    });
    let state = Arc::new(AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));

    // Reverse lookup, tenant-scoped: returns the caller's decision, not the
    // other tenant's — even though both matched the policy.
    let (status, body) = get(
        api_router(state.clone()),
        "/api/v1/audit/decisions?policy_id=step-up-delete-dataset",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let events = json["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1, "only the caller-tenant decision: {body}");
    assert_eq!(events[0]["id"].as_str().unwrap(), mine_id.to_string());

    // Detail on the OTHER tenant's decision → 404 (no cross-tenant leak).
    let (status, _) = get(
        api_router(state.clone()),
        &format!("/api/v1/audit/decisions/{other_id}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant detail must 404"
    );

    // Detail on the caller's own decision → 200.
    let (status, _) = get(
        api_router(state),
        &format!("/api/v1/audit/decisions/{mine_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// The Decision Log spans BOTH decision classes — tool-call
/// (`invocation`) and model (`llm_completion`) — since both authorize through
/// the Cedar gate and record fired policy ids. And the detail endpoint refuses
/// non-decision rows: a same-tenant admin who learns an `admin_mutation` id
/// can't read it through the decisions detail path. All three rows are in the
/// caller's tenant and fired the same policy id; only the two decisions are
/// reachable.
#[tokio::test]
pub(crate) async fn decisions_api_spans_model_decisions_and_excludes_non_decision_rows() {
    fn admin_principal() -> waygate_oidc::Principal {
        waygate_oidc::Principal {
            sub: "admin@example.com".into(),
            email: None,
            groups: vec![],
            issuer: "test".into(),
            scopes: vec!["mcp:admin".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }
    async fn get(app: axum::Router, uri: &str) -> (StatusCode, String) {
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        req.extensions_mut().insert(admin_principal());
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let tenant = waygate_core::TenantId::default().as_str().to_owned();
    let policy = "10-baseline-models";

    // A tool-call decision, a model decision, and a NON-decision admin_mutation
    // row — all same tenant, all carrying the same fired policy id.
    let mut tool = sample_row("denied", Some("example-messages"), Some("high"));
    tool.tenant_id = tenant.clone();
    tool.category = Some("invocation".into());
    tool.policy_ids = vec![policy.into()];

    let mut model = sample_row("success", Some("llm"), None);
    model.tenant_id = tenant.clone();
    model.category = Some("llm_completion".into());
    model.policy_ids = vec![policy.into()];
    let model_id = model.id;
    let model_id_str = model_id.to_string();

    let mut admin = sample_row("success", None, None);
    admin.tenant_id = tenant.clone();
    admin.category = Some("admin_mutation".into());
    admin.policy_ids = vec![policy.into()]; // same id, but NOT a decision row
    let admin_id = admin.id;

    // A fail-closed pre-dispatch evidence row: a real decision category, but
    // reason='pre_call'. The list omits it (reason_ne) and the detail endpoint
    // must omit it too — it pairs with a later outcome row.
    let mut pre_call = sample_row("success", Some("example-messages"), Some("high"));
    pre_call.tenant_id = tenant.clone();
    pre_call.category = Some("invocation".into());
    pre_call.reason = Some("pre_call".into());
    pre_call.policy_ids = vec![policy.into()];
    let pre_call_id = pre_call.id;

    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![tool, model, admin, pre_call],
    });
    let state = Arc::new(AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));

    // Reverse lookup surfaces BOTH decisions (tool + model), never the
    // admin_mutation row — even though it carries the same policy id.
    let (status, body) = get(
        api_router(state.clone()),
        &format!("/api/v1/audit/decisions?policy_id={policy}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let events = json["events"].as_array().expect("events array");
    assert_eq!(
        events.len(),
        2,
        "both decision classes, not the non-decision or pre_call rows: {body}"
    );
    let ids: Vec<&str> = events.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert!(
        ids.iter().any(|id| *id == model_id_str),
        "the model (llm_completion) decision must be surfaced: {body}"
    );

    // Detail on the model decision → 200 (it IS a decision).
    let (status, _) = get(
        api_router(state.clone()),
        &format!("/api/v1/audit/decisions/{model_id}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a model decision must be readable via the detail endpoint"
    );

    // Detail on the same-tenant NON-decision admin_mutation row → 404. The
    // decisions detail endpoint must never serve a non-decision category.
    let (status, _) = get(
        api_router(state.clone()),
        &format!("/api/v1/audit/decisions/{admin_id}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-decision row must not be readable via the decisions detail endpoint"
    );

    // Detail on the same-tenant pre_call evidence row → 404. The list omits it
    // (reason_ne), so detail must too — parity, or detail leaks a row the list
    // deliberately hides.
    let (status, _) = get(
        api_router(state),
        &format!("/api/v1/audit/decisions/{pre_call_id}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a pre_call evidence row must not be readable via the decisions detail endpoint"
    );
}

// ---- Policy-UX: Decision Log pane (dashboard_decisions_log) ---------------

/// The Decision Log pane reuses the SAME decision filter as the REST endpoint
/// (`decision_store_query`): it surfaces both decision classes (tool-call
/// `invocation` + model `llm_completion`) and drops non-decision categories +
/// the fail-closed `pre_call` evidence rows. Seed one of each and assert the
/// decisions render while the non-decision / pre_call rows do NOT — proving the
/// pane shares the filter rather than re-implementing (or omitting) it.
#[tokio::test]
pub(crate) async fn decisions_log_page_renders() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let tenant = waygate_core::TenantId::default().as_str().to_owned();

    let mut tool = sample_row("denied", Some("example-messages"), Some("high"));
    tool.tenant_id = tenant.clone();
    tool.category = Some("invocation".into());
    tool.principal_sub = Some("tool-caller@example.com".into());
    tool.principal_email = tool.principal_sub.clone();

    let mut model = sample_row("success", Some("llm-gateway"), None);
    model.tenant_id = tenant.clone();
    model.category = Some("llm_completion".into());
    model.principal_sub = Some("model-caller@example.com".into());
    model.principal_email = model.principal_sub.clone();

    // A non-decision admin_mutation row — must NOT appear in the Decision Log.
    let mut admin = sample_row("success", None, None);
    admin.tenant_id = tenant.clone();
    admin.category = Some("admin_mutation".into());
    admin.principal_sub = Some("admin-mutation-actor@example.com".into());
    admin.principal_email = admin.principal_sub.clone();

    // A fail-closed pre-dispatch evidence row — a decision category but
    // reason='pre_call'; the decision filter drops it.
    let mut pre_call = sample_row("success", Some("example-messages"), Some("high"));
    pre_call.tenant_id = tenant.clone();
    pre_call.category = Some("invocation".into());
    pre_call.reason = Some("pre_call".into());
    pre_call.principal_sub = Some("pre-call-intent@example.com".into());
    pre_call.principal_email = pre_call.principal_sub.clone();

    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![tool, model, admin, pre_call],
    });
    let state = Arc::new(AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/decisions-log").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Decision Log"), "page title renders");
    assert!(
        body.contains("tool-caller@example.com"),
        "the tool-call (invocation) decision must render",
    );
    assert!(
        body.contains("model-caller@example.com"),
        "the model (llm_completion) decision must render — the pane spans both \
         decision classes, not just tool calls",
    );
    assert!(
        !body.contains("admin-mutation-actor@example.com"),
        "a non-decision admin_mutation row must NOT appear in the Decision Log",
    );
    assert!(
        !body.contains("pre-call-intent@example.com"),
        "a fail-closed pre_call evidence row must NOT appear in the Decision Log \
         (the decision filter excludes reason='pre_call')",
    );
}

/// The `?policy_id=` reverse lookup — the signature feature. Seed two decisions
/// firing different policies; filtering by one policy id shows only the matching
/// decision and renders the "Decisions that matched policy <id>" banner.
#[tokio::test]
pub(crate) async fn decisions_log_filters_by_policy_id() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let tenant = waygate_core::TenantId::default().as_str().to_owned();
    let wanted = "step-up-delete-dataset";

    let mut hit = sample_row("denied", Some("example-messages"), Some("high"));
    hit.tenant_id = tenant.clone();
    hit.category = Some("invocation".into());
    hit.policy_ids = vec![wanted.into()];
    hit.principal_sub = Some("matched-decision@example.com".into());
    hit.principal_email = hit.principal_sub.clone();

    let mut miss = sample_row("success", Some("example-observability"), Some("low"));
    miss.tenant_id = tenant.clone();
    miss.category = Some("invocation".into());
    miss.policy_ids = vec!["some-other-policy".into()];
    miss.principal_sub = Some("unmatched-decision@example.com".into());
    miss.principal_email = miss.principal_sub.clone();

    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![hit, miss],
    });
    let state = Arc::new(AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, &format!("/decisions-log?policy_id={wanted}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Decisions that matched policy"),
        "the reverse-lookup banner must render when policy_id is set",
    );
    assert!(
        body.contains(wanted),
        "the banner names the filtered policy id",
    );
    assert!(
        body.contains("matched-decision@example.com"),
        "the decision that fired this policy must appear",
    );
    assert!(
        !body.contains("unmatched-decision@example.com"),
        "a decision firing a DIFFERENT policy must be excluded by the reverse lookup",
    );
}

/// When the page fills its limit, the htmx "Load more" fragment carries a
/// keyset cursor (`after_id=`) so pagination continues. Seed more rows than the
/// page limit and assert the load-more link appears with a cursor.
#[tokio::test]
pub(crate) async fn decisions_log_rows_paginate() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let tenant = waygate_core::TenantId::default().as_str().to_owned();
    // > PAGE_LIMIT (50) decisions so the first page fills and yields a cursor.
    let rows: Vec<AuditRow> = (0..60)
        .map(|_| {
            let mut r = sample_row("success", Some("example-messages"), Some("low"));
            r.tenant_id = tenant.clone();
            r.category = Some("invocation".into());
            r
        })
        .collect();
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
    let state = Arc::new(AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/decisions-log").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/decisions-log/rows?after_id="),
        "a full first page must render the htmx load-more link with a cursor",
    );
    assert!(
        body.contains("Load 50 more"),
        "the load-more button must render when there's another page",
    );
}

/// The Policies pane cross-links each policy to its Decision Log reverse
/// lookup. Assert every loaded policy renders a `/decisions-log?policy_id=`
/// link — the discoverability half of the signature feature.
#[tokio::test]
pub(crate) async fn policies_page_links_to_decision_log() {
    let app = dashboard_router(state_with_layered_cedar().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/policies").await;
    assert_eq!(status, StatusCode::OK);
    // LAYERED_POLICY declares @id("baseline-discovery") and
    // @id("step-up-delete-dataset"); each must carry a Decision Log cross-link.
    assert!(
        body.contains("/decisions-log?policy_id=baseline-discovery"),
        "each policy must link to its Decision Log reverse lookup",
    );
    assert!(
        body.contains("/decisions-log?policy_id=step-up-delete-dataset"),
        "the second policy must also link to its Decision Log reverse lookup",
    );
    assert!(
        body.contains("View recent decisions"),
        "the cross-link label must render on the policy item",
    );
}

// ---- Policy-aware preview on the /changes approval queue ------------------

pub(crate) const DRAFT_ID: &str = "11111111-1111-1111-1111-111111111111";

/// A replayable decision row (auth_method present ⇒ the impact
/// replay reconstructs it), in the default tenant, matching the decision query.
pub(crate) fn replayable_decision_row() -> AuditRow {
    let mut r = sample_row("success", Some("bank"), Some("high"));
    r.tool = Some("wire_money".into());
    r.reason = None; // not a pre_call evidence row → passes the decision query
    r.auth_method = Some("oauth".into()); // captured ⇒ replayable
    r.req_scopes = vec!["mcp:invoke".into()];
    r
}

/// State with the three stores the policy-change preview needs: a seeded policy
/// store (the draft to publish), an audit reader (decisions to replay), and a
/// change-request store (the pending policy.publish).
pub(crate) async fn replayable_decision_state(
    draft: waygate_policy::PolicyBundle,
    rows: Vec<AuditRow>,
    cr: Arc<dyn waygate_changeset::ChangeRequestStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let policy_store: waygate_policy::SharedPolicyStore =
        Arc::new(InMemoryPolicyStore::seeded(vec![draft]));
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
    Arc::new(
        AdminState::new(
            pool,
            None,
            Some(audit),
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_policy_store(Some(policy_store))
        .with_change_request_store(Some(cr)),
    )
}

/// Seed a pending `policy.publish` change request targeting `bundle_id`.
pub(crate) async fn seed_publish_cr(
    store: &waygate_changeset::InMemoryChangeRequestStore,
    bundle_id: Uuid,
) -> Uuid {
    store
        .propose(waygate_changeset::NewChangeRequest {
            tenant_id: "default".into(),
            requested_by: "example-agent".into(),
            client_id: None,
            action_type: "policy.publish".into(),
            params: serde_json::json!({ "bundle_id": bundle_id.to_string() }),
            preview: None,
            target_etag: None,
            justification: "ship the reviewed policy".into(),
            requirement: waygate_changeset::ApprovalRequirement::single("dashboard-admins"),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        })
        .await
        .unwrap()
        .id
}

#[tokio::test]
pub(crate) async fn changes_queue_policy_publish_shows_compile_tests_and_blast_radius() {
    // A compiling draft with a PASSING attached test, plus one recorded
    // high-risk allow. permit-all keeps that decision an allow ⇒ unchanged.
    let mut draft = seeded_bundle(
        DRAFT_ID,
        9,
        waygate_policy::PolicyStatus::Draft,
        "permit(principal, action, resource);",
        None,
    );
    draft.tests = Some(serde_json::json!([{
        "name": "allows the call",
        "request": {
            "principal": { "sub": "alice" },
            "action": { "type": "call_tool", "name": "wire_money", "risk": "high" },
            "resource": { "type": "tool", "server": "bank", "name": "wire_money", "risk": "high", "side_effects": true }
        },
        "expect": { "decision": "allow" }
    }]));

    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    seed_publish_cr(&cr, DRAFT_ID.parse().unwrap()).await;
    let state = replayable_decision_state(draft, vec![replayable_decision_row()], cr).await;

    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/changes").await;
    assert_eq!(status, StatusCode::OK);

    // The policy-aware preview: the human-legible action, the compile badge,
    // the passing-tests badge, and the blast-radius panel — so the approver
    // reviews the EFFECT, not just the bundle_id.
    assert!(
        body.contains("Publish draft as v9"),
        "kind label missing from the preview"
    );
    assert!(body.contains("compiles"), "compile badge missing");
    assert!(body.contains("tests 1/1"), "passing-tests badge missing");
    assert!(body.contains("Replaying"), "blast-radius panel missing");
    // The raw params well still carries the captured bundle_id in full.
    assert!(
        body.contains(DRAFT_ID),
        "captured params must still show the bundle_id"
    );
}

#[tokio::test]
pub(crate) async fn changes_queue_policy_publish_broken_cedar_shows_wont_compile() {
    // A draft whose Cedar does NOT parse: the approver sees "won't compile" and
    // NO blast radius (a broken engine has nothing to replay) — they must not
    // approve a publish that can't land.
    let draft = seeded_bundle(
        DRAFT_ID,
        9,
        waygate_policy::PolicyStatus::Draft,
        "this is not valid cedar {{{",
        None,
    );
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    seed_publish_cr(&cr, DRAFT_ID.parse().unwrap()).await;
    let state = replayable_decision_state(draft, vec![replayable_decision_row()], cr).await;

    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/changes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("won't compile"),
        "compile-error badge missing"
    );
    assert!(
        !body.contains("Replaying"),
        "a non-parsing draft must NOT show a blast radius"
    );
}

#[tokio::test]
pub(crate) async fn changes_queue_policy_publish_non_draft_target_shows_wont_execute() {
    // The publish executor refuses a non-Draft target. A pending policy.publish
    // whose target is already Published must therefore surface "will not
    // execute" — not a rosy "will publish" effect the approval can't deliver.
    let draft = seeded_bundle(
        DRAFT_ID,
        9,
        waygate_policy::PolicyStatus::Published,
        "permit(principal, action, resource);",
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    seed_publish_cr(&cr, DRAFT_ID.parse().unwrap()).await;
    let state = replayable_decision_state(draft, vec![replayable_decision_row()], cr).await;

    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/changes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Will not execute"),
        "a non-draft publish target must show the will-not-execute banner"
    );
    assert!(
        body.contains("no longer a draft"),
        "the banner must name the precondition the executor enforces"
    );
}

#[tokio::test]
pub(crate) async fn changes_queue_policy_publish_malformed_tests_shows_wont_execute() {
    // A draft whose attached tests are malformed: the publish gate refuses them
    // at execute. The preview must surface that ("will not execute"), not a
    // silent "no tests".
    let mut draft = seeded_bundle(
        DRAFT_ID,
        9,
        waygate_policy::PolicyStatus::Draft,
        "permit(principal, action, resource);",
        None,
    );
    draft.tests = Some(serde_json::json!("this is not a test-case array"));
    let cr = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    seed_publish_cr(&cr, DRAFT_ID.parse().unwrap()).await;
    let state = replayable_decision_state(draft, vec![replayable_decision_row()], cr).await;

    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/changes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Will not execute"),
        "malformed tests must show the will-not-execute banner"
    );
    assert!(
        body.contains("malformed"),
        "the banner must name the malformed-tests reason"
    );
}
