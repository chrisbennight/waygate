//! `UpstreamPool` unit tests, split out of `pool.rs`.
//! Content moved verbatim (one indent level removed); `super::*` still
//! resolves to the pool module.

use super::reload::slot_count_stable;
use super::*;
use crate::{SessionConfig, ToolClassification};
use rmcp::model::{MetaObject as Meta, Tool, ToolAnnotations};
use waygate_mcp::catalog::ResolutionAuthority;
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::AuthMethod;

#[test]
fn reload_report_requires_restart_only_for_unapplied_changes() {
    // Hot-applied fields (classifications / identity) ⇒ no restart.
    let hot = ReloadReport {
        classifications_updated: vec!["a".into()],
        identity_updated: vec!["b".into()],
        ..Default::default()
    };
    assert!(!hot.requires_restart());
    // A same-slot-count shape change re-dialed live IS applied ⇒
    // no restart, but it is NOT a no-op.
    let redialed = ReloadReport {
        redialed: vec!["a".into()],
        ..Default::default()
    };
    assert!(!redialed.requires_restart());
    assert!(!redialed.is_noop());
    // A connection-shape change whose every new-shape dial failed kept the
    // OLD shape ⇒ NOT applied ⇒ restart-required (and not a no-op). This is
    // one restart-required case: a same-count redial OR a
    // slot-resize rebuild whose dials all failed both land in redial_failed
    // (The transport_changed bucket was retired.)
    let failed = ReloadReport {
        redial_failed: vec!["a".into()],
        ..Default::default()
    };
    assert!(failed.requires_restart());
    assert!(!failed.is_noop());
    let coupled = ReloadReport {
        resource_shape_restart_required: vec!["a".into()],
        ..Default::default()
    };
    assert!(coupled.requires_restart());
    assert!(!coupled.is_noop());
    // Hot add/remove are dialed-and-published / drained-and-dropped live ⇒
    // NO restart (but they ARE changes, not no-ops).
    let added = ReloadReport {
        added: vec!["a".into()],
        ..Default::default()
    };
    assert!(!added.requires_restart());
    assert!(!added.is_noop());
    let removed = ReloadReport {
        removed: vec!["a".into()],
        ..Default::default()
    };
    assert!(!removed.requires_restart());
    assert!(!removed.is_noop());
    // Nothing changed ⇒ no restart, and a no-op.
    assert!(!ReloadReport::default().requires_restart());
    assert!(ReloadReport::default().is_noop());
}

fn shape_manifest(transport: Transport, concurrency: Option<usize>) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        inline_response_threshold_bytes: None,
        long_running_tools: Vec::new(),
        limits: None,
        name: "x".into(),
        transport,
        protocol: Default::default(),
        url: Some("http://unused.test/mcp".into()),
        command: Some(vec!["cmd".into()]),
        env_passthrough: Vec::new(),
        tools: Vec::new(),
        resources: Vec::new(),
        exchange: None,
        auth: None,
        headers: Default::default(),
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        trust: crate::TrustLevel::Internal,
        identity: None,
        forward_trace_context: None,
        session: concurrency.map(|c| SessionConfig {
            concurrency: Some(c),
            ..Default::default()
        }),
    }
}

#[test]
fn slot_count_stable_only_when_count_provably_unchanged() {
    // Both stdio ⇒ always 1 slot, stable regardless of session config.
    assert!(slot_count_stable(
        &shape_manifest(Transport::Stdio, None),
        &shape_manifest(Transport::Stdio, Some(4)),
    ));
    // stdio↔network flips 1↔N ⇒ never stable (either direction).
    assert!(!slot_count_stable(
        &shape_manifest(Transport::Stdio, None),
        &shape_manifest(Transport::Http, None),
    ));
    assert!(!slot_count_stable(
        &shape_manifest(Transport::Http, None),
        &shape_manifest(Transport::Stdio, None),
    ));
    // Both network, same explicit concurrency ⇒ stable (a url/auth/mtls
    // change with concurrency untouched is the canonical re-dial case).
    assert!(slot_count_stable(
        &shape_manifest(Transport::Http, Some(3)),
        &shape_manifest(Transport::Http, Some(3)),
    ));
    // Http↔Sse keeps the count (both network) ⇒ stable.
    assert!(slot_count_stable(
        &shape_manifest(Transport::Http, Some(2)),
        &shape_manifest(Transport::Sse, Some(2)),
    ));
    // A concurrency change resizes the pool ⇒ not stable.
    assert!(!slot_count_stable(
        &shape_manifest(Transport::Http, Some(2)),
        &shape_manifest(Transport::Http, Some(5)),
    ));
    // Conservative direction: None→Some is treated as unstable even though
    // the numeric count MIGHT match the global default (safe: never
    // mis-sizes the live pool).
    assert!(!slot_count_stable(
        &shape_manifest(Transport::Http, None),
        &shape_manifest(Transport::Http, Some(8)),
    ));
}

#[test]
fn redial_committed_fields_eq_covers_shape_and_identity_not_classifications() {
    let base = shape_manifest(Transport::Http, Some(2));
    // Identical ⇒ equal (the CAS commits on this).
    assert!(redial_committed_fields_eq(&base, &base.clone()));
    // A classification difference is NOT a committed field — the CAS must
    // not abort a re-dial just because tools/risk were edited in the same
    // set (redial never writes `tools`).
    let mut diff_tools = base.clone();
    diff_tools.tools = vec![ToolClassification::new("x", RiskTier::High, true, false)];
    assert!(redial_committed_fields_eq(&base, &diff_tools));
    // Each connection-shape field difference IS detected.
    let mut url = base.clone();
    url.url = Some("http://moved.test/mcp".into());
    assert!(!redial_committed_fields_eq(&base, &url));
    let mut command = base.clone();
    command.command = Some(vec!["other".into()]);
    assert!(!redial_committed_fields_eq(&base, &command));
    let mut env_passthrough = base.clone();
    env_passthrough.env_passthrough = vec!["EXAMPLE_API_TOKEN".into()];
    assert!(!redial_committed_fields_eq(&base, &env_passthrough));
    let mut transport = base.clone();
    transport.transport = Transport::Sse;
    assert!(!redial_committed_fields_eq(&base, &transport));
    let mut auth = base.clone();
    auth.auth = Some(UpstreamAuth {
        bearer_env: Some("NEW_BEARER".into()),
        ..Default::default()
    });
    assert!(!redial_committed_fields_eq(&base, &auth));
    let mut session = base.clone();
    session.session = Some(SessionConfig {
        concurrency: Some(9),
        ..Default::default()
    });
    assert!(!redial_committed_fields_eq(&base, &session));
    // Retry policy hot-applies without changing the connection shape, but a
    // slow shape re-dial still writes the complete session block. Its CAS must
    // therefore observe a newer policy change rather than clobber it.
    let mut retry_policy = base.clone();
    retry_policy
        .session
        .get_or_insert_default()
        .retry_on_setup_failure = Some(false);
    assert!(!redial_committed_fields_eq(&base, &retry_policy));
    // Each COUPLED IDENTITY field difference is ALSO detected — redial now
    // commits these atomically with the shape, so the CAS must guard them
    // too: a stale re-dial must not clobber a newer reload's
    // Authorization posture.
    let mut exchange = base.clone();
    exchange.exchange = Some(crate::ExchangeConfig {
        audience: "aud".into(),
        scope: None,
    });
    assert!(!redial_committed_fields_eq(&base, &exchange));
    let mut tier_a = base.clone();
    tier_a.tier_a_required = !base.tier_a_required;
    assert!(!redial_committed_fields_eq(&base, &tier_a));
    let mut tier_c = base.clone();
    tier_c.tier_c_peer = Some(uuid::Uuid::from_u128(0x315));
    assert!(!redial_committed_fields_eq(&base, &tier_c));
}

#[test]
fn catalog_risk_mapping() {
    assert_eq!(catalog_risk_to_tier("low"), RiskTier::Low);
    assert_eq!(catalog_risk_to_tier("medium"), RiskTier::Medium);
    assert_eq!(catalog_risk_to_tier("high"), RiskTier::High);
    // `critical` has no RiskTier analogue — must fail safe to High.
    assert_eq!(catalog_risk_to_tier("critical"), RiskTier::High);
    // Unknown future value — fail safe to High, never Low.
    assert_eq!(catalog_risk_to_tier("nonsense"), RiskTier::High);
}

/// In-memory `CatalogStore` returning a scripted `resolve_tool`
/// outcome, for exercising the pool's dual-read fallback. With a
/// `generation`, it reports that durable catalog generation and can advance
/// it while a resolution is in progress.
#[derive(Default)]
struct ScriptedCatalog {
    outcome: std::sync::Mutex<Option<waygate_catalog::ResolvedTool>>,
    err: bool,
    generation: Option<std::sync::atomic::AtomicI64>,
    advance_during_resolve: std::sync::atomic::AtomicBool,
    resolves: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl waygate_catalog::CatalogStore for ScriptedCatalog {
    async fn approved_servers(
        &self,
        _tenant: &str,
    ) -> Result<Vec<waygate_catalog::CatalogServerSummary>, waygate_catalog::CatalogError> {
        Ok(vec![])
    }
    async fn discovery_generation(&self) -> Result<Option<i64>, waygate_catalog::CatalogError> {
        Ok(self
            .generation
            .as_ref()
            .map(|generation| generation.load(Ordering::SeqCst)))
    }
    async fn resolve_tool(
        &self,
        _tenant: &str,
        _fq: &str,
    ) -> Result<waygate_catalog::ResolvedTool, waygate_catalog::CatalogError> {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        if self.advance_during_resolve.load(Ordering::SeqCst) {
            if let Some(generation) = self.generation.as_ref() {
                generation.fetch_add(1, Ordering::SeqCst);
            }
        }
        if self.err {
            return Err(waygate_catalog::CatalogError::Unknown("scripted error"));
        }
        Ok(self
            .outcome
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(waygate_catalog::ResolvedTool::NotFound))
    }
    async fn record_drift(
        &self,
        _o: waygate_catalog::DriftObservation<'_>,
    ) -> Result<(), waygate_catalog::CatalogError> {
        Ok(())
    }
    async fn record_approval(
        &self,
        _a: waygate_catalog::ApprovalAction<'_>,
    ) -> Result<(), waygate_catalog::CatalogError> {
        Ok(())
    }
    async fn list_drift_events(
        &self,
        _t: &str,
        _since: time::OffsetDateTime,
        _limit: u32,
    ) -> Result<Vec<waygate_catalog::DriftEvent>, waygate_catalog::CatalogError> {
        Ok(vec![])
    }
    async fn set_server_status(
        &self,
        _tenant: &str,
        _server_id: uuid::Uuid,
        _status: waygate_catalog::CatalogServerStatus,
        _actor: &str,
        _reason: Option<&str>,
    ) -> Result<bool, waygate_catalog::CatalogError> {
        Ok(false)
    }
    async fn last_approve_actor(
        &self,
        _tenant: &str,
        _server_id: uuid::Uuid,
    ) -> Result<Option<String>, waygate_catalog::CatalogError> {
        Ok(None)
    }
    async fn find_grant<'a>(
        &self,
        _lookup: waygate_catalog::GrantLookup<'a>,
    ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
        // Stub: pool tests don't exercise grants; the
        // enforcement slice has its own test surface.
        Ok(None)
    }
    async fn claim_grant<'a>(
        &self,
        _lookup: waygate_catalog::GrantLookup<'a>,
    ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
        Ok(None)
    }
    async fn create_grant<'a>(
        &self,
        _g: waygate_catalog::NewApprovalGrant<'a>,
    ) -> Result<waygate_catalog::ApprovalGrant, waygate_catalog::CatalogError> {
        Err(waygate_catalog::CatalogError::Unknown(
            "create_grant not supported in pool test fake",
        ))
    }
    async fn list_grants<'a>(
        &self,
        _t: &'a str,
        _f: waygate_catalog::GrantFilter<'a>,
    ) -> Result<Vec<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
        Ok(vec![])
    }
    async fn revoke_grant(
        &self,
        _t: &str,
        _id: uuid::Uuid,
    ) -> Result<bool, waygate_catalog::CatalogError> {
        Ok(false)
    }
    async fn sweep_grants(
        &self,
        _older_than: time::OffsetDateTime,
    ) -> Result<u64, waygate_catalog::CatalogError> {
        Ok(0)
    }
}

fn pool_with_manifest_tool() -> UpstreamPool {
    // Disconnected pool whose manifest classifies example-messages.send
    // as High + side_effects, so we can tell catalog-sourced
    // facts (which the scripted store controls) apart from
    // manifest-sourced fallback facts.
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        "example-messages".to_owned(),
        UpstreamManifest {
            classification_mode: Default::default(),
            approval_mode: Default::default(),
            inline_response_threshold_bytes: None,
            long_running_tools: Vec::new(),
            limits: None,
            name: "example-messages".into(),
            transport: Transport::Http,
            protocol: Default::default(),
            url: Some("http://example-messages.test/mcp".into()),
            command: None,
            env_passthrough: Vec::new(),
            tools: vec![ToolClassification::new("send", RiskTier::High, true, false)],
            resources: Vec::new(),
            exchange: None,
            auth: None,
            headers: Default::default(),
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            trust: crate::TrustLevel::Internal,
            identity: None,
            forward_trace_context: None,
            session: None,
        },
    );
    UpstreamPool::from_manifests_disconnected(map)
}

#[test]
fn annotation_native_tool_facts_stay_conservative_until_policy_enforcement() {
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        "komodo".to_owned(),
        UpstreamManifest {
            classification_mode: crate::ClassificationMode::McpAnnotations,
            approval_mode: Default::default(),
            inline_response_threshold_bytes: None,
            long_running_tools: Vec::new(),
            limits: None,
            name: "komodo".into(),
            transport: Transport::Http,
            protocol: Default::default(),
            url: Some("http://komodo.test/mcp".into()),
            command: None,
            env_passthrough: Vec::new(),
            tools: vec![ToolClassification {
                approved_behavior_hash: Some("a".repeat(64)),
                ..ToolClassification::new("stacks.config.read", RiskTier::High, false, false)
            }],
            resources: Vec::new(),
            exchange: None,
            auth: None,
            headers: Default::default(),
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            trust: crate::TrustLevel::Internal,
            identity: None,
            forward_trace_context: None,
            session: None,
        },
    );
    let pool = UpstreamPool::from_manifests_disconnected(map);

    let facts = pool.tool_facts("komodo", "stacks.config.read");

    assert_eq!(facts.risk, RiskTier::High);
    assert!(facts.side_effects);
    assert!(facts.pii);
}

#[tokio::test]
async fn admission_reuses_catalog_reads_only_within_one_generation() {
    let source_version =
        waygate_catalog::manifest_classification_hash("send", "high", true, false, None, &[]);
    let catalog = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
            waygate_catalog::ToolDefinition {
                discriminator: None,
                operations: Vec::new(),
                tool_id: uuid_nil(),
                server_id: uuid_nil(),
                server_name: "example-messages".into(),
                tool_name: "send".into(),
                schema_hash: source_version,
                description: "d".into(),
                classification_mode: "manifest".into(),
                input_schema: Some(serde_json::json!({"type": "object"})),
                output_schema: None,
                tool_annotations: None,
                action_metadata: None,
                risk: "high".into(),
                side_effects: true,
                pii: false,
                data_classification: None,
                cost_class: None,
                requires_approval: false,
            },
        )))),
        generation: Some(std::sync::atomic::AtomicI64::new(1)),
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog.clone());
    let resolves = || catalog.resolves.load(Ordering::SeqCst);
    let admit = || pool.resolve_invocation_tool("default", "example-messages", "send");

    expect_snapshot(admit().await);
    assert_eq!(resolves(), 1);
    expect_snapshot(admit().await);
    assert_eq!(resolves(), 1, "an unchanged generation reuses the read");

    catalog
        .generation
        .as_ref()
        .unwrap()
        .fetch_add(1, Ordering::SeqCst);
    expect_snapshot(admit().await);
    assert_eq!(resolves(), 2, "a new generation reads again");

    // A read that a committed change overlaps is used once, never kept.
    catalog.advance_during_resolve.store(true, Ordering::SeqCst);
    catalog
        .generation
        .as_ref()
        .unwrap()
        .fetch_add(1, Ordering::SeqCst);
    expect_snapshot(admit().await);
    assert_eq!(resolves(), 3);
    catalog
        .advance_during_resolve
        .store(false, Ordering::SeqCst);
    expect_snapshot(admit().await);
    assert_eq!(resolves(), 4, "the overlapped read was not kept");
    expect_snapshot(admit().await);
    assert_eq!(resolves(), 4);
}

#[tokio::test]
async fn long_running_tools_follow_the_live_manifest_without_reconnecting() {
    let pool = pool_with_manifest_tool();
    assert!(!pool.long_running_tool("example-messages", "send"));
    let mut manifests: BTreeMap<_, _> = pool
        .manifests()
        .into_iter()
        .map(|manifest| (manifest.name.clone(), manifest))
        .collect();
    for (listed, expected) in [(vec!["send".to_owned()], true), (Vec::new(), false)] {
        manifests
            .get_mut("example-messages")
            .expect("configured server")
            .long_running_tools = listed;
        let report = pool.reload_manifests(&manifests).await;
        assert_eq!(report.response_policy_updated, ["example-messages"]);
        assert!(
            report.redialed.is_empty() && report.redial_failed.is_empty(),
            "the list is request-path policy, not connection shape: {report:?}"
        );
        assert!(!report.requires_restart());
        assert_eq!(pool.long_running_tool("example-messages", "send"), expected);
    }
    assert!(!pool.long_running_tool("example-messages", "unlisted"));
    assert!(!pool.long_running_tool("unknown-server", "send"));
}

#[tokio::test]
async fn call_limits_follow_the_live_manifest_without_reconnecting() {
    let pool = pool_with_manifest_tool()
        .with_call_timeout(Some(Duration::from_secs(300)))
        .with_call_response_max_bytes(4096);
    let live = |pool: &UpstreamPool| {
        pool.manifests()
            .into_iter()
            .find(|manifest| manifest.name == "example-messages")
            .expect("configured server")
    };
    assert_eq!(
        pool.call_timeout_for(&live(&pool)),
        Some(Duration::from_secs(300))
    );
    assert_eq!(pool.call_response_limit_for(&live(&pool)), Some(4096));

    let mut manifests: BTreeMap<_, _> = pool
        .manifests()
        .into_iter()
        .map(|manifest| (manifest.name.clone(), manifest))
        .collect();
    for (limits, timeout, response_limit) in [
        (
            Some(crate::UpstreamLimits {
                call_timeout_seconds: Some(7),
                call_response_max_bytes: Some(1024),
            }),
            Some(Duration::from_secs(7)),
            Some(1024),
        ),
        (
            Some(crate::UpstreamLimits {
                call_timeout_seconds: Some(0),
                call_response_max_bytes: None,
            }),
            None,
            Some(4096),
        ),
        (None, Some(Duration::from_secs(300)), Some(4096)),
    ] {
        manifests
            .get_mut("example-messages")
            .expect("configured server")
            .limits = limits.clone();
        let report = pool.reload_manifests(&manifests).await;
        assert_eq!(report.response_policy_updated, ["example-messages"]);
        assert!(
            report.redialed.is_empty() && report.redial_failed.is_empty(),
            "limits are request-path policy, not connection shape: {report:?}"
        );
        assert_eq!(live(&pool).limits, limits);
        assert_eq!(pool.call_timeout_for(&live(&pool)), timeout, "{limits:?}");
        assert_eq!(
            pool.call_response_limit_for(&live(&pool)),
            response_limit,
            "{limits:?}"
        );
    }

    let disabled_globally = pool.with_call_timeout(None);
    let mut overridden = live(&disabled_globally);
    overridden.limits = Some(crate::UpstreamLimits {
        call_timeout_seconds: Some(30),
        call_response_max_bytes: None,
    });
    assert_eq!(
        disabled_globally.call_timeout_for(&overridden),
        Some(Duration::from_secs(30)),
        "a server's timeout applies even when the gateway-wide one is disabled"
    );
    for transport in [Transport::Sse, Transport::Stdio] {
        assert_eq!(
            disabled_globally.call_response_limit_for(&shape_manifest(transport, None)),
            None,
            "only streamable HTTP carries the limit to an enforcing transport"
        );
    }
}

#[tokio::test]
async fn resolve_invocation_tool_prefers_catalog_live() {
    // Catalog says Low/no-side-effects/pii; manifest says
    // High/side_effects. The catalog Live result must win when its version is
    // bound to that source manifest generation.
    let source_version =
        waygate_catalog::manifest_classification_hash("send", "high", true, false, None, &[]);
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
            waygate_catalog::ToolDefinition {
                discriminator: None,
                operations: Vec::new(),
                tool_id: uuid_nil(),
                server_id: uuid_nil(),
                server_name: "example-messages".into(),
                tool_name: "send".into(),
                schema_hash: source_version.clone(),
                description: "d".into(),
                classification_mode: "manifest".into(),
                input_schema: Some(serde_json::json!({"type": "object"})),
                output_schema: Some(serde_json::json!({"type": "integer"})),
                tool_annotations: None,
                action_metadata: None,
                risk: "low".into(),
                side_effects: false,
                pii: true,
                data_classification: None,
                cost_class: None,
                requires_approval: false,
            },
        )))),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog);
    let threshold = std::num::NonZeroUsize::new(64 * 1024);
    let mut manifests: BTreeMap<_, _> = pool
        .manifests()
        .into_iter()
        .map(|manifest| (manifest.name.clone(), manifest))
        .collect();
    manifests
        .get_mut("example-messages")
        .expect("configured server")
        .inline_response_threshold_bytes = threshold;
    let report = pool.reload_manifests(&manifests).await;
    assert_eq!(report.response_policy_updated, ["example-messages"]);
    let snapshot = expect_snapshot(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
    );
    let facts = snapshot.facts();
    assert_eq!(snapshot.inline_response_threshold_bytes(), threshold);
    assert_eq!(facts.risk, RiskTier::Low, "catalog Live risk must win");
    assert!(!facts.side_effects, "catalog Live side_effects must win");
    assert!(facts.pii, "catalog Live pii must win");
    assert!(matches!(
        snapshot.authority(),
        ResolutionAuthority::Catalog {
            tool_id,
            schema_hash
        } if *tool_id == uuid_nil() && schema_hash == &source_version
    ));
    assert_eq!(
        snapshot.input_schema(),
        Some(&serde_json::json!({"type": "object"}))
    );
    assert_eq!(
        snapshot.output_schema(),
        Some(&serde_json::json!({"type": "integer"}))
    );
}

#[tokio::test]
async fn catalog_transition_fence_tracks_generation_without_erasing_catalog_override() {
    let final_source_version =
        waygate_catalog::manifest_classification_hash("send", "low", true, false, None, &[]);
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
            waygate_catalog::ToolDefinition {
                discriminator: None,
                operations: Vec::new(),
                tool_id: uuid_nil(),
                server_id: uuid_nil(),
                server_name: "example-messages".into(),
                tool_name: "send".into(),
                schema_hash: final_source_version,
                description: "d".into(),
                classification_mode: "manifest".into(),
                input_schema: Some(serde_json::json!({"type": "object"})),
                output_schema: None,
                tool_annotations: None,
                action_metadata: None,
                risk: "low".into(),
                side_effects: false,
                pii: true,
                data_classification: None,
                cost_class: None,
                requires_approval: false,
            },
        )))),
        err: false,
        ..Default::default()
    });
    let manifest_set = |risk| {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "example-messages".to_owned(),
            UpstreamManifest {
                classification_mode: Default::default(),
                approval_mode: Default::default(),
                inline_response_threshold_bytes: None,
                long_running_tools: Vec::new(),
                limits: None,
                name: "example-messages".into(),
                transport: Transport::Http,
                protocol: Default::default(),
                url: Some("http://example-messages.test/mcp".into()),
                command: None,
                env_passthrough: Vec::new(),
                tools: vec![
                    ToolClassification::new("send", risk, true, false),
                    ToolClassification::new("receive", RiskTier::Low, false, false),
                ],
                resources: Vec::new(),
                exchange: None,
                auth: None,
                headers: Default::default(),
                mtls: None,
                tier_a_required: false,
                tier_c_peer: None,
                trust: crate::TrustLevel::Internal,
                identity: None,
                forward_trace_context: None,
                session: None,
            },
        );
        map
    };
    let pool = UpstreamPool::from_manifests_disconnected(manifest_set(RiskTier::High))
        .with_catalog(catalog);
    let epoch = pool.tool_catalog_epoch();

    let first = pool.reload_manifests(&manifest_set(RiskTier::Medium)).await;
    assert_eq!(
        epoch.current(),
        1,
        "a governance-only manifest edit must invalidate cached discovery",
    );
    assert!(pool
        .catalog_transition_state("example-messages", "send")
        .is_some_and(|transition| transition.pending));
    assert!(
        pool.catalog_transition_state("example-messages", "receive")
            .is_none(),
        "an unchanged tool on the same server must remain available",
    );
    assert!(matches!(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
        ResolvedInvocationTool::Unavailable {
            reason: TemporaryUnavailability::CatalogConverging,
            ..
        }
    ));

    let second = pool.reload_manifests(&manifest_set(RiskTier::Low)).await;
    assert_eq!(epoch.current(), 2);
    pool.settle_catalog_reconcile(&first);
    assert_eq!(
        epoch.current(),
        2,
        "an obsolete settlement changes no visible transition",
    );
    assert!(
        pool.catalog_transition_state("example-messages", "send")
            .is_some_and(|transition| transition.pending),
        "an older reconcile must not clear a newer manifest transition",
    );

    pool.settle_catalog_reconcile(&second);
    assert_eq!(
        epoch.current(),
        3,
        "settlement makes the reconciled tool discoverable again",
    );
    assert!(
        pool.catalog_transition_state("example-messages", "send")
            .is_some_and(|transition| !transition.pending),
        "settlement must retain the generation witness for in-flight readers",
    );
    let settled = expect_snapshot(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
    );
    assert_eq!(
        settled.facts().risk,
        RiskTier::Low,
        "the reviewed catalog override remains authoritative after convergence",
    );
    assert!(!settled.facts().side_effects);
    assert!(settled.facts().pii);
}

#[tokio::test]
async fn shared_catalog_generation_fences_a_replica_with_an_older_manifest() {
    // Another replica has already reconciled a newer Low-risk manifest into
    // the shared catalog. This pool still serves the older High-risk source
    // generation and has no process-local transition marker, so the durable
    // source-version binding must refuse the mixed snapshot on its own.
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
            waygate_catalog::ToolDefinition {
                discriminator: None,
                operations: Vec::new(),
                tool_id: uuid_nil(),
                server_id: uuid_nil(),
                server_name: "example-messages".into(),
                tool_name: "send".into(),
                schema_hash: waygate_catalog::manifest_classification_hash(
                    "send",
                    "low",
                    true,
                    false,
                    None,
                    &[],
                ),
                description: "d".into(),
                classification_mode: "manifest".into(),
                input_schema: Some(serde_json::json!({"type": "object"})),
                output_schema: None,
                tool_annotations: None,
                action_metadata: None,
                risk: "low".into(),
                side_effects: true,
                pii: false,
                data_classification: None,
                cost_class: None,
                requires_approval: false,
            },
        )))),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog);

    assert!(matches!(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
        ResolvedInvocationTool::Unavailable {
            reason: TemporaryUnavailability::CatalogConverging,
            ..
        }
    ));
}

#[tokio::test]
async fn resolve_invocation_tool_falls_back_on_not_found() {
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::NotFound)),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog);
    let facts = expect_facts(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
    );
    // Manifest fallback: High + side_effects.
    assert_eq!(facts.risk, RiskTier::High);
    assert!(facts.side_effects);
}

#[tokio::test]
async fn authoritative_catalog_refuses_not_found_instead_of_reviving_manifest_tool() {
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::NotFound)),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_authoritative_catalog(catalog);

    assert!(matches!(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
        ResolvedInvocationTool::Refused {
            reason: ToolRefusal::NotInCatalog,
            ..
        }
    ));
    // An unknown server under the authoritative catalog is the same refusal,
    // not a fallback to default facts.
    assert!(matches!(
        pool.resolve_invocation_tool("default", "garage", "searchTools")
            .await,
        ResolvedInvocationTool::Refused {
            reason: ToolRefusal::NotInCatalog,
            ..
        }
    ));
}

#[tokio::test]
async fn resolve_invocation_tool_falls_back_on_pending_approval() {
    // Default (strict mode OFF): `PendingApproval` falls back to the
    // manifest classification. This is the transitional behavior
    // path, kept so deployments that haven't approved
    // every catalog tool yet aren't broken by a `--import-manifests`
    // run that leaves tools at PendingApproval.
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::PendingApproval {
            server_name: "example-messages".into(),
            tool_name: "send".into(),
        })),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog);
    let facts = expect_facts(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
    );
    assert_eq!(
        facts.risk,
        RiskTier::High,
        "pending-approval falls back to manifest"
    );
}

/// Strict mode ON → `PendingApproval` is refused as `ApprovalPending`
/// instead of falling back, so a un-approved schema can't be
/// dispatched against. This is the right end-state once the
/// catalog is reliably populated; operators opt in via env.
#[tokio::test]
async fn resolve_invocation_tool_strict_mode_refuses_pending_approval() {
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::PendingApproval {
            server_name: "example-messages".into(),
            tool_name: "send".into(),
        })),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool()
        .with_catalog(catalog)
        .with_catalog_strict_pending_approval(true);
    match pool
        .resolve_invocation_tool("default", "example-messages", "send")
        .await
    {
        ResolvedInvocationTool::Refused {
            server,
            tool,
            reason,
        } => {
            assert_eq!(server, "example-messages");
            assert_eq!(tool, "send");
            assert_eq!(reason, ToolRefusal::ApprovalPending);
        }
        ResolvedInvocationTool::Ready(_) => {
            panic!("strict mode must refuse PendingApproval, not fall back to manifest")
        }
        ResolvedInvocationTool::Unavailable { .. } => {
            panic!("pending approval is a lifecycle state, not catalog unavailability")
        }
    }
}

/// Even under strict mode, `NotFound` and catalog DB errors
/// keep the manifest fallback — those are distinct failure modes
/// (catalog not yet seeded vs an outage) that warrant a different
/// story than "tool exists in catalog but isn't yet approved."
/// Without this guard, turning on strict mode would lock out every
/// tool the catalog hasn't yet imported.
#[tokio::test]
async fn resolve_invocation_tool_strict_mode_does_not_block_not_found() {
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::NotFound)),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool()
        .with_catalog(catalog)
        .with_catalog_strict_pending_approval(true);
    let facts = expect_facts(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
    );
    assert_eq!(
        facts.risk,
        RiskTier::High,
        "NotFound still falls back to manifest even under strict mode",
    );
}

#[test]
fn catalog_strict_pending_approval_from_env_recognizes_truthy() {
    let saved = std::env::var("GATEWAY_CATALOG_STRICT_PENDING_APPROVAL").ok();
    // Default: unset → false.
    unsafe { std::env::remove_var("GATEWAY_CATALOG_STRICT_PENDING_APPROVAL") };
    assert!(!catalog_strict_pending_approval_from_env());
    for (raw, expected) in [
        ("true", true),
        ("TRUE", true),
        ("1", true),
        ("false", false),
        ("FALSE", false),
        ("0", false),
        // Unknown / unparseable falls back to false — never silent
        // auto-enable of a behavior that BLOCKS calls.
        ("yes", false),
        ("bogus", false),
        ("", false),
    ] {
        unsafe { std::env::set_var("GATEWAY_CATALOG_STRICT_PENDING_APPROVAL", raw) };
        assert_eq!(
            catalog_strict_pending_approval_from_env(),
            expected,
            "env value {raw:?} should parse to {expected}",
        );
    }
    match saved {
        Some(v) => unsafe { std::env::set_var("GATEWAY_CATALOG_STRICT_PENDING_APPROVAL", v) },
        None => unsafe { std::env::remove_var("GATEWAY_CATALOG_STRICT_PENDING_APPROVAL") },
    }
}

#[tokio::test]
async fn resolve_invocation_tool_falls_back_on_catalog_error() {
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(None),
        err: true,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog);
    let snapshot = expect_snapshot(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
    );
    let facts = snapshot.facts();
    assert_eq!(
        facts.risk,
        RiskTier::High,
        "catalog error falls back to manifest"
    );
    assert!(matches!(
        snapshot.authority(),
        ResolutionAuthority::ManifestFallback {
            approval_requirements_known: false,
            ..
        }
    ));
}

#[tokio::test]
async fn authoritative_catalog_reports_store_error_as_retryable_unavailability() {
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(None),
        err: true,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_authoritative_catalog(catalog);

    assert!(matches!(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
        ResolvedInvocationTool::Unavailable {
            server,
            tool,
            reason: TemporaryUnavailability::CatalogUnavailable,
        } if server == "example-messages" && tool == "send"
    ));
    assert_eq!(pool.discovery_error_generation(), 1);
}

#[tokio::test]
async fn resolve_invocation_tool_no_catalog_uses_manifest() {
    let pool = pool_with_manifest_tool();
    let snapshot = expect_snapshot(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
    );
    let facts = snapshot.facts();
    assert_eq!(facts.risk, RiskTier::High);
    assert!(facts.side_effects);
    assert!(matches!(
        snapshot.authority(),
        ResolutionAuthority::ManifestFallback {
            approval_requirements_known: true,
            ..
        }
    ));
}

fn uuid_nil() -> uuid::Uuid {
    uuid::Uuid::nil()
}

/// Unwrap the listable-facts arm; panic if the catalog signalled a
/// refusal (the tests that exercise the block assert on it
/// directly instead).
fn expect_facts(r: ResolvedInvocationTool) -> ToolFacts {
    expect_snapshot(r).facts().clone()
}

fn expect_snapshot(r: ResolvedInvocationTool) -> InvocationToolSnapshot {
    match r {
        ResolvedInvocationTool::Ready(snapshot) => snapshot,
        ResolvedInvocationTool::Refused {
            server,
            tool,
            reason,
        } => {
            panic!("expected Facts, got Refused {{ {server}, {tool}, {reason:?} }}")
        }
        ResolvedInvocationTool::Unavailable {
            server,
            tool,
            reason,
        } => {
            panic!("expected Facts, got Unavailable {{ {server}, {tool}, {reason:?} }}")
        }
    }
}

#[tokio::test]
async fn resolve_invocation_tool_quarantined_does_not_fall_back() {
    // A quarantined catalog server must NOT be rehabilitated by the
    // manifest fallback — that's the whole point of the quarantine
    // admin endpoint. The result is an authoritative block, even
    // though the manifest still classifies example-messages.send.
    for (retired, expected) in [
        (false, ToolRefusal::ServerQuarantined),
        (true, ToolRefusal::ServerRetired),
    ] {
        let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
            outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Quarantined {
                server_name: "example-messages".into(),
                tool_name: "send".into(),
                retired,
            })),
            err: false,
            ..Default::default()
        });
        let pool = pool_with_manifest_tool().with_catalog(catalog);
        match pool
            .resolve_invocation_tool("default", "example-messages", "send")
            .await
        {
            ResolvedInvocationTool::Refused {
                server,
                tool,
                reason,
            } => {
                assert_eq!(server, "example-messages");
                assert_eq!(tool, "send");
                assert_eq!(reason, expected);
            }
            ResolvedInvocationTool::Ready(_) => {
                panic!("quarantine must not fall back to manifest facts")
            }
            ResolvedInvocationTool::Unavailable { .. } => {
                panic!("quarantine is a lifecycle state, not catalog unavailability")
            }
        }
    }
}

/// A streamable-HTTP MCP upstream that lists the same tools on every session.
#[derive(Clone)]
struct ListedToolsUpstream(Arc<Vec<Tool>>);

impl rmcp::ServerHandler for ListedToolsUpstream {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        rmcp::model::ServerConfig::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, McpError> {
        Ok(rmcp::model::ListToolsResult::with_all_items(
            self.0.as_ref().clone(),
        ))
    }
}

/// Connect a pool to a live upstream named `garage` that lists `live` and
/// whose manifest classifies `classified`.
async fn pool_connected_to(
    mode: crate::ClassificationMode,
    live: Vec<Tool>,
    classified: Vec<ToolClassification>,
) -> UpstreamPool {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    let handler = ListedToolsUpstream(Arc::new(live));
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test upstream");
    let url = format!("http://{}/mcp", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, axum::Router::new().nest_service("/mcp", service)).await;
    });
    let mut manifest = manifest_with(false);
    manifest.name = "garage".into();
    manifest.url = Some(url);
    manifest.classification_mode = mode;
    manifest.tools = classified;
    let pool = UpstreamPool::connect(BTreeMap::from([("garage".to_owned(), manifest)])).await;
    assert!(
        pool.is_connected("garage").await,
        "fixture upstream connects"
    );
    pool
}

fn refusal_reason(resolved: ResolvedInvocationTool) -> Result<ToolRefusal, String> {
    match resolved {
        ResolvedInvocationTool::Refused { reason, .. } => Ok(reason),
        ResolvedInvocationTool::Ready(_) => Err("Ready".into()),
        ResolvedInvocationTool::Unavailable { reason, .. } => Err(format!("{reason:?}")),
    }
}

/// A stale client cache can name a tool the upstream no longer serves, such
/// as a retired adapter. That is an absent tool, not a quarantine, and an
/// advertised name with no classification is distinguishable for operators.
#[tokio::test]
async fn manifest_mode_refuses_unclassified_and_absent_names_with_their_reasons() {
    let pool = pool_connected_to(
        crate::ClassificationMode::Manifest,
        vec![live("read"), live("extra")],
        vec![classification("read")],
    )
    .await;

    expect_snapshot(
        pool.resolve_invocation_tool("default", "garage", "read")
            .await,
    );
    assert_eq!(
        refusal_reason(
            pool.resolve_invocation_tool("default", "garage", "extra")
                .await
        ),
        Ok(ToolRefusal::Unclassified),
    );
    assert_eq!(
        refusal_reason(
            pool.resolve_invocation_tool("default", "garage", "searchTools")
                .await
        ),
        Ok(ToolRefusal::NotInCatalog),
    );
}

#[tokio::test]
async fn annotation_mode_refuses_unlisted_unclassified_and_unapproved_names() {
    let mut unapproved = classification("read");
    unapproved.approved_behavior_hash = Some("0".repeat(64));
    let pool = pool_connected_to(
        crate::ClassificationMode::McpAnnotations,
        vec![
            annotation_native_live("read"),
            annotation_native_live("extra"),
        ],
        vec![unapproved],
    )
    .await;

    let cases = [
        ("searchTools", ToolRefusal::NotInCatalog),
        ("extra", ToolRefusal::Unclassified),
        ("read", ToolRefusal::NotAdmitted),
    ];
    for (tool, expected) in cases {
        assert_eq!(
            refusal_reason(
                pool.resolve_invocation_tool("default", "garage", tool)
                    .await
            ),
            Ok(expected),
            "{tool}",
        );
    }
    // Discovery's batch reader applies the same rules to the same names.
    let names: Vec<String> = cases.iter().map(|(tool, _)| (*tool).to_owned()).collect();
    let batch = pool
        .resolve_discovery_tools("default", "garage", &names)
        .await
        .expect("discovery batch");
    for ((tool, expected), resolved) in cases.into_iter().zip(batch) {
        assert_eq!(refusal_reason(resolved), Ok(expected), "batch {tool}");
    }
}

/// With no connected session an annotation-mode name cannot be checked
/// against its approved contract. That clears when the upstream reconnects,
/// so it is retryable unavailability rather than a refusal.
#[tokio::test]
async fn annotation_mode_without_a_connected_lane_is_temporarily_unavailable() {
    let mut manifest = manifest_with(false);
    manifest.classification_mode = crate::ClassificationMode::McpAnnotations;
    let mut approved = classification("send_message");
    approved.approved_behavior_hash = Some("a".repeat(64));
    manifest.tools = vec![approved];
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
        "example-messages".to_owned(),
        manifest,
    )]));

    assert!(matches!(
        pool.resolve_invocation_tool("default", "example-messages", "send_message")
            .await,
        ResolvedInvocationTool::Unavailable {
            reason: TemporaryUnavailability::NoConnectedLane,
            ..
        }
    ));
}

#[tokio::test]
async fn in_process_drift_quarantine_is_its_own_refusal() {
    let pool = pool_with_one_upstream("send", RiskTier::High);
    pool.entries
        .load()
        .get("example-messages")
        .expect("entry")
        .quarantined
        .write()
        .expect("upstream quarantine lock poisoned")
        .insert("send".to_owned());

    assert_eq!(
        refusal_reason(
            pool.resolve_invocation_tool("default", "example-messages", "send")
                .await
        ),
        Ok(ToolRefusal::DriftQuarantined),
    );
}

/// A server the catalog has quarantined or retired is reported as blocked
/// even when the live contract check would refuse the tool for its own
/// reason or call it temporarily unavailable, so a caller is never told to
/// retry a call that only an administrator can unblock.
#[tokio::test]
async fn a_catalog_server_block_outranks_live_contract_reasons() {
    let quarantined_catalog = |retired| -> waygate_catalog::SharedCatalogStore {
        Arc::new(ScriptedCatalog {
            outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Quarantined {
                server_name: "example-messages".into(),
                tool_name: "send_message".into(),
                retired,
            })),
            err: false,
            ..Default::default()
        })
    };
    for (retired, expected) in [
        (false, ToolRefusal::ServerQuarantined),
        (true, ToolRefusal::ServerRetired),
    ] {
        // No connected session: the live check alone reports a temporary state.
        let mut manifest = manifest_with(false);
        manifest.classification_mode = crate::ClassificationMode::McpAnnotations;
        let mut approved = classification("send_message");
        approved.approved_behavior_hash = Some("a".repeat(64));
        manifest.tools = vec![approved];
        let disconnected = UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
            "example-messages".to_owned(),
            manifest,
        )]))
        .with_catalog(quarantined_catalog(retired));
        assert_eq!(
            refusal_reason(
                disconnected
                    .resolve_invocation_tool("default", "example-messages", "send_message")
                    .await
            ),
            Ok(expected),
            "disconnected, retired={retired}",
        );

        // An in-process drift quarantine is a per-tool reason.
        let drifted = pool_with_one_upstream("send_message", RiskTier::High)
            .with_catalog(quarantined_catalog(retired));
        drifted
            .entries
            .load()
            .get("example-messages")
            .expect("entry")
            .quarantined
            .write()
            .expect("upstream quarantine lock poisoned")
            .insert("send_message".to_owned());
        assert_eq!(
            refusal_reason(
                drifted
                    .resolve_invocation_tool("default", "example-messages", "send_message")
                    .await
            ),
            Ok(expected),
            "drift quarantined, retired={retired}",
        );
    }
}

/// A catalog transition that has not converged is temporary for a live
/// server, but a quarantined or retired server stays reported as blocked.
#[tokio::test]
async fn a_catalog_server_block_outranks_a_converging_transition() {
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Quarantined {
            server_name: "example-messages".into(),
            tool_name: "send_message".into(),
            retired: false,
        })),
        err: false,
        ..Default::default()
    });
    let manifest_set = |risk| {
        let mut manifest = manifest_with(false);
        manifest.tools = vec![ToolClassification::new("send_message", risk, true, false)];
        BTreeMap::from([("example-messages".to_owned(), manifest)])
    };
    let pool = UpstreamPool::from_manifests_disconnected(manifest_set(RiskTier::High))
        .with_catalog(catalog);
    // A governance-only edit leaves the tool's catalog facts unsettled.
    pool.reload_manifests(&manifest_set(RiskTier::Medium)).await;
    assert!(pool
        .catalog_transition_state("example-messages", "send_message")
        .is_some_and(|transition| transition.pending));

    assert_eq!(
        refusal_reason(
            pool.resolve_invocation_tool("default", "example-messages", "send_message")
                .await
        ),
        Ok(ToolRefusal::ServerQuarantined),
    );
}

#[tokio::test]
async fn resolved_side_effects_reports_resolver_facts_and_defaults_conservative() {
    // Ready snapshot: the derived side-effect fact is returned as-is
    // (example-messages.send is a manifest-classified side-effecting tool), matching the
    // resolver rather than the synchronous conservative fallback.
    let pool = pool_with_manifest_tool();
    assert!(
        pool.resolved_side_effects("default", "example-messages", "send")
            .await
    );

    // A quarantined tool cannot resolve, so it is reported side-effecting and
    // routed through approval instead of being silently treated as a read.
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Quarantined {
            server_name: "example-messages".into(),
            tool_name: "send".into(),
            retired: false,
        })),
        err: false,
        ..Default::default()
    });
    let quarantined = pool_with_manifest_tool().with_catalog(catalog);
    assert!(
        quarantined
            .resolved_side_effects("default", "example-messages", "send")
            .await
    );
}

/// Helper: construct a `Principal` with explicit `auth_method`.
/// Other fields are fixed because the gate only branches on
/// `auth_method`; passing-through irrelevant fields keeps the
/// test bodies focused on the predicate being asserted.
fn principal_with(auth_method: AuthMethod) -> Principal {
    Principal {
        sub: "alice@example.com".into(),
        email: None,
        groups: vec![],
        issuer: "https://auth.test/".into(),
        scopes: vec![],
        tenant: waygate_core::TenantId::default(),
        auth_method,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

#[test]
fn tier_a_gate_allows_oauth_with_exchange() {
    // The expected happy-path cell: an OAuth caller hitting an
    // upstream whose manifest declares `exchange:`. The gate
    // must let the lookup proceed.
    let exchange = ExchangeSettings {
        audience: "https://example-messages.test/mcp".into(),
        scope: None,
    };
    let p = principal_with(AuthMethod::Oauth);
    assert!(should_consult_tier_a_session(&p, Some(&exchange)));
}

#[test]
fn tier_a_gate_blocks_api_key_even_with_matching_sub() {
    // Privilege escalation: an API-key principal
    // whose `sub` happens to match an OAuth user (operator-minted
    // for impersonation, or just shared identifier convention)
    // MUST NOT be allowed to borrow stored upstream sessions.
    // Locking the gate here means a future change has to break
    // this test before it can ship.
    let exchange = ExchangeSettings {
        audience: "https://example-messages.test/mcp".into(),
        scope: None,
    };
    let p = principal_with(AuthMethod::ApiKey);
    assert!(
        !should_consult_tier_a_session(&p, Some(&exchange)),
        "API-key principals must NOT be allowed to consult durable OAuth upstream sessions \
         (privilege-escalation guard — see should_consult_tier_a_session doc)",
    );
}

#[test]
fn tier_a_gate_blocks_when_upstream_did_not_opt_into_exchange() {
    // Without `exchange:`, the upstream doesn't want a downscoped
    // bearer at all — there's nothing to feed a subject token to.
    // Save the DB round-trip.
    let p = principal_with(AuthMethod::Oauth);
    assert!(!should_consult_tier_a_session(&p, None));
}

fn manifest_with(tier_a_required: bool) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        inline_response_threshold_bytes: None,
        long_running_tools: Vec::new(),
        limits: None,
        name: "example-messages".into(),
        transport: Transport::Http,
        protocol: Default::default(),
        url: Some("http://example-messages:8000/mcp".into()),
        command: None,
        env_passthrough: Vec::new(),
        tools: vec![ToolClassification::new(
            "send_message",
            RiskTier::Low,
            false,
            false,
        )],
        resources: Vec::new(),
        exchange: None,
        auth: None,
        headers: Default::default(),
        mtls: None,
        tier_a_required,
        tier_c_peer: None,
        trust: crate::TrustLevel::Internal,
        identity: None,
        forward_trace_context: None,
        session: None,
    }
}

#[tokio::test]
async fn reload_reports_exchange_only_change_not_noop() {
    // A bundle that flips only `exchange` is hot-applied but changes no
    // classification or connection shape. The report must record it as an
    // identity update so the dashboard doesn't render a no-op.
    let mut map = BTreeMap::new();
    map.insert("example-messages".into(), manifest_with(false));
    let pool = UpstreamPool::from_manifests_disconnected(map);

    let mut fresh = manifest_with(false);
    fresh.exchange = Some(crate::ExchangeConfig {
        audience: "https://idp/upstream".into(),
        scope: None,
    });
    let mut fresh_map = BTreeMap::new();
    fresh_map.insert("example-messages".into(), fresh);

    let report = pool.reload_manifests(&fresh_map).await;
    assert_eq!(
        report.identity_updated,
        vec!["example-messages".to_string()]
    );
    assert!(
        report.classifications_updated.is_empty(),
        "tools were unchanged"
    );
    assert!(!report.is_noop(), "an exchange-only change is not a no-op");

    // Re-reloading the now-current set is a genuine no-op (verifies the
    // compare-before-copy doesn't false-positive on unchanged identity).
    let report2 = pool.reload_manifests(&fresh_map).await;
    assert!(report2.identity_updated.is_empty());
    assert!(report2.is_noop(), "an unchanged reload must be a no-op");
}

#[tokio::test]
async fn reload_reports_readd_of_tombstoned_upstream_as_added() {
    // remove-then-readd across two reloads: removal HOT-drops the entry from
    // the registry (not just a lingering tombstone), and the re-add builds a
    // fresh, dialed entry — reported as `added` and HOT (not restart-
    // required). The short redial timeout bounds the re-add's (failing) dial
    // so the test stays fast; the disconnected fixture has no real upstream,
    // so the rebuilt entry is down but PRESENT in the registry.
    let mut map = BTreeMap::new();
    map.insert("example-messages".into(), manifest_with(false));
    let pool = UpstreamPool::from_manifests_disconnected(map)
        .with_redial_dial_timeout(Duration::from_millis(200));

    // Reload to an empty set → example-messages removed AND dropped from the map.
    let empty: BTreeMap<String, UpstreamManifest> = BTreeMap::new();
    let r1 = pool.reload_manifests(&empty).await;
    assert_eq!(r1.removed, vec!["example-messages".to_string()]);
    assert!(!r1.requires_restart(), "a hot remove needs no restart");
    assert!(
        pool.manifests().is_empty(),
        "hot remove drops the entry from the registry, not just tombstones it",
    );

    // Reload re-adding it → built fresh, reported as added, hot (no restart),
    // and present in the registry again (a fresh entry, not a refused
    // tombstone).
    let mut readd = BTreeMap::new();
    readd.insert("example-messages".into(), manifest_with(false));
    let r2 = pool.reload_manifests(&readd).await;
    assert_eq!(r2.added, vec!["example-messages".to_string()]);
    assert!(!r2.requires_restart(), "a hot re-add needs no restart");
    assert!(
        r2.classifications_updated.is_empty() && r2.identity_updated.is_empty(),
        "a re-add is a fresh build, not an in-place update",
    );
    assert!(!r2.is_noop(), "a re-add is a change, not a no-op");
    let names: Vec<String> = pool.manifests().into_iter().map(|m| m.name).collect();
    assert_eq!(
        names,
        vec!["example-messages".to_string()],
        "the re-added upstream is back in the registry",
    );
}

/// Build a second test manifest under a distinct name/key. The black-hole
/// HTTP target is irrelevant — the disconnected fixture's dial fails fast
/// (bounded by the short redial timeout); we only assert registry topology.
fn named_manifest(name: &str) -> UpstreamManifest {
    let mut m = manifest_with(false);
    m.name = name.to_owned();
    m
}

/// Like [`named_manifest`] but with the `send_message` tool classified at a
/// chosen risk tier, so a test can observe which reload's in-place
/// classification update won.
fn named_manifest_risk(name: &str, risk: RiskTier) -> UpstreamManifest {
    let mut m = named_manifest(name);
    m.tools = vec![ToolClassification::new("send_message", risk, false, false)];
    m
}

#[tokio::test]
async fn reload_hot_adds_a_new_upstream_into_the_registry() {
    // Start with one upstream; reload a set that also lists a second. The
    // new upstream is dialed-and-published into the live registry with NO
    // restart — present in `manifests()` and addressable (`breaker_state`
    // returns Some). The disconnected fixture's dial fails, so it's down,
    // but — like a boot-time dial failure — still registered for the
    // re-probe to heal.
    let mut map = BTreeMap::new();
    map.insert("example-messages".into(), manifest_with(false));
    let pool = UpstreamPool::from_manifests_disconnected(map)
        .with_redial_dial_timeout(Duration::from_millis(50));

    let mut fresh = BTreeMap::new();
    fresh.insert("example-messages".into(), manifest_with(false));
    fresh.insert("example-mailbox".into(), named_manifest("example-mailbox"));

    let report = pool.reload_manifests(&fresh).await;
    assert_eq!(report.added, vec!["example-mailbox".to_string()]);
    assert!(report.removed.is_empty());
    assert!(!report.requires_restart(), "a hot add needs no restart");
    assert!(
        pool.breaker_state("example-mailbox").is_some(),
        "the added upstream is addressable in the live registry",
    );
    let mut names: Vec<String> = pool.manifests().into_iter().map(|m| m.name).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "example-mailbox".to_string(),
            "example-messages".to_string()
        ]
    );
}

#[tokio::test]
async fn reload_hot_removes_an_upstream_from_the_registry() {
    // Two upstreams; reload a set that drops one. The removed upstream is
    // tombstoned, drained, and dropped from the registry with NO restart —
    // gone from `manifests()` and no longer addressable (`breaker_state`
    // returns None). The kept one is untouched.
    let mut map = BTreeMap::new();
    map.insert("example-messages".into(), manifest_with(false));
    map.insert("example-mailbox".into(), named_manifest("example-mailbox"));
    let pool = UpstreamPool::from_manifests_disconnected(map);

    let mut fresh = BTreeMap::new();
    fresh.insert("example-messages".into(), manifest_with(false));
    let report = pool.reload_manifests(&fresh).await;
    assert_eq!(report.removed, vec!["example-mailbox".to_string()]);
    assert!(report.added.is_empty());
    assert!(!report.requires_restart(), "a hot remove needs no restart");
    assert!(
        pool.breaker_state("example-mailbox").is_none(),
        "the removed upstream is dropped from the registry, not just tombstoned",
    );
    let names: Vec<String> = pool.manifests().into_iter().map(|m| m.name).collect();
    assert_eq!(names, vec!["example-messages".to_string()]);
}

#[tokio::test]
async fn reload_applies_an_add_and_a_remove_in_one_pass() {
    // A single reload that both adds `example-mailbox` and removes `example-messages` swaps
    // the registry atomically to exactly the fresh set — both structural
    // changes land in one published map, with no restart.
    let mut map = BTreeMap::new();
    map.insert("example-messages".into(), manifest_with(false));
    let pool = UpstreamPool::from_manifests_disconnected(map)
        .with_redial_dial_timeout(Duration::from_millis(50));

    let mut fresh = BTreeMap::new();
    fresh.insert("example-mailbox".into(), named_manifest("example-mailbox"));

    let report = pool.reload_manifests(&fresh).await;
    assert_eq!(report.added, vec!["example-mailbox".to_string()]);
    assert_eq!(report.removed, vec!["example-messages".to_string()]);
    assert!(!report.requires_restart());
    assert!(pool.breaker_state("example-mailbox").is_some());
    assert!(
        pool.breaker_state("example-messages").is_none(),
        "the dropped upstream is gone even though the add raced it in the same pass",
    );
    let names: Vec<String> = pool.manifests().into_iter().map(|m| m.name).collect();
    assert_eq!(names, vec!["example-mailbox".to_string()]);
}

#[tokio::test]
async fn concurrent_divergent_structural_reloads_never_merge() {
    // Regression: two overlapping reloads with DIVERGENT desired
    // sets must never publish a merged map matching neither. Live `{a}`; one
    // reload wants `{a,b}`, the other `{a,c}`. The published registry must end
    // up as EXACTLY one reload's complete set ({a,b} or {a,c}) — never the
    // stale-delta merge {a,b,c}. The narrow splice lock + reconcile-to-`fresh`
    // guarantees this regardless of interleaving (the last splicer wins).
    use std::collections::HashSet;
    let mut map = BTreeMap::new();
    map.insert("a".into(), named_manifest("a"));
    let pool = UpstreamPool::from_manifests_disconnected(map)
        .with_redial_dial_timeout(Duration::from_millis(50));

    let mut p = BTreeMap::new();
    p.insert("a".into(), named_manifest("a"));
    p.insert("b".into(), named_manifest("b"));
    let mut q = BTreeMap::new();
    q.insert("a".into(), named_manifest("a"));
    q.insert("c".into(), named_manifest("c"));

    // Drive both reloads concurrently on the same pool; their dials run
    // concurrently and their structural splices serialize on `reload_lock`.
    let (_rp, _rq) = tokio::join!(pool.reload_manifests(&p), pool.reload_manifests(&q));

    let names: HashSet<String> = pool.manifests().into_iter().map(|m| m.name).collect();
    assert!(
        names.contains("a"),
        "the common upstream is always retained"
    );
    assert!(
        names.contains("b") ^ names.contains("c"),
        "exactly one divergent add wins — never a merge (got {names:?})",
    );
    assert_eq!(
        names.len(),
        2,
        "the published map is exactly one reload's complete set, not a merge (got {names:?})",
    );
}

#[tokio::test]
async fn a_superseded_stale_reload_cannot_resurrect_a_removed_upstream() {
    // Regression: a slow, STALE reload that reaches the commit
    // AFTER a newer reload must be fenced — it must not publish a server the
    // newer reload omitted. Reload P (gen 0) adds `b`, but `b`'s dial hangs;
    // reload Q (gen 1) wants only `{a}` and commits first. When P's dial
    // finally times out, its generation is below the applied generation, so it
    // abandons its commit. The final registry is `{a}` — `b` is NOT resurrected.
    use std::collections::HashSet;
    // A listener that accepts the TCP connection but never responds, so the
    // MCP handshake hangs until the (short) redial dial timeout fires — making
    // P's add-of-`b` dial reliably slower than Q's no-dial reload.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock); // hold open, never reply
        }
    });

    let mut map = BTreeMap::new();
    map.insert("a".into(), named_manifest("a"));
    let pool = UpstreamPool::from_manifests_disconnected(map)
        .with_redial_dial_timeout(Duration::from_millis(200));

    // P wants {a, b}; b points at the hanging listener so its dial stalls.
    let mut b = named_manifest("b");
    b.url = Some(format!("http://{addr}/mcp"));
    let mut p = BTreeMap::new();
    p.insert("a".into(), named_manifest("a"));
    p.insert("b".into(), b);
    // Q wants only {a} — no dial, so it commits well before P's hanging dial.
    let mut q = BTreeMap::new();
    q.insert("a".into(), named_manifest("a"));

    // join! polls P first (gen 0, parks on b's dial), then Q (gen 1, no dial,
    // commits {a} and advances the applied generation past P's).
    let (rp, _rq) = tokio::join!(pool.reload_manifests(&p), pool.reload_manifests(&q));

    let names: HashSet<String> = pool.manifests().into_iter().map(|m| m.name).collect();
    assert_eq!(
        names,
        HashSet::from(["a".to_string()]),
        "a stale reload's slow add must be fenced out — b must not be resurrected (got {names:?})",
    );
    // The fenced (older) reload reports itself superseded, so its caller skips
    // the activation/heartbeat audit for a set that didn't win.
    assert!(
        rp.superseded,
        "the superseded reload must flag itself so callers skip the activation audit",
    );
}

#[tokio::test]
async fn a_superseded_stale_reload_cannot_roll_back_a_kept_entry_classification() {
    // Regression: a slow, STALE reload must not roll back a kept
    // entry's IN-PLACE fields after a newer reload advanced them. Live z=Low.
    // Reload P (gen 0) adds `a` (its dial hangs) and would keep z at Low;
    // reload Q (gen 1) raises z to High and commits first. When P's hanging
    // dial returns it processes z, but its per-entry generation is below z's,
    // so it does NOT roll z back to Low.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });

    let mut map = BTreeMap::new();
    map.insert("z".into(), named_manifest_risk("z", RiskTier::Low));
    let pool = UpstreamPool::from_manifests_disconnected(map)
        .with_redial_dial_timeout(Duration::from_millis(200));

    // P adds `a` (sorts before z, so it is dialed first and parks P) and
    // would keep z at Low.
    let mut a = named_manifest("a");
    a.url = Some(format!("http://{addr}/mcp"));
    let mut p = BTreeMap::new();
    p.insert("a".into(), a);
    p.insert("z".into(), named_manifest_risk("z", RiskTier::Low));
    // Q (newer) raises z to High and touches nothing else.
    let mut q = BTreeMap::new();
    q.insert("z".into(), named_manifest_risk("z", RiskTier::High));

    let (_rp, _rq) = tokio::join!(pool.reload_manifests(&p), pool.reload_manifests(&q));

    assert_eq!(
        pool.tool_facts("z", "send_message").risk,
        RiskTier::High,
        "a stale reload must not roll back a kept entry's classification after a newer reload",
    );
}

#[tokio::test]
async fn build_entry_stamps_the_adding_generation() {
    // A hot-added entry must be fenced as of the reload that
    // built it, so `build_entry` seeds `last_reload_gen` from `initial_gen`
    // (NOT 0). That is what stops an OLDER concurrent reload — one that finds
    // the just-added entry in the in-place update branch — from passing the
    // per-entry fence against a `0` baseline and rolling its fields back. The
    // companion `..._roll_back_a_kept_entry_classification` test proves the
    // fence CHECKS `last_reload_gen`; this proves a hot-add SETS it.
    let entry = UpstreamPool::build_entry(
        "b",
        named_manifest("b"),
        None,
        None,
        1,
        Duration::from_millis(20),
        7,
        reconnect::ReconnectPolicy::random(),
        Arc::new(Notify::new()),
    )
    .await;
    assert_eq!(entry.last_reload_gen.load(Ordering::Acquire), 7);
}

#[tokio::test]
async fn inherit_drift_state_carries_quarantine_and_baseline() {
    // A live slot-resize REBUILD replaces the entry with a
    // fresh `build_entry` result, which starts with an empty quarantine set and
    // re-seeds its schema baseline. Without carrying the old entry's drift
    // state, the rebuild would silently clear an active quarantine (the
    // authoritative dispatch BLOCK that `is_quarantined` enforces) and
    // re-baseline schema history — which `clear_quarantine` documents as a
    // restart-only operation. `inherit_drift_state_from` must copy both.
    let old = UpstreamPool::build_entry(
        "s",
        named_manifest("s"),
        None,
        None,
        1,
        Duration::from_millis(20),
        0,
        reconnect::ReconnectPolicy::random(),
        Arc::new(Notify::new()),
    )
    .await;
    let new = UpstreamPool::build_entry(
        "s",
        named_manifest("s"),
        None,
        None,
        2,
        Duration::from_millis(20),
        1,
        reconnect::ReconnectPolicy::random(),
        Arc::new(Notify::new()),
    )
    .await;
    // Accumulate drift state on the entry a rebuild would replace: a
    // quarantined tool (the BLOCK) and a non-empty schema baseline.
    old.quarantined
        .write()
        .expect("upstream quarantine lock poisoned")
        .insert("send_message".to_string());
    old.observed_schemas
        .lock()
        .expect("upstream observed-schema lock poisoned")
        .insert("send_message".to_string(), "schema-hash-v1".to_string());
    // A freshly-built entry starts clean — proving the carry-over is needed.
    assert!(!new.is_quarantined("send_message").await);
    assert!(new
        .observed_schemas
        .lock()
        .expect("upstream observed-schema lock poisoned")
        .is_empty());

    new.inherit_drift_state_from(&old).await;

    assert!(
        new.is_quarantined("send_message").await,
        "the dispatch BLOCK must survive a live rebuild (no silent un-quarantine)",
    );
    assert_eq!(
        new.observed_schemas
            .lock()
            .expect("upstream observed-schema lock poisoned")
            .get("send_message")
            .map(String::as_str),
        Some("schema-hash-v1"),
        "the schema baseline must survive a rebuild (no silent re-baseline)",
    );
}

#[tokio::test]
async fn dispatch_to_a_tombstoned_entry_is_refused() {
    // A hot remove tombstones + drains an entry BEFORE it
    // publishes the map without it. A dispatch that loaded the OLD map during
    // that window holds a cloned `Arc` to the tombstoned entry; the call must
    // be refused (observing `entry.removed`) rather than start a new RPC on a
    // removed upstream.
    let mut map = BTreeMap::new();
    map.insert("example-messages".into(), manifest_with(false));
    let pool = UpstreamPool::from_manifests_disconnected(map);
    // Tombstone the entry as the remove path does, before the map drop.
    pool.entries
        .load()
        .get("example-messages")
        .unwrap()
        .removed
        .store(true, Ordering::Release);

    let err = pool
        .call_tool_inner(
            "example-messages",
            "send_message",
            None,
            None,
            None,
            dispatch::ToolCallDispatchOptions {
                task: None,
                mrtr: Default::default(),
                processor: None,
            },
        )
        .await
        .expect_err("a call to a tombstoned upstream must be refused");
    assert!(
        err.message.contains("being removed"),
        "expected a 'being removed' refusal, got: {}",
        err.message,
    );
}

/// Regression: a manifest that
/// declares `tier_c_peer:` MUST refuse dispatch when the
/// pool was built without identity forwarding (no
/// IdentityIssuer / `forwards_identity == false`).
/// Pre-fix the resolver lived inside the
/// `(forwards_identity, Some(principal))` arm only;
/// callers reaching the `_ => None` arm dispatched
/// without the Tier-C Authorization header.
#[tokio::test]
async fn tier_c_peer_refuses_when_no_identity_forwarding() {
    let mut m = manifest_with(false);
    m.tier_c_peer = Some(::uuid::Uuid::new_v4());
    let mut map = BTreeMap::new();
    map.insert("example-messages".into(), m);
    let pool = UpstreamPool::from_manifests_disconnected(map);

    // Disconnected pool has `forwards_identity == false`.
    let principal = principal_with(AuthMethod::Oauth);
    let err = pool
        .call_tool(
            "example-messages",
            "send_message",
            None,
            Some(&principal),
            None,
        )
        .await
        .expect_err("tier_c_peer without identity forwarding must refuse");
    let display = format!("{err:?}");
    assert!(
        display.contains("tier_c_peer"),
        "error must name the Tier-C invariant: {display}",
    );
    assert!(
        display.contains("identity issuer") || display.contains("GATEWAY_IDENTITY"),
        "error must point operator at the missing identity wiring: {display}",
    );
}

/// Companion: tier_c_peer with
/// no principal (auth disabled) must also refuse loud
/// rather than dispatch unauthenticated.
#[tokio::test]
async fn tier_c_peer_refuses_when_no_principal() {
    let mut m = manifest_with(false);
    m.tier_c_peer = Some(::uuid::Uuid::new_v4());
    let mut map = BTreeMap::new();
    map.insert("example-messages".into(), m);
    let pool = UpstreamPool::from_manifests_disconnected(map);

    // Disconnected fixture also hits the
    // `forwards_identity == false` branch first, which
    // refuses on identity wiring before the principal
    // check fires. That's the correct error to surface
    // — operator fix is the missing wiring, not the
    // anonymous caller. The pin here is just that we
    // don't dispatch.
    let err = pool
        .call_tool("example-messages", "send_message", None, None, None)
        .await
        .expect_err("tier_c_peer without principal must refuse");
    let display = format!("{err:?}");
    assert!(
        display.contains("tier_c_peer"),
        "error must name the Tier-C invariant: {display}",
    );
}

#[test]
fn refuse_when_no_durable_session_blocks_dispatch_under_required() {
    // Refuse point 1: the per-call resolver couldn't produce a
    // stored subject token (user never logged in, row revoked,
    // refresh failed, etc). This check MUST run BEFORE
    // `preflight_exchange` so the pool's
    // raw_token fallback can't satisfy `tier_a_required: true`
    // by exchanging the gateway-issued bearer.
    let m = manifest_with(true);
    let err = refuse_when_no_durable_session(&m, None, "example-messages", "alice@example.com")
        .expect_err("must refuse dispatch when tier_a_required && no stored token");
    let display = format!("{err:?}");
    assert!(
        display.contains("alice@example.com"),
        "error text must name the principal: {display}",
    );
    assert!(
        display.contains("Tier-A"),
        "error text must name the Tier-A invariant: {display}",
    );
    // Operator-routing signal: this refusal points at the user
    // (re-login), distinct from the exchange-failed branch.
    assert!(
        display.contains("no session available"),
        "no-session error text must distinguish from exchange-failure: {display}",
    );
}

#[test]
fn refuse_when_no_durable_session_allows_with_stored_token() {
    let m = manifest_with(true);
    refuse_when_no_durable_session(&m, Some("user-upstream-token"), "example-messages", "alice")
        .expect("stored token satisfies tier_a_required");
}

#[test]
fn refuse_when_no_durable_session_allows_when_flag_false() {
    // Default posture: manifest does NOT require Tier-A. The
    // augmenter falls back to `principal.raw_token` as before
    // — this is the legacy / graceful-fallback path that PRs
    // #86 / #87 / #88 preserve and that this PR's new flag
    // explicitly opts OUT of.
    let m = manifest_with(false);
    refuse_when_no_durable_session(&m, None, "example-messages", "alice")
        .expect("no Tier-A requirement means fallback is permitted");
}

#[test]
fn refuse_when_exchange_failed_blocks_on_none_bearer() {
    // Refuse point 2: the durable session was present (refuse
    // point 1 passed) but the RFC 8693 exchange itself failed
    // (IdP unreachable, scope mismatch, refresh died). Distinct
    // error text from refuse point 1 routes the operator to
    // investigate the IdP rather than ask the user to re-login.
    let m = manifest_with(true);
    let err = refuse_when_exchange_failed(&m, None, "example-messages", "alice")
        .expect_err("None exchanged_bearer must refuse under tier_a_required");
    let display = format!("{err:?}");
    assert!(
        display.contains("Tier-A"),
        "error text must name the Tier-A invariant: {display}",
    );
    // Operator-routing signal: this refusal points at the IdP.
    assert!(
        display.contains("token exchange failed"),
        "exchange-failure error text must distinguish from no-session: {display}",
    );
}

#[test]
fn refuse_when_exchange_failed_allows_with_bearer() {
    let m = manifest_with(true);
    refuse_when_exchange_failed(&m, Some("downscoped-bearer"), "example-messages", "alice")
        .expect("present exchanged bearer satisfies tier_a_required");
}

/// A Tier-A refusal at the
/// dispatch path must NOT consume a breaker permit. The permit
/// is acquired AFTER all gateway-side refuse gates so dropped-
/// unreported permits (which `Permit::drop` defaults to failure)
/// can't trip the upstream circuit on routine refusals. Without
/// the fix, six refusals (default `failure_threshold = 5`) would
/// open the breaker and block subsequent valid Tier-A callers.
#[tokio::test]
async fn tier_a_refusal_does_not_trip_breaker() {
    let mut map = BTreeMap::new();
    let mut m = manifest_with(true);
    m.tools.push(ToolClassification::new(
        "send_message",
        RiskTier::Low,
        false,
        false,
    ));
    map.insert("example-messages".into(), m);
    let pool = UpstreamPool::from_manifests_disconnected(map);

    // Disconnected pools have `identity_cell = None`, so this hits
    // the `tier_a_required && identity_cell.is_none()` refusal
    // path — one of the refuse sites. Other refuse points
    // (no durable session, exchange failure) sit behind the same
    // permit-acquisition reordering, so this test pins the
    // breaker-accounting invariant for all three.
    let principal = principal_with(AuthMethod::Oauth);
    for _ in 0..(BreakerConfig::default().failure_threshold + 3) {
        let res = pool
            .call_tool(
                "example-messages",
                "send_message",
                None,
                Some(&principal),
                None,
            )
            .await;
        assert!(res.is_err(), "tier_a refusal must error out");
    }
    assert_eq!(
        pool.breaker_state("example-messages"),
        Some(BreakerState::Closed),
        "tier_a refusals must not consume the upstream's failure budget",
    );
}

#[test]
fn refuse_when_exchange_failed_allows_when_flag_false() {
    // Non-required upstreams skip the post-pre-flight refuse so
    // legacy behaviour (no exchange settings, fall through to
    // Tier-B / on-the-fly exchange) still works.
    let m = manifest_with(false);
    refuse_when_exchange_failed(&m, None, "example-messages", "alice")
        .expect("no Tier-A requirement means missing exchanged bearer is allowed");
}

fn live(name: &str) -> Tool {
    Tool::new(name.to_owned(), "test", serde_json::Map::new())
}

fn annotation_native_live(name: &str) -> Tool {
    let mut tool = live(name);
    tool.annotations = Some(ToolAnnotations::from_raw(
        None,
        Some(true),
        Some(false),
        Some(true),
        Some(false),
    ));
    tool.meta = Some(Meta(
        serde_json::from_value(serde_json::json!({
            crate::security_metadata::ACTION_METADATA_KEY: {
                "inputMetadata": {
                    "destination": "internal",
                    "sensitivity": "sensitive"
                },
                "returnMetadata": {
                    "source": "first-party",
                    "sensitivity": "sensitive"
                },
                "outcome": "benign",
                "requiresReview": false
            }
        }))
        .expect("object"),
    ));
    tool
}

fn classification(name: &str) -> ToolClassification {
    ToolClassification::new(name, RiskTier::Low, false, false)
}

#[test]
fn partition_keeps_only_classified_tools() {
    let classifications = vec![classification("ok_a"), classification("ok_b")];
    let live_tools = vec![live("ok_a"), live("rogue"), live("ok_b")];
    let (kept, unclassified, ghosts) = partition_live_tools(
        &classifications,
        crate::ClassificationMode::Manifest,
        &live_tools,
    );
    let kept_names: Vec<&str> = kept.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(kept_names, vec!["ok_a", "ok_b"]);
    assert_eq!(unclassified, vec!["rogue".to_owned()]);
    assert!(ghosts.is_empty());
}

#[test]
fn partition_reports_ghost_classifications() {
    let classifications = vec![classification("ok"), classification("phantom")];
    let live_tools = vec![live("ok")];
    let (kept, unclassified, ghosts) = partition_live_tools(
        &classifications,
        crate::ClassificationMode::Manifest,
        &live_tools,
    );
    assert_eq!(kept.len(), 1);
    assert!(unclassified.is_empty());
    assert_eq!(ghosts, vec!["phantom".to_owned()]);
}

#[test]
fn partition_handles_empty_classifications_by_quarantining_all() {
    // The unsafe-default scenario: operator forgot to fill `tools:` in
    // the manifest. Every live tool ends up unclassified, none kept.
    let classifications: Vec<ToolClassification> = Vec::new();
    let live_tools = vec![live("a"), live("b")];
    let (kept, unclassified, ghosts) = partition_live_tools(
        &classifications,
        crate::ClassificationMode::Manifest,
        &live_tools,
    );
    assert!(kept.is_empty());
    assert_eq!(unclassified, vec!["a".to_owned(), "b".to_owned()]);
    assert!(ghosts.is_empty());
}

#[test]
fn annotation_native_partition_fails_closed_without_complete_claims() {
    let valid = annotation_native_live("valid");
    let mut valid_classification = classification("valid");
    valid_classification.approved_behavior_hash =
        Some(crate::security_metadata::behavior_hash(&valid));
    let mut missing_classification = classification("missing");
    missing_classification.approved_behavior_hash = Some("0".repeat(64));
    let classifications = vec![valid_classification, missing_classification];
    let live_tools = vec![valid, live("missing")];
    let (kept, quarantined, ghosts) = partition_live_tools(
        &classifications,
        crate::ClassificationMode::McpAnnotations,
        &live_tools,
    );

    assert_eq!(
        kept.iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>(),
        vec!["valid"]
    );
    assert_eq!(quarantined, vec!["missing"]);
    assert!(ghosts.is_empty());
}

#[test]
fn annotation_native_partition_quarantines_unapproved_behavior_drift() {
    let original = annotation_native_live("read");
    let mut classification = classification("read");
    classification.approved_behavior_hash =
        Some(crate::security_metadata::behavior_hash(&original));

    let mut changed = original;
    changed.description = Some("changed behavior description".to_owned().into());
    let (kept, quarantined, _) = partition_live_tools(
        &[classification],
        crate::ClassificationMode::McpAnnotations,
        &[changed],
    );

    assert!(kept.is_empty());
    assert_eq!(quarantined, vec!["read"]);
}

#[test]
fn final_dispatch_fence_rejects_a_changed_approved_behavior() {
    let entry = entry_with_slots(1);
    let live_tool = annotation_native_live("read");
    let mut initial = manifest_with(false);
    initial.classification_mode = crate::ClassificationMode::McpAnnotations;
    let mut approved = classification("read");
    approved.approved_behavior_hash = Some(crate::security_metadata::behavior_hash(&live_tool));
    initial.tools = vec![approved];

    assert!(dispatch_contract_is_current(
        &entry,
        &initial,
        &initial,
        std::slice::from_ref(&live_tool),
        "read",
        true,
    ));

    let mut changed = initial.clone();
    changed.tools[0].approved_behavior_hash = Some("0".repeat(64));
    assert!(
        !dispatch_contract_is_current(
            &entry,
            &initial,
            &changed,
            std::slice::from_ref(&live_tool),
            "read",
            true,
        ),
        "a classification-only reload must invalidate the pre-reload admission"
    );
}

/// Pins the SIGHUP-promotion path: a previously-quarantined live tool
/// must move into the kept set the moment a classification arrives,
/// without a reconnect. The reload path runs the same partition against
/// the connection's stored `live_tools`, so this test is the unit-level
/// proof that the promotion is visible in the kept set.
#[test]
fn partition_promotes_previously_unclassified_tool_when_classification_added() {
    let live_tools = vec![live("a"), live("b")];

    let initial = vec![classification("a")];
    let (kept_initial, unclassified_initial, _) =
        partition_live_tools(&initial, crate::ClassificationMode::Manifest, &live_tools);
    let initial_names: Vec<&str> = kept_initial.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(initial_names, vec!["a"]);
    assert_eq!(unclassified_initial, vec!["b".to_owned()]);

    // SIGHUP arrives; operator classified `b`. Same live snapshot,
    // expanded classification list — promotion is immediate.
    let promoted = vec![classification("a"), classification("b")];
    let (kept_after, unclassified_after, _) =
        partition_live_tools(&promoted, crate::ClassificationMode::Manifest, &live_tools);
    let after_names: Vec<&str> = kept_after.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(after_names, vec!["a", "b"]);
    assert!(unclassified_after.is_empty());
}

// ----- Connection-pool tests -----

#[test]
fn pool_size_from_env_clamps_zero_to_one() {
    // An env-set GATEWAY_UPSTREAM_POOL_SIZE=0
    // must collapse to a single lane (the documented behaviour), not
    // silently fall back to DEFAULT_UPSTREAM_POOL_SIZE. Only an unset
    // / unparseable value uses the default.
    let var = "GW_TEST_POOL_SIZE_CLAMP";
    unsafe { std::env::set_var(var, "0") };
    let saved = std::env::var("GATEWAY_UPSTREAM_POOL_SIZE").ok();
    unsafe { std::env::set_var("GATEWAY_UPSTREAM_POOL_SIZE", "0") };
    assert_eq!(pool_size_from_env(), 1, "env=0 must clamp to 1");
    unsafe { std::env::set_var("GATEWAY_UPSTREAM_POOL_SIZE", "7") };
    assert_eq!(pool_size_from_env(), 7, "valid env value used verbatim");
    unsafe { std::env::set_var("GATEWAY_UPSTREAM_POOL_SIZE", "garbage") };
    assert_eq!(
        pool_size_from_env(),
        DEFAULT_UPSTREAM_POOL_SIZE,
        "unparseable falls back to default",
    );
    // Restore prior env so sibling tests aren't affected.
    match saved {
        Some(v) => unsafe { std::env::set_var("GATEWAY_UPSTREAM_POOL_SIZE", v) },
        None => unsafe { std::env::remove_var("GATEWAY_UPSTREAM_POOL_SIZE") },
    }
    unsafe { std::env::remove_var(var) };
}

#[test]
fn slot_count_caps_stdio_and_scales_network() {
    let mut http = manifest_with(false);
    http.transport = Transport::Http;
    assert_eq!(slot_count(&http, 4), 4);
    assert_eq!(slot_count(&http, 1), 1);
    // pool_size 0 is clamped to 1 (never zero slots).
    assert_eq!(slot_count(&http, 0), 1);

    let mut sse = manifest_with(false);
    sse.transport = Transport::Sse;
    assert_eq!(slot_count(&sse, 4), 4);

    // Stdio is a single child process regardless of the configured size.
    let mut stdio = manifest_with(false);
    stdio.transport = Transport::Stdio;
    assert_eq!(slot_count(&stdio, 4), 1);
    assert_eq!(slot_count(&stdio, 1), 1);
}

#[test]
fn slot_count_honors_per_upstream_concurrency() {
    // A per-upstream `session.concurrency` overrides the global
    // pool_size for HTTP/SSE, in both directions.
    let mut http = manifest_with(false);
    http.transport = Transport::Http;
    http.session = Some(crate::SessionConfig {
        concurrency: Some(2),
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    assert_eq!(slot_count(&http, 4), 2, "override beats a larger global");
    assert_eq!(slot_count(&http, 1), 2, "override beats a smaller global");

    // Explicit 0 is clamped to 1 — never zero live sessions.
    http.session = Some(crate::SessionConfig {
        concurrency: Some(0),
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    assert_eq!(slot_count(&http, 4), 1);

    // `None` inside the block ⇒ inherit the global pool_size.
    http.session = Some(crate::SessionConfig {
        concurrency: None,
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    assert_eq!(slot_count(&http, 4), 4);

    // Stdio ignores the override — always one child process.
    let mut stdio = manifest_with(false);
    stdio.transport = Transport::Stdio;
    stdio.session = Some(crate::SessionConfig {
        concurrency: Some(8),
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    assert_eq!(slot_count(&stdio, 4), 1);
}

#[test]
fn resolve_isolation_defaults_paranoid_and_forces_stdio_reuse() {
    use crate::SessionIsolation;

    // HTTP/SSE with no explicit isolation → PerCall (the paranoid default).
    let mut http = manifest_with(false);
    http.transport = Transport::Http;
    http.session = None;
    assert_eq!(resolve_isolation(&http), SessionIsolation::PerCall);
    let mut sse = manifest_with(false);
    sse.transport = Transport::Sse;
    assert_eq!(resolve_isolation(&sse), SessionIsolation::PerCall);

    // Explicit reuse on HTTP is honored (operator opt-in).
    http.session = Some(crate::SessionConfig {
        concurrency: None,
        isolation: Some(SessionIsolation::Reuse),
        scope: None,
        retry_on_setup_failure: None,
    });
    assert_eq!(resolve_isolation(&http), SessionIsolation::Reuse);

    // Explicit per_call on HTTP is honored.
    http.session = Some(crate::SessionConfig {
        concurrency: None,
        isolation: Some(SessionIsolation::PerCall),
        scope: None,
        retry_on_setup_failure: None,
    });
    assert_eq!(resolve_isolation(&http), SessionIsolation::PerCall);

    // stdio is FORCED to Reuse regardless of the manifest — a child
    // process is a single long-lived session; per_call would respawn it.
    let mut stdio = manifest_with(false);
    stdio.transport = Transport::Stdio;
    stdio.session = None;
    assert_eq!(resolve_isolation(&stdio), SessionIsolation::Reuse);
    stdio.session = Some(crate::SessionConfig {
        concurrency: None,
        isolation: Some(SessionIsolation::PerCall),
        scope: None,
        retry_on_setup_failure: None,
    });
    assert_eq!(
        resolve_isolation(&stdio),
        SessionIsolation::Reuse,
        "stdio ignores an explicit per_call",
    );
}

fn entry_with_slots(n: usize) -> Arc<UpstreamEntry> {
    entry_with_lanes(n, false)
}

fn entry_with_lanes(n: usize, bounded: bool) -> Arc<UpstreamEntry> {
    let slots = (0..n)
        .map(|_| ConnectionSlot {
            conn: RwLock::new(None),
            in_use: Mutex::new(()),
        })
        .collect();
    Arc::new(UpstreamEntry {
        manifest: StdRwLock::new(manifest_with(false)),
        slots: lanes::ConnectionSlots::new(slots, bounded),
        session_mutation: Mutex::new(()),
        forwards_identity: false,
        breaker: Breaker::new(BreakerConfig::default()),
        recovery: StdRwLock::new(health::UpstreamRecovery::default()),
        reconnect: StdMutex::new(reconnect::ReconnectState::after_boot(
            reconnect::ReconnectPolicy::random(),
            "test",
            true,
            transport::CredentialMaterialVersion::test_value(0),
        )),
        reconnect_notify: Arc::new(Notify::new()),
        removed: AtomicBool::new(false),
        undeclared_resources_reported: AtomicBool::new(false),
        observed_schemas: StdMutex::new(HashMap::new()),
        quarantined: StdRwLock::new(HashSet::new()),
        last_reload_gen: AtomicU64::new(0),
    })
}

/// The security-critical invariant of the pool: `checkout` never hands
/// the same slot to two callers at once. Because each slot's
/// connection carries its OWN identity cell (built fresh in `dial`)
/// and a call only ever writes the cell of the slot it has checked
/// out, exclusive checkout is exactly what prevents one caller's
/// identity from leaking into another's concurrent call. This hammers
/// `checkout` from many tasks on real threads; the per-slot `swap`
/// flag would trip if any slot were ever doubly held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checkout_grants_each_slot_to_one_caller_at_a_time() {
    use std::sync::atomic::AtomicBool as Flag;

    let entry = entry_with_slots(4);
    // slot pointer -> "currently held" flag.
    let occupied: Arc<HashMap<usize, Flag>> = {
        let mut m = HashMap::new();
        for slot in &entry.slots {
            m.insert(slot as *const ConnectionSlot as usize, Flag::new(false));
        }
        Arc::new(m)
    };

    let mut handles = Vec::new();
    for _ in 0..32 {
        let entry = entry.clone();
        let occupied = occupied.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let co = entry.checkout().await;
                let key = co.slot as *const ConnectionSlot as usize;
                let flag = &occupied[&key];
                assert!(
                    !flag.swap(true, Ordering::AcqRel),
                    "checkout handed one slot to two callers concurrently — \
                     identity isolation would be broken",
                );
                // Yield while holding so other tasks race to (wrongly)
                // grab the same slot if the in_use lock were absent.
                tokio::task::yield_now().await;
                flag.store(false, Ordering::Release);
                drop(co);
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

/// With more concurrent holders than slots, every slot is handed out
/// (full parallelism) and the excess callers queue — none are lost or
/// deadlocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checkout_uses_all_slots_under_contention() {
    let entry = entry_with_slots(3);
    let hold = Arc::new(tokio::sync::Notify::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Three holders check out and park (holding their slot) until
    // notified — proving three distinct slots are live at once.
    let mut holders = Vec::new();
    for _ in 0..3 {
        let entry = entry.clone();
        let hold = hold.clone();
        let tx = tx.clone();
        holders.push(tokio::spawn(async move {
            let co = entry.checkout().await;
            // Register before publishing readiness so release notifications
            // cannot collapse into one permit for multiple late waiters.
            let notified = hold.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            tx.send(co.slot as *const ConnectionSlot as usize).unwrap();
            notified.await;
            drop(co);
        }));
    }
    drop(tx);

    // Collect the three slot pointers; they must be distinct.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..3 {
        let ptr = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("a holder should check out a slot")
            .expect("sender alive");
        assert!(seen.insert(ptr), "two holders got the same slot");
    }
    assert_eq!(seen.len(), 3, "all three slots handed out concurrently");

    // Release the holders.
    for _ in 0..3 {
        hold.notify_one();
    }
    for h in holders {
        tokio::time::timeout(std::time::Duration::from_secs(5), h)
            .await
            .expect("released holders must finish")
            .unwrap();
    }
}

/// A call waiting with every slot busy takes whichever slot frees first,
/// rather than queueing behind one particular slot whose call may run until
/// the upstream call timeout.
#[tokio::test]
async fn a_waiting_checkout_takes_whichever_slot_frees_first() {
    let entry = entry_with_slots(2);
    let first = entry.checkout().await;
    let second = entry.checkout().await;
    let waiting = {
        let entry = entry.clone();
        tokio::spawn(async move {
            let co = entry.checkout().await;
            co.slot as *const ConnectionSlot as usize
        })
    };
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished(), "every slot is busy");

    // Free whichever slot is not the first in the pool, and keep the other.
    let (kept, freed) = if std::ptr::eq(first.slot, &entry.slots[0]) {
        (first, second)
    } else {
        (second, first)
    };
    let freed_slot = freed.slot as *const ConnectionSlot as usize;
    drop(freed);
    let taken = tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
        .await
        .expect("the waiting call proceeds once any slot is free")
        .unwrap();
    assert_eq!(taken, freed_slot);
    drop(kept);
}

/// A busy slot's call holds its connection for reading, and a reconnect may
/// queue a writer behind it. A waiting checkout must not stall on that lock
/// while another slot is free.
#[tokio::test]
async fn a_waiting_checkout_does_not_stall_on_a_busy_slot_being_reconnected() {
    let entry = entry_with_slots(2);
    let first = entry.checkout().await;
    let second = entry.checkout().await;
    let (busy, other) = if std::ptr::eq(first.slot, &entry.slots[0]) {
        (first, second)
    } else {
        (second, first)
    };
    let dispatching = busy.slot.conn.read().await;
    let reconnect = {
        let entry = entry.clone();
        tokio::spawn(async move {
            drop(entry.slots[0].conn.write().await);
        })
    };
    while entry.slots[0].conn.try_read().is_ok() {
        tokio::task::yield_now().await;
    }
    let waiting = {
        let entry = entry.clone();
        tokio::spawn(async move {
            let co = entry.checkout().await;
            co.slot as *const ConnectionSlot as usize
        })
    };
    let other_slot = other.slot as *const ConnectionSlot as usize;
    drop(other);
    let taken = tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
        .await
        .expect("a queued reconnect on a busy slot must not hold up a free one")
        .unwrap();
    assert_eq!(taken, other_slot);
    drop(dispatching);
    drop(busy);
    reconnect.await.unwrap();
}

/// Only stdio and an explicit `session.concurrency` bound the calls in flight;
/// an HTTP/SSE upstream is unbounded by default, including with a `session`
/// block that leaves `concurrency` unset.
#[test]
fn calls_are_bounded_only_by_stdio_or_explicit_concurrency() {
    let session = |concurrency| crate::SessionConfig {
        concurrency,
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    };
    for transport in [Transport::Http, Transport::Sse] {
        let mut network = manifest_with(false);
        network.transport = transport;
        assert!(!lanes::calls_bounded(&network));
        network.session = Some(session(None));
        assert!(!lanes::calls_bounded(&network));
        network.session = Some(session(Some(3)));
        assert!(lanes::calls_bounded(&network));
    }
    let mut stdio = manifest_with(false);
    stdio.transport = Transport::Stdio;
    assert!(lanes::calls_bounded(&stdio));
}

fn admitted_now<'a>(
    entry: &'a UpstreamEntry,
    isolation: crate::SessionIsolation,
) -> lanes::CallLane<'a> {
    use futures::FutureExt;

    entry
        .admit(isolation)
        .now_or_never()
        .expect("admission must not wait")
}

#[tokio::test(start_paused = true)]
async fn admission_deadline_expires_without_taking_capacity() {
    for isolation in [SessionIsolation::PerCall, SessionIsolation::Reuse] {
        let entry = entry_with_lanes(1, true);
        let held = admitted_now(&entry, isolation);
        let cancellation = tokio_util::sync::CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let result = entry
            .admit_with_budget("mock", isolation, Some(deadline), &cancellation)
            .await;
        let Err(error) = result else {
            panic!("a full upstream must time out")
        };
        assert_eq!(tokio::time::Instant::now(), deadline);
        let data = error.data.unwrap();
        assert_eq!(data["error"], "upstream_admission_timeout");
        assert_eq!(data["phase"], "pre_dispatch");
        assert_eq!(data["retryable"], true);
        drop(held);
        let _next = admitted_now(&entry, isolation);
    }
}

#[tokio::test]
async fn admission_cancellation_releases_its_wait_without_a_timeout() {
    use futures::FutureExt;

    for isolation in [SessionIsolation::PerCall, SessionIsolation::Reuse] {
        let entry = entry_with_lanes(1, true);
        let held = admitted_now(&entry, isolation);
        let cancellation = tokio_util::sync::CancellationToken::new();
        let waiting = entry.admit_with_budget("mock", isolation, None, &cancellation);
        tokio::pin!(waiting);
        assert!(waiting.as_mut().now_or_never().is_none());
        cancellation.cancel();
        let Err(error) = waiting.await else {
            panic!("a cancelled waiter must not be admitted")
        };
        let data = error.data.unwrap();
        assert_eq!(data["error"], "upstream_call_cancelled");
        assert_eq!(data["phase"], "pre_dispatch");
        drop(held);
        let _next = admitted_now(&entry, isolation);
    }
}

/// An unbounded upstream admits more per-call calls than it has slots, all at
/// once, and they leave every slot free for a reuse call.
#[tokio::test]
async fn unbounded_per_call_admission_never_waits_or_takes_a_slot() {
    use crate::SessionIsolation;

    let entry = entry_with_lanes(2, false);
    let shared: Vec<_> = (0..8)
        .map(|_| admitted_now(&entry, SessionIsolation::PerCall))
        .collect();
    assert!(shared
        .iter()
        .all(|lane| lane.isolation == SessionIsolation::PerCall));
    let first = admitted_now(&entry, SessionIsolation::Reuse);
    let second = admitted_now(&entry, SessionIsolation::Reuse);
    assert_eq!(first.isolation, SessionIsolation::Reuse);
    assert_eq!(second.isolation, SessionIsolation::Reuse);
    assert!(
        !std::ptr::eq(first.slot, second.slot),
        "reuse calls hold distinct slots"
    );
}

/// On an unbounded upstream a reuse call that finds every slot busy runs on
/// its own session instead of waiting, and a freed slot is reused again.
#[tokio::test]
async fn unbounded_reuse_admission_runs_per_call_when_every_slot_is_busy() {
    use crate::SessionIsolation;

    let entry = entry_with_lanes(1, false);
    let held = admitted_now(&entry, SessionIsolation::Reuse);
    assert_eq!(held.isolation, SessionIsolation::Reuse);
    let overflow = admitted_now(&entry, SessionIsolation::Reuse);
    assert_eq!(overflow.isolation, SessionIsolation::PerCall);
    drop(held);
    let reused = admitted_now(&entry, SessionIsolation::Reuse);
    assert_eq!(reused.isolation, SessionIsolation::Reuse);
    drop(overflow);
}

/// A bounded upstream admits no more calls than its slots, of either
/// isolation, and admits a waiting call once one finishes.
#[tokio::test]
async fn bounded_admission_caps_calls_in_flight() {
    use crate::SessionIsolation;

    for isolation in [SessionIsolation::PerCall, SessionIsolation::Reuse] {
        let entry = entry_with_lanes(2, true);
        let first = admitted_now(&entry, isolation);
        let second = admitted_now(&entry, isolation);
        let waiting = {
            let entry = entry.clone();
            tokio::spawn(async move { entry.admit(isolation).await.isolation })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "the third call waits for a permit");
        drop(first);
        let admitted = tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
            .await
            .expect("a finished call admits the next")
            .unwrap();
        assert_eq!(admitted, isolation, "a bounded call keeps its isolation");
        drop(second);
    }
}

/// Regression for the 2026-06-10 prod boot deadlock: a stdio upstream that
/// spawns but never answers the MCP `initialize` handshake (`sleep` ignores
/// stdin and writes no stdout) used to hang `dial_slots` forever, parking the
/// sequential boot so the gateway never bound its port. With the per-lane
/// boot dial timeout the wedged lane is abandoned and the slot is marked
/// Disconnected, so `dial_slots` — and thus boot — returns. The test-runner
/// watchdog catches a missing timeout; scheduler speed is not an assertion.
#[tokio::test]
async fn boot_dial_timeout_bounds_a_hung_upstream() {
    let manifest = UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        inline_response_threshold_bytes: None,
        long_running_tools: Vec::new(),
        limits: None,
        name: "hung".into(),
        transport: Transport::Stdio,
        protocol: Default::default(),
        url: None,
        // `sleep` spawns, ignores stdin, and never writes stdout — so the MCP
        // initialize read blocks indefinitely (a true post-spawn wedge, the
        // shape of the prod incident).
        command: Some(vec!["sleep".into(), "86400".into()]),
        env_passthrough: Vec::new(),
        tools: Vec::new(),
        resources: Vec::new(),
        exchange: None,
        auth: None,
        headers: Default::default(),
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        trust: crate::TrustLevel::Internal,
        identity: None,
        forward_trace_context: None,
        session: None,
    };
    let (slots, error_class) =
        dial_slots("hung", &manifest, None, None, 4, Duration::from_millis(300)).await;
    assert_eq!(error_class, Some(health::UpstreamErrorClass::Timeout));
    // The wedged upstream is Disconnected: stdio yields one slot, with no
    // live connection.
    assert_eq!(slots.len(), 1, "stdio yields a single slot");
    assert!(
        slots[0].conn.read().await.is_none(),
        "a hung upstream's slot must be Disconnected after the boot dial timeout",
    );
}

fn live_with(name: &str, description: &str) -> Tool {
    // Tool::new wants Cow<'static, _> for description; own the slice.
    Tool::new(
        name.to_owned(),
        description.to_owned(),
        serde_json::Map::new(),
    )
}

/// Count occurrences of `mcp_tool_drift_total{server="<svc>"}` in
/// the Prometheus text export. Used by the drift tests to assert
/// the counter moved (or didn't) for a unique-per-test server name
/// — the process-wide registry is shared across tests, so each
/// test picks a fresh `svc` to avoid cross-test interference.
fn drift_count(svc: &str) -> u64 {
    let text = waygate_telemetry::gather_text();
    for line in text.lines() {
        if line.starts_with("mcp_tool_drift_total") && line.contains(&format!("server=\"{svc}\"")) {
            // Format: `mcp_tool_drift_total{server="svc"} N`
            if let Some(n) = line.rsplit(' ').next().and_then(|s| s.parse::<f64>().ok()) {
                return n as u64;
            }
        }
    }
    0
}

/// First observation of any tool MUST be silent — drift means "this
/// tool's behavior contract changed since we last looked," not "we never had a
/// contract until now." The boot/reconnect seeding path relies
/// on this; without it, every fresh upstream connection would emit
/// a drift event per tool on its first observation.
#[tokio::test]
async fn record_observed_schemas_silent_on_first_observation() {
    let svc = "drift_test_first";
    let before = drift_count(svc);
    let entry = entry_with_slots(1);
    entry.record_observed_schemas(
        svc,
        &[live("foo"), live("bar")],
        "test",
        QuarantineThreshold::Off,
    );
    assert_eq!(
        drift_count(svc),
        before,
        "first observation must not record drift"
    );
}

/// Second observation with a changed schema for a known tool MUST
/// bump the counter exactly once for that tool, and update the
/// baseline so a subsequent re-observation of the *new* schema is
/// quiet again.
#[tokio::test]
async fn record_observed_schemas_detects_change_and_updates_baseline() {
    let svc = "drift_test_change";
    let before = drift_count(svc);
    let entry = entry_with_slots(1);

    // Baseline pass — silent.
    entry.record_observed_schemas(
        svc,
        &[live_with("foo", "v1")],
        "test",
        QuarantineThreshold::Off,
    );
    assert_eq!(drift_count(svc), before, "baseline must not bump counter");

    // Same tool, changed description → different behavior hash → drift.
    entry.record_observed_schemas(
        svc,
        &[live_with("foo", "v2")],
        "test",
        QuarantineThreshold::Off,
    );
    assert_eq!(
        drift_count(svc),
        before + 1,
        "drift on changed description must bump counter once"
    );

    // Same schema as last pass → baseline updated, no further drift.
    entry.record_observed_schemas(
        svc,
        &[live_with("foo", "v2")],
        "test",
        QuarantineThreshold::Off,
    );
    assert_eq!(
        drift_count(svc),
        before + 1,
        "re-observing the new schema must not bump counter again"
    );
}

#[tokio::test]
async fn output_and_annotation_drift_is_observed_in_both_classification_modes() {
    let original = live("read");
    let mut changed = original.clone();
    changed.output_schema = Some(Arc::new(
        serde_json::json!({"type": "object"})
            .as_object()
            .expect("object schema")
            .clone(),
    ));
    changed.annotations = Some(ToolAnnotations::from_raw(
        None,
        Some(true),
        Some(false),
        Some(true),
        Some(false),
    ));

    let legacy = entry_with_slots(1);
    legacy.record_observed_schemas(
        "legacy_output_drift",
        std::slice::from_ref(&original),
        "test",
        QuarantineThreshold::Off,
    );
    assert_eq!(
        legacy
            .record_observed_schemas(
                "legacy_output_drift",
                std::slice::from_ref(&changed),
                "test",
                QuarantineThreshold::Off,
            )
            .len(),
        1,
        "manifest mode must observe output and annotation drift"
    );

    let annotation_native = entry_with_slots(1);
    let classifications = vec![classification("read")];
    annotation_native.record_observed_schemas_against(
        "annotation_output_drift",
        std::slice::from_ref(&original),
        "test",
        QuarantineThreshold::Off,
        &classifications,
        crate::ClassificationMode::McpAnnotations,
    );
    assert_eq!(
        annotation_native
            .record_observed_schemas_against(
                "annotation_output_drift",
                std::slice::from_ref(&changed),
                "test",
                QuarantineThreshold::Off,
                &classifications,
                crate::ClassificationMode::McpAnnotations,
            )
            .len(),
        1,
        "annotation mode must observe output and security metadata drift"
    );
}

#[tokio::test]
async fn classification_mode_cutover_reseeds_before_observing_new_contract() {
    let entry = entry_with_slots(1);
    let original = annotation_native_live("read");
    let classifications = vec![classification("read")];
    entry.record_observed_schemas_against(
        "mode_cutover",
        std::slice::from_ref(&original),
        "test",
        QuarantineThreshold::High,
        &classifications,
        crate::ClassificationMode::Manifest,
    );
    assert!(
        entry
            .record_observed_schemas_against(
                "mode_cutover",
                std::slice::from_ref(&original),
                "test",
                QuarantineThreshold::High,
                &classifications,
                crate::ClassificationMode::McpAnnotations,
            )
            .is_empty(),
        "an approved authority switch must not create synthetic drift"
    );

    let mut changed = original;
    changed.description = Some("changed after cutover".to_owned().into());
    assert_eq!(
        entry
            .record_observed_schemas_against(
                "mode_cutover",
                std::slice::from_ref(&changed),
                "test",
                QuarantineThreshold::High,
                &classifications,
                crate::ClassificationMode::McpAnnotations,
            )
            .len(),
        1,
        "real annotation-native drift after cutover must still be observed"
    );
}

/// Annotation mode forbids the legacy `side_effects` manifest flag, and the
/// authorization posture presents every annotation-native tool
/// conservatively as side-effecting until claim enforcement lands. The drift
/// quarantine threshold must key on that same posture: reading the literal
/// manifest flag (always `false` in this mode) would drop low-risk
/// annotation-native drift out of the documented `high`/`medium` bands.
#[tokio::test]
async fn annotation_native_drift_quarantines_as_side_effecting() {
    let entry = entry_with_slots(1);
    let original = annotation_native_live("read");
    // Low risk, `side_effects: false` — the flag annotation mode requires.
    let classifications = vec![classification("read")];
    entry.record_observed_schemas_against(
        "annotation_threshold",
        std::slice::from_ref(&original),
        "test",
        QuarantineThreshold::High,
        &classifications,
        crate::ClassificationMode::McpAnnotations,
    );

    let mut changed = original;
    changed.description = Some("changed behavior".to_owned().into());
    let reports = entry.record_observed_schemas_against(
        "annotation_threshold",
        std::slice::from_ref(&changed),
        "test",
        QuarantineThreshold::High,
        &classifications,
        crate::ClassificationMode::McpAnnotations,
    );

    assert_eq!(reports.len(), 1, "the changed contract must report drift");
    assert!(
        reports[0].side_effects,
        "annotation-native drift must present as side-effecting",
    );
    assert!(
        reports[0].quarantined,
        "low-risk annotation-native drift must stay inside the high-threshold quarantine band",
    );
    assert!(
        entry.is_quarantined("read").await,
        "the drifted tool must be blocked from dispatch",
    );
}

/// A changed schema for a known tool returns a `DriftReport` (the
/// signal the pool turns into a `CatalogDrift` audit row). First
/// observation returns nothing; `QuarantineThreshold::Off` never
/// quarantines.
#[tokio::test]
async fn record_observed_schemas_returns_drift_reports() {
    let entry = entry_with_slots(1);
    let seed = entry.record_observed_schemas(
        "drift_reports_svc",
        &[live_with("foo", "v1")],
        "test",
        QuarantineThreshold::Off,
    );
    assert!(
        seed.is_empty(),
        "first observation is a baseline seed, not drift"
    );
    let drift = entry.record_observed_schemas(
        "drift_reports_svc",
        &[live_with("foo", "v2-changed")],
        "test",
        QuarantineThreshold::Off,
    );
    assert_eq!(drift.len(), 1, "one report for the changed tool");
    assert_eq!(drift[0].tool, "foo");
    assert!(!drift[0].quarantined, "threshold Off never quarantines");
}

/// Drift rows use the trace captured before a bare task handoff, and
/// `emit_drift_audit` preserves one row per event — a quarantined drift as
/// `Denied` (the tool is now blocked), an informational drift as `Success`.
#[test]
fn publication_drift_events_drop_tools_changed_by_more_than_one_session() {
    let (first, second, other) = (
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let events = super::tool_reviews::publication_drift_events([
        HashMap::from([("search".to_string(), first), ("list".to_string(), other)]),
        HashMap::new(),
        HashMap::from([("search".to_string(), second)]),
    ]);
    assert_eq!(events, HashMap::from([("list".to_string(), other)]));
}

#[tokio::test]
async fn detached_drift_audit_preserves_pre_handoff_trace_and_event_contract() {
    let sink = std::sync::Arc::new(waygate_mcp::audit::InMemorySink::new());
    let evidence: waygate_mcp::audit::SharedEvidence = sink.clone();
    let expected_trace_id = "0123456789abcdef0123456789abcdef";
    let drift_event = uuid::Uuid::new_v4();
    let drift = vec![
        DriftReport {
            tool: "send_msg".to_string(),
            risk: Some(waygate_core::RiskTier::High),
            side_effects: true,
            quarantined: true,
            drift_event: Some(drift_event),
        },
        DriftReport {
            tool: "list".to_string(),
            risk: Some(waygate_core::RiskTier::Low),
            side_effects: false,
            quarantined: false,
            drift_event: None,
        },
        // The campaign-decouple case: a LOW-risk side-effecting tool
        // quarantines because the threshold covers side_effects. The audit
        // reason must explain it, not just say "Low-risk tool".
        DriftReport {
            tool: "post_pods".to_string(),
            risk: Some(waygate_core::RiskTier::Low),
            side_effects: true,
            quarantined: true,
            drift_event: None,
        },
    ];
    tokio::spawn(async move {
        UpstreamPool::emit_drift_audit(
            &evidence,
            "example-messages",
            &drift,
            Some(expected_trace_id.to_string()),
        )
        .await;
    })
    .await
    .expect("detached drift submission task");
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 3, "one audit row per drift event");
    let recorded = sink.snapshot_with_posture().await;
    assert!(recorded
        .iter()
        .all(|row| row.posture == waygate_mcp::audit::EvidencePosture::ChainedBestEffort));
    let se_quarantined = events
        .iter()
        .find(|e| e.tool.as_deref() == Some("post_pods"))
        .expect("side-effecting quarantine row present");
    assert!(
        matches!(se_quarantined.outcome, waygate_mcp::AuditOutcome::Denied),
        "a low-risk side-effecting tool that drifts is quarantined (Denied)",
    );
    assert!(
        se_quarantined
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("side_effects=true"),
        "the drift reason must name side_effects so a low-risk quarantine is explained: {:?}",
        se_quarantined.reason,
    );
    for e in &events {
        assert_eq!(e.action, "ToolDrift");
        assert_eq!(
            e.trace_id.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(matches!(
            e.category,
            waygate_mcp::EvidenceCategory::CatalogDrift
        ));
        assert_eq!(e.server.as_deref(), Some("example-messages"));
    }
    let quarantined = events
        .iter()
        .find(|e| e.tool.as_deref() == Some("send_msg"))
        .expect("quarantined drift row present");
    assert!(
        matches!(quarantined.outcome, waygate_mcp::AuditOutcome::Denied),
        "a quarantined drift is recorded as Denied (the tool is now blocked)",
    );
    assert_eq!(
        quarantined.target,
        Some(drift_event.to_string()),
        "the audit row names the drift event that records the change",
    );
    assert!(se_quarantined.target.is_none());
    assert!(quarantined
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("quarantined"));
    let informational = events
        .iter()
        .find(|e| e.tool.as_deref() == Some("list"))
        .expect("informational drift row present");
    assert!(
        matches!(informational.outcome, waygate_mcp::AuditOutcome::Success),
        "an informational (non-quarantine) drift is recorded as Success",
    );
}

/// A pass containing several tools where only one changed MUST
/// record exactly one drift event — not one per tool in the pass.
#[tokio::test]
async fn record_observed_schemas_bumps_only_for_changed_tool() {
    let svc = "drift_test_mixed";
    let before = drift_count(svc);
    let entry = entry_with_slots(1);

    entry.record_observed_schemas(
        svc,
        &[
            live_with("a", "v1"),
            live_with("b", "v1"),
            live_with("c", "v1"),
        ],
        "test",
        QuarantineThreshold::Off,
    );
    assert_eq!(drift_count(svc), before, "baseline pass silent");

    // Only `b` changes.
    entry.record_observed_schemas(
        svc,
        &[
            live_with("a", "v1"),
            live_with("b", "v2"),
            live_with("c", "v1"),
        ],
        "test",
        QuarantineThreshold::Off,
    );
    assert_eq!(
        drift_count(svc),
        before + 1,
        "exactly one drift event for the one changed tool"
    );
}

// ----- Quarantine-on-drift tests -----

/// Build an entry whose manifest classifies `tool_name` at `risk`.
/// Used by the drift-quarantine tests so `record_observed_schemas`
/// can look up risk by name and apply the threshold.
fn entry_with_classification(tool_name: &str, risk: RiskTier) -> Arc<UpstreamEntry> {
    let mut manifest = manifest_with(false);
    manifest
        .tools
        .push(ToolClassification::new(tool_name, risk, false, false));
    Arc::new(UpstreamEntry {
        slots: lanes::ConnectionSlots::new(
            vec![ConnectionSlot {
                conn: RwLock::new(None),
                in_use: Mutex::new(()),
            }],
            lanes::calls_bounded(&manifest),
        ),
        manifest: StdRwLock::new(manifest),
        session_mutation: Mutex::new(()),
        forwards_identity: false,
        breaker: Breaker::new(BreakerConfig::default()),
        recovery: StdRwLock::new(health::UpstreamRecovery::default()),
        reconnect: StdMutex::new(reconnect::ReconnectState::after_boot(
            reconnect::ReconnectPolicy::random(),
            "test",
            true,
            transport::CredentialMaterialVersion::test_value(0),
        )),
        reconnect_notify: Arc::new(Notify::new()),
        removed: AtomicBool::new(false),
        undeclared_resources_reported: AtomicBool::new(false),
        observed_schemas: StdMutex::new(HashMap::new()),
        quarantined: StdRwLock::new(HashSet::new()),
        last_reload_gen: AtomicU64::new(0),
    })
}

#[test]
fn quarantine_threshold_covers_risk_correctly() {
    // --- risk axis (side_effects = false): unchanged from before the
    // campaign decoupled the operational controls onto side_effects. ---
    // Off: never.
    assert!(!QuarantineThreshold::Off.covers(RiskTier::Low, false));
    assert!(!QuarantineThreshold::Off.covers(RiskTier::Medium, false));
    assert!(!QuarantineThreshold::Off.covers(RiskTier::High, false));
    // High: only High (critical maps to High at the runtime).
    assert!(!QuarantineThreshold::High.covers(RiskTier::Low, false));
    assert!(!QuarantineThreshold::High.covers(RiskTier::Medium, false));
    assert!(QuarantineThreshold::High.covers(RiskTier::High, false));
    // Medium: Medium + High.
    assert!(!QuarantineThreshold::Medium.covers(RiskTier::Low, false));
    assert!(QuarantineThreshold::Medium.covers(RiskTier::Medium, false));
    assert!(QuarantineThreshold::Medium.covers(RiskTier::High, false));
    // All: every risk.
    assert!(QuarantineThreshold::All.covers(RiskTier::Low, false));
    assert!(QuarantineThreshold::All.covers(RiskTier::Medium, false));
    assert!(QuarantineThreshold::All.covers(RiskTier::High, false));

    // --- side_effects axis: a low + side_effects tool (the shape a
    // destructive tool takes after `high -> low + side_effects`) is covered
    // at the high/medium/all thresholds, but NEVER at `off`. ---
    assert!(
        QuarantineThreshold::High.covers(RiskTier::Low, true),
        "side-effecting low must be drift-quarantined at the high threshold"
    );
    assert!(QuarantineThreshold::Medium.covers(RiskTier::Low, true));
    assert!(QuarantineThreshold::All.covers(RiskTier::Low, true));
    assert!(
        !QuarantineThreshold::Off.covers(RiskTier::Low, true),
        "off never quarantines, even a side-effecting tool"
    );
    // Read-only low (the baseline surface) stays uncovered below `all`.
    assert!(!QuarantineThreshold::High.covers(RiskTier::Low, false));
    assert!(!QuarantineThreshold::Medium.covers(RiskTier::Low, false));
}

#[test]
fn quarantine_threshold_from_env_recognizes_known_values() {
    let saved = std::env::var("GATEWAY_QUARANTINE_ON_DRIFT_RISK").ok();
    // Unset → Off (the documented safe default).
    unsafe { std::env::remove_var("GATEWAY_QUARANTINE_ON_DRIFT_RISK") };
    assert_eq!(quarantine_threshold_from_env(), QuarantineThreshold::Off);
    for (raw, expected) in [
        ("off", QuarantineThreshold::Off),
        ("OFF", QuarantineThreshold::Off),
        ("high", QuarantineThreshold::High),
        ("HIGH", QuarantineThreshold::High),
        ("medium", QuarantineThreshold::Medium),
        ("all", QuarantineThreshold::All),
        // Unknown / unparseable → Off (don't silently auto-enable).
        ("bogus", QuarantineThreshold::Off),
        ("", QuarantineThreshold::Off),
    ] {
        unsafe { std::env::set_var("GATEWAY_QUARANTINE_ON_DRIFT_RISK", raw) };
        assert_eq!(
            quarantine_threshold_from_env(),
            expected,
            "env value {raw:?} should parse to {expected:?}",
        );
    }
    match saved {
        Some(v) => unsafe { std::env::set_var("GATEWAY_QUARANTINE_ON_DRIFT_RISK", v) },
        None => unsafe { std::env::remove_var("GATEWAY_QUARANTINE_ON_DRIFT_RISK") },
    }
}

/// Drift on a High-risk tool under threshold=High MUST add it to the
/// quarantine set; subsequent `is_quarantined` returns true. This is
/// the headline behavior: a tool whose schema mutated AND
/// whose manifest classifies it as high-risk gets blocked at
/// dispatch without operator action.
#[tokio::test]
async fn drift_quarantines_when_threshold_met() {
    let entry = entry_with_classification("send", RiskTier::High);
    let svc = "qtest_meets";
    // Baseline pass — silent, no quarantine.
    entry.record_observed_schemas(
        svc,
        &[live_with("send", "v1")],
        "test",
        QuarantineThreshold::High,
    );
    assert!(
        !entry.is_quarantined("send").await,
        "baseline must not quarantine"
    );
    // Drift → quarantine because risk meets threshold.
    entry.record_observed_schemas(
        svc,
        &[live_with("send", "v2")],
        "test",
        QuarantineThreshold::High,
    );
    assert!(
        entry.is_quarantined("send").await,
        "drift on High-risk tool under threshold=High must quarantine",
    );
}

/// With threshold=Off (the documented default), drift on any
/// tool — even High-risk — MUST NOT quarantine. The
/// observed-only signal stands, no auto-blocking, until
/// the operator explicitly opts in.
#[tokio::test]
async fn drift_does_not_quarantine_when_threshold_off() {
    let entry = entry_with_classification("send", RiskTier::High);
    entry.record_observed_schemas(
        "qtest_off",
        &[live_with("send", "v1")],
        "test",
        QuarantineThreshold::Off,
    );
    entry.record_observed_schemas(
        "qtest_off",
        &[live_with("send", "v2")],
        "test",
        QuarantineThreshold::Off,
    );
    assert!(
        !entry.is_quarantined("send").await,
        "threshold=Off must never quarantine, even on drift",
    );
}

/// Drift on a Low-risk tool under threshold=High MUST NOT quarantine —
/// only the configured risk band auto-blocks.
#[tokio::test]
async fn drift_does_not_quarantine_below_threshold() {
    let entry = entry_with_classification("hello", RiskTier::Low);
    entry.record_observed_schemas(
        "qtest_below",
        &[live_with("hello", "v1")],
        "test",
        QuarantineThreshold::High,
    );
    entry.record_observed_schemas(
        "qtest_below",
        &[live_with("hello", "v2")],
        "test",
        QuarantineThreshold::High,
    );
    assert!(
        !entry.is_quarantined("hello").await,
        "Low-risk tool drift under threshold=High must not quarantine",
    );
}

/// `published_tools()` returns empty when no slot is connected
/// (the only state we can reach in a unit test without a live
/// rmcp client) — guards against a regression where the
/// quarantine-empty fast path leaks an out-of-bounds read on the
/// absent connection.
#[tokio::test]
async fn published_tools_empty_when_disconnected() {
    let entry = entry_with_classification("send", RiskTier::High);
    assert!(entry.published_tools(true).await.is_empty());
    entry
        .quarantined
        .write()
        .expect("upstream quarantine lock poisoned")
        .insert("send".to_owned());
    assert!(entry.published_tools(true).await.is_empty());
}

/// The quarantine-filter conditional that `published_tools` runs
/// against `Connection.tools` is straight `filter`-by-contains.
/// Exercising it directly here (without needing to construct a
/// real `Connection`, which requires a live rmcp client) is
/// sufficient to prove the published-tools quarantine exclusion.
#[tokio::test]
async fn quarantine_filter_excludes_named_tools() {
    let entry = entry_with_classification("send", RiskTier::High);
    let tools = [live("send"), live("read"), live("delete")];
    entry
        .quarantined
        .write()
        .expect("upstream quarantine lock poisoned")
        .insert("send".to_owned());
    entry
        .quarantined
        .write()
        .expect("upstream quarantine lock poisoned")
        .insert("delete".to_owned());
    let q = entry
        .quarantined
        .read()
        .expect("upstream quarantine lock poisoned");
    let filtered: Vec<&str> = tools
        .iter()
        .filter(|t| !q.contains(t.name.as_ref()))
        .map(|t| t.name.as_ref())
        .collect();
    assert_eq!(filtered, vec!["read"]);
}

// ----- Admin-API quarantine inspect/clear tests -----

/// Build a disconnected pool whose single upstream's manifest
/// classifies one tool at the named risk. Used by the inspect /
/// clear method tests so we exercise the per-entry quarantine API
/// through `UpstreamPool::quarantined_tools` /
/// `UpstreamPool::clear_quarantine`, not the entry directly.
fn pool_with_one_upstream(tool_name: &str, risk: RiskTier) -> UpstreamPool {
    let mut manifests = BTreeMap::new();
    let mut manifest = manifest_with(false);
    manifest
        .tools
        .push(ToolClassification::new(tool_name, risk, false, false));
    manifests.insert("example-messages".to_owned(), manifest);
    UpstreamPool::from_manifests_disconnected(manifests)
}

/// Unknown upstream returns `None` from both inspect + clear, so the
/// admin handler can map to 404 instead of silently returning empty.
#[tokio::test]
async fn quarantine_admin_methods_return_none_for_unknown_server() {
    let pool = pool_with_one_upstream("send", RiskTier::High);
    assert!(pool.quarantined_tools("does-not-exist").await.is_none());
    assert!(pool.clear_quarantine("does-not-exist").await.is_none());
}

/// Steady state (nothing quarantined): inspect returns an empty list
/// — NOT `None` — and clear reports zero cleared so operators get a
/// clean "no-op succeeded" response instead of a confusing 404.
#[tokio::test]
async fn quarantine_admin_methods_steady_state_is_empty_not_missing() {
    let pool = pool_with_one_upstream("send", RiskTier::High);
    let epoch = pool.tool_catalog_epoch();
    assert_eq!(
        pool.quarantined_tools("example-messages").await,
        Some(vec![])
    );
    assert_eq!(pool.clear_quarantine("example-messages").await, Some(0));
    assert_eq!(epoch.current(), 0, "an empty clear must not notify");
}

/// After the drift recorder quarantines a tool, inspect returns
/// it (sorted), clear removes it (returning the prior count), and a
/// second inspect shows the empty list. This is the happy-path
/// admin-workflow test.
#[tokio::test]
async fn quarantine_inspect_and_clear_roundtrip() {
    let pool = pool_with_one_upstream("send", RiskTier::High);
    let epoch = pool.tool_catalog_epoch();
    // Reach into the entry to seed two quarantined tools without
    // having to drive a real drift observation (that path is
    // covered by the record_observed_schemas tests; this test
    // exercises the admin-API surface).
    {
        let entry = pool
            .entries
            .load()
            .get("example-messages")
            .cloned()
            .expect("entry present");
        let mut q = entry
            .quarantined
            .write()
            .expect("upstream quarantine lock poisoned");
        q.insert("send".to_owned());
        q.insert("delete".to_owned());
    }
    // Inspect returns sorted names so the admin UI doesn't have to
    // re-sort and tests are deterministic.
    let listed = pool.quarantined_tools("example-messages").await.unwrap();
    assert_eq!(listed, vec!["delete".to_owned(), "send".to_owned()]);

    // Clear empties the set and returns the count cleared.
    let cleared = pool.clear_quarantine("example-messages").await.unwrap();
    assert_eq!(cleared, 2);
    assert_eq!(epoch.current(), 1, "cleared tools become visible again");
    assert_eq!(
        pool.quarantined_tools("example-messages").await,
        Some(vec![])
    );

    // Idempotent: a second clear returns zero cleared.
    assert_eq!(pool.clear_quarantine("example-messages").await, Some(0));
    assert_eq!(epoch.current(), 1, "an idempotent clear stays quiet");
}

/// Clearing one upstream's quarantine MUST NOT affect another
/// upstream's quarantine set — the per-entry isolation has to hold
/// at the pool-level admin API, not just at the recorder layer.
#[tokio::test]
async fn clear_quarantine_is_scoped_to_named_server() {
    let mut manifests = BTreeMap::new();
    let mut m1 = manifest_with(false);
    m1.name = "alpha".to_owned();
    m1.tools
        .push(ToolClassification::new("a", RiskTier::High, false, false));
    let mut m2 = manifest_with(false);
    m2.name = "beta".to_owned();
    m2.tools
        .push(ToolClassification::new("b", RiskTier::High, false, false));
    manifests.insert("alpha".to_owned(), m1);
    manifests.insert("beta".to_owned(), m2);
    let pool = UpstreamPool::from_manifests_disconnected(manifests);

    {
        let alpha = pool.entries.load().get("alpha").cloned().unwrap();
        alpha
            .quarantined
            .write()
            .expect("upstream quarantine lock poisoned")
            .insert("a".to_owned());
        let beta = pool.entries.load().get("beta").cloned().unwrap();
        beta.quarantined
            .write()
            .expect("upstream quarantine lock poisoned")
            .insert("b".to_owned());
    }

    // Clear alpha; beta's quarantine survives.
    assert_eq!(pool.clear_quarantine("alpha").await, Some(1));
    assert_eq!(pool.quarantined_tools("alpha").await, Some(vec![]));
    assert_eq!(
        pool.quarantined_tools("beta").await,
        Some(vec!["b".to_owned()]),
    );
}

// -------------------------------------------------------------
// tier_c_peer audience resolution
// -------------------------------------------------------------

/// Build a disconnected pool wired with the supplied peer
/// JWKS cache so `resolve_tier_c_audience` can be driven
/// without standing up a real upstream connection.
fn pool_with_peer_cache(cache: waygate_federation::jwks::SharedPeerJwksCache) -> UpstreamPool {
    let manifests = BTreeMap::new();
    UpstreamPool::from_manifests_disconnected(manifests).with_peer_jwks_cache(cache)
}

fn cached_entry(
    peer_id: ::uuid::Uuid,
    tenant: &str,
    issuer: &str,
) -> waygate_federation::jwks::CachedJwks {
    waygate_federation::jwks::CachedJwks {
        peer_id,
        tenant_id: tenant.to_owned(),
        issuer: issuer.to_owned(),
        trust_tier: waygate_federation::TrustTier::Full,
        keys: jsonwebtoken::jwk::JwkSet { keys: vec![] },
        fetched_at: time::OffsetDateTime::now_utc(),
    }
}

#[tokio::test]
async fn resolve_tier_c_audience_returns_peer_issuer_on_hit() {
    let cache_arc = std::sync::Arc::new(waygate_federation::jwks::InMemoryPeerJwksCache::new());
    let peer_id = ::uuid::Uuid::new_v4();
    cache_arc.upsert(cached_entry(peer_id, "tenant-a", "https://peer-a.example/"));
    let shared: waygate_federation::jwks::SharedPeerJwksCache = cache_arc.clone();
    let pool = pool_with_peer_cache(shared);

    let aud = pool
        .resolve_tier_c_audience("example-messages", peer_id, "alice")
        .await
        .expect("hit must return peer issuer");
    assert_eq!(aud, "https://peer-a.example/");
}

#[tokio::test]
async fn resolve_tier_c_audience_refuses_on_cache_miss() {
    // Cache is empty — operator may have just deleted the
    // peer, or the refresh hasn't completed yet. Either
    // way, refuse rather than mint a Tier-B aud the remote
    // can't verify.
    let cache_arc = std::sync::Arc::new(waygate_federation::jwks::InMemoryPeerJwksCache::new());
    let shared: waygate_federation::jwks::SharedPeerJwksCache = cache_arc;
    let pool = pool_with_peer_cache(shared);

    let err = pool
        .resolve_tier_c_audience("example-messages", ::uuid::Uuid::new_v4(), "alice")
        .await
        .expect_err("cache miss must refuse");
    let display = format!("{err:?}");
    assert!(
        display.contains("Tier-C peer"),
        "error must name Tier-C invariant: {display}",
    );
    assert!(
        display.contains("federated_peers"),
        "error must point at the registry: {display}",
    );
}

#[tokio::test]
async fn resolve_tier_c_audience_refuses_when_no_cache_wired() {
    // Operator forgot `.with_peer_jwks_cache(...)`; refuse
    // loud so a misconfigured deployment can't silently
    // downgrade.
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::new());
    let err = pool
        .resolve_tier_c_audience("example-messages", ::uuid::Uuid::new_v4(), "alice")
        .await
        .expect_err("no cache wired must refuse");
    let display = format!("{err:?}");
    assert!(
        display.contains("with_peer_jwks_cache"),
        "error must name the missing builder call: {display}",
    );
}

#[tokio::test]
async fn resolve_tier_c_audience_resolves_independent_of_tenant() {
    // A peer registered in `tenant-x` is reachable by id
    // from a call originating in any tenant — the
    // refresh-side scan is cross-tenant and the cache is
    // keyed by peer_id. Per-tenant gating on registration
    // is enforced by the admin CRUD; per-call enforcement
    // doesn't re-check at this layer.
    let cache_arc = std::sync::Arc::new(waygate_federation::jwks::InMemoryPeerJwksCache::new());
    let peer_id = ::uuid::Uuid::new_v4();
    cache_arc.upsert(cached_entry(peer_id, "tenant-x", "https://x.example/"));
    let shared: waygate_federation::jwks::SharedPeerJwksCache = cache_arc;
    let pool = pool_with_peer_cache(shared);

    let aud = pool
        .resolve_tier_c_audience("example-messages", peer_id, "alice")
        .await
        .expect("cross-tenant lookup must still hit");
    assert_eq!(aud, "https://x.example/");
}

/// A `tools/call` identifies its operation by name alone, so annotation
/// admission must rule the NAME unambiguous: an approved descriptor paired
/// with a different descriptor under the same name would let the upstream
/// pick which contract executes. Identical approved duplicates remain
/// admissible; any unapproved same-name duplicate fails the whole name
/// closed, at dispatch admission and at publication.
#[test]
fn annotation_native_duplicate_names_fail_closed() {
    let approved = annotation_native_live("x");
    let mut classification_x = classification("x");
    classification_x.approved_behavior_hash =
        Some(crate::security_metadata::behavior_hash(&approved));
    let mut rogue = approved.clone();
    rogue.description = Some("different behavior".to_owned().into());

    let mut manifest = manifest_with(false);
    manifest.classification_mode = crate::ClassificationMode::McpAnnotations;
    manifest.tools = vec![classification_x.clone()];
    assert!(
        admission::tool_is_admitted_in_catalog(
            &manifest,
            &[approved.clone(), approved.clone()],
            "x",
        ),
        "identical approved duplicates share one unambiguous contract",
    );
    assert!(
        !admission::tool_is_admitted_in_catalog(&manifest, &[approved.clone(), rogue.clone()], "x"),
        "an unapproved same-name duplicate makes the executable contract ambiguous",
    );

    let (kept, quarantined, _) = partition_live_tools(
        &[classification_x],
        crate::ClassificationMode::McpAnnotations,
        &[approved, rogue],
    );
    assert!(
        kept.is_empty(),
        "the approved copy must not publish alongside a same-name rogue",
    );
    assert_eq!(quarantined, vec!["x".to_owned()]);
}

fn published_with_hash(approved: Option<&str>) -> schema_admission::PublishedToolContract {
    // Annotation-mode resolution derives policy facts from these reviewed
    // claims, so an admitted published contract carries valid standard
    // annotations and action metadata (a non-side-effecting, non-review
    // tool here); the generation-binding tests assert on the hash/mode/risk
    // gates, not on the derived facts.
    schema_admission::PublishedToolContract {
        definition: None,
        advertised_definition: None,
        native_tasks: false,
        input_schema: Some(serde_json::json!({"type": "object"})),
        output_schema: None,
        tool_annotations: Some(serde_json::json!({
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false,
        })),
        action_metadata: Some(serde_json::json!({
            "inputMetadata": {"destination": "internal", "sensitivity": "normal"},
            "returnMetadata": {"source": "first-party", "sensitivity": "normal"},
            "outcome": "benign",
            "requiresReview": false,
        })),
        behavior_hash: approved.map(str::to_owned),
    }
}

/// Catalog policy facts may only overlay a live contract from the SAME
/// reviewed generation: the reload paths update the pool and the catalog
/// non-atomically, so an annotation-mode catalog row must match the manifest
/// on BOTH the reviewed behavior hash and the imported risk before its facts
/// apply — the hash alone would wave through a risk-only manifest change and
/// let calls authorize under the prior risk while the reconcile is pending.
#[tokio::test]
async fn annotation_generation_mismatch_fails_closed() {
    fn live_def(hash: &str, risk: &str) -> waygate_catalog::ToolDefinition {
        waygate_catalog::ToolDefinition {
            discriminator: None,
            operations: Vec::new(),
            tool_id: uuid_nil(),
            server_id: uuid_nil(),
            server_name: "example-messages".into(),
            tool_name: "send".into(),
            schema_hash: hash.into(),
            description: "d".into(),
            classification_mode: "mcp_annotations".into(),
            input_schema: None,
            output_schema: None,
            tool_annotations: None,
            action_metadata: None,
            risk: risk.into(),
            side_effects: false,
            pii: false,
            data_classification: None,
            cost_class: None,
            requires_approval: false,
        }
    }
    fn facts() -> ToolFacts {
        ToolFacts {
            server: "example-messages".into(),
            name: "send".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: true,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
    async fn resolve_with(
        def: waygate_catalog::ToolDefinition,
        approved: String,
    ) -> ResolvedInvocationTool {
        let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
            outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
                def,
            )))),
            err: false,
            ..Default::default()
        });
        let pool = pool_with_manifest_tool().with_catalog(catalog);
        pool.resolve_snapshot_from(
            "default",
            "example-messages",
            "send",
            contract_binding::SnapshotInputs {
                manifest_facts: facts(),
                annotation_mode: true,
                approval_mode: crate::ApprovalMode::PerCall,
                inline_response_threshold_bytes: None,
                approved_behavior_hash: Some(approved.clone()),
                manifest_version_hash: None,
                manifest_discriminator: None,
                manifest_operations: Vec::new(),
                published: published_with_hash(Some(&approved)),
            },
        )
        .await
    }
    let approved = "a".repeat(64);

    let hash_mismatch = resolve_with(live_def(&"b".repeat(64), "high"), approved.clone()).await;
    assert!(
        matches!(
            hash_mismatch,
            ResolvedInvocationTool::Unavailable {
                reason: TemporaryUnavailability::CatalogConverging,
                ..
            }
        ),
        "a catalog row from another behavior generation must fail closed",
    );

    let risk_mismatch = resolve_with(live_def(&approved, "low"), approved.clone()).await;
    assert!(
        matches!(
            risk_mismatch,
            ResolvedInvocationTool::Unavailable {
                reason: TemporaryUnavailability::CatalogConverging,
                ..
            }
        ),
        "an unchanged hash must not wave through a risk-only generation split",
    );

    let matching = resolve_with(live_def(&approved, "high"), approved).await;
    let snapshot = expect_snapshot(matching);
    assert_eq!(
        snapshot.facts().risk,
        RiskTier::High,
        "a same-generation catalog row supplies its risk",
    );
}

/// The annotation-mode catalog overlay may add an approval requirement in the
/// default mode, while an explicit policy-only manifest suppresses catalog and
/// annotation approval sources. The upstream name has no bearing on the
/// decision.
#[tokio::test]
async fn approval_mode_controls_catalog_requirement_independent_of_server_name() {
    let approved = "a".repeat(64);

    // A same-generation annotation-mode catalog row (matching hash + risk)
    // that classifies the tool `requires_approval: true`.
    fn approving_def(server: &str, tool: &str, hash: &str) -> waygate_catalog::ToolDefinition {
        waygate_catalog::ToolDefinition {
            discriminator: None,
            operations: Vec::new(),
            tool_id: uuid_nil(),
            server_id: uuid_nil(),
            server_name: server.into(),
            tool_name: tool.into(),
            schema_hash: hash.into(),
            description: "d".into(),
            classification_mode: "mcp_annotations".into(),
            input_schema: None,
            output_schema: None,
            tool_annotations: None,
            action_metadata: None,
            risk: "high".into(),
            side_effects: true,
            pii: false,
            data_classification: None,
            cost_class: None,
            requires_approval: true,
        }
    }
    fn side_effecting_facts(server: &str, tool: &str) -> ToolFacts {
        ToolFacts {
            server: server.into(),
            name: tool.into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
    async fn resolved_requires_approval(
        server: &str,
        tool: &str,
        approved: &str,
        approval_mode: crate::ApprovalMode,
    ) -> bool {
        let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
            outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
                approving_def(server, tool, approved),
            )))),
            err: false,
            ..Default::default()
        });
        let pool = pool_with_manifest_tool().with_catalog(catalog);
        expect_snapshot(
            pool.resolve_snapshot_from(
                "default",
                server,
                tool,
                contract_binding::SnapshotInputs {
                    manifest_facts: side_effecting_facts(server, tool),
                    annotation_mode: true,
                    approval_mode,
                    inline_response_threshold_bytes: None,
                    approved_behavior_hash: Some(approved.to_owned()),
                    manifest_version_hash: None,
                    manifest_discriminator: None,
                    manifest_operations: Vec::new(),
                    published: published_with_hash(Some(approved)),
                },
            )
            .await,
        )
        .facts()
        .requires_approval
    }

    assert!(
        !resolved_requires_approval(
            "deployment-controller",
            "workloads.apply",
            &approved,
            crate::ApprovalMode::PolicyOnly,
        )
        .await,
        "policy-only mode must suppress the ordinary catalog approval source",
    );
    // A historically special-looking name receives no exemption: the default
    // mode still honors the identical catalog requirement.
    assert!(
        resolved_requires_approval(
            "komodo",
            "workloads.apply",
            &approved,
            crate::ApprovalMode::PerCall,
        )
        .await,
        "an upstream name must never select approval semantics",
    );
}

/// Policy-only mode suppresses only the catalog's ordinary approval bit. A
/// legacy manifest-mode catalog row remains authoritative for the behavioral
/// facts Cedar evaluates.
#[tokio::test]
async fn policy_only_manifest_mode_preserves_catalog_side_effect_and_pii_facts() {
    let version = "manifest-v1";
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
            waygate_catalog::ToolDefinition {
                discriminator: None,
                operations: Vec::new(),
                tool_id: uuid_nil(),
                server_id: uuid_nil(),
                server_name: "deployment-controller".into(),
                tool_name: "workloads.apply".into(),
                schema_hash: version.into(),
                description: "d".into(),
                classification_mode: "manifest".into(),
                input_schema: None,
                output_schema: None,
                tool_annotations: None,
                action_metadata: None,
                risk: "high".into(),
                side_effects: true,
                pii: true,
                data_classification: None,
                cost_class: None,
                requires_approval: true,
            },
        )))),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog);
    let snapshot = expect_snapshot(
        pool.resolve_snapshot_from(
            "default",
            "deployment-controller",
            "workloads.apply",
            contract_binding::SnapshotInputs {
                manifest_facts: ToolFacts {
                    server: "deployment-controller".into(),
                    name: "workloads.apply".into(),
                    risk: RiskTier::Low,
                    side_effects: false,
                    pii: false,
                    requires_approval: false,
                    requires_approval_known: true,
                },
                annotation_mode: false,
                approval_mode: crate::ApprovalMode::PolicyOnly,
                inline_response_threshold_bytes: None,
                approved_behavior_hash: None,
                manifest_version_hash: Some(version.into()),
                manifest_discriminator: None,
                manifest_operations: Vec::new(),
                published: published_with_hash(None),
            },
        )
        .await,
    );

    assert_eq!(snapshot.facts().risk, RiskTier::High);
    assert!(snapshot.facts().side_effects);
    assert!(snapshot.facts().pii);
    assert!(!snapshot.facts().requires_approval);
}

/// Legacy manifest-mode fallbacks keep the pre-annotation snapshot shape —
/// input schema only. Stages 6 and 12 compile and enforce every carried
/// output schema, so attaching the upstream's published output contract to a
/// manifest-mode fallback would newly reject calls legacy deployments
/// accepted. Annotation mode carries the complete published contract: that
/// contract is the reviewed behavior.
#[tokio::test]
async fn manifest_fallback_keeps_legacy_snapshot_shape() {
    fn published() -> schema_admission::PublishedToolContract {
        schema_admission::PublishedToolContract {
            definition: None,
            advertised_definition: None,
            native_tasks: false,
            input_schema: Some(serde_json::json!({"type": "object"})),
            output_schema: Some(serde_json::json!({"type": "integer"})),
            tool_annotations: Some(serde_json::json!({
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false,
            })),
            action_metadata: Some(serde_json::json!({
                "inputMetadata": {"destination": "internal", "sensitivity": "normal"},
                "returnMetadata": {"source": "first-party", "sensitivity": "normal"},
                "outcome": "benign",
                "requiresReview": false,
            })),
            behavior_hash: Some("a".repeat(64)),
        }
    }
    fn facts() -> ToolFacts {
        ToolFacts {
            server: "example-messages".into(),
            name: "send".into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
    // No catalog wired: both resolutions take the fallback arm.
    let pool = pool_with_manifest_tool();

    let legacy = expect_snapshot(
        pool.resolve_snapshot_from(
            "default",
            "example-messages",
            "send",
            contract_binding::SnapshotInputs {
                manifest_facts: facts(),
                annotation_mode: false,
                approval_mode: crate::ApprovalMode::PerCall,
                inline_response_threshold_bytes: None,
                approved_behavior_hash: None,
                manifest_version_hash: None,
                manifest_discriminator: None,
                manifest_operations: Vec::new(),
                published: published(),
            },
        )
        .await,
    );
    assert!(
        legacy.input_schema().is_some(),
        "input admission is legacy behavior"
    );
    assert!(
        legacy.output_schema().is_none(),
        "a manifest-mode fallback must not newly enforce an output schema",
    );
    assert!(legacy.tool_annotations().is_none());
    assert!(legacy.action_metadata().is_none());

    let annotated = expect_snapshot(
        pool.resolve_snapshot_from(
            "default",
            "example-messages",
            "send",
            contract_binding::SnapshotInputs {
                manifest_facts: facts(),
                annotation_mode: true,
                approval_mode: crate::ApprovalMode::PerCall,
                inline_response_threshold_bytes: None,
                approved_behavior_hash: Some("a".repeat(64)),
                manifest_version_hash: None,
                manifest_discriminator: None,
                manifest_operations: Vec::new(),
                published: published(),
            },
        )
        .await,
    );
    assert!(annotated.input_schema().is_some());
    assert!(
        annotated.output_schema().is_some(),
        "an annotation-mode fallback carries the complete published contract",
    );
    assert!(annotated.tool_annotations().is_some());
    assert!(annotated.action_metadata().is_some());
}

/// The reviewed behavior hash covers the COMPLETE namespaced `Tool._meta`
/// object: a claim under any sibling namespace is still an upstream
/// behavior/sensitivity assertion, so adding or changing one must produce a
/// new reviewed hash rather than drifting silently past approval.
#[test]
fn unknown_namespaced_metadata_changes_the_behavior_hash() {
    let base = annotation_native_live("read");
    let mut with_sibling = base.clone();
    with_sibling.meta.as_mut().expect("fixture meta").0.insert(
        "com.example/custom-claim".to_owned(),
        serde_json::json!({"tier": "internal"}),
    );
    assert_ne!(
        crate::security_metadata::behavior_hash(&base),
        crate::security_metadata::behavior_hash(&with_sibling),
        "an unknown namespaced claim must participate in the reviewed hash",
    );

    let mut changed_sibling = with_sibling.clone();
    changed_sibling.meta.as_mut().expect("meta").0.insert(
        "com.example/custom-claim".to_owned(),
        serde_json::json!({"tier": "public"}),
    );
    assert_ne!(
        crate::security_metadata::behavior_hash(&with_sibling),
        crate::security_metadata::behavior_hash(&changed_sibling),
        "a changed unknown namespaced claim must change the reviewed hash",
    );
}

/// An annotation-mode manifest fallback binds the approved behavior hash
/// into the contract identity: separately approved generations may differ
/// only in fields OUTSIDE the four schema hashes — description, a sibling
/// namespaced claim — and without the bound hash their fallback identities
/// would be indistinguishable across discovery, Code Mode, and dispatch.
/// Legacy manifest-mode fallbacks carry no hash and keep their identity.
#[tokio::test]
async fn annotation_fallback_identity_binds_the_approved_generation() {
    fn facts() -> ToolFacts {
        ToolFacts {
            server: "example-messages".into(),
            name: "send".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: true,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
    let pool = pool_with_manifest_tool();
    let identity_for = |approved: Option<String>, annotation_mode: bool| {
        let pool = &pool;
        async move {
            expect_snapshot(
                pool.resolve_snapshot_from(
                    "default",
                    "example-messages",
                    "send",
                    contract_binding::SnapshotInputs {
                        manifest_facts: facts(),
                        annotation_mode,
                        approval_mode: crate::ApprovalMode::PerCall,
                        inline_response_threshold_bytes: None,
                        approved_behavior_hash: approved.clone(),
                        manifest_version_hash: None,
                        manifest_discriminator: None,
                        manifest_operations: Vec::new(),
                        published: published_with_hash(approved.as_deref()),
                    },
                )
                .await,
            )
            .contract_identity()
        }
    };

    let generation_a = identity_for(Some("a".repeat(64)), true).await;
    let generation_b = identity_for(Some("b".repeat(64)), true).await;
    assert_ne!(
        generation_a, generation_b,
        "fallback identities must differ across approved behavior generations",
    );

    let legacy_a = identity_for(None, false).await;
    let legacy_b = identity_for(None, false).await;
    assert_eq!(
        legacy_a, legacy_b,
        "legacy manifest-mode fallback identity is unchanged",
    );
}

/// A catalog row and the live manifest must agree on classification mode
/// before the row's facts apply: an annotation-imported row carries
/// forced-false legacy `side_effects`/`pii`, so overlaying it onto a
/// legacy-mode tool would weaken its facts, and the reverse split lends
/// legacy facts to an annotation tool. Either direction is a generation
/// split and fails closed.
#[tokio::test]
async fn classification_mode_split_fails_closed() {
    fn live_def(mode: &str) -> waygate_catalog::ToolDefinition {
        waygate_catalog::ToolDefinition {
            discriminator: None,
            operations: Vec::new(),
            tool_id: uuid_nil(),
            server_id: uuid_nil(),
            server_name: "example-messages".into(),
            tool_name: "send".into(),
            schema_hash: "a".repeat(64),
            description: "d".into(),
            classification_mode: mode.into(),
            input_schema: None,
            output_schema: None,
            tool_annotations: None,
            action_metadata: None,
            risk: "high".into(),
            side_effects: false,
            pii: false,
            data_classification: None,
            cost_class: None,
            requires_approval: false,
        }
    }

    // Legacy live manifest + annotation-imported catalog row.
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
            live_def("mcp_annotations"),
        )))),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog);
    let resolved = pool
        .resolve_invocation_tool("default", "example-messages", "send")
        .await;
    assert!(
        matches!(
            resolved,
            ResolvedInvocationTool::Unavailable {
                reason: TemporaryUnavailability::CatalogConverging,
                ..
            }
        ),
        "an annotation-imported row must not overlay a legacy-mode tool",
    );

    // Annotation live manifest + legacy-imported catalog row.
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
            live_def("manifest"),
        )))),
        err: false,
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog);
    let resolved = pool
        .resolve_snapshot_from(
            "default",
            "example-messages",
            "send",
            contract_binding::SnapshotInputs {
                manifest_facts: ToolFacts {
                    server: "example-messages".into(),
                    name: "send".into(),
                    risk: RiskTier::High,
                    side_effects: true,
                    pii: true,
                    requires_approval: false,
                    requires_approval_known: true,
                },
                annotation_mode: true,
                approval_mode: crate::ApprovalMode::PerCall,
                inline_response_threshold_bytes: None,
                approved_behavior_hash: Some("a".repeat(64)),
                manifest_version_hash: None,
                manifest_discriminator: None,
                manifest_operations: Vec::new(),
                published: published_with_hash(Some(&"a".repeat(64))),
            },
        )
        .await;
    assert!(
        matches!(
            resolved,
            ResolvedInvocationTool::Unavailable {
                reason: TemporaryUnavailability::CatalogConverging,
                ..
            }
        ),
        "a legacy-imported row must not lend facts to an annotation-mode tool",
    );
}

/// A manifest-declared dispatch tool keeps its reviewed operation set when it
/// resolves through the fallback arm — no catalog configured, or a catalog that
/// could not answer. Dropping it there would present the lane as a tool
/// classified by name alone, and every caller that reasons about the reviewed
/// set would then admit operations no reviewer named, on the tool-level entry
/// alone. The ceiling filter still applies, exactly as on the catalog arm.
#[tokio::test]
async fn manifest_fallback_snapshot_keeps_its_reviewed_operation_set() {
    let pool = pool_with_manifest_tool();

    let resolved = pool
        .resolve_snapshot_from(
            "default",
            "example-messages",
            "send",
            contract_binding::SnapshotInputs {
                manifest_facts: ToolFacts {
                    server: "example-messages".into(),
                    name: "send".into(),
                    risk: RiskTier::High,
                    side_effects: true,
                    // The manifest declares this tool without PII, so an entry
                    // claiming PII exceeds it on that dimension.
                    pii: false,
                    requires_approval: false,
                    requires_approval_known: true,
                },
                annotation_mode: false,
                approval_mode: crate::ApprovalMode::PerCall,
                inline_response_threshold_bytes: None,
                approved_behavior_hash: None,
                manifest_version_hash: None,
                manifest_discriminator: Some("operation".to_owned()),
                manifest_operations: vec![
                    waygate_catalog::OperationClassification {
                        value: "messages.list".to_owned(),
                        risk: "low".to_owned(),
                        side_effects: false,
                        pii: false,
                    },
                    // Exceeds the tool it refines, so the shared ceiling drops
                    // it and the tool-level entry stands.
                    waygate_catalog::OperationClassification {
                        value: "messages.purge".to_owned(),
                        risk: "high".to_owned(),
                        side_effects: true,
                        pii: true,
                    },
                ],
                published: published_with_hash(None),
            },
        )
        .await;

    let ResolvedInvocationTool::Ready(snapshot) = resolved else {
        panic!("a manifest fallback resolves Ready");
    };
    assert_eq!(snapshot.discriminator(), Some("operation"));
    assert!(
        snapshot
            .resolve_operation(serde_json::json!({"operation": "messages.list"}).as_object())
            .classified,
        "a reviewed operation must stay classified on the fallback arm",
    );
    assert!(
        !snapshot
            .resolve_operation(serde_json::json!({"operation": "messages.purge"}).as_object())
            .classified,
        "an entry the ceiling drops must leave its value unclassified, or the \
         fallback arm would carry a refinement more severe than its tool",
    );
    assert!(
        !snapshot
            .resolve_operation(serde_json::json!({"operation": "messages.delete"}).as_object())
            .classified,
        "an operation no entry names must not be classified",
    );
}

/// Annotation mode must never resolve `Ready` from an EMPTY published
/// contract: an admitted live descriptor always publishes at least its
/// input schema, so emptiness means the manifest and the published
/// inventory diverged — and a snapshot built from nothing would dispatch
/// with no schemas or metadata bound.
#[tokio::test]
async fn annotation_empty_published_contract_fails_closed() {
    fn facts() -> ToolFacts {
        ToolFacts {
            server: "example-messages".into(),
            name: "send".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: true,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
    let pool = pool_with_manifest_tool();

    let empty = pool
        .resolve_snapshot_from(
            "default",
            "example-messages",
            "send",
            contract_binding::SnapshotInputs {
                manifest_facts: facts(),
                annotation_mode: true,
                approval_mode: crate::ApprovalMode::PerCall,
                inline_response_threshold_bytes: None,
                approved_behavior_hash: Some("a".repeat(64)),
                manifest_version_hash: None,
                manifest_discriminator: None,
                manifest_operations: Vec::new(),
                published: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(
            empty,
            ResolvedInvocationTool::Unavailable {
                reason: TemporaryUnavailability::CatalogConverging,
                ..
            }
        ),
        "an empty published contract must fail closed in annotation mode",
    );

    let complete = pool
        .resolve_snapshot_from(
            "default",
            "example-messages",
            "send",
            contract_binding::SnapshotInputs {
                manifest_facts: facts(),
                annotation_mode: true,
                approval_mode: crate::ApprovalMode::PerCall,
                inline_response_threshold_bytes: None,
                approved_behavior_hash: Some("a".repeat(64)),
                manifest_version_hash: None,
                manifest_discriminator: None,
                manifest_operations: Vec::new(),
                published: published_with_hash(Some(&"a".repeat(64))),
            },
        )
        .await;
    assert!(
        matches!(complete, ResolvedInvocationTool::Ready(_)),
        "a published contract restores resolution",
    );
}

/// The published view is read separately from the manifest snapshot that
/// governs a resolution, so a classification reload can interleave the two
/// reads. The resolver binds them by generation: a published descriptor
/// whose own behavior hash differs from the approved hash must refuse
/// rather than flow into validation, authorization, or Code Mode discovery
/// as a snapshot no single generation ever admitted.
#[tokio::test]
async fn annotation_mixed_generation_published_contract_fails_closed() {
    fn facts() -> ToolFacts {
        ToolFacts {
            server: "example-messages".into(),
            name: "send".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: true,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
    let pool = pool_with_manifest_tool();

    let stale = pool
        .resolve_snapshot_from(
            "default",
            "example-messages",
            "send",
            contract_binding::SnapshotInputs {
                manifest_facts: facts(),
                annotation_mode: true,
                approval_mode: crate::ApprovalMode::PerCall,
                inline_response_threshold_bytes: None,
                approved_behavior_hash: Some("a".repeat(64)),
                manifest_version_hash: None,
                manifest_discriminator: None,
                manifest_operations: Vec::new(),
                published: published_with_hash(Some(&"b".repeat(64))),
            },
        )
        .await;
    assert!(
        matches!(
            stale,
            ResolvedInvocationTool::Unavailable {
                reason: TemporaryUnavailability::CatalogConverging,
                ..
            }
        ),
        "a published contract from another generation must fail closed",
    );
}

#[test]
fn an_operation_more_severe_than_its_tool_is_ignored() {
    // Storage does not enforce the manifest ceiling: these columns take writes
    // that never pass through a manifest. This read turns them into
    // authorization inputs, so a row above its tool has to be dropped here —
    // otherwise a value nobody named would be classified more severely than one
    // an operator did, inverting the fallback the design depends on.
    let facts = ToolFacts {
        server: "example-secrets".into(),
        name: "read".into(),
        risk: RiskTier::Medium,
        side_effects: false,
        pii: false,
        requires_approval: false,
        requires_approval_known: true,
    };
    let row =
        |value: &str, risk: &str, side_effects, pii| waygate_catalog::OperationClassification {
            value: value.to_owned(),
            risk: risk.to_owned(),
            side_effects,
            pii,
        };

    let kept = super::contract_binding::operation_classifications(
        &facts,
        false,
        vec![
            row("projects.list", "low", false, false),
            row("secrets.reveal", "high", false, false),
            row("secrets.write", "low", true, false),
            row("identities.get", "low", false, true),
            row("folders.list", "medium", false, false),
        ],
        super::admission::Effects::Record,
    );

    let names: Vec<&str> = kept.iter().map(|o| o.value.as_str()).collect();
    assert_eq!(
        names,
        vec!["projects.list", "folders.list"],
        "only entries within the tool's risk and flags may refine it"
    );
}

#[test]
fn annotation_mode_pins_operation_flags_to_the_tool() {
    // Annotation mode forces the tool-level flags true at runtime because the
    // reviewed claims are not bound into the snapshot yet. An entry validated
    // against a manifest that forces those flags clear carries false, so
    // applying it would lower the posture; risk is the one dimension both
    // authorities have agreed on.
    let facts = ToolFacts {
        server: "example-secrets".into(),
        name: "read".into(),
        risk: RiskTier::High,
        side_effects: true,
        pii: true,
        requires_approval: false,
        requires_approval_known: true,
    };

    let kept = super::contract_binding::operation_classifications(
        &facts,
        true,
        vec![waygate_catalog::OperationClassification {
            value: "projects.list".into(),
            risk: "low".into(),
            side_effects: false,
            pii: false,
        }],
        super::admission::Effects::Record,
    );

    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].risk, RiskTier::Low, "risk still refines");
    assert!(kept[0].side_effects, "flags stay pinned to the tool");
    assert!(kept[0].pii, "flags stay pinned to the tool");
}

#[test]
fn annotation_mode_cannot_launder_an_out_of_ceiling_row() {
    // The reported hazard: annotation mode pins each entry's flags to the
    // tool's, so normalizing before the ceiling test would rewrite a stored row
    // that exceeds those flags into one that passes — and it would keep the
    // narrower risk that arrived with it. A high-risk tool would then authorize
    // the call at `low` on the strength of a row the manifest loader would have
    // refused. The row has to be judged as stored.
    let facts = ToolFacts {
        server: "example-secrets".into(),
        name: "read".into(),
        risk: RiskTier::High,
        side_effects: false,
        pii: false,
        requires_approval: false,
        requires_approval_known: true,
    };

    let kept = super::contract_binding::operation_classifications(
        &facts,
        true,
        vec![
            waygate_catalog::OperationClassification {
                value: "secrets.write".into(),
                risk: "low".into(),
                side_effects: true,
                pii: false,
            },
            waygate_catalog::OperationClassification {
                value: "identities.get".into(),
                risk: "low".into(),
                side_effects: false,
                pii: true,
            },
            waygate_catalog::OperationClassification {
                value: "projects.list".into(),
                risk: "low".into(),
                side_effects: false,
                pii: false,
            },
        ],
        super::admission::Effects::Record,
    );

    let names: Vec<&str> = kept.iter().map(|o| o.value.as_str()).collect();
    assert_eq!(
        names,
        vec!["projects.list"],
        "a stored row exceeding the tool's flags must be dropped, not normalized \
         into one that passes and keeps its lower risk"
    );
}

/// `protocol:` is a connection-shape field in BOTH predicates that gate a
/// re-dial: the reconnect/CAS comparison pinned here, and the live reload
/// trigger, which `protocol_only_reload_redials_and_renegotiates` in the
/// HTTP suite drives end to end against a real upstream.
#[test]
fn protocol_change_is_a_connection_shape_change() {
    let base: crate::UpstreamManifest =
        serde_yaml::from_str("name: a\ntransport: http\nurl: http://u/mcp\n").expect("parse");
    let mut legacy = base.clone();
    legacy.protocol = crate::UpstreamProtocol::Legacy;
    assert!(super::reload::redial_committed_fields_eq(
        &base,
        &base.clone()
    ));
    assert!(
        !super::reload::redial_committed_fields_eq(&base, &legacy),
        "a protocol override must trigger a re-dial, not apply silently in place"
    );
}

// ---- read-only refusal report ----------------------------------------------

/// Counts `tracing` events this crate emits while it is the thread's default
/// subscriber, so a test can prove a code path logs nothing.
struct CountingSubscriber(Arc<std::sync::atomic::AtomicUsize>);

impl tracing::Subscriber for CountingSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target().starts_with("waygate_upstream") {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// The report for one server, which must be present.
async fn server_report(pool: &UpstreamPool, server: &str) -> ServerRefusals {
    let mut report = pool.refusals("default", |name| name == server).await;
    assert_eq!(report.len(), 1, "one report for {server}");
    report.remove(0)
}

/// Report first, then ask the call path about every name: each name the
/// call path does not admit must be reported with the same reason, and each
/// admitted name must be absent. Returns the report for further assertions.
async fn report_matches_call_path(
    pool: &UpstreamPool,
    server: &str,
    names: &[&str],
) -> ServerRefusals {
    let report = server_report(pool, server).await;
    for name in names {
        let expected = match pool.resolve_invocation_tool("default", server, name).await {
            ResolvedInvocationTool::Ready(_) => None,
            ResolvedInvocationTool::Refused { reason, .. } => Some(ToolBlock::Refused(reason)),
            ResolvedInvocationTool::Unavailable { reason, .. } => {
                Some(ToolBlock::Unavailable(reason))
            }
        };
        let reported = report
            .tools
            .iter()
            .find(|blocked| blocked.tool == *name)
            .map(|blocked| blocked.block);
        assert_eq!(reported, expected, "{server}.{name}");
    }
    report
}

fn scripted(outcome: Option<waygate_catalog::ResolvedTool>, err: bool) -> Arc<ScriptedCatalog> {
    Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(outcome),
        err,
        ..Default::default()
    })
}

/// Manifest mode: `extra` is advertised but unclassified, `ghost` is
/// classified but not advertised, and `read` is both.
async fn manifest_mode_garage() -> UpstreamPool {
    pool_connected_to(
        crate::ClassificationMode::Manifest,
        vec![live("read"), live("extra")],
        vec![classification("read"), classification("ghost")],
    )
    .await
}

#[tokio::test]
async fn refusal_report_matches_the_call_path_for_admission_states() {
    let names = ["read", "extra", "ghost"];
    let pool = manifest_mode_garage().await;
    let report = report_matches_call_path(&pool, "garage", &names).await;
    assert!(report.connected && !report.truncated);
    assert_eq!(
        report.tools,
        vec![BlockedTool {
            tool: "extra".into(),
            block: ToolBlock::Refused(ToolRefusal::Unclassified),
            advertised: true,
            review_recorded: false,
        }],
        "only the unclassified name is refused without a catalog",
    );

    // Contract drift held only in this process's memory.
    pool.entries
        .load()
        .get("garage")
        .expect("entry")
        .quarantined
        .write()
        .expect("upstream quarantine lock poisoned")
        .insert("read".to_owned());
    let report = report_matches_call_path(&pool, "garage", &names).await;
    assert!(report.tools.contains(&BlockedTool {
        tool: "read".into(),
        block: ToolBlock::Refused(ToolRefusal::DriftQuarantined),
        advertised: true,
        review_recorded: false,
    }));

    // Annotation mode: an unapproved hash, an unclassified name, and a
    // classified name nobody advertises; the approved tool is admitted.
    let mut approved = classification("ok");
    approved.approved_behavior_hash = Some(crate::security_metadata::behavior_hash(
        &annotation_native_live("ok"),
    ));
    let mut unapproved = classification("read");
    unapproved.approved_behavior_hash = Some("0".repeat(64));
    let mut ghost = classification("ghost");
    ghost.approved_behavior_hash = Some("1".repeat(64));
    let pool = pool_connected_to(
        crate::ClassificationMode::McpAnnotations,
        vec![
            annotation_native_live("read"),
            annotation_native_live("extra"),
            annotation_native_live("ok"),
        ],
        vec![approved, unapproved, ghost],
    )
    .await;
    let report = report_matches_call_path(&pool, "garage", &["ok", "read", "extra", "ghost"]).await;
    let blocks: Vec<_> = report
        .tools
        .iter()
        .map(|blocked| (blocked.tool.as_str(), blocked.block, blocked.advertised))
        .collect();
    assert_eq!(
        blocks,
        vec![
            ("extra", ToolBlock::Refused(ToolRefusal::Unclassified), true),
            (
                "ghost",
                ToolBlock::Refused(ToolRefusal::NotInCatalog),
                false
            ),
            ("read", ToolBlock::Refused(ToolRefusal::NotAdmitted), true),
        ],
    );
}

#[tokio::test]
async fn refusal_report_matches_the_call_path_for_catalog_states() {
    let names = ["read", "extra", "ghost"];
    let quarantined = |retired| waygate_catalog::ResolvedTool::Quarantined {
        server_name: "garage".into(),
        tool_name: "read".into(),
        retired,
    };
    let pending = waygate_catalog::ResolvedTool::PendingApproval {
        server_name: "garage".into(),
        tool_name: "read".into(),
    };
    let cases: Vec<(&str, UpstreamPool, ToolBlock)> = vec![
        (
            "quarantined",
            manifest_mode_garage()
                .await
                .with_authoritative_catalog(scripted(Some(quarantined(false)), false)),
            ToolBlock::Refused(ToolRefusal::ServerQuarantined),
        ),
        (
            "retired",
            manifest_mode_garage()
                .await
                .with_authoritative_catalog(scripted(Some(quarantined(true)), false)),
            ToolBlock::Refused(ToolRefusal::ServerRetired),
        ),
        (
            "pending approval",
            manifest_mode_garage()
                .await
                .with_authoritative_catalog(scripted(Some(pending), false))
                .with_catalog_strict_pending_approval(true),
            ToolBlock::Refused(ToolRefusal::ApprovalPending),
        ),
        (
            "missing from the catalog",
            manifest_mode_garage()
                .await
                .with_authoritative_catalog(scripted(None, false)),
            ToolBlock::Refused(ToolRefusal::NotInCatalog),
        ),
        (
            "catalog unreadable",
            manifest_mode_garage()
                .await
                .with_authoritative_catalog(scripted(None, true)),
            ToolBlock::Unavailable(TemporaryUnavailability::CatalogUnavailable),
        ),
    ];
    for (case, pool, expected) in cases {
        let report = report_matches_call_path(&pool, "garage", &names).await;
        // Admission refuses the unclassified name before the catalog is read,
        // but a quarantined or retired server outranks that reason too.
        let server_block = matches!(
            expected,
            ToolBlock::Refused(ToolRefusal::ServerQuarantined | ToolRefusal::ServerRetired)
        );
        let unclassified = if server_block {
            expected
        } else {
            ToolBlock::Refused(ToolRefusal::Unclassified)
        };
        let blocks: Vec<_> = report
            .tools
            .iter()
            .map(|blocked| (blocked.tool.as_str(), blocked.block))
            .collect();
        assert_eq!(
            blocks,
            vec![
                ("extra", unclassified),
                ("ghost", expected),
                ("read", expected),
            ],
            "{case}",
        );
    }

    // A manifest/catalog transition in progress is temporary.
    let pool = manifest_mode_garage()
        .await
        .with_authoritative_catalog(scripted(None, false));
    pool.catalog_transitions
        .write()
        .expect("catalog transition lock poisoned")
        .insert(
            ("garage".to_owned(), "read".to_owned()),
            CatalogTransition {
                generation: 1,
                pending: true,
            },
        );
    let report = report_matches_call_path(&pool, "garage", &names).await;
    assert!(report.tools.contains(&BlockedTool {
        tool: "read".into(),
        block: ToolBlock::Unavailable(TemporaryUnavailability::CatalogConverging),
        advertised: true,
        review_recorded: false,
    }));

    // With no connected session, an annotation-mode name cannot be checked.
    let mut manifest = manifest_with(false);
    manifest.classification_mode = crate::ClassificationMode::McpAnnotations;
    let mut approved = classification("send_message");
    approved.approved_behavior_hash = Some("a".repeat(64));
    manifest.tools = vec![approved];
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
        "example-messages".to_owned(),
        manifest,
    )]));
    let report = report_matches_call_path(&pool, "example-messages", &["send_message"]).await;
    assert!(!report.connected);
    assert_eq!(
        report.tools,
        vec![BlockedTool {
            tool: "send_message".into(),
            block: ToolBlock::Unavailable(TemporaryUnavailability::NoConnectedLane),
            advertised: false,
            review_recorded: false,
        }],
    );
}

/// The report logs nothing, writes no audit record, and does not tell
/// discovery that the catalog failed, although the call path does all three
/// for the same refusal.
#[tokio::test]
async fn refusal_report_logs_records_and_signals_nothing() {
    // A drift-quarantined tool and one whose catalog read fails: the call
    // path logs each and signals discovery about the failure.
    let refusing_pool = |sink: Arc<waygate_mcp::audit::InMemorySink>| {
        let mut manifest = manifest_with(false);
        manifest.tools.push(classification("send"));
        let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
            "example-messages".to_owned(),
            manifest,
        )]))
        .with_evidence(sink)
        .with_authoritative_catalog(scripted(None, true));
        pool.entries
            .load()
            .get("example-messages")
            .expect("entry")
            .quarantined
            .write()
            .expect("upstream quarantine lock poisoned")
            .insert("send".to_owned());
        pool
    };
    let events = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _subscriber = tracing::subscriber::set_default(CountingSubscriber(events.clone()));

    // Control first, on an identical pool: this subscriber must observe the
    // call path's log events, or "the report logs nothing" below would pass
    // vacuously. A test on another thread can register those log callsites
    // while no subscriber wants them, caching them as disabled, so rebuild
    // the cache and retry a bounded number of times. Once observed, later
    // rebuilds include this subscriber and cannot disable them again.
    let control = refusing_pool(Arc::new(waygate_mcp::audit::InMemorySink::new()));
    let mut observed = 0;
    for _ in 0..20 {
        events.store(0, Ordering::SeqCst);
        tracing::callsite::rebuild_interest_cache();
        for tool in ["send", "send_message"] {
            assert!(!matches!(
                control
                    .resolve_invocation_tool("default", "example-messages", tool)
                    .await,
                ResolvedInvocationTool::Ready(_)
            ));
        }
        observed = events.load(Ordering::SeqCst);
        if observed >= 2 {
            break;
        }
    }
    assert!(observed >= 2, "the call path logs: {observed} events");

    let sink = Arc::new(waygate_mcp::audit::InMemorySink::new());
    let pool = refusing_pool(sink.clone());
    events.store(0, Ordering::SeqCst);
    let error_generation = pool.discovery_error_generation();

    let report = server_report(&pool, "example-messages").await;
    assert_eq!(
        report
            .tools
            .iter()
            .map(|blocked| (blocked.tool.as_str(), blocked.block))
            .collect::<Vec<_>>(),
        vec![
            ("send", ToolBlock::Refused(ToolRefusal::DriftQuarantined)),
            (
                "send_message",
                ToolBlock::Unavailable(TemporaryUnavailability::CatalogUnavailable)
            ),
        ],
    );
    assert_eq!(events.load(Ordering::SeqCst), 0, "the report logs nothing");
    assert_eq!(pool.discovery_error_generation(), error_generation);
    assert!(sink.snapshot().await.is_empty(), "no audit record");

    // The call path, given the same state, signals the failure.
    for tool in ["send", "send_message"] {
        assert!(!matches!(
            pool.resolve_invocation_tool("default", "example-messages", tool)
                .await,
            ResolvedInvocationTool::Ready(_)
        ));
    }
    assert_ne!(pool.discovery_error_generation(), error_generation);
}

/// The report reads the catalog without filling the admission read cache, so
/// the call path's next admission still reads the catalog itself.
#[tokio::test]
async fn refusal_report_leaves_the_admission_cache_untouched() {
    let source_version =
        waygate_catalog::manifest_classification_hash("send", "high", true, false, None, &[]);
    let catalog = Arc::new(ScriptedCatalog {
        outcome: std::sync::Mutex::new(Some(waygate_catalog::ResolvedTool::Live(Box::new(
            waygate_catalog::ToolDefinition {
                discriminator: None,
                operations: Vec::new(),
                tool_id: uuid_nil(),
                server_id: uuid_nil(),
                server_name: "example-messages".into(),
                tool_name: "send".into(),
                schema_hash: source_version,
                description: "d".into(),
                classification_mode: "manifest".into(),
                input_schema: Some(serde_json::json!({"type": "object"})),
                output_schema: None,
                tool_annotations: None,
                action_metadata: None,
                risk: "high".into(),
                side_effects: true,
                pii: false,
                data_classification: None,
                cost_class: None,
                requires_approval: false,
            },
        )))),
        generation: Some(std::sync::atomic::AtomicI64::new(1)),
        ..Default::default()
    });
    let pool = pool_with_manifest_tool().with_catalog(catalog.clone());
    let resolves = || catalog.resolves.load(Ordering::SeqCst);

    let report = server_report(&pool, "example-messages").await;
    assert!(report.tools.is_empty(), "the live tool is admitted");
    assert_eq!(resolves(), 1, "the report reads the catalog once per name");
    expect_snapshot(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
    );
    assert_eq!(resolves(), 2, "the report left nothing in the cache");
    expect_snapshot(
        pool.resolve_invocation_tool("default", "example-messages", "send")
            .await,
    );
    assert_eq!(resolves(), 2, "the call path's own read is reused");
}

#[tokio::test]
async fn refusal_report_is_bounded_per_server() {
    let mut manifest = manifest_with(false);
    manifest.classification_mode = crate::ClassificationMode::McpAnnotations;
    manifest.tools = (0..=REFUSAL_REPORT_TOOL_LIMIT)
        .map(|index| {
            let mut tool = classification(&format!("tool-{index:05}"));
            tool.approved_behavior_hash = Some("a".repeat(64));
            tool
        })
        .collect();
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
        "example-messages".to_owned(),
        manifest,
    )]));
    let report = server_report(&pool, "example-messages").await;
    assert!(report.truncated);
    assert_eq!(report.tools.len(), REFUSAL_REPORT_TOOL_LIMIT);
    assert_eq!(report.tools[0].tool, "tool-00000");
    assert!(pool.refusals("default", |_| false).await.is_empty());
}

#[test]
fn undeclared_resources_are_reported_only_when_the_condition_becomes_true() {
    let undeclared = manifest_with(false);
    let mut declared = undeclared.clone();
    declared.resources = vec![crate::ResourceClassification {
        uri_prefix: "example-messages://".to_owned(),
        risk: RiskTier::Low,
    }];
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
        undeclared.name.clone(),
        undeclared.clone(),
    )]));
    let entry = pool
        .entries
        .load()
        .get(&undeclared.name)
        .cloned()
        .expect("entry");

    assert!(
        !entry.report_undeclared_resources(&undeclared, Some(false)),
        "an upstream offering no resources has nothing to report",
    );
    assert!(entry.report_undeclared_resources(&undeclared, Some(true)));
    assert!(
        !entry.report_undeclared_resources(&undeclared, Some(true)),
        "an unchanged condition repeats nothing",
    );
    assert!(
        !entry.report_undeclared_resources(&declared, Some(true)),
        "a declaration clears the condition without a report",
    );
    assert!(
        entry.report_undeclared_resources(&undeclared, Some(true)),
        "removing the last declaration makes it true again",
    );
    assert!(!entry.report_undeclared_resources(&undeclared, Some(false)));
    assert!(
        entry.report_undeclared_resources(&undeclared, Some(true)),
        "the upstream offering resources again makes it true again",
    );
    assert!(
        !entry.report_undeclared_resources(&manifest_with(true), Some(true)),
        "an upstream the gateway cannot read resources from is not reported",
    );

    // With no lane up the capability is unknown.
    assert!(entry.report_undeclared_resources(&undeclared, Some(true)));
    assert!(
        !entry.report_undeclared_resources(&undeclared, None),
        "a moment with no lane up neither reports nor clears",
    );
    assert!(
        !entry.report_undeclared_resources(&undeclared, Some(true)),
        "so the next connection repeats nothing",
    );
    assert!(
        !entry.report_undeclared_resources(&declared, None),
        "a declaration settles the condition even with no lane up",
    );
    assert!(
        entry.report_undeclared_resources(&undeclared, Some(true)),
        "a declaration added and removed while disconnected still clears it",
    );
}
