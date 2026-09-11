//! Verifies `UpstreamPool::reload_manifests` applies tool and resource
//! classification changes in place and hot-applies topology changes — add (dial + publish)
//! and remove (drain + drop) land live in the registry with no restart, and
//! EVERY connection-shape change is re-dialed or rebuilt live — all surfaced in
//! the returned report so the SIGHUP handler can act on them.
//!
//! Connection-shape changes split by slot-count stability into live re-dial
//! vs live rebuild:
//!   - A same-slot-count shape change (url / auth / mtls / Http↔Sse, concurrency
//!     untouched) is re-dialed live in place.
//!   - A slot-count-CHANGING shape edit (stdio↔network flip or a
//!     `session.concurrency` change) is REBUILT live — a fresh entry with the new
//!     slot count is dialed and swapped into the registry under the structural
//!     fence, the old entry draining via its `Arc`.
//!
//! Both land in `redialed` on success and `redial_failed` on failure; neither is
//! restart-required unless every new-shape dial fails. On the disconnected
//! fixture the dial points at a fast-refused loopback port (`FAIL_URL`) or a
//! command that exits immediately, so every shape change here fails
//! deterministically — landing the entry in `redial_failed` with the OLD entry
//! kept WHOLE and the stored shape NOT advanced (the security property: a failed
//! re-dial / rebuild never lies that the new bearer / cert / url / identity took
//! effect).

use std::collections::BTreeMap;
use std::time::Duration;

use rmcp::model::ReadResourceRequestParams;
use waygate_mcp::catalog::{ResourceReadAdmission, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_upstream::{
    ApprovalMode, MtlsConfig, ReloadReport, ResourceClassification, SessionConfig,
    ToolClassification, Transport, UpstreamAuth, UpstreamManifest, UpstreamPool,
};

/// A loopback address that refuses instantly (port 1 is privileged and never
/// listening) — used as the NEW shape's url in the re-dial-failure tests so the
/// dial fails fast and deterministically, with no DNS in the path.
const FAIL_URL: &str = "http://127.0.0.1:1/mcp";

/// Run a reload under a generous timeout. The live re-dial path now actually
/// dials the new shape; a hung dial would otherwise wedge the test rather than
/// fail it.
async fn reload_timed(
    pool: &UpstreamPool,
    fresh: &BTreeMap<String, UpstreamManifest>,
) -> ReloadReport {
    tokio::time::timeout(Duration::from_secs(10), pool.reload_manifests(fresh))
        .await
        .expect("reload_manifests hung (live re-dial should fail fast against a refused port)")
}

fn classification(name: &str, risk: RiskTier, side_effects: bool) -> ToolClassification {
    ToolClassification::new(name, risk, side_effects, false)
}

fn manifest(name: &str, url: &str, tools: Vec<ToolClassification>) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: name.into(),
        transport: Transport::Http,
        protocol: Default::default(),
        url: Some(url.into()),
        command: None,
        tools,
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        session: None,
    }
}

fn seed() -> UpstreamPool {
    let mut map = BTreeMap::new();
    map.insert(
        "example-messages".into(),
        manifest(
            "example-messages",
            "http://unused.test/mcp",
            vec![classification("send_message", RiskTier::Low, false)],
        ),
    );
    UpstreamPool::from_manifests_disconnected(map)
}

#[tokio::test]
async fn reload_applies_new_risk_tier_to_tool_facts() {
    let pool = seed();
    assert_eq!(
        pool.tool_facts("example-messages", "send_message").risk,
        RiskTier::Low
    );

    let mut fresh = BTreeMap::new();
    fresh.insert(
        "example-messages".into(),
        manifest(
            "example-messages",
            "http://unused.test/mcp",
            vec![classification("send_message", RiskTier::High, true)],
        ),
    );
    let report = pool.reload_manifests(&fresh).await;

    assert_eq!(
        report.classifications_updated,
        vec!["example-messages".to_string()]
    );
    assert!(report.added.is_empty());
    assert!(report.removed.is_empty());

    let facts = pool.tool_facts("example-messages", "send_message");
    assert_eq!(facts.risk, RiskTier::High);
    assert!(facts.side_effects);
}

#[tokio::test]
async fn reload_hot_applies_explicit_approval_mode() {
    let pool = seed();
    let mut changed = manifest(
        "example-messages",
        "http://unused.test/mcp",
        vec![classification("send_message", RiskTier::Low, false)],
    );
    changed.approval_mode = ApprovalMode::PolicyOnly;

    let report = pool
        .reload_manifests(&BTreeMap::from([("example-messages".to_owned(), changed)]))
        .await;

    assert_eq!(
        report.classifications_updated,
        vec!["example-messages".to_owned()]
    );
    assert!(report.redialed.is_empty());
    assert!(report.redial_failed.is_empty());
    assert!(report.session_policy_updated.is_empty());
    assert_eq!(
        pool.manifests()[0].approval_mode,
        ApprovalMode::PolicyOnly,
        "approval authority must change in place without disrupting the upstream connection",
    );
}

#[tokio::test]
async fn reload_hot_applies_setup_retry_policy_without_a_redial() {
    let pool = seed();
    let mut changed = manifest(
        "example-messages",
        "http://unused.test/mcp",
        vec![classification("send_message", RiskTier::Low, false)],
    );
    changed.session = Some(SessionConfig {
        retry_on_setup_failure: Some(false),
        ..Default::default()
    });

    let report = pool
        .reload_manifests(&BTreeMap::from([("example-messages".to_owned(), changed)]))
        .await;

    assert!(report.redialed.is_empty());
    assert!(report.redial_failed.is_empty());
    assert_eq!(
        report.session_policy_updated,
        vec!["example-messages".to_owned()]
    );
    assert!(!report.is_noop());
    assert_eq!(
        pool.manifests()[0]
            .session
            .as_ref()
            .and_then(|session| session.retry_on_setup_failure),
        Some(false),
        "request-path retry policy must change without replacing healthy sessions",
    );
}

#[tokio::test]
async fn reload_applies_resource_routing_and_risk_without_a_redial() {
    let pool = seed();
    assert!(pool.resource_claims("example-messages").is_empty());

    let mut example_messages = manifest(
        "example-messages",
        "http://unused.test/mcp",
        vec![classification("send_message", RiskTier::Low, false)],
    );
    example_messages.resources = vec![ResourceClassification {
        uri_prefix: "example-messages://attachment/".to_owned(),
        risk: RiskTier::High,
    }];
    let fresh = BTreeMap::from([("example-messages".to_owned(), example_messages)]);

    let report = pool.reload_manifests(&fresh).await;

    assert_eq!(
        report.classifications_updated,
        vec!["example-messages".to_owned()]
    );
    assert!(report.redialed.is_empty());
    assert!(report.redial_failed.is_empty());
    assert_eq!(
        pool.resource_claims("example-messages"),
        vec![waygate_mcp::catalog::ResourceClaim {
            uri_prefix: "example-messages://attachment/".to_owned(),
            risk: RiskTier::High,
        }],
        "a resources-only reload must immediately replace the live routing table",
    );
}

#[tokio::test]
async fn resource_reload_invalidates_an_earlier_read_admission() {
    let pool = seed();
    let admitted = ResourceReadAdmission {
        generation: pool.resource_routing_snapshot().await.generation,
        server: "example-messages".into(),
        claim: None,
    };

    let mut example_messages = manifest(
        "example-messages",
        "http://unused.test/mcp",
        vec![classification("send_message", RiskTier::Low, false)],
    );
    example_messages.resources = vec![ResourceClassification {
        uri_prefix: "example-messages://attachment/".to_owned(),
        risk: RiskTier::High,
    }];
    pool.reload_manifests(&BTreeMap::from([(
        "example-messages".to_owned(),
        example_messages,
    )]))
    .await;

    let error = pool
        .read_resource_admitted(
            "example-messages",
            ReadResourceRequestParams::new("example-messages://attachment/a"),
            None,
            &admitted,
        )
        .await
        .expect_err("a stale routing generation must be refused before dispatch");
    assert!(
        matches!(
            error,
            waygate_mcp::catalog::AdmittedResourceReadError::RoutingChanged
        ),
        "a stale admission must retain local routing-refusal provenance",
    );
}

#[tokio::test]
async fn resource_eligibility_reload_invalidates_an_earlier_read_admission() {
    let alpha = manifest("alpha", "http://unused.test/alpha", vec![]);
    let mut gated = manifest("gated", "http://unused.test/gated", vec![]);
    gated.tier_c_peer = Some(uuid::Uuid::from_u128(0x967));
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([
        ("alpha".to_owned(), alpha.clone()),
        ("gated".to_owned(), gated),
    ]));
    let old_generation = pool.resource_routing_snapshot().await.generation;
    let admitted = ResourceReadAdmission {
        generation: old_generation,
        server: "alpha".into(),
        claim: None,
    };

    let newly_eligible = manifest("gated", "http://unused.test/gated", vec![]);
    let report = pool
        .reload_manifests(&BTreeMap::from([
            ("alpha".to_owned(), alpha),
            ("gated".to_owned(), newly_eligible),
        ]))
        .await;

    assert_eq!(report.identity_updated, vec!["gated".to_owned()]);
    assert_eq!(
        pool.resource_routing_snapshot().await.generation,
        old_generation + 1,
        "a newly eligible legacy server can change ambiguity and must stale old admissions",
    );
    let error = pool
        .read_resource_admitted(
            "alpha",
            ReadResourceRequestParams::new("shared://resource/a"),
            None,
            &admitted,
        )
        .await
        .expect_err("the old owner admission must be refused before dispatch");
    assert!(matches!(
        error,
        waygate_mcp::catalog::AdmittedResourceReadError::RoutingChanged
    ));
}

#[tokio::test]
async fn moving_a_resource_prefix_is_one_fleet_routing_transition() {
    let prefix = "example-messages://attachment/";
    let mut old_owner = manifest("alpha", "http://unused.test/alpha", vec![]);
    old_owner.resources = vec![ResourceClassification {
        uri_prefix: prefix.to_owned(),
        risk: RiskTier::High,
    }];
    let other = manifest("omega", "http://unused.test/omega", vec![]);
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([
        ("alpha".to_owned(), old_owner),
        ("omega".to_owned(), other),
    ]));
    let old_generation = pool.resource_routing_snapshot().await.generation;

    let alpha = manifest("alpha", "http://unused.test/alpha", vec![]);
    let mut omega = manifest("omega", "http://unused.test/omega", vec![]);
    omega.resources = vec![ResourceClassification {
        uri_prefix: prefix.to_owned(),
        risk: RiskTier::High,
    }];
    pool.reload_manifests(&BTreeMap::from([
        ("alpha".to_owned(), alpha),
        ("omega".to_owned(), omega),
    ]))
    .await;

    let activated = pool.resource_routing_snapshot().await;
    assert_eq!(
        activated.generation,
        old_generation + 1,
        "one manifest set must activate as one fleet routing generation",
    );
    assert!(pool.resource_claims("alpha").is_empty());
    assert_eq!(
        pool.resource_claims("omega"),
        vec![waygate_mcp::catalog::ResourceClaim {
            uri_prefix: prefix.to_owned(),
            risk: RiskTier::High,
        }],
    );
}

#[tokio::test]
async fn shape_coupled_owner_move_refuses_the_complete_manifest_set() {
    let prefix = "example-messages://attachment/";
    let alpha = manifest("alpha", "http://unused.test/alpha", vec![]);
    let mut omega = manifest("omega", "http://unused.test/omega", vec![]);
    omega.resources = vec![ResourceClassification {
        uri_prefix: prefix.to_owned(),
        risk: RiskTier::High,
    }];
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([
        ("alpha".to_owned(), alpha),
        ("omega".to_owned(), omega),
    ]));
    let old_generation = pool.resource_routing_snapshot().await.generation;

    let mut new_alpha = manifest("alpha", "http://unused.test/alpha", vec![]);
    new_alpha.resources = vec![ResourceClassification {
        uri_prefix: prefix.to_owned(),
        risk: RiskTier::High,
    }];
    // Moving the claim off omega is coupled to a backend that cannot dial.
    let new_omega = manifest("omega", FAIL_URL, vec![]);
    let report = reload_timed(
        &pool,
        &BTreeMap::from([
            ("alpha".to_owned(), new_alpha),
            ("omega".to_owned(), new_omega),
        ]),
    )
    .await;

    assert_eq!(
        report.resource_shape_restart_required,
        vec!["omega".to_owned()],
    );
    assert!(
        report.redial_failed.is_empty(),
        "the refused set never dialed"
    );
    assert!(pool.resource_claims("alpha").is_empty());
    assert_eq!(
        pool.resource_claims("omega"),
        vec![waygate_mcp::catalog::ResourceClaim {
            uri_prefix: prefix.to_owned(),
            risk: RiskTier::High,
        }],
        "a failed owner move must expose the complete old set, never both owners",
    );
    assert_eq!(
        pool.resource_routing_snapshot().await.generation,
        old_generation,
        "a set refused before mutation does not advance the routing generation",
    );
    let stored = pool
        .manifests()
        .into_iter()
        .find(|manifest| manifest.name == "omega")
        .expect("omega remains present");
    assert_eq!(stored.url.as_deref(), Some("http://unused.test/omega"));
}

#[tokio::test]
async fn reload_reports_added_and_removed_entries() {
    // New topology drops "example-messages" and introduces "example-observability" — both applied HOT
    // (no restart). `reload_timed` bounds the new entry's fast-failing dial.
    let pool = seed();
    let epoch = pool.tool_catalog_epoch();
    let mut fresh = BTreeMap::new();
    fresh.insert(
        "example-observability".into(),
        manifest(
            "example-observability",
            "http://unused.test/example-observability",
            vec![],
        ),
    );
    let report = reload_timed(&pool, &fresh).await;

    assert_eq!(report.added, vec!["example-observability".to_string()]);
    assert_eq!(report.removed, vec!["example-messages".to_string()]);
    // Only topology changes — no in-place updates to report.
    assert!(report.classifications_updated.is_empty());
    assert!(!report.is_noop());
    // Hot, not restart-required: the live registry actually swapped to exactly
    // the fresh set — "example-observability" is now addressable and "example-messages" is gone.
    assert!(!report.requires_restart());
    let names: Vec<String> = pool.manifests().into_iter().map(|m| m.name).collect();
    assert_eq!(names, vec!["example-observability".to_string()]);
    assert!(pool.breaker_state("example-observability").is_some());
    assert!(pool.breaker_state("example-messages").is_none());
    assert_eq!(epoch.current(), 1, "one topology commit emits one change");

    let unchanged = reload_timed(&pool, &fresh).await;
    assert!(unchanged.is_noop());
    assert_eq!(epoch.current(), 1, "a topology no-op must not notify");
}

#[tokio::test]
async fn undeclared_topology_changes_advance_legacy_resource_routing_generation() {
    let pool = seed();
    let old_generation = pool.resource_routing_snapshot().await.generation;
    let mut fresh: BTreeMap<String, _> = pool
        .manifests()
        .into_iter()
        .map(|manifest| (manifest.name.clone(), manifest))
        .collect();
    fresh.insert(
        "legacy-resource-server".to_owned(),
        manifest(
            "legacy-resource-server",
            "http://unused.test/legacy",
            vec![],
        ),
    );

    let added = reload_timed(&pool, &fresh).await;
    assert_eq!(added.added, vec!["legacy-resource-server".to_owned()]);
    assert_eq!(
        pool.resource_routing_snapshot().await.generation,
        old_generation + 1,
        "an undeclared add can change enumeration ownership and must stale old admissions",
    );

    fresh.remove("legacy-resource-server");
    let removed = reload_timed(&pool, &fresh).await;
    assert_eq!(removed.removed, vec!["legacy-resource-server".to_owned()]);
    assert_eq!(
        pool.resource_routing_snapshot().await.generation,
        old_generation + 2,
        "an undeclared removal can change ambiguity and must stale old admissions",
    );
}

/// A resource-ownership edit coupled to a url change is refused before any
/// mutation. The resource claims and serving backend therefore remain paired,
/// and the operator gets an explicit restart-required outcome.
#[tokio::test]
async fn reload_redials_url_change_and_keeps_old_url_when_dial_fails() {
    let mut old_manifest = manifest(
        "example-messages",
        "http://unused.test/mcp",
        vec![classification("send_message", RiskTier::Low, false)],
    );
    old_manifest.resources = vec![ResourceClassification {
        uri_prefix: "example-messages://old/".to_owned(),
        risk: RiskTier::Low,
    }];
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
        "example-messages".to_owned(),
        old_manifest,
    )]));
    let mut fresh = BTreeMap::new();
    let mut new_manifest = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    new_manifest.resources = vec![ResourceClassification {
        uri_prefix: "example-messages://new/".to_owned(),
        risk: RiskTier::High,
    }];
    fresh.insert("example-messages".into(), new_manifest);
    let report = reload_timed(&pool, &fresh).await;

    assert_eq!(
        report.resource_shape_restart_required,
        vec!["example-messages".to_string()],
        "a resource-and-shape edit is refused as one manifest set",
    );
    assert!(
        report.redial_failed.is_empty(),
        "the refused set never dialed"
    );
    assert!(report.classifications_updated.is_empty());

    // Safety: every new-shape dial failed, so the stored url must remain the
    // boot-time value — never advanced to a target we couldn't reach.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "example-messages")
        .expect("example-messages still present");
    assert_eq!(
        stored.url.as_deref(),
        Some("http://unused.test/mcp"),
        "a failed re-dial must not advance the stored url",
    );
    assert_eq!(
        pool.resource_claims("example-messages"),
        vec![waygate_mcp::catalog::ResourceClaim {
            uri_prefix: "example-messages://old/".to_owned(),
            risk: RiskTier::Low,
        }],
        "a failed re-dial must not route new claims to the old backend",
    );
}

/// An `auth.bearer_env` edit is connection-shape (the bearer is baked into
/// the rmcp transport at dial time), so with a stable slot count it is
/// re-dialed live rather than flagged restart-required. The security
/// invariant: when the live re-dial fails on every lane, the stored auth
/// must NOT be advanced — a failed re-dial never lies about which bearer
/// the live client is sending. Seeded and reloaded at the same refused url so
/// the only changed field is `auth`.
#[tokio::test]
async fn reload_redials_auth_change_and_keeps_old_bearer_when_dial_fails() {
    let mut map = BTreeMap::new();
    map.insert(
        "example-messages".into(),
        manifest(
            "example-messages",
            FAIL_URL,
            vec![classification("send_message", RiskTier::Low, false)],
        ),
    );
    let pool = UpstreamPool::from_manifests_disconnected(map);

    let mut fresh = BTreeMap::new();
    let mut new_manifest = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    new_manifest.auth = Some(UpstreamAuth {
        bearer_env: Some("EXAMPLE_MESSAGES_BEARER_NEW".into()),
        ..Default::default()
    });
    fresh.insert("example-messages".into(), new_manifest);

    let report = reload_timed(&pool, &fresh).await;

    assert_eq!(
        report.redial_failed,
        vec!["example-messages".to_string()],
        "an auth change is re-dialed live; an unreachable target lands in \
         redial_failed (restart-required)",
    );
    assert!(report.classifications_updated.is_empty());

    // The failed re-dial must not advance the stored auth: mirroring it would
    // lie about which bearer the live rmcp client is actually sending.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "example-messages")
        .expect("example-messages still present");
    assert!(
        stored.auth.is_none(),
        "a failed re-dial must not advance the stored auth/bearer",
    );
}

#[tokio::test]
async fn reload_redials_catalog_probe_group_changes() {
    let mut seed_manifest = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    seed_manifest.auth = Some(UpstreamAuth::default());
    let mut seed = BTreeMap::new();
    seed.insert("example-messages".into(), seed_manifest);
    let pool = UpstreamPool::from_manifests_disconnected(seed);

    let mut changed = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    changed.auth = Some(UpstreamAuth {
        catalog_probe_groups: vec!["service-operators".into()],
        ..Default::default()
    });
    let mut fresh = BTreeMap::new();
    fresh.insert("example-messages".into(), changed);

    let report = reload_timed(&pool, &fresh).await;
    assert_eq!(report.redial_failed, vec!["example-messages".to_string()]);

    let stored = pool
        .manifests()
        .into_iter()
        .find(|manifest| manifest.name == "example-messages")
        .expect("example-messages still present");
    assert!(
        stored.auth.unwrap().catalog_probe_groups.is_empty(),
        "a failed re-dial must not claim the new catalog identity is active",
    );
}

/// A `session.concurrency` edit
/// is connection-shape and RESIZES the slot pool (the slot Vec is sized once in
/// `dial_slots`), so it can't be re-dialed in place — it is REBUILT live: a fresh
/// entry with the new slot count is dialed and swapped in. On this disconnected
/// fixture the rebuild dials the new (refused) shape and fails on every lane, so
/// the OLD entry is kept whole and the entry lands in `redial_failed`
/// (restart-required) — NOT silently a no-op. The security invariant: a failed
/// rebuild must not mutate the stored concurrency, which would imply the new pool
/// size took effect while the live slot Vec is unchanged.
#[tokio::test]
async fn reload_rebuilds_session_concurrency_change_and_keeps_old_when_dial_fails() {
    let mut map = BTreeMap::new();
    let mut seed_m = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    seed_m.session = Some(SessionConfig {
        concurrency: Some(2),
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    map.insert("example-messages".into(), seed_m);
    let pool = UpstreamPool::from_manifests_disconnected(map);

    // Only change: concurrency 2 → 1, which resizes the slot pool (count-unstable).
    let mut new_manifest = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    new_manifest.session = Some(SessionConfig {
        concurrency: Some(1),
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    let mut fresh = BTreeMap::new();
    fresh.insert("example-messages".into(), new_manifest);

    let report = reload_timed(&pool, &fresh).await;

    assert_eq!(
        report.redial_failed,
        vec!["example-messages".to_string()],
        "a session.concurrency resize is rebuilt live; an unreachable target \
         lands in redial_failed (restart-required) — never a silent no-op",
    );
    assert!(report.requires_restart());
    assert!(report.classifications_updated.is_empty());

    // The failed rebuild kept the OLD entry: the stored concurrency must remain
    // the boot-time value, never advanced to a pool size that never dialed.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "example-messages")
        .expect("example-messages still present");
    assert_eq!(
        stored.session.as_ref().and_then(|s| s.concurrency),
        Some(2),
        "a failed rebuild must not advance the stored concurrency",
    );
}

/// A slot-resize whose rebuild FAILS keeps the old entry, but
/// a co-resident tool-classification change must STILL advance on that kept entry.
/// The SIGHUP/doorbell handler reconciles the governed catalog from the fresh
/// manifests on every non-noop reload, and `resolve_invocation_tool` reads the catalog
/// (with the manifest as fallback) as authoritative for authz — so leaving the
/// entry on the OLD classification while the catalog advances to the new
/// (possibly downgraded) one would desync authz from what the upstream serves.
/// Classification is a hot field uncoupled from the connection shape, so it lands
/// regardless of whether the shape rebuild succeeds.
#[tokio::test]
async fn failed_resize_rebuild_still_advances_classification() {
    let mut map = BTreeMap::new();
    let mut seed_m = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::High, true)],
    );
    seed_m.session = Some(SessionConfig {
        concurrency: Some(2),
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    map.insert("example-messages".into(), seed_m);
    let pool = UpstreamPool::from_manifests_disconnected(map);

    // Reload: resize concurrency 2 → 1 (a rebuild that fails at FAIL_URL) AND
    // downgrade the classification (High + side_effects → Low, no side_effects).
    let mut new_manifest = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    new_manifest.session = Some(SessionConfig {
        concurrency: Some(1),
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    let mut fresh = BTreeMap::new();
    fresh.insert("example-messages".into(), new_manifest);

    let report = reload_timed(&pool, &fresh).await;

    // The SHAPE rebuild failed and kept the old entry...
    assert_eq!(report.redial_failed, vec!["example-messages".to_string()]);
    // ...but the co-resident classification STILL advanced on the kept entry.
    assert_eq!(
        report.classifications_updated,
        vec!["example-messages".to_string()],
        "a failed resize rebuild must still advance the co-resident classification \
         so the kept entry stays in sync with the catalog reconcile",
    );
    let facts = pool.tool_facts("example-messages", "send_message");
    assert_eq!(
        facts.risk,
        RiskTier::Low,
        "the classification downgrade must land on the kept entry's served facts",
    );
    assert!(
        !facts.side_effects,
        "the side_effects downgrade must land on the kept entry too",
    );
}

/// An `mtls:` edit
/// is connection-shape (the cert is baked into the `reqwest::Client` at dial
/// time), so with a stable slot count it is re-dialed live. The security
/// invariant: when the re-dial fails on every lane, the stored mtls
/// must NOT be advanced — a failed re-dial must never claim mTLS hardening took
/// effect while the live client is unchanged. Same refused url old and new so
/// the only changed field is `mtls`.
#[tokio::test]
async fn reload_redials_mtls_addition_and_keeps_old_client_when_dial_fails() {
    let mut map = BTreeMap::new();
    map.insert(
        "example-messages".into(),
        manifest(
            "example-messages",
            FAIL_URL,
            vec![classification("send_message", RiskTier::Low, false)],
        ),
    );
    let pool = UpstreamPool::from_manifests_disconnected(map);

    let mut fresh = BTreeMap::new();
    let mut new_manifest = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    new_manifest.mtls = Some(MtlsConfig {
        cert_path: Some(std::path::PathBuf::from(
            "/etc/gateway/example-messages.crt",
        )),
        key_path: Some(std::path::PathBuf::from(
            "/etc/gateway/example-messages.key",
        )),
        ca_path: None,
    });
    fresh.insert("example-messages".into(), new_manifest);

    let report = reload_timed(&pool, &fresh).await;

    assert_eq!(
        report.redial_failed,
        vec!["example-messages".to_string()],
        "an mtls addition is re-dialed live; an unreachable target lands in \
         redial_failed (restart-required)",
    );
    assert!(report.classifications_updated.is_empty());

    // The failed re-dial must not advance the stored mtls — otherwise the
    // operator believes mTLS hardening took effect while the live client never
    // changed.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "example-messages")
        .expect("example-messages still present");
    assert!(
        stored.mtls.is_none(),
        "a failed re-dial must not advance the stored mtls",
    );
}

/// Removing an existing `mtls:` block is likewise a same-slot-count shape
/// change → re-dialed live. On a failed re-dial the stored mtls must remain
/// PRESENT (not advanced to "removed"), so the gateway keeps presenting the
/// cert it is actually still using. Defense-in-depth on the add-mtls case.
#[tokio::test]
async fn reload_redials_mtls_removal_and_keeps_old_cert_when_dial_fails() {
    // Seed with mTLS already present so we can diff it away.
    let mut map = BTreeMap::new();
    let mut m = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    m.mtls = Some(MtlsConfig {
        cert_path: Some(std::path::PathBuf::from(
            "/etc/gateway/example-messages.crt",
        )),
        key_path: Some(std::path::PathBuf::from(
            "/etc/gateway/example-messages.key",
        )),
        ca_path: None,
    });
    map.insert("example-messages".into(), m);
    let pool = UpstreamPool::from_manifests_disconnected(map);

    // Reload with the mtls block stripped.
    let mut fresh = BTreeMap::new();
    fresh.insert(
        "example-messages".into(),
        manifest(
            "example-messages",
            FAIL_URL,
            vec![classification("send_message", RiskTier::Low, false)],
        ),
    );
    let report = reload_timed(&pool, &fresh).await;
    assert_eq!(
        report.redial_failed,
        vec!["example-messages".to_string()],
        "removing the mtls block is re-dialed live; an unreachable target lands \
         in redial_failed (restart-required)",
    );

    // The failed re-dial must not advance the stored mtls to "removed" — the
    // live client is still presenting the boot-time cert.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "example-messages")
        .expect("example-messages still present");
    assert!(
        stored.mtls.is_some(),
        "a failed re-dial must not advance the stored mtls to removed",
    );
}

/// Pins the security invariant from the scheduled + SIGHUP reconnect paths:
/// an Http→Stdio flip RESIZES the slot pool, so it is rebuilt
/// live (a fresh entry dialed with the new shape). On this disconnected fixture
/// the rebuild spawns `/bin/false`, which exits immediately, so every lane fails
/// → the OLD entry is kept whole → `redial_failed`. `reload_manifests` must NOT
/// mirror the new transport / url / command into the kept entry: its
/// `identity_cell` is allocated at boot from the boot-time transport, so leaving
/// a stale Stdio shape on a kept Http entry would mis-wire identity forwarding.
#[tokio::test]
async fn reload_does_not_mutate_transport_url_or_command() {
    let pool = seed();
    let mut fresh = BTreeMap::new();
    let mut new_manifest = manifest(
        "example-messages",
        "http://elsewhere.test/mcp", // url change
        vec![classification("send_message", RiskTier::Low, false)],
    );
    new_manifest.transport = Transport::Stdio;
    new_manifest.url = None;
    new_manifest.command = Some(vec!["/bin/false".into()]);
    fresh.insert("example-messages".into(), new_manifest);

    let report = reload_timed(&pool, &fresh).await;
    assert_eq!(
        report.redial_failed,
        vec!["example-messages".to_string()],
        "an Http→Stdio flip is rebuilt live; a command that exits immediately \
         fails on every lane, keeping the old entry → redial_failed",
    );

    // The failed rebuild kept the OLD entry: its transport / url / command must
    // be unchanged from boot.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "example-messages")
        .expect("example-messages still present");
    assert!(matches!(stored.transport, Transport::Http));
    assert_eq!(stored.url.as_deref(), Some("http://unused.test/mcp"));
    assert!(stored.command.is_none());
}

/// Classification edits at
/// SIGHUP must propagate to the published view, not just to `tool_facts`.
/// Adding a brand-new classification (the "promotion" case) and dropping
/// an existing one (the "demotion" case) both flip `classifications_updated`
/// in the report, so the SIGHUP handler logs the change. Verification of the
/// re-publish into `Connection.tools` and the search index requires a live
/// upstream (covered by the unit test on `partition_live_tools` and by
/// inspection of `reload_manifests`).
#[tokio::test]
async fn reload_flags_added_and_removed_classifications() {
    let pool = seed();

    // Promotion: add `receive_message` to the manifest. Demotion: drop
    // `send_message` from the manifest. Both must show up as a single
    // `classifications_updated` entry for "example-messages".
    let mut fresh = BTreeMap::new();
    fresh.insert(
        "example-messages".into(),
        manifest(
            "example-messages",
            "http://unused.test/mcp",
            vec![classification("receive_message", RiskTier::Low, false)],
        ),
    );
    let report = pool.reload_manifests(&fresh).await;

    assert_eq!(
        report.classifications_updated,
        vec!["example-messages".to_string()]
    );
    assert!(report.added.is_empty());
    assert!(report.removed.is_empty());
}

#[tokio::test]
async fn noop_reload_reports_nothing() {
    let pool = seed();
    let mut fresh = BTreeMap::new();
    fresh.insert(
        "example-messages".into(),
        manifest(
            "example-messages",
            "http://unused.test/mcp",
            vec![classification("send_message", RiskTier::Low, false)],
        ),
    );
    let report = pool.reload_manifests(&fresh).await;
    assert!(report.is_noop(), "unchanged reload should report nothing");
}

/// A reload that moves an upstream from a static
/// `auth.bearer_env` to `tier_c_peer` (mutually exclusive per the loader)
/// changes the auth SHAPE *and* the coupled identity field together. If the
/// live re-dial fails, NEITHER may land — otherwise the stored manifest would
/// hold the new `tier_c_peer` beside the old, un-reverted bearer (an
/// exclusivity-violating hybrid), and the surviving old connection would serve
/// the baked static bearer AND new per-call Tier-C Authorization. A failed
/// re-dial must preserve the OLD auth posture intact, with neither field
/// applied nor reported.
#[tokio::test]
async fn failed_redial_moving_bearer_to_tier_c_keeps_old_auth_no_hybrid() {
    let mut map = BTreeMap::new();
    let mut seed = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    seed.auth = Some(UpstreamAuth {
        bearer_env: Some("OLD_BEARER".into()),
        ..Default::default()
    });
    map.insert("example-messages".into(), seed);
    let pool = UpstreamPool::from_manifests_disconnected(map);

    // Move to tier_c_peer + drop bearer_env, at a refused url ⇒ the re-dial
    // fails on every lane.
    let mut new_manifest = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    new_manifest.auth = None;
    new_manifest.tier_c_peer = Some(uuid::Uuid::from_u128(0x315));
    let mut fresh = BTreeMap::new();
    fresh.insert("example-messages".into(), new_manifest);

    let report = reload_timed(&pool, &fresh).await;

    assert_eq!(report.redial_failed, vec!["example-messages".to_string()]);
    // No hybrid: the failed re-dial kept the OLD bearer and did NOT apply the
    // coupled new tier_c_peer.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "example-messages")
        .expect("example-messages still present");
    assert!(
        stored.auth.is_some(),
        "a failed re-dial must keep the old bearer",
    );
    assert!(
        stored.tier_c_peer.is_none(),
        "a failed re-dial must NOT apply the coupled new tier_c_peer — no \
         exclusivity-violating hybrid",
    );
    assert!(
        report.identity_updated.is_empty(),
        "identity must not be reported applied on a failed re-dial",
    );
}

/// A pure identity-chaining change with NO connection-shape change is still
/// hot-applied in place (the runtime-tunable path) — gating on
/// `!transport_changed` must not regress this.
#[tokio::test]
async fn pure_identity_change_applies_in_place() {
    let pool = seed(); // example-messages @ http://unused.test/mcp, auth None, identity None
    let mut new_manifest = manifest(
        "example-messages",
        "http://unused.test/mcp", // unchanged shape
        vec![classification("send_message", RiskTier::Low, false)],
    );
    new_manifest.tier_c_peer = Some(uuid::Uuid::from_u128(0x315));
    let mut fresh = BTreeMap::new();
    fresh.insert("example-messages".into(), new_manifest);

    let report = pool.reload_manifests(&fresh).await;

    assert_eq!(
        report.identity_updated,
        vec!["example-messages".to_string()]
    );
    assert!(report.redialed.is_empty());
    assert!(report.redial_failed.is_empty());
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "example-messages")
        .expect("example-messages still present");
    assert_eq!(stored.tier_c_peer, Some(uuid::Uuid::from_u128(0x315)));
}

/// A reload that RESIZES the slot pool (a
/// `session.concurrency` change, count-unstable) while ALSO moving from
/// `auth.bearer_env` to `tier_c_peer` is rebuilt live. The rebuild's fresh entry
/// carries the new auth shape (no bearer) AND the new tier_c_peer TOGETHER —
/// never a hybrid. When the rebuild's dial fails on every lane (refused target),
/// the OLD entry is kept WHOLE: the old bearer stays and the coupled
/// tier_c_peer is NOT applied, preserving the old Authorization posture intact
/// (no exclusivity-violating bearer+tier_c hybrid on a surviving connection).
#[tokio::test]
async fn restart_required_shape_change_does_not_apply_coupled_identity() {
    let mut map = BTreeMap::new();
    let mut seed_m = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    seed_m.auth = Some(UpstreamAuth {
        bearer_env: Some("OLD_BEARER".into()),
        ..Default::default()
    });
    seed_m.session = Some(SessionConfig {
        concurrency: Some(2),
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    map.insert("example-messages".into(), seed_m);
    let pool = UpstreamPool::from_manifests_disconnected(map);

    // Move bearer→tier_c AND resize concurrency (2→3, count-unstable ⇒ rebuilt,
    // NOT in-place redial).
    let mut new_manifest = manifest(
        "example-messages",
        FAIL_URL,
        vec![classification("send_message", RiskTier::Low, false)],
    );
    new_manifest.auth = None;
    new_manifest.tier_c_peer = Some(uuid::Uuid::from_u128(0x315));
    new_manifest.session = Some(SessionConfig {
        concurrency: Some(3),
        isolation: None,
        scope: None,
        retry_on_setup_failure: None,
    });
    let mut fresh = BTreeMap::new();
    fresh.insert("example-messages".into(), new_manifest);

    let report = reload_timed(&pool, &fresh).await;

    assert_eq!(
        report.redial_failed,
        vec!["example-messages".to_string()],
        "a session.concurrency resize is rebuilt live; an unreachable target \
         lands in redial_failed (restart-required)",
    );
    assert!(report.requires_restart());
    assert!(report.redialed.is_empty());
    assert!(
        report.identity_updated.is_empty(),
        "the coupled identity must NOT be reported applied on a failed rebuild",
    );
    // No hybrid: the restart-required reload kept the OLD bearer AND did NOT
    // apply the coupled new tier_c_peer.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "example-messages")
        .expect("example-messages still present");
    assert!(
        stored.auth.is_some(),
        "old bearer must be preserved until restart",
    );
    assert!(
        stored.tier_c_peer.is_none(),
        "coupled tier_c_peer must NOT be applied while the old bearer stays — no hybrid",
    );
}
