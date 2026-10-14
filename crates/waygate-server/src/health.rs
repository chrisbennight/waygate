//! `/healthz` is a liveness probe (the process is running).
//! `/readyz` is a readiness probe — returns 503 if a gateway-wide dependency
//! is unhealthy or a non-empty upstream set has no usable member. Individual
//! upstream outages stay visible as degraded without taking healthy routes out
//! of rotation.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde_json::json;

use waygate_upstream::{UpstreamHealth, UpstreamRuntimeState};

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_placeholder))
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

/// Readyz composes several per-subsystem checks. The response body always
/// includes the full check set (even on 200) so an operator hitting the
/// endpoint can see everything that's healthy at a glance, not just the
/// breakage.
async fn readyz(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let policies = check_policies(&s);
    let upstreams = summarize_upstreams(&s.upstreams.health_snapshot().await);
    let audit = check_audit(&s);
    let skills = check_skills(&s);

    let all_ok = policies.ok && upstreams.ok && audit.ok && skills.ok;
    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = json!({
        "status": if all_ok { "ready" } else { "unready" },
        "checks": {
            "policies": policies.body,
            "upstreams": upstreams.body,
            "audit": audit.body,
            "skills": skills.body,
        }
    });
    (status, Json(body))
}

struct Check {
    ok: bool,
    body: serde_json::Value,
}

fn check_policies(s: &AppState) -> Check {
    match s.cedar.as_ref() {
        None => Check {
            // Auth is disabled; nothing to check. Keep it green so the
            // disabled-mode dev loop doesn't trip readyz.
            ok: true,
            body: json!({ "status": "skipped", "reason": "auth disabled" }),
        },
        Some(engine) => {
            let count = engine.list_policies().len();
            // Zero policies + enforce mode = deny-all, which is technically
            // still "ready" (the gateway will refuse every call) but a strong
            // misconfiguration signal — flag it unready so operators notice.
            Check {
                ok: count > 0,
                body: json!({
                    "status": if count > 0 { "ok" } else { "no_policies_loaded" },
                    "count": count,
                }),
            }
        }
    }
}

fn summarize_upstreams(health: &[UpstreamHealth]) -> Check {
    if health.is_empty() {
        return Check {
            // No upstreams configured → gateway is trivially ready from an
            // upstream standpoint. This is the bootstrap / integration-test
            // case; production with zero upstreams is meaningless but not
            // a readyz failure.
            ok: true,
            body: json!({ "status": "skipped", "reason": "no upstreams configured" }),
        };
    }
    let total = health.len();
    let connected = health.iter().filter(|h| h.connected).count();
    let open_breakers: Vec<&str> = health
        .iter()
        .filter(|h| h.breaker == waygate_upstream::BreakerState::Open)
        .map(|h| h.name.as_str())
        .collect();
    let available = health
        .iter()
        .filter(|h| h.runtime_state != UpstreamRuntimeState::Disconnected)
        .count();

    // Each upstream is independently routable. Keep the gateway in rotation
    // while at least one can serve traffic; the detailed degraded state still
    // drives operator recovery for unavailable peers.
    let ok = available > 0;
    let degraded = health
        .iter()
        .any(|h| h.runtime_state != UpstreamRuntimeState::Connected);
    Check {
        ok,
        body: json!({
            "status": if degraded { "degraded" } else { "ok" },
            "total": total,
            "connected": connected,
            "open_breakers": open_breakers,
            "detail": health,
        }),
    }
}

fn check_audit(s: &AppState) -> Check {
    // Audit readiness is coarse: either the sink was built (configured
    // correctly at startup) or it wasn't. A per-request DB ping would be
    // better but requires plumbing through a live sqlx handle to readyz;
    // defer until we see sqlx connection churn in production.
    Check {
        ok: true,
        body: json!({
            "status": if s.audit_enabled { "ok" } else { "null_sink" },
        }),
    }
}

fn check_skills(s: &AppState) -> Check {
    match (&s.config.skills, &s.skills) {
        (None, None) => Check {
            ok: true,
            body: json!({ "status": "skipped", "reason": "no skill source configured" }),
        },
        (Some(_), Some(catalog)) => {
            let health = catalog.status();
            match health.snapshot {
                Some(snapshot) => Check {
                    ok: true,
                    body: json!({
                        "status": if health.latest_refresh_failed || health.resource_read_failed {
                            "degraded"
                        } else {
                            "ok"
                        },
                        "source_digest": snapshot.source().resolved_digest.clone(),
                        "source_tree_digest": snapshot.source().resolved_tree_digest.clone(),
                        "skill_count": snapshot.skills().len(),
                    }),
                },
                None => Check {
                    ok: true,
                    body: json!({ "status": "source_unavailable", "skill_count": 0 }),
                },
            }
        }
        _ => Check {
            ok: false,
            body: json!({ "status": "configuration_mismatch" }),
        },
    }
}

async fn metrics_placeholder(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let health = s.upstreams.health_snapshot().await;
    for upstream in &health {
        waygate_telemetry::metrics::set_upstream_runtime_state(
            &upstream.name,
            Some(upstream.runtime_state.as_str()),
        );
    }
    waygate_telemetry::metrics::reconcile_upstream_runtime_states(
        health.iter().map(|upstream| upstream.name.as_str()),
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        waygate_telemetry::gather_text(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{Map, Value};
    use tower::util::ServiceExt;
    use waygate_authz::{CedarEngine, ReloadableCedar};
    use waygate_mcp::protocol::RiskTier;
    use waygate_skills::{
        verify_catalog_snapshot, CatalogManifest, CatalogSkill, CatalogSourceIdentity,
        InMemorySkillResourceLoader, ReloadableSkillCatalog, SkillCatalogSnapshot,
        SkillCatalogSource, SkillResourceDescriptor, SkillSourceError, CATALOG_SCHEMA_VERSION,
    };
    use waygate_upstream::{ToolClassification, Transport, UpstreamManifest, UpstreamPool};

    use super::*;
    use crate::config::{
        AuditMode, AuthMode, CodeModeCapacityLimits, CodeModeResultStorage, Config,
        DeploymentProfile,
    };
    use crate::database::DatabasePoolConfig;
    use crate::skills_git::{SkillsGitConfig, DEFAULT_GIT_SNAPSHOT_TIMEOUT};

    const ADMIN_ONLY_POLICY: &str = r#"
        permit(principal, action, resource)
        when { principal has groups && principal.groups.contains("admins") };
    "#;

    struct StaticSkillSource(SkillCatalogSnapshot);

    #[async_trait]
    impl SkillCatalogSource for StaticSkillSource {
        async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
            Ok(self.0.clone())
        }
    }

    fn skill_snapshot_with_loader(
        loader_resources: BTreeMap<String, Vec<u8>>,
    ) -> SkillCatalogSnapshot {
        let skill_md = b"---\nname: demo\ndescription: Demo skill\n---\n# Demo\n";
        let uri = "skill://homelab/demo/SKILL.md".to_owned();
        let mut frontmatter = Map::new();
        frontmatter.insert("name".into(), Value::String("demo".into()));
        frontmatter.insert("description".into(), Value::String("Demo skill".into()));
        verify_catalog_snapshot(
            CatalogSourceIdentity {
                origin: "git+https://git.example/api/v1/owner/skills".into(),
                reference: "owner/skills@main".into(),
                resolved_digest: format!("git-sha1:{}", "a".repeat(40)),
                resolved_tree_digest: format!("git-sha1:{}", "b".repeat(40)),
            },
            CatalogManifest {
                schema_version: CATALOG_SCHEMA_VERSION,
                skills: vec![CatalogSkill {
                    uri: uri.clone(),
                    frontmatter,
                    resources: vec![SkillResourceDescriptor {
                        uri: uri.clone(),
                        source_path: "skills/demo/SKILL.md".into(),
                        source_object: format!("git-sha1:{}", "b".repeat(40)),
                        size: skill_md.len() as u64,
                        media_type: "text/markdown".into(),
                    }],
                }],
            },
            BTreeMap::from([(uri, skill_md.to_vec())]),
            Arc::new(InMemorySkillResourceLoader::new(loader_resources)),
        )
        .expect("valid skill fixture")
    }

    fn skill_snapshot() -> SkillCatalogSnapshot {
        let uri = "skill://homelab/demo/SKILL.md".to_owned();
        let bytes = b"---\nname: demo\ndescription: Demo skill\n---\n# Demo\n".to_vec();
        skill_snapshot_with_loader(BTreeMap::from([(uri, bytes)]))
    }

    fn test_config() -> Config {
        Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            public_url: "http://127.0.0.1:0".into(),
            authentik_issuer: None,
            audience: "test".into(),
            auth_mode: AuthMode::Disabled,
            otel_endpoint: None,
            servers_dir: PathBuf::from("/dev/null"),
            skills: None,
            policies_dir: PathBuf::from("/dev/null"),
            policy_editing: true,
            database_url: None,
            database_pools: DatabasePoolConfig::default(),
            identity: None,
            introspection: None,
            dashboard: None,
            token_exchange: None,
            as_server: None,
            accept_upstream_tokens: false,
            authentik_additional_issuers: Vec::new(),
            mcp_allowed_hosts: None,
            mcp_allowed_origins: waygate_mcp::origin::OriginPolicy::from_config(
                "https://gateway.example",
                None,
            )
            .unwrap(),
            codemode_result_storage: CodeModeResultStorage::Disabled,
            codemode_capacity: CodeModeCapacityLimits::default(),
            codemode_limits: crate::codemode_limits::CodeModeLimits::default(),
            codemode_only_tools_clients: Vec::new(),
            root_composition_clients: Vec::new(),
            upstream_reconnect_base: std::time::Duration::from_secs(60),
            upstream_reconnect_ceiling: std::time::Duration::from_secs(900),
            drain_timeout: std::time::Duration::from_secs(20),
            reencrypt_interval: None,
            peer_jwks_refresh_interval: std::time::Duration::from_secs(600),
            session_keepalive: Some(std::time::Duration::from_secs(3600)),
            tools_list_cache_ttl: None,
            sse_keepalive: Some(std::time::Duration::from_secs(120)),
            mcp_ping_interval: Some(std::time::Duration::from_secs(120)),
            upstream_call_timeout: Some(std::time::Duration::from_secs(300)),
            resource_response_max_bytes: waygate_mcp::DEFAULT_RESOURCE_RESPONSE_MAX_BYTES,
            file_transfer: crate::file_transfer_config::FileTransferConfig {
                storage_dir: None,
                retention: crate::file_transfer_config::FileRetention::DEFAULT,
                max_bytes: None,
                concurrency: 8,
                inline_response_threshold_bytes: None,
            },
            mrtr_state_key: None,
            upstream_task_retention_seconds: 129600,
            api_keys: None,
            deployment_profile: DeploymentProfile::Dev,
            audit_mode: AuditMode::BestEffort,
            grant_sweep_interval: None,
            grant_retention: std::time::Duration::from_secs(7 * 24 * 3600),
            hitl_ws_buffer: 256,
            evidence_drain_interval: None,
            retention_sweep_interval: None,
            audit_rollup_interval: None,
            evidence_webhook_url: None,
            hitl_webhook_url: None,
            trace_url_template: None,
            evidence_ocsf_url: None,
            evidence_ocsf_aos_trace: false,
            evidence_syslog_target: None,
            evidence_syslog_hostname: "mcp-gateway".to_owned(),
            evidence_syslog_facility: 16,
            evidence_syslog_pen: 32_473,
            evidence_bundle_signing_key_pem: None,
            evidence_bundle_signing_key_id: None,
            evidence_ecs_url: None,
            evidence_outbox_targets: Vec::new(),
        }
    }

    fn test_manifest(name: &str) -> UpstreamManifest {
        UpstreamManifest {
            classification_mode: Default::default(),
            approval_mode: Default::default(),
            inline_response_threshold_bytes: None,
            long_running_tools: Vec::new(),
            name: name.to_owned(),
            transport: Transport::Http,
            protocol: Default::default(),
            url: Some("http://unused.test/mcp".into()),
            command: None,
            tools: vec![ToolClassification::new("t", RiskTier::Low, false, false)],
            resources: Vec::new(),
            exchange: None,
            auth: None,
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            session: None,
        }
    }

    fn metrics_scrape_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    async fn fetch_readyz(state: Arc<AppState>) -> (StatusCode, serde_json::Value) {
        let app = router().with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).expect("readyz body must be JSON");
        (status, body)
    }

    #[tokio::test]
    async fn readyz_green_when_no_upstreams_and_auth_disabled() {
        // Dev loop: nothing configured, nothing to be unready about.
        let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new()));
        let state = Arc::new(AppState::new(test_config(), pool, None, None, false));
        let (status, body) = fetch_readyz(state).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
        assert_eq!(body["checks"]["policies"]["status"], "skipped");
        assert_eq!(body["checks"]["upstreams"]["status"], "skipped");
    }

    #[tokio::test]
    async fn readyz_red_when_policy_engine_is_empty() {
        // Enforce-mode with zero policies = deny-all. Not literally broken,
        // but a strong misconfig signal — readyz must flag it.
        let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new()));
        let empty_engine = CedarEngine::from_source("").expect("empty cedar source compiles");
        let cedar = Arc::new(ReloadableCedar::new(empty_engine));
        let state = Arc::new(AppState::new(test_config(), pool, Some(cedar), None, false));
        let (status, body) = fetch_readyz(state).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "unready");
        assert_eq!(body["checks"]["policies"]["status"], "no_policies_loaded");
        assert_eq!(body["checks"]["policies"]["count"], 0);
    }

    #[tokio::test]
    async fn readyz_stays_green_when_a_configured_skill_source_has_no_snapshot() {
        let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new()));
        let mut config = test_config();
        config.skills = Some(SkillsGitConfig {
            api_url: url::Url::parse("https://git.example/api/v1").unwrap(),
            repository: "owner/skills".into(),
            reference: "main".into(),
            expected_commit: None,
            expected_tree: None,
            source_id: "homelab".into(),
            roots: vec!["skills".into()],
            token_env: None,
            refresh_interval: None,
            snapshot_timeout: DEFAULT_GIT_SNAPSHOT_TIMEOUT,
        });
        let skills = Arc::new(ReloadableSkillCatalog::default());
        let state = Arc::new(AppState::new(config, pool, None, Some(skills), false));

        let (status, body) = fetch_readyz(state).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["checks"]["skills"]["status"], "source_unavailable");
    }

    #[tokio::test]
    async fn readyz_reports_degraded_while_serving_a_last_known_good_skill_snapshot() {
        let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new()));
        let mut config = test_config();
        config.skills = Some(SkillsGitConfig {
            api_url: url::Url::parse("https://git.example/api/v1").unwrap(),
            repository: "owner/skills".into(),
            reference: "main".into(),
            expected_commit: None,
            expected_tree: None,
            source_id: "homelab".into(),
            roots: vec!["skills".into()],
            token_env: None,
            refresh_interval: None,
            snapshot_timeout: DEFAULT_GIT_SNAPSHOT_TIMEOUT,
        });
        let skills = Arc::new(ReloadableSkillCatalog::default());
        skills
            .refresh(&StaticSkillSource(skill_snapshot()))
            .await
            .expect("publish fixture");
        skills.mark_refresh_failed();
        let state = Arc::new(AppState::new(config, pool, None, Some(skills), false));

        let (status, body) = fetch_readyz(state).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["checks"]["skills"]["status"], "degraded");
        assert_eq!(body["checks"]["skills"]["skill_count"], 1);
    }

    #[tokio::test]
    async fn readyz_reports_degraded_after_an_active_skill_resource_read_fails() {
        let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new()));
        let mut config = test_config();
        config.skills = Some(SkillsGitConfig {
            api_url: url::Url::parse("https://git.example/api/v1").unwrap(),
            repository: "owner/skills".into(),
            reference: "main".into(),
            expected_commit: None,
            expected_tree: None,
            source_id: "homelab".into(),
            roots: vec!["skills".into()],
            token_env: None,
            refresh_interval: None,
            snapshot_timeout: DEFAULT_GIT_SNAPSHOT_TIMEOUT,
        });
        let skills = Arc::new(ReloadableSkillCatalog::default());
        skills
            .refresh(&StaticSkillSource(skill_snapshot_with_loader(
                BTreeMap::new(),
            )))
            .await
            .expect("publish fixture");
        let snapshot = skills.current().expect("published snapshot");
        assert!(skills
            .load_resource(&snapshot, "skill://homelab/demo/SKILL.md")
            .await
            .is_err());
        let state = Arc::new(AppState::new(config, pool, None, Some(skills), false));

        let (status, body) = fetch_readyz(state).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["checks"]["skills"]["status"], "degraded");
        assert_eq!(body["checks"]["skills"]["skill_count"], 1);
    }

    #[tokio::test]
    async fn readyz_red_when_no_upstream_is_connected() {
        let mut manifests = BTreeMap::new();
        manifests.insert(
            "example-messages".into(),
            UpstreamManifest {
                classification_mode: Default::default(),
                approval_mode: Default::default(),
                inline_response_threshold_bytes: None,
                long_running_tools: Vec::new(),
                name: "example-messages".into(),
                transport: Transport::Http,
                protocol: Default::default(),
                url: Some("http://unused.test/mcp".into()),
                command: None,
                tools: vec![ToolClassification::new("t", RiskTier::Low, false, false)],
                resources: Vec::new(),
                exchange: None,
                auth: None,
                mtls: None,
                tier_a_required: false,
                tier_c_peer: None,
                session: None,
            },
        );
        let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
        let engine = CedarEngine::from_source(ADMIN_ONLY_POLICY).unwrap();
        let cedar = Arc::new(ReloadableCedar::new(engine));
        let state = Arc::new(AppState::new(test_config(), pool, Some(cedar), None, true));
        let (status, body) = fetch_readyz(state).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "unready");
        assert_eq!(body["checks"]["upstreams"]["status"], "degraded");
        assert_eq!(body["checks"]["upstreams"]["connected"], 0);
        assert_eq!(body["checks"]["upstreams"]["total"], 1);
        // Policies + audit should still show as individually healthy so an
        // operator can locate the failing subsystem at a glance.
        assert_eq!(body["checks"]["policies"]["status"], "ok");
        assert_eq!(body["checks"]["audit"]["status"], "ok");
    }

    #[tokio::test]
    async fn metrics_projects_authoritative_runtime_state_as_one_hot_gauge() {
        let _registry_guard = metrics_scrape_test_lock().lock().await;
        let manifests = BTreeMap::from([(
            "metric-contract-down".to_owned(),
            test_manifest("metric-contract-down"),
        )]);
        let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
        let state = Arc::new(AppState::new(test_config(), pool, None, None, false));
        let response = router()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains(
            "gateway_upstream_runtime_state{server=\"metric-contract-down\",state=\"disconnected\"} 1"
        ));
    }

    #[tokio::test]
    async fn metrics_scrape_clears_runtime_state_for_removed_servers() {
        let _registry_guard = metrics_scrape_test_lock().lock().await;
        let removed = "metric-contract-removed-reconcile";
        waygate_telemetry::metrics::set_upstream_runtime_state(removed, Some("connected"));

        let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new()));
        let state = Arc::new(AppState::new(test_config(), pool, None, None, false));
        let response = router()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        for runtime_state in waygate_telemetry::metrics::UPSTREAM_RUNTIME_STATES {
            assert!(text.contains(&format!(
                "gateway_upstream_runtime_state{{server=\"{removed}\",state=\"{runtime_state}\"}} 0"
            )));
        }
    }

    fn upstream_health(
        name: &str,
        connected: bool,
        breaker: waygate_upstream::BreakerState,
    ) -> UpstreamHealth {
        UpstreamHealth {
            name: name.to_owned(),
            runtime_state: if connected {
                if breaker == waygate_upstream::BreakerState::Open {
                    UpstreamRuntimeState::Disconnected
                } else if breaker == waygate_upstream::BreakerState::Closed {
                    UpstreamRuntimeState::Connected
                } else {
                    UpstreamRuntimeState::Degraded
                }
            } else {
                UpstreamRuntimeState::Disconnected
            },
            last_success_at: None,
            last_error_class: None,
            next_retry_at: None,
            connected,
            breaker,
            connected_lanes: usize::from(connected),
            total_lanes: 1,
            published_tool_count: usize::from(connected),
            quarantined_tool_count: 0,
            rejected_output_schema_count: 0,
            protocol_versions: Vec::new(),
        }
    }

    #[test]
    fn upstream_check_stays_ready_when_one_upstream_is_down() {
        let check = summarize_upstreams(&[
            upstream_health("gitea", false, waygate_upstream::BreakerState::Open),
            upstream_health(
                "example-messages",
                true,
                waygate_upstream::BreakerState::Closed,
            ),
        ]);

        assert!(
            check.ok,
            "a healthy upstream must keep the gateway routable"
        );
        assert_eq!(check.body["status"], "degraded");
        assert_eq!(check.body["connected"], 1);
        assert_eq!(check.body["open_breakers"], json!(["gitea"]));
    }

    #[test]
    fn upstream_check_reports_wholly_partial_fleet_as_degraded_but_routable() {
        let check = summarize_upstreams(&[
            upstream_health("gitea", true, waygate_upstream::BreakerState::HalfOpen),
            upstream_health(
                "example-messages",
                true,
                waygate_upstream::BreakerState::HalfOpen,
            ),
        ]);

        assert!(check.ok, "partial capacity remains routable");
        assert_eq!(check.body["status"], "degraded");
    }
}
