//! Deterministic discovery contract tests over a live MCP upstream and a
//! controllable catalog boundary. No database or timing race is involved.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rmcp::model::Tool;
use serde_json::json;
use tokio::sync::oneshot;
use waygate_catalog::*;
use waygate_mcp::catalog::{ResolvedInvocationTool, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_upstream::{ToolClassification, Transport, UpstreamManifest, UpstreamPool};

use super::discovery_scale::{request, serve, HttpFixture, LargeCatalog};

struct PausedRead {
    started: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}

#[derive(Default)]
struct ControlledCatalog {
    rows: Mutex<BTreeMap<String, ResolvedTool>>,
    batches: Mutex<Vec<(String, Vec<String>)>>,
    singles: AtomicUsize,
    generation: AtomicI64,
    pause: Mutex<Option<PausedRead>>,
}

#[async_trait]
impl CatalogStore for ControlledCatalog {
    async fn discovery_generation(&self) -> Result<Option<i64>, CatalogError> {
        Ok(Some(self.generation.load(Ordering::Acquire)))
    }
    async fn resolve_tool(&self, _: &str, fq: &str) -> Result<ResolvedTool, CatalogError> {
        self.singles.fetch_add(1, Ordering::Relaxed);
        Ok(fq
            .split_once('.')
            .and_then(|(_, name)| self.rows.lock().unwrap().get(name).cloned())
            .unwrap_or(ResolvedTool::NotFound))
    }
    async fn resolve_tools(
        &self,
        tenant: &str,
        _: &str,
        names: &[String],
    ) -> Result<Vec<ResolvedTool>, CatalogError> {
        assert!(names.len() <= TOOL_RESOLUTION_BATCH_SIZE);
        self.batches
            .lock()
            .unwrap()
            .push((tenant.to_owned(), names.to_vec()));
        let rows = {
            let rows = self.rows.lock().unwrap();
            names
                .iter()
                .map(|name| rows.get(name).cloned().unwrap_or(ResolvedTool::NotFound))
                .collect()
        };
        let pause = self.pause.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.started.send(()).unwrap();
            pause.resume.await.unwrap();
        }
        Ok(rows)
    }
    async fn approved_servers(&self, _: &str) -> Result<Vec<CatalogServerSummary>, CatalogError> {
        unreachable!("discovery uses the live pool's server inventory")
    }
    async fn record_drift(&self, _: DriftObservation<'_>) -> Result<(), CatalogError> {
        unreachable!("discovery must not mutate catalog drift")
    }
    async fn record_approval(&self, _: ApprovalAction<'_>) -> Result<(), CatalogError> {
        unreachable!("discovery must not approve")
    }
    async fn list_drift_events(
        &self,
        _: &str,
        _: time::OffsetDateTime,
        _: u32,
    ) -> Result<Vec<DriftEvent>, CatalogError> {
        unreachable!()
    }
    async fn set_server_status(
        &self,
        _: &str,
        _: uuid::Uuid,
        _: CatalogServerStatus,
        _: &str,
        _: Option<&str>,
    ) -> Result<bool, CatalogError> {
        unreachable!()
    }
    async fn last_approve_actor(
        &self,
        _: &str,
        _: uuid::Uuid,
    ) -> Result<Option<String>, CatalogError> {
        unreachable!()
    }
    async fn find_grant<'a>(
        &self,
        _: GrantLookup<'a>,
    ) -> Result<Option<ApprovalGrant>, CatalogError> {
        unreachable!("discovery cannot consume grants")
    }
    async fn claim_grant<'a>(
        &self,
        _: GrantLookup<'a>,
    ) -> Result<Option<ApprovalGrant>, CatalogError> {
        unreachable!("discovery cannot consume grants")
    }
    async fn create_grant<'a>(
        &self,
        _: NewApprovalGrant<'a>,
    ) -> Result<ApprovalGrant, CatalogError> {
        unreachable!()
    }
    async fn list_grants<'a>(
        &self,
        _: &'a str,
        _: GrantFilter<'a>,
    ) -> Result<Vec<ApprovalGrant>, CatalogError> {
        unreachable!()
    }
    async fn revoke_grant(&self, _: &str, _: uuid::Uuid) -> Result<bool, CatalogError> {
        unreachable!()
    }
    async fn sweep_grants(&self, _: time::OffsetDateTime) -> Result<u64, CatalogError> {
        unreachable!()
    }
}

async fn fixture(
    count: usize,
) -> (
    Arc<UpstreamPool>,
    Arc<ControlledCatalog>,
    HttpFixture,
    Vec<String>,
) {
    let names = (0..count)
        .map(|i| format!("tool-{i:05}"))
        .collect::<Vec<_>>();
    let tools = names
        .iter()
        .map(|name| {
            Tool::new(
                name.clone(),
                "discovery fixture",
                json!({"type":"object"}).as_object().unwrap().clone(),
            )
        })
        .collect::<Vec<_>>();
    let upstream = serve(LargeCatalog(Arc::new(tools))).await;
    let catalog = Arc::new(ControlledCatalog::default());
    for name in &names {
        catalog.rows.lock().unwrap().insert(
            name.clone(),
            ResolvedTool::Live(Box::new(ToolDefinition {
                tool_id: uuid::Uuid::new_v4(),
                server_id: uuid::Uuid::new_v4(),
                server_name: "scale".into(),
                tool_name: name.clone(),
                schema_hash: manifest_classification_hash(name, "low", false, false, None, &[]),
                classification_mode: "manifest".into(),
                description: "governed description".into(),
                input_schema: Some(json!({"type":"object"})),
                output_schema: None,
                tool_annotations: None,
                action_metadata: None,
                risk: "low".into(),
                side_effects: false,
                pii: false,
                data_classification: None,
                cost_class: None,
                requires_approval: true,
                discriminator: None,
                operations: vec![],
            })),
        );
    }
    let manifest = UpstreamManifest {
        name: "scale".into(),
        transport: Transport::Http,
        protocol: Default::default(),
        url: Some(upstream.url.clone()),
        command: None,
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        tools: names
            .iter()
            .map(|name| ToolClassification::new(name, RiskTier::Low, false, false))
            .collect(),
        resources: vec![],
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        session: None,
    };
    let pool = UpstreamPool::connect(BTreeMap::from([("scale".into(), manifest)]))
        .await
        .with_authoritative_catalog(catalog.clone());
    (Arc::new(pool), catalog, upstream, names)
}

#[tokio::test]
async fn discovery_batches_preserve_order_tenant_and_invocation_contracts() {
    let (pool, catalog, _upstream, names) = fixture(TOOL_RESOLUTION_BATCH_SIZE + 3).await;
    let resolved = pool
        .resolve_discovery_tools("tenant-a", "scale", &names)
        .await
        .unwrap();
    assert_eq!(
        catalog.singles.load(Ordering::Relaxed),
        0,
        "discovery must not fall back to per-tool store reads"
    );
    let batches = catalog.batches.lock().unwrap().clone();
    assert_eq!(batches.len(), 2);
    assert!(batches.iter().all(|(tenant, _)| tenant == "tenant-a"));
    assert_eq!(
        batches
            .into_iter()
            .flat_map(|(_, names)| names)
            .collect::<Vec<_>>(),
        names
    );
    for (name, resolved) in names.iter().zip(resolved) {
        let ResolvedInvocationTool::Ready(batched) = resolved else {
            panic!("tool should be admitted");
        };
        assert_eq!(&batched.facts().name, name);
        assert!(batched.facts().requires_approval);
        let ResolvedInvocationTool::Ready(single) = pool
            .resolve_invocation_tool("tenant-a", "scale", name)
            .await
        else {
            panic!("single tool should be admitted");
        };
        assert_eq!(batched.contract_identity(), single.contract_identity());
        assert_eq!(batched.input_schema(), single.input_schema());
        assert_eq!(
            batched.published_definition(),
            single.published_definition()
        );
    }
}

#[tokio::test]
async fn a_catalog_change_during_a_batch_refuses_the_stale_projection() {
    let (pool, catalog, _upstream, names) = fixture(3).await;
    let (started_tx, started_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    *catalog.pause.lock().unwrap() = Some(PausedRead {
        started: started_tx,
        resume: resume_rx,
    });
    let reading = {
        let pool = pool.clone();
        let names = names.clone();
        tokio::spawn(async move {
            pool.resolve_discovery_tools("tenant-a", "scale", &names)
                .await
        })
    };
    started_rx.await.unwrap();
    catalog.rows.lock().unwrap().insert(
        names[0].clone(),
        ResolvedTool::Quarantined {
            server_name: "scale".into(),
            tool_name: names[0].clone(),
        },
    );
    catalog.rows.lock().unwrap().remove(&names[1]);
    catalog.generation.fetch_add(1, Ordering::AcqRel);
    resume_tx.send(()).unwrap();
    assert!(
        reading.await.unwrap().is_err(),
        "a previously read allowed row cannot survive a later quarantine generation"
    );
    let refreshed = pool
        .resolve_discovery_tools("tenant-a", "scale", &names)
        .await
        .unwrap();
    assert!(matches!(
        refreshed[0],
        ResolvedInvocationTool::Quarantined { .. }
    ));
    assert!(matches!(
        refreshed[1],
        ResolvedInvocationTool::Quarantined { .. }
    ));
    assert!(matches!(refreshed[2], ResolvedInvocationTool::Ready(_)));
}

#[tokio::test]
async fn http_pages_and_search_use_batches_instead_of_individual_catalog_reads() {
    let (pool, catalog, _upstream, names) = fixture(TOOL_RESOLUTION_BATCH_SIZE + 3).await;
    let epoch = pool.tool_catalog_epoch();
    let gateway = serve(
        waygate_mcp::GatewayServer::new(pool)
            .with_eager_tools_list(true)
            .with_tool_catalog_epoch(&epoch),
    )
    .await;
    let client = reqwest::Client::new();
    let first = request(&client, &gateway.url, "tools/list", json!({})).await;
    assert_eq!(first.http_status, 200);
    assert!(first.error.is_none(), "{:?}", first.error);
    assert!(
        catalog.batches.lock().unwrap().len()
            <= 3 * names.len().div_ceil(TOOL_RESOLUTION_BATCH_SIZE)
    );
    let cursor = first.result["nextCursor"]
        .as_str()
        .expect("catalog needs multiple pages");
    for (method, params) in [
        ("tools/list", json!({"cursor":cursor})),
        (
            "tools/call",
            json!({"name":"scale.searchTools", "arguments":{"mode":"operations", "filters":{"query":"discovery"}, "limit":20}}),
        ),
    ] {
        catalog.batches.lock().unwrap().clear();
        let result = request(&client, &gateway.url, method, params).await;
        assert_eq!(result.http_status, 200);
        assert!(result.error.is_none(), "{:?}", result.error);
        assert!(!result.result.is_null());
        assert!(
            catalog.batches.lock().unwrap().len()
                <= 3 * names.len().div_ceil(TOOL_RESOLUTION_BATCH_SIZE)
        );
    }
    assert_eq!(
        catalog.singles.load(Ordering::Relaxed),
        0,
        "every page and search must use the bulk storage boundary"
    );
}

#[tokio::test]
async fn repeated_bulk_discovery_rechecks_each_callers_profile() {
    use waygate_oidc::{ApiKeyProfileRestrictions, AuthMethod, Principal};
    let (pool, catalog, _upstream, names) = fixture(3).await;
    let gateway = waygate_mcp::GatewayServer::new(pool).with_eager_tools_list(true);
    for (tenant, sub, index) in [
        ("tenant-a", "alice", 0),
        ("tenant-b", "bob", 2),
        ("tenant-a", "alice", 0),
    ] {
        let allowed = format!("scale.{}", names[index]);
        let principal = Principal {
            sub: sub.into(),
            email: None,
            groups: vec![],
            issuer: "https://issuer.test".into(),
            scopes: vec!["mcp:read".into()],
            tenant: waygate_core::TenantId::parse(tenant).unwrap(),
            auth_method: AuthMethod::ApiKey,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: Some(ApiKeyProfileRestrictions {
                profile_id: sub.into(),
                profile_name: "test profile".into(),
                allowed_servers: Some(vec!["scale".into()]),
                allowed_tools: Some(vec![allowed.clone()]),
            }),
        };
        let visible = gateway.list_visible_tools(Some(&principal)).await;
        let direct: Vec<_> = visible
            .iter()
            .filter(|tool| tool.name != "scale.searchTools")
            .map(|tool| tool.name.to_string())
            .collect();
        assert_eq!(direct, vec![allowed]);
    }
    let tenants = catalog
        .batches
        .lock()
        .unwrap()
        .iter()
        .map(|(tenant, _)| tenant.clone())
        .collect::<Vec<_>>();
    assert!(tenants.iter().any(|tenant| tenant == "tenant-a"));
    assert!(tenants.iter().any(|tenant| tenant == "tenant-b"));
}
