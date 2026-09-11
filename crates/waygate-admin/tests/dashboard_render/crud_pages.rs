//! Peers/break-glass/inspection/consent/RBAC CRUD + dual-mount — split from
//! the monolithic `dashboard_render.rs`; bodies verbatim, cut at the file's
//! own section markers.

use crate::common::*;
use crate::scim_rbac::seed_role;
use crate::scim_rbac::state_with_rbac_store;
use crate::scim_rbac::InMemoryRbacStub;

// ---- Federation peers inline CRUD -----------------------------------------

#[derive(Default)]
pub(crate) struct FakePeersStore {
    peers: std::sync::Mutex<Vec<waygate_federation::FederatedPeer>>,
}

#[async_trait]
impl waygate_federation::FederatedPeersStore for FakePeersStore {
    async fn insert(
        &self,
        peer: waygate_federation::NewFederatedPeer<'_>,
    ) -> Result<waygate_federation::FederatedPeer, waygate_federation::PeerError> {
        let mut g = self.peers.lock().unwrap();
        if g.iter()
            .any(|p| p.peer_name == peer.peer_name || p.issuer == peer.issuer)
        {
            return Err(waygate_federation::PeerError::DuplicateName);
        }
        let row = waygate_federation::FederatedPeer {
            id: Uuid::new_v4(),
            tenant_id: peer.tenant_id.to_owned(),
            peer_name: peer.peer_name.to_owned(),
            issuer: peer.issuer.to_owned(),
            jwks_url: peer.jwks_url.to_owned(),
            trust_tier: peer.trust_tier,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        g.push(row.clone());
        Ok(row)
    }
    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<waygate_federation::FederatedPeer>, waygate_federation::PeerError> {
        Ok(self
            .peers
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.id == id && p.tenant_id == tenant_id)
            .cloned())
    }
    async fn list(
        &self,
        tenant_id: &str,
        _filter: waygate_federation::PeerFilter<'_>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<waygate_federation::FederatedPeer>, waygate_federation::PeerError> {
        Ok(self
            .peers
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.tenant_id == tenant_id)
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }
    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: waygate_federation::PeerUpdate<'_>,
    ) -> Result<Option<waygate_federation::FederatedPeer>, waygate_federation::PeerError> {
        let mut g = self.peers.lock().unwrap();
        if let Some(new_name) = update.peer_name {
            if g.iter()
                .any(|p| p.id != id && p.tenant_id == tenant_id && p.peer_name == new_name)
            {
                return Err(waygate_federation::PeerError::DuplicateName);
            }
        }
        match g
            .iter_mut()
            .find(|p| p.id == id && p.tenant_id == tenant_id)
        {
            Some(p) => {
                if let Some(n) = update.peer_name {
                    p.peer_name = n.to_owned();
                }
                if let Some(i) = update.issuer {
                    p.issuer = i.to_owned();
                }
                if let Some(u) = update.jwks_url {
                    p.jwks_url = u.to_owned();
                }
                if let Some(t) = update.trust_tier {
                    p.trust_tier = t;
                }
                Ok(Some(p.clone()))
            }
            None => Ok(None),
        }
    }
    async fn delete(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<bool, waygate_federation::PeerError> {
        let mut g = self.peers.lock().unwrap();
        let before = g.len();
        g.retain(|p| !(p.id == id && p.tenant_id == tenant_id));
        Ok(g.len() != before)
    }
    async fn list_all_for_refresh(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<waygate_federation::FederatedPeer>, waygate_federation::PeerError> {
        Ok(self
            .peers
            .lock()
            .unwrap()
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }
}

pub(crate) async fn state_with_peers_store(
    store: Arc<dyn waygate_federation::FederatedPeersStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // The peer cores audit via record_required (fail-closed) → needs a real
    // sink, not NullSink.
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
        .with_federated_peers_store(Some(store)),
    )
}

pub(crate) fn seed_peer(store: &FakePeersStore, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    store
        .peers
        .lock()
        .unwrap()
        .push(waygate_federation::FederatedPeer {
            id,
            tenant_id: "default".into(),
            peer_name: name.into(),
            issuer: "https://peer.example".into(),
            jwks_url: "https://peer.example/.well-known/jwks.json".into(),
            trust_tier: waygate_federation::TrustTier::Restricted,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        });
    id
}

pub(crate) async fn post_form(app: axum::Router, uri: &str, body: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (status, loc)
}

/// POST a form body and return the response BODY (for JSON endpoints that
/// return a body rather than a PRG redirect, e.g. the diagnostics endpoint).
pub(crate) async fn post_form_body(
    app: axum::Router,
    uri: &str,
    body: &str,
) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

pub(crate) const FED_CREATE: &str = "/federation/peers/create";

#[tokio::test]
pub(crate) async fn federation_create_persists_and_redirects() {
    let store = Arc::new(FakePeersStore::default());
    let app = dashboard_router(
        state_with_peers_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        FED_CREATE,
        "csrf=dev-csrf&peer_name=acme-prod&issuer=https://peer.example\
         &jwks_url=https://peer.example/jwks&trust_tier=restricted",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(loc.contains("/federation"), "redirect target: {loc}");
    assert!(
        !loc.contains("fed_error"),
        "success must not carry an error: {loc}"
    );
    let peers = store.peers.lock().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].peer_name, "acme-prod");
    assert_eq!(
        peers[0].trust_tier,
        waygate_federation::TrustTier::Restricted
    );
}

#[tokio::test]
pub(crate) async fn federation_create_rejects_bad_csrf() {
    let store = Arc::new(FakePeersStore::default());
    let app = dashboard_router(
        state_with_peers_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_form(
        app,
        FED_CREATE,
        "csrf=WRONG&peer_name=x&issuer=https://peer.example\
         &jwks_url=https://peer.example/jwks&trust_tier=restricted",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        store.peers.lock().unwrap().len(),
        0,
        "CSRF failure must not persist"
    );
}

#[tokio::test]
pub(crate) async fn federation_create_rejects_bad_trust_tier() {
    let store = Arc::new(FakePeersStore::default());
    let app = dashboard_router(
        state_with_peers_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        FED_CREATE,
        "csrf=dev-csrf&peer_name=x&issuer=https://peer.example\
         &jwks_url=https://peer.example/jwks&trust_tier=bogus",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("fed_error"),
        "bad trust tier must redirect with error: {loc}"
    );
    assert_eq!(store.peers.lock().unwrap().len(), 0);
}

#[tokio::test]
pub(crate) async fn federation_create_rejects_issuer_userinfo() {
    // The refuse-url-userinfo invariant is enforced by the shared core's
    // validate_issuer; this confirms the dashboard surfaces it.
    let store = Arc::new(FakePeersStore::default());
    let app = dashboard_router(
        state_with_peers_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        FED_CREATE,
        "csrf=dev-csrf&peer_name=x&issuer=https://user:pass@peer.example/\
         &jwks_url=https://peer.example/jwks&trust_tier=restricted",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("fed_error"),
        "userinfo issuer must be refused: {loc}"
    );
    assert!(
        loc.contains("userinfo"),
        "the rejection reason should surface: {loc}"
    );
    assert_eq!(store.peers.lock().unwrap().len(), 0);
}

#[tokio::test]
pub(crate) async fn federation_update_persists_and_redirects() {
    let store = Arc::new(FakePeersStore::default());
    let id = seed_peer(&store, "before");
    let app = dashboard_router(
        state_with_peers_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/federation/peers/{id}/update"),
        "csrf=dev-csrf&peer_name=after&issuer=https://peer.example\
         &jwks_url=https://peer.example/jwks&trust_tier=full",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("fed_error"), "update should succeed: {loc}");
    let peers = store.peers.lock().unwrap();
    assert_eq!(peers[0].peer_name, "after");
    assert_eq!(peers[0].trust_tier, waygate_federation::TrustTier::Full);
}

#[tokio::test]
pub(crate) async fn federation_delete_persists_and_redirects() {
    let store = Arc::new(FakePeersStore::default());
    let id = seed_peer(&store, "doomed");
    let app = dashboard_router(
        state_with_peers_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/federation/peers/{id}/delete"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("fed_error"), "delete should succeed: {loc}");
    assert_eq!(store.peers.lock().unwrap().len(), 0, "peer should be gone");
}

#[tokio::test]
pub(crate) async fn federation_delete_rejects_bad_csrf() {
    let store = Arc::new(FakePeersStore::default());
    let id = seed_peer(&store, "keep");
    let app = dashboard_router(
        state_with_peers_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) =
        post_form(app, &format!("/federation/peers/{id}/delete"), "csrf=WRONG").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        store.peers.lock().unwrap().len(),
        1,
        "CSRF failure must not delete"
    );
}

#[tokio::test]
pub(crate) async fn federation_page_renders_crud_for_admin_when_store_wired() {
    let store = Arc::new(FakePeersStore::default());
    let app = dashboard_router(state_with_peers_store(store).await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/federation").await;
    assert_eq!(status, StatusCode::OK);
    // Create form renders for the admin dev principal, built on shared .form-*.
    assert!(
        body.contains("Add a federated peer") && body.contains(r#"name="jwks_url""#),
        "create form should render for an admin when the store is wired"
    );
    assert!(
        body.contains(r#"action="/admin/federation/peers/create""#),
        "create form posts to the create route"
    );
}

// ---- Break-glass mint + revoke --------------------------------------------

#[derive(Default)]
pub(crate) struct FakeBreakGlassStore {
    pub(crate) tokens: std::sync::Mutex<Vec<waygate_authz::BreakGlassToken>>,
}

#[async_trait]
impl waygate_authz::BreakGlassStore for FakeBreakGlassStore {
    async fn mint(
        &self,
        m: waygate_authz::NewBreakGlassToken<'_>,
    ) -> Result<waygate_authz::BreakGlassToken, waygate_authz::BreakGlassError> {
        let t = waygate_authz::BreakGlassToken {
            id: Uuid::new_v4(),
            tenant_id: m.tenant_id.to_owned(),
            issued_to: m.issued_to.to_owned(),
            issued_by: m.issued_by.to_owned(),
            reason: m.reason.to_owned(),
            scope_pattern: m.scope_pattern.to_owned(),
            requires_amr: m.requires_amr.to_vec(),
            expires_at: m.expires_at,
            used_at: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        self.tokens.lock().unwrap().push(t.clone());
        Ok(t)
    }
    async fn list(
        &self,
        tenant_id: &str,
        lifecycle: Option<waygate_authz::BreakGlassLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<waygate_authz::BreakGlassToken>, waygate_authz::BreakGlassError> {
        use waygate_authz::BreakGlassLifecycle as L;
        let now = time::OffsetDateTime::now_utc();
        Ok(self
            .tokens
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.tenant_id == tenant_id)
            .filter(|t| match lifecycle {
                None => true,
                Some(L::Active) => t.used_at.is_none() && t.expires_at > now,
                Some(L::Expired) => t.used_at.is_none() && t.expires_at <= now,
                Some(L::Used) => t.used_at.is_some(),
            })
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }
    async fn delete(
        &self,
        tenant_id: &str,
        token_id: Uuid,
    ) -> Result<bool, waygate_authz::BreakGlassError> {
        let mut g = self.tokens.lock().unwrap();
        let before = g.len();
        g.retain(|t| !(t.id == token_id && t.tenant_id == tenant_id));
        Ok(g.len() != before)
    }
    async fn list_candidates(
        &self,
        _tenant_id: &str,
        _principal_sub: &str,
        _fq_tool_name: &str,
    ) -> Result<Vec<waygate_authz::BreakGlassToken>, waygate_authz::BreakGlassError> {
        Ok(Vec::new())
    }
    async fn try_claim(
        &self,
        _token_id: Uuid,
    ) -> Result<Option<waygate_authz::BreakGlassToken>, waygate_authz::BreakGlassError> {
        Ok(None)
    }
}

pub(crate) async fn state_with_break_glass_store(
    store: Arc<dyn waygate_authz::BreakGlassStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // mint/revoke audit via record_required (fail-closed) → real sink.
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
        .with_break_glass_store(Some(store)),
    )
}

pub(crate) fn seed_bg_token(store: &FakeBreakGlassStore) -> Uuid {
    let id = Uuid::new_v4();
    store
        .tokens
        .lock()
        .unwrap()
        .push(waygate_authz::BreakGlassToken {
            id,
            tenant_id: "default".into(),
            issued_to: "alice".into(),
            issued_by: "op".into(),
            reason: "incident-123".into(),
            scope_pattern: "example-messages.*".into(),
            requires_amr: vec![],
            // Far future so it lands in the Active bucket.
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            used_at: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        });
    id
}

pub(crate) const BG_MINT: &str = "/break_glass/mint";

#[tokio::test]
pub(crate) async fn break_glass_mint_persists_and_redirects() {
    let store = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_break_glass_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        BG_MINT,
        "csrf=dev-csrf&issued_to=alice&scope_pattern=example-messages.send_msg&reason=incident&ttl_seconds=3600",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(loc.contains("/break_glass"), "redirect target: {loc}");
    assert!(
        !loc.contains("bg_error"),
        "success must not carry an error: {loc}"
    );
    let tokens = store.tokens.lock().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].issued_to, "alice");
    assert_eq!(tokens[0].scope_pattern, "example-messages.send_msg");
    assert!(
        tokens[0].requires_amr.is_empty(),
        "dashboard mint sends no AMR"
    );
}

#[tokio::test]
pub(crate) async fn break_glass_mint_rejects_bad_csrf() {
    let store = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_break_glass_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_form(
        app,
        BG_MINT,
        "csrf=WRONG&issued_to=alice&scope_pattern=example-messages.send_msg&reason=incident&ttl_seconds=3600",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        store.tokens.lock().unwrap().len(),
        0,
        "CSRF failure must not mint"
    );
}

#[tokio::test]
pub(crate) async fn break_glass_mint_rejects_bad_scope_pattern() {
    // validate_mint_request refuses a pattern that isn't server.tool / server.*.
    let store = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_break_glass_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        BG_MINT,
        "csrf=dev-csrf&issued_to=alice&scope_pattern=nodot&reason=incident&ttl_seconds=3600",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("bg_error"),
        "malformed scope must redirect with error: {loc}"
    );
    assert_eq!(store.tokens.lock().unwrap().len(), 0);
}

#[tokio::test]
pub(crate) async fn break_glass_revoke_persists_and_redirects() {
    let store = Arc::new(FakeBreakGlassStore::default());
    let id = seed_bg_token(&store);
    let app = dashboard_router(
        state_with_break_glass_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(app, &format!("/break_glass/{id}/revoke"), "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("bg_error"), "revoke should succeed: {loc}");
    assert_eq!(
        store.tokens.lock().unwrap().len(),
        0,
        "token should be gone"
    );
}

#[tokio::test]
pub(crate) async fn break_glass_revoke_rejects_bad_csrf() {
    let store = Arc::new(FakeBreakGlassStore::default());
    let id = seed_bg_token(&store);
    let app = dashboard_router(
        state_with_break_glass_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_form(app, &format!("/break_glass/{id}/revoke"), "csrf=WRONG").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        store.tokens.lock().unwrap().len(),
        1,
        "CSRF failure must not revoke"
    );
}

#[tokio::test]
pub(crate) async fn break_glass_page_renders_mint_form_for_admin() {
    let store = Arc::new(FakeBreakGlassStore::default());
    let app = dashboard_router(
        state_with_break_glass_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/break_glass").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Mint a token") && body.contains(r#"name="scope_pattern""#),
        "mint form should render for an admin when the store is wired"
    );
    assert!(
        body.contains("No active break-glass tokens"),
        "empty active section should use the shared empty-state"
    );
    assert!(
        body.contains(r#"action="/admin/break_glass/mint""#),
        "mint form posts to the mint route"
    );
}

// ---- Dual-mount Path extraction across dashboard mutations ----------------
//
// `page_routes` is nested under `/t/{tenant}` AND merged at `/`, so the
// canonical tenant-scoped mutation routes carry an extra `tenant` capture. A
// handler extracting `Path<String>` (or `Path<(String,String)>`) expects a
// fixed arity and axum 0.8 rejects with a 500 BEFORE the handler body runs.
// The fix reads the wanted capture(s) by name from
// `Path<HashMap<String,String>>`.
//
// Each test below POSTs to the tenant-scoped URL on a STORELESS state: the
// framework-level Path extraction is what used to 500. A fixed handler instead
// reaches its body and (no store wired) PRG-redirects with an error → 303
// (or, for the playground handler whose store-check precedes a raw response,
// 503). The point is purely "the handler ran", i.e. NOT a 500 at extraction.
// Regression guard for every handler; the legacy un-prefixed URLs already pass.

pub(crate) const TENANT_SCOPED_TEST_UUID: &str = "00000000-0000-0000-0000-000000000000";

pub(crate) async fn tenant_scoped_post(uri: &str) -> StatusCode {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, _loc) = post_form(app, uri, "csrf=dev-csrf").await;
    status
}

#[tokio::test]
pub(crate) async fn tenant_scoped_tenants_update_reaches_handler() {
    assert_eq!(
        tenant_scoped_post("/t/default/tenants/acme/update").await,
        StatusCode::SEE_OTHER,
    );
}

#[tokio::test]
pub(crate) async fn tenant_scoped_tenants_delete_reaches_handler() {
    assert_eq!(
        tenant_scoped_post("/t/default/tenants/acme/delete").await,
        StatusCode::SEE_OTHER,
    );
}

#[tokio::test]
pub(crate) async fn tenant_scoped_rbac_role_update_reaches_handler() {
    assert_eq!(
        tenant_scoped_post(&format!(
            "/t/default/rbac/roles/{TENANT_SCOPED_TEST_UUID}/update"
        ))
        .await,
        StatusCode::SEE_OTHER,
    );
}

#[tokio::test]
pub(crate) async fn tenant_scoped_rbac_role_delete_reaches_handler() {
    assert_eq!(
        tenant_scoped_post(&format!(
            "/t/default/rbac/roles/{TENANT_SCOPED_TEST_UUID}/delete"
        ))
        .await,
        StatusCode::SEE_OTHER,
    );
}

#[tokio::test]
pub(crate) async fn tenant_scoped_rbac_assignment_delete_reaches_handler() {
    assert_eq!(
        tenant_scoped_post(&format!(
            "/t/default/rbac/assignments/{TENANT_SCOPED_TEST_UUID}/delete"
        ))
        .await,
        StatusCode::SEE_OTHER,
    );
}

#[tokio::test]
pub(crate) async fn tenant_scoped_rbac_group_mapping_delete_reaches_handler() {
    // Dual-capture route (group_id + role_id) → 3 captures with the tenant
    // prefix; the old `Path<(String,String)>` mismatched and 500'd.
    assert_eq!(
        tenant_scoped_post(&format!(
            "/t/default/rbac/group-mappings/{TENANT_SCOPED_TEST_UUID}/{TENANT_SCOPED_TEST_UUID}/delete"
        ))
        .await,
        StatusCode::SEE_OTHER,
    );
}

#[tokio::test]
pub(crate) async fn tenant_scoped_approvals_revoke_reaches_handler() {
    assert_eq!(
        tenant_scoped_post(&format!(
            "/t/default/approvals/{TENANT_SCOPED_TEST_UUID}/revoke"
        ))
        .await,
        StatusCode::SEE_OTHER,
    );
}

#[tokio::test]
pub(crate) async fn tenant_scoped_break_glass_revoke_reaches_handler() {
    assert_eq!(
        tenant_scoped_post(&format!(
            "/t/default/break_glass/{TENANT_SCOPED_TEST_UUID}/revoke"
        ))
        .await,
        StatusCode::SEE_OTHER,
    );
}

#[tokio::test]
pub(crate) async fn tenant_scoped_federation_delete_reaches_handler() {
    assert_eq!(
        tenant_scoped_post(&format!(
            "/t/default/federation/peers/{TENANT_SCOPED_TEST_UUID}/delete"
        ))
        .await,
        StatusCode::SEE_OTHER,
    );
}

#[tokio::test]
pub(crate) async fn tenant_scoped_playground_delete_reaches_handler() {
    // Playground's store-check precedes a raw 503 (not a PRG redirect), so a
    // storeless run yields 503 — still proving the handler body ran, not a
    // 500 at Path extraction.
    assert_eq!(
        tenant_scoped_post("/t/default/playground/scenarios/demo/delete").await,
        StatusCode::SERVICE_UNAVAILABLE,
    );
}

// The same dual-mount bug also affected dashboard mutation handlers outside
// the dashboard_* modules — api-key rename/revoke/usage, api-key-profile
// delete, policy-bundle publish/rollback, and the inline activity drawer +
// saved-view delete in dashboard_activity_page.rs. For these, a storeless
// run can return various non-303 statuses, so we assert the tenant-scoped
// mount matches the legacy mount: equal ⇒ the handler ran on both; a
// pre-fix 500 at Path extraction would differ.

/// Run the same request against the legacy `/...` mount and the canonical
/// `/t/default/...` mount; return `(legacy, tenant_scoped)` statuses.
pub(crate) async fn dual_mount_parity(suffix: &str, post: bool) -> (StatusCode, StatusCode) {
    let legacy = {
        let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
        if post {
            post_form(app, suffix, "csrf=dev-csrf").await.0
        } else {
            body_of(app, suffix).await.0
        }
    };
    let scoped = {
        let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
        let uri = format!("/t/default{suffix}");
        if post {
            post_form(app, &uri, "csrf=dev-csrf").await.0
        } else {
            body_of(app, &uri).await.0
        }
    };
    (legacy, scoped)
}

macro_rules! dual_mount_parity_test {
    ($name:ident, $suffix:expr, $post:expr) => {
        #[tokio::test]
        async fn $name() {
            let (legacy, scoped) = dual_mount_parity($suffix, $post).await;
            assert_ne!(
                scoped,
                StatusCode::INTERNAL_SERVER_ERROR,
                "tenant-scoped mount 500'd at Path extraction",
            );
            assert_eq!(
                scoped, legacy,
                "tenant-scoped mount must behave like the legacy mount",
            );
        }
    };
}

dual_mount_parity_test!(
    dual_mount_parity_api_key_rename,
    &format!("/identities/api-keys/{TENANT_SCOPED_TEST_UUID}/rename"),
    true
);
dual_mount_parity_test!(
    dual_mount_parity_api_key_revoke,
    &format!("/identities/api-keys/{TENANT_SCOPED_TEST_UUID}/revoke"),
    true
);
dual_mount_parity_test!(
    dual_mount_parity_api_key_usage,
    &format!("/identities/api-keys/{TENANT_SCOPED_TEST_UUID}/usage"),
    false
);
dual_mount_parity_test!(
    dual_mount_parity_api_key_profile_delete,
    &format!("/identities/api-key-profiles/{TENANT_SCOPED_TEST_UUID}/delete"),
    true
);
dual_mount_parity_test!(
    dual_mount_parity_policy_bundle_publish,
    &format!("/policy_bundles/{TENANT_SCOPED_TEST_UUID}/publish"),
    true
);
dual_mount_parity_test!(
    dual_mount_parity_policy_bundle_rollback,
    "/policy_bundles/3/rollback",
    true
);
dual_mount_parity_test!(
    dual_mount_parity_activity_drawer,
    &format!("/activity/{TENANT_SCOPED_TEST_UUID}"),
    false
);
dual_mount_parity_test!(
    dual_mount_parity_activity_saved_view_delete,
    "/activity/saved_views/demo/delete",
    true
);

/// Federation update was a dual-mount handler without a tenant-scoped test.
/// Storeless, the trust-tier validation fails first → PRG 303, proving the
/// handler ran.
#[tokio::test]
pub(crate) async fn tenant_scoped_federation_update_reaches_handler() {
    assert_eq!(
        tenant_scoped_post(&format!(
            "/t/default/federation/peers/{TENANT_SCOPED_TEST_UUID}/update"
        ))
        .await,
        StatusCode::SEE_OTHER,
    );
}

// ---- Inspection-rules page (new, full CRUD) -------------------------------

pub(crate) struct FakeInspectionRulesStore {
    rules: std::sync::Mutex<Vec<waygate_dashboard_stores::inspection_rules::InspectionRule>>,
}

impl FakeInspectionRulesStore {
    fn with(rules: Vec<waygate_dashboard_stores::inspection_rules::InspectionRule>) -> Self {
        Self {
            rules: std::sync::Mutex::new(rules),
        }
    }
}

#[async_trait]
impl waygate_dashboard_stores::inspection_rules::InspectionRulesStore for FakeInspectionRulesStore {
    async fn insert(
        &self,
        rule: waygate_dashboard_stores::inspection_rules::NewInspectionRule<'_>,
    ) -> Result<
        waygate_dashboard_stores::inspection_rules::InspectionRule,
        waygate_dashboard_stores::inspection_rules::RuleError,
    > {
        let mut v = self.rules.lock().unwrap();
        if v.iter().any(|r| {
            r.tenant_id == rule.tenant_id && r.inspector == rule.inspector && r.name == rule.name
        }) {
            return Err(waygate_dashboard_stores::inspection_rules::RuleError::DuplicateName);
        }
        let now = OffsetDateTime::now_utc();
        let stored = waygate_dashboard_stores::inspection_rules::InspectionRule {
            id: Uuid::now_v7(),
            tenant_id: rule.tenant_id.to_owned(),
            inspector: rule.inspector,
            name: rule.name.to_owned(),
            config: rule.config.clone(),
            applies_to: rule.applies_to.clone(),
            enabled: rule.enabled,
            created_at: now,
            updated_at: now,
        };
        v.push(stored.clone());
        Ok(stored)
    }
    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<
        Option<waygate_dashboard_stores::inspection_rules::InspectionRule>,
        waygate_dashboard_stores::inspection_rules::RuleError,
    > {
        Ok(self
            .rules
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.id == id)
            .cloned())
    }
    async fn list(
        &self,
        tenant_id: &str,
        filter: waygate_dashboard_stores::inspection_rules::RuleFilter<'_>,
        limit: u32,
        offset: u32,
    ) -> Result<
        Vec<waygate_dashboard_stores::inspection_rules::InspectionRule>,
        waygate_dashboard_stores::inspection_rules::RuleError,
    > {
        let v = self.rules.lock().unwrap();
        let out: Vec<_> = v
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .filter(|r| filter.inspector.map(|i| r.inspector == i).unwrap_or(true))
            .filter(|r| filter.name.map(|n| r.name == n).unwrap_or(true))
            .filter(|r| filter.enabled.map(|e| r.enabled == e).unwrap_or(true))
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(out)
    }
    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: waygate_dashboard_stores::inspection_rules::RuleUpdate<'_>,
    ) -> Result<
        Option<waygate_dashboard_stores::inspection_rules::InspectionRule>,
        waygate_dashboard_stores::inspection_rules::RuleError,
    > {
        let mut v = self.rules.lock().unwrap();
        match v
            .iter_mut()
            .find(|r| r.tenant_id == tenant_id && r.id == id)
        {
            Some(r) => {
                if let Some(n) = update.name {
                    r.name = n.to_owned();
                }
                if let Some(c) = update.config {
                    r.config = c.clone();
                }
                if let Some(a) = update.applies_to {
                    r.applies_to = a.clone();
                }
                if let Some(e) = update.enabled {
                    r.enabled = e;
                }
                r.updated_at = OffsetDateTime::now_utc();
                Ok(Some(r.clone()))
            }
            None => Ok(None),
        }
    }
    async fn delete(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<bool, waygate_dashboard_stores::inspection_rules::RuleError> {
        let mut v = self.rules.lock().unwrap();
        let before = v.len();
        v.retain(|r| !(r.tenant_id == tenant_id && r.id == id));
        Ok(v.len() < before)
    }
}

pub(crate) fn ir_fixture(
    id: Uuid,
    name: &str,
) -> waygate_dashboard_stores::inspection_rules::InspectionRule {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    waygate_dashboard_stores::inspection_rules::InspectionRule {
        id,
        tenant_id: "default".into(),
        inspector: waygate_dashboard_stores::inspection_rules::InspectorKind::Pii,
        name: name.into(),
        config: serde_json::json!({"pattern": "x"}),
        applies_to: serde_json::json!({}),
        enabled: true,
        created_at: now,
        updated_at: now,
    }
}

pub(crate) async fn state_with_inspection_store(
    store: Arc<dyn waygate_dashboard_stores::inspection_rules::InspectionRulesStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // Inspection-rule mutations audit via record_required (fail-closed).
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
        .with_inspection_rules_store(Some(store)),
    )
}

#[tokio::test]
pub(crate) async fn inspection_rules_admin_rows_render_action_forms() {
    let id = Uuid::from_u128(0xA1);
    let store = Arc::new(FakeInspectionRulesStore::with(vec![ir_fixture(id, "seed")]));
    let app = dashboard_router(
        state_with_inspection_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/inspection_rules").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/inspection_rules/create"),
        "composer missing"
    );
    assert!(body.contains("<th>Actions</th>"), "Actions column missing");
    assert!(
        body.contains(&format!("/inspection_rules/{id}/update"))
            && body.contains(&format!("/inspection_rules/{id}/delete")),
        "per-row edit/delete actions missing",
    );
    assert!(
        !body.contains("POST /api/v1/admin/inspection_rules"),
        "raw curl instruction must not appear",
    );
}

#[tokio::test]
pub(crate) async fn inspection_rules_create_persists_and_redirects() {
    let store = Arc::new(FakeInspectionRulesStore::with(vec![]));
    let app = dashboard_router(
        state_with_inspection_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/inspection_rules/create",
        "csrf=dev-csrf&inspector=secrets&name=block-keys&config=%7B%22pattern%22%3A%22sk-%22%7D&applies_to=&enabled=on",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("ir_error"), "create carried an error: {loc}");
    let rules = store.rules.lock().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "block-keys");
    assert_eq!(
        rules[0].inspector,
        waygate_dashboard_stores::inspection_rules::InspectorKind::Secrets
    );
    assert_eq!(rules[0].config, serde_json::json!({"pattern": "sk-"}));
    assert_eq!(rules[0].applies_to, serde_json::json!({}));
    assert!(rules[0].enabled);
}

#[tokio::test]
pub(crate) async fn inspection_rules_create_rejects_missing_csrf() {
    let store = Arc::new(FakeInspectionRulesStore::with(vec![]));
    let app = dashboard_router(
        state_with_inspection_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_form(
        app,
        "/inspection_rules/create",
        "inspector=pii&name=x&config=%7B%7D",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn inspection_rules_create_invalid_json_reports_error() {
    let store = Arc::new(FakeInspectionRulesStore::with(vec![]));
    let app = dashboard_router(
        state_with_inspection_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/inspection_rules/create",
        "csrf=dev-csrf&inspector=pii&name=x&config=not-json",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("ir_error"),
        "invalid JSON must redirect with error: {loc}"
    );
    assert!(
        store.rules.lock().unwrap().is_empty(),
        "invalid rule must not persist",
    );
}

#[tokio::test]
pub(crate) async fn inspection_rules_update_persists_and_redirects() {
    let id = Uuid::from_u128(0xA2);
    let store = Arc::new(FakeInspectionRulesStore::with(vec![ir_fixture(id, "seed")]));
    let app = dashboard_router(
        state_with_inspection_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/inspection_rules/{id}/update"),
        "csrf=dev-csrf&name=renamed&config=%7B%22pattern%22%3A%22y%22%7D&applies_to=",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("ir_error"), "update carried an error: {loc}");
    let rules = store.rules.lock().unwrap();
    assert_eq!(rules[0].name, "renamed");
    assert_eq!(rules[0].config, serde_json::json!({"pattern": "y"}));
    // Checkbox absent ⇒ disabled (full-replace edit semantics).
    assert!(
        !rules[0].enabled,
        "unchecked enabled box should disable the rule"
    );
}

#[tokio::test]
pub(crate) async fn inspection_rules_delete_removes_and_redirects() {
    let id = Uuid::from_u128(0xA3);
    let store = Arc::new(FakeInspectionRulesStore::with(vec![ir_fixture(id, "seed")]));
    let app = dashboard_router(
        state_with_inspection_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/inspection_rules/{id}/delete"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("ir_error"));
    assert!(store.rules.lock().unwrap().is_empty(), "rule not deleted");
}

#[tokio::test]
pub(crate) async fn inspection_rules_delete_unknown_reports_error() {
    let store = Arc::new(FakeInspectionRulesStore::with(vec![ir_fixture(
        Uuid::from_u128(0xA4),
        "seed",
    )]));
    let app = dashboard_router(
        state_with_inspection_store(store).await,
        DashboardAuth::Disabled,
    );
    let ghost = Uuid::from_u128(0xBEEF);
    let (status, loc) = post_form(
        app,
        &format!("/inspection_rules/{ghost}/delete"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("ir_error"),
        "unknown-id delete must carry an error: {loc}"
    );
}

/// New page wired correctly under the canonical `/t/{tenant}` mount from the
/// start (no dual-mount Path bug — by-name extraction).
#[tokio::test]
pub(crate) async fn inspection_rules_tenant_scoped_delete_reaches_handler() {
    let id = Uuid::from_u128(0xA5);
    let store = Arc::new(FakeInspectionRulesStore::with(vec![ir_fixture(id, "seed")]));
    let app = dashboard_router(
        state_with_inspection_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/t/default/inspection_rules/{id}/delete"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "tenant-scoped delete loc={loc}"
    );
    assert!(
        store.rules.lock().unwrap().is_empty(),
        "rule not deleted on tenant mount"
    );
}

/// The delete confirm must be a static inline-JS string — `r.name` must never
/// be interpolated into it (XSS lesson).
#[tokio::test]
pub(crate) async fn inspection_rules_delete_confirm_is_static() {
    let id = Uuid::from_u128(0xA6);
    let mut rule = ir_fixture(id, "evil'); alert(1); //");
    rule.inspector = waygate_dashboard_stores::inspection_rules::InspectorKind::Custom;
    let store = Arc::new(FakeInspectionRulesStore::with(vec![rule]));
    let app = dashboard_router(
        state_with_inspection_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/inspection_rules").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("onsubmit=\"return confirm('Delete this inspection rule?"),
        "delete confirm must be the static string (no name interpolation)",
    );
    assert!(
        !body.contains("evil'); alert(1)"),
        "the unescaped quote-breakout form must never render",
    );
}

// ---- OAuth-consent inline revoke ------------------------------------------

#[derive(Default)]
pub(crate) struct FakeConsentStore {
    grants: std::sync::Mutex<Vec<waygate_as::consent::ConsentGrant>>,
}

#[async_trait]
impl waygate_as::consent::ConsentStore for FakeConsentStore {
    async fn upsert(
        &self,
        _grant: waygate_as::consent::NewConsentGrant<'_>,
    ) -> Result<waygate_as::consent::ConsentGrant, waygate_as::consent::ConsentStoreError> {
        // The dashboard never upserts (grants come from /oauth/authorize).
        unimplemented!("FakeConsentStore::upsert is not exercised by dashboard tests")
    }
    async fn list(
        &self,
        tenant_id: &str,
        principal_sub: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<waygate_as::consent::ConsentGrant>, waygate_as::consent::ConsentStoreError>
    {
        Ok(self
            .grants
            .lock()
            .unwrap()
            .iter()
            .filter(|g| g.tenant_id == tenant_id)
            .filter(|g| principal_sub.is_none_or(|s| g.principal_sub == s))
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }
    async fn revoke(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        client_id: &str,
    ) -> Result<bool, waygate_as::consent::ConsentStoreError> {
        let mut gs = self.grants.lock().unwrap();
        for g in gs.iter_mut() {
            if g.tenant_id == tenant_id
                && g.principal_sub == principal_sub
                && g.client_id == client_id
                && g.revoked_at.is_none()
            {
                g.revoked_at = Some(OffsetDateTime::now_utc());
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn find_active(
        &self,
        _tenant_id: &str,
        _principal_sub: &str,
        _client_id: &str,
    ) -> Result<Option<waygate_as::consent::ConsentGrant>, waygate_as::consent::ConsentStoreError>
    {
        Ok(None)
    }
}

pub(crate) async fn state_with_consent_store(
    store: Arc<dyn waygate_as::consent::ConsentStore>,
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
        .with_consent_store(Some(store)),
    )
}

pub(crate) fn seed_active_grant(store: &FakeConsentStore, sub: &str, client_id: &str) {
    store
        .grants
        .lock()
        .unwrap()
        .push(waygate_as::consent::ConsentGrant {
            id: Uuid::new_v4(),
            tenant_id: "default".into(),
            principal_sub: sub.into(),
            client_id: client_id.into(),
            scopes: vec!["mcp:invoke".into()],
            granted_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: None,
            revoked_at: None,
        });
}

pub(crate) const OC_REVOKE: &str = "/oauth_consent/revoke";

#[tokio::test]
pub(crate) async fn oauth_consent_revoke_persists_and_redirects() {
    let store = Arc::new(FakeConsentStore::default());
    seed_active_grant(&store, "alice", "https://client.example/cimd");
    let app = dashboard_router(
        state_with_consent_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        OC_REVOKE,
        "csrf=dev-csrf&principal_sub=alice&client_id=https://client.example/cimd",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(loc.contains("/oauth_consent"), "redirect target: {loc}");
    assert!(
        !loc.contains("oc_error"),
        "success must not carry an error: {loc}"
    );
    let gs = store.grants.lock().unwrap();
    assert!(
        gs[0].revoked_at.is_some(),
        "the active grant should be revoked"
    );
}

#[tokio::test]
pub(crate) async fn oauth_consent_revoke_rejects_bad_csrf() {
    let store = Arc::new(FakeConsentStore::default());
    seed_active_grant(&store, "alice", "https://client.example/cimd");
    let app = dashboard_router(
        state_with_consent_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_form(
        app,
        OC_REVOKE,
        "csrf=WRONG&principal_sub=alice&client_id=https://client.example/cimd",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        store.grants.lock().unwrap()[0].revoked_at.is_none(),
        "CSRF failure must not revoke"
    );
}

#[tokio::test]
pub(crate) async fn oauth_consent_revoke_missing_fields_redirects_with_error() {
    let store = Arc::new(FakeConsentStore::default());
    seed_active_grant(&store, "alice", "https://client.example/cimd");
    let app = dashboard_router(
        state_with_consent_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(app, OC_REVOKE, "csrf=dev-csrf&principal_sub=&client_id=").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("oc_error"),
        "missing fields must redirect with error: {loc}"
    );
    assert!(
        store.grants.lock().unwrap()[0].revoked_at.is_none(),
        "no revoke on missing identifiers"
    );
}

#[tokio::test]
pub(crate) async fn oauth_consent_page_renders_revoke_for_admin() {
    let store = Arc::new(FakeConsentStore::default());
    seed_active_grant(&store, "alice", "https://client.example/cimd");
    let app = dashboard_router(
        state_with_consent_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/oauth_consent").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"action="/admin/oauth_consent/revoke""#),
        "active grant should render a revoke form"
    );
    assert!(
        body.contains(r#"name="principal_sub""#) && body.contains(r#"name="client_id""#),
        "revoke form carries the grant identifiers as hidden fields"
    );
}

// ---- RBAC assignments + group-mappings CRUD -------------------------------

#[tokio::test]
pub(crate) async fn rbac_assignment_create_persists_and_redirects() {
    let store = Arc::new(InMemoryRbacStub::default());
    let role_id = seed_role(&store, "ops");
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/rbac/assignments/create",
        &format!("csrf=dev-csrf&role_id={role_id}&subject_sub=alice"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        !loc.contains("rbac_error"),
        "assignment create should succeed: {loc}"
    );
    let a = store.assignments.lock().unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].subject_sub, "alice");
    assert_eq!(a[0].role_id, role_id);
}

#[tokio::test]
pub(crate) async fn rbac_assignment_create_rejects_bad_csrf() {
    let store = Arc::new(InMemoryRbacStub::default());
    let role_id = seed_role(&store, "ops");
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_form(
        app,
        "/rbac/assignments/create",
        &format!("csrf=WRONG&role_id={role_id}&subject_sub=alice"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        store.assignments.lock().unwrap().len(),
        0,
        "CSRF failure must not assign"
    );
}

#[tokio::test]
pub(crate) async fn rbac_assignment_delete_persists_and_redirects() {
    let store = Arc::new(InMemoryRbacStub::default());
    let role_id = seed_role(&store, "ops");
    let assignment_id = Uuid::new_v4();
    store
        .assignments
        .lock()
        .unwrap()
        .push(waygate_rbac::RoleAssignment {
            id: assignment_id,
            tenant_id: "default".into(),
            role_id,
            subject_sub: "alice".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        });
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/rbac/assignments/{assignment_id}/delete"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        !loc.contains("rbac_error"),
        "assignment delete should succeed: {loc}"
    );
    assert_eq!(
        store.assignments.lock().unwrap().len(),
        0,
        "assignment should be gone"
    );
}

#[tokio::test]
pub(crate) async fn rbac_group_mapping_create_persists_and_redirects() {
    let store = Arc::new(InMemoryRbacStub::default());
    let role_id = seed_role(&store, "ops");
    let group_id = Uuid::new_v4();
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/rbac/group-mappings/create",
        &format!("csrf=dev-csrf&group_id={group_id}&role_id={role_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        !loc.contains("rbac_error"),
        "mapping create should succeed: {loc}"
    );
    let m = store.mappings.lock().unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].group_id, group_id);
    assert_eq!(m[0].role_id, role_id);
}

#[tokio::test]
pub(crate) async fn rbac_group_mapping_delete_persists_and_redirects() {
    let store = Arc::new(InMemoryRbacStub::default());
    let role_id = seed_role(&store, "ops");
    let group_id = Uuid::new_v4();
    store
        .mappings
        .lock()
        .unwrap()
        .push(waygate_rbac::GroupRoleMapping {
            tenant_id: "default".into(),
            group_id,
            role_id,
            created_at: OffsetDateTime::UNIX_EPOCH,
        });
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/rbac/group-mappings/{group_id}/{role_id}/delete"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        !loc.contains("rbac_error"),
        "mapping delete should succeed: {loc}"
    );
    assert_eq!(
        store.mappings.lock().unwrap().len(),
        0,
        "mapping should be gone"
    );
}

#[tokio::test]
pub(crate) async fn rbac_page_renders_assignment_and_mapping_forms_when_roles_exist() {
    let store = Arc::new(InMemoryRbacStub::default());
    seed_role(&store, "ops");
    let app = dashboard_router(state_with_rbac_store(store).await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/rbac").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"action="/admin/rbac/assignments/create""#),
        "assignment composer should render when at least one role exists"
    );
    assert!(
        body.contains(r#"action="/admin/rbac/group-mappings/create""#),
        "group-mapping composer should render when at least one role exists"
    );
}

/// The Decisions badge endpoint returns a plain-text count, is
/// no-store (the 30s cache is server-side, per tenant), and degrades
/// to "0" when no decision stores are configured — the badge is a
/// hint, never an error surface.
#[tokio::test]
pub(crate) async fn decisions_badge_endpoint_returns_zero_without_stores() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/badge/decisions").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.trim(), "0");
}

/// Tab hrefs carry the tenant prefix on the tenant-scoped mount, same
/// as sidebar destinations — second-level navigation must not drop the
/// operator out of their tenant.
#[tokio::test]
pub(crate) async fn tab_bar_hrefs_carry_tenant_prefix() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (_status, body) = body_of(app, "/t/default/scim").await;
    assert!(
        body.contains(
            r#"class="tab tab--active" href="/admin/t/default/scim" aria-current="page""#
        ),
        "Users tab should be active with a tenant-prefixed href",
    );
    // /scim is the Access Control destination default, so the destination
    // header link carries the tenant prefix too.
    assert!(
        body.contains(r#"href="/admin/t/default/scim" aria-current="page""#),
        "Access Control destination should be current with a tenant-prefixed href",
    );
}
