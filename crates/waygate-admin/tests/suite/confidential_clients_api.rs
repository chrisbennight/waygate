//! `/api/v1/admin/confidential-clients` route-level coverage (EMA).
//!
//! Uses an in-memory `ConfidentialClientStore` fake so the test needs no live
//! Postgres — the Pg impl is exercised by the `waygate-as` integration suite.
//! Pins: 503 without a store; scope-gating (mcp:read insufficient, mcp:admin
//! ok); create mints a one-shot client_secret and never leaks it on list;
//! create with a JWKS; "no credential" rejected; duplicate → 409; delete
//! removes (and a missing delete → 404).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use time::OffsetDateTime;
use tower::util::ServiceExt;

use waygate_admin::{api_router, AdminState};
use waygate_as::{
    ConfidentialClient, ConfidentialClientError, ConfidentialClientStore,
    SharedConfidentialClientStore,
};
use waygate_oidc::Principal;
use waygate_upstream::pool::UpstreamPool;

const PATH: &str = "/api/v1/admin/confidential-clients";

#[derive(Default, Clone)]
struct MemoryClientStore {
    rows: Arc<Mutex<Vec<ConfidentialClient>>>,
}

#[async_trait]
impl ConfidentialClientStore for MemoryClientStore {
    async fn upsert(
        &self,
        client_id: &str,
        secret_hash: Option<&str>,
        jwks: Option<&Value>,
    ) -> Result<(), ConfidentialClientError> {
        let mut g = self.rows.lock().unwrap();
        if let Some(r) = g.iter_mut().find(|r| r.client_id == client_id) {
            r.secret_hash = secret_hash.map(str::to_owned);
            r.jwks = jwks.cloned();
        } else {
            g.push(ConfidentialClient {
                client_id: client_id.to_owned(),
                secret_hash: secret_hash.map(str::to_owned),
                jwks: jwks.cloned(),
                created_at: OffsetDateTime::now_utc(),
            });
        }
        Ok(())
    }

    async fn insert(
        &self,
        client_id: &str,
        secret_hash: Option<&str>,
        jwks: Option<&Value>,
    ) -> Result<bool, ConfidentialClientError> {
        let mut g = self.rows.lock().unwrap();
        if g.iter().any(|r| r.client_id == client_id) {
            return Ok(false);
        }
        g.push(ConfidentialClient {
            client_id: client_id.to_owned(),
            secret_hash: secret_hash.map(str::to_owned),
            jwks: jwks.cloned(),
            created_at: OffsetDateTime::now_utc(),
        });
        Ok(true)
    }

    async fn get(
        &self,
        client_id: &str,
    ) -> Result<Option<ConfidentialClient>, ConfidentialClientError> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.client_id == client_id)
            .cloned())
    }

    async fn list(&self) -> Result<Vec<ConfidentialClient>, ConfidentialClientError> {
        Ok(self.rows.lock().unwrap().clone())
    }

    async fn delete(&self, client_id: &str) -> Result<bool, ConfidentialClientError> {
        let mut g = self.rows.lock().unwrap();
        let before = g.len();
        g.retain(|r| r.client_id != client_id);
        Ok(g.len() < before)
    }
}

fn principal_with(scopes: &[&str]) -> Principal {
    Principal {
        sub: "admin@example.com".into(),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

async fn state_with(store: Option<SharedConfidentialClientStore>) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // Real in-memory sink: create/delete use fail-closed record_required, which
    // NullSink rejects by design.
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
        .with_confidential_clients(store),
    )
}

fn post(
    client_id: &str,
    generate_secret: bool,
    jwks: Option<Value>,
    scopes: &[&str],
) -> Request<Body> {
    let mut body = json!({ "client_id": client_id, "generate_secret": generate_secret });
    if let Some(j) = jwks {
        body["jwks"] = j;
    }
    let mut req = Request::builder()
        .method("POST")
        .uri(PATH)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(principal_with(scopes));
    req
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn create_503s_without_store() {
    let app = api_router(state_with(None).await);
    let resp = app
        .oneshot(post("app-1", true, None, &["mcp:admin"]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn create_requires_admin_scope() {
    let store: SharedConfidentialClientStore = Arc::new(MemoryClientStore::default());
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(post("app-1", true, None, &["mcp:read"]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_mints_secret_once_and_list_hides_it() {
    let store: SharedConfidentialClientStore = Arc::new(MemoryClientStore::default());
    let app = api_router(state_with(Some(store)).await);

    let resp = app
        .clone()
        .oneshot(post(
            "https://app.example/client.json",
            true,
            None,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let secret = body.get("client_secret").and_then(Value::as_str);
    assert!(
        secret.is_some_and(|s| s.starts_with("cs_")),
        "create must return a one-shot client_secret: {body}",
    );
    assert_eq!(
        body.get("auth_methods").and_then(Value::as_array),
        Some(&vec![json!("client_secret")]),
    );

    // List must NOT leak the secret/hash — only has_secret.
    let mut lreq = Request::builder().uri(PATH).body(Body::empty()).unwrap();
    lreq.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let lresp = app.oneshot(lreq).await.unwrap();
    assert_eq!(lresp.status(), StatusCode::OK);
    let list = body_json(lresp).await;
    let clients = list.get("clients").and_then(Value::as_array).unwrap();
    assert_eq!(clients.len(), 1);
    let c = &clients[0];
    assert_eq!(c.get("has_secret").and_then(Value::as_bool), Some(true));
    assert_eq!(c.get("has_jwks").and_then(Value::as_bool), Some(false));
    let serialized = serde_json::to_string(&list).unwrap();
    assert!(
        !serialized.contains("cs_") && !serialized.contains("secret_hash"),
        "list must never include secret material: {serialized}",
    );
}

#[tokio::test]
async fn create_with_jwks_sets_private_key_jwt() {
    let store: SharedConfidentialClientStore = Arc::new(MemoryClientStore::default());
    let app = api_router(state_with(Some(store)).await);
    let jwks = json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc", "kid": "k1"}]});
    let resp = app
        .oneshot(post("app-pkjwt", false, Some(jwks), &["mcp:admin"]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(
        body.get("auth_methods").and_then(Value::as_array),
        Some(&vec![json!("private_key_jwt")]),
    );
    assert!(body.get("client_secret").is_none());
}

#[tokio::test]
async fn create_rejects_no_credential() {
    let store: SharedConfidentialClientStore = Arc::new(MemoryClientStore::default());
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(post("app-x", false, None, &["mcp:admin"]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_duplicate_conflicts() {
    let store: SharedConfidentialClientStore = Arc::new(MemoryClientStore::default());
    let app = api_router(state_with(Some(store)).await);
    let r1 = app
        .clone()
        .oneshot(post("dup-1", true, None, &["mcp:admin"]))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::CREATED);
    let r2 = app
        .oneshot(post("dup-1", true, None, &["mcp:admin"]))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_removes_then_404s() {
    let store: SharedConfidentialClientStore = Arc::new(MemoryClientStore::default());
    let app = api_router(state_with(Some(store)).await);

    app.clone()
        .oneshot(post("del-1", true, None, &["mcp:admin"]))
        .await
        .unwrap();

    let mut dreq = Request::builder()
        .method("DELETE")
        .uri(format!("{PATH}?client_id=del-1"))
        .body(Body::empty())
        .unwrap();
    dreq.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let dresp = app.clone().oneshot(dreq).await.unwrap();
    assert_eq!(dresp.status(), StatusCode::NO_CONTENT);

    // Second delete → 404.
    let mut dreq2 = Request::builder()
        .method("DELETE")
        .uri(format!("{PATH}?client_id=del-1"))
        .body(Body::empty())
        .unwrap();
    dreq2
        .extensions_mut()
        .insert(principal_with(&["mcp:admin"]));
    let dresp2 = app.oneshot(dreq2).await.unwrap();
    assert_eq!(dresp2.status(), StatusCode::NOT_FOUND);
}
