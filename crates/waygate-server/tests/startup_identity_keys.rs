//! An upstream that verifies `X-MCP-Identity` can fetch the gateway's keys
//! while the gateway is still making its first connection to it.

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;

/// What the upstream saw on the gateway's first request to it.
#[derive(Clone, Debug)]
struct FirstContact {
    carried_identity: bool,
    jwks_status: Option<u16>,
    jwks_has_keys: bool,
}

#[derive(Clone)]
struct Upstream {
    gateway_jwks: String,
    first: Arc<Mutex<Option<FirstContact>>>,
    seen: Arc<tokio::sync::Notify>,
}

/// Like an identity-verifying MCP server meeting an unknown token: fetch the
/// issuer's keys before deciding. The answer is always a refusal; only what
/// the key fetch returned matters here.
async fn verify_on_first_contact(
    State(upstream): State<Upstream>,
    headers: HeaderMap,
) -> StatusCode {
    if upstream.first.lock().unwrap().is_some() {
        return StatusCode::UNAUTHORIZED;
    }
    let fetched = reqwest::get(&upstream.gateway_jwks).await;
    let (jwks_status, jwks_has_keys) = match fetched {
        Ok(response) => {
            let status = response.status().as_u16();
            let body: serde_json::Value = response.json().await.unwrap_or_default();
            let has_keys = body["keys"].as_array().is_some_and(|keys| !keys.is_empty());
            (Some(status), has_keys)
        }
        Err(_) => (None, false),
    };
    *upstream.first.lock().unwrap() = Some(FirstContact {
        carried_identity: headers.contains_key("x-mcp-identity"),
        jwks_status,
        jwks_has_keys,
    });
    upstream.seen.notify_one();
    StatusCode::UNAUTHORIZED
}

fn free_local_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a port")
        .local_addr()
        .expect("reserved address")
        .port()
}

#[tokio::test]
async fn upstreams_can_fetch_the_gateway_keys_during_its_first_connection() {
    let gateway_port = free_local_port();
    let upstream = Upstream {
        gateway_jwks: format!("http://127.0.0.1:{gateway_port}/.well-known/jwks.json"),
        first: Arc::default(),
        seen: Arc::default(),
    };
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream address");
    let app = Router::new()
        .route("/mcp", post(verify_on_first_contact))
        .with_state(upstream.clone());
    let upstream_task = tokio::spawn(async move { axum::serve(upstream_listener, app).await });

    let servers = tempfile::tempdir().expect("servers dir");
    std::fs::write(
        servers.path().join("verifier.yaml"),
        format!(
            "name: verifier\ntransport: http\ntrust: internal\nurl: http://{upstream_addr}/mcp\ntools: []\n"
        ),
    )
    .expect("write manifest");
    let policies = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../waygate-authz/tests/fixtures/policies");
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .expect("generate identity key")
        .serialize_pem();

    let mut gateway = tokio::process::Command::new(env!("CARGO_BIN_EXE_gateway-server"));
    gateway
        .env_clear()
        .env("GATEWAY_AUTH_MODE", "disabled")
        .env("GATEWAY_LISTEN_ADDR", format!("127.0.0.1:{gateway_port}"))
        .env(
            "GATEWAY_PUBLIC_URL",
            format!("http://127.0.0.1:{gateway_port}"),
        )
        .env("GATEWAY_MCP_ALLOWED_HOSTS", "")
        .env("GATEWAY_SERVERS_DIR", servers.path())
        .env("GATEWAY_POLICIES_DIR", &policies)
        .env("GATEWAY_IDENTITY_SIGNING_KEY_PEM", signing_key)
        .env("GATEWAY_IDENTITY_KID", "startup-test")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut gateway = gateway.spawn().expect("start gateway");

    tokio::time::timeout(Duration::from_secs(120), upstream.seen.notified())
        .await
        .expect("the gateway connects to its upstream while starting");
    let first = upstream
        .first
        .lock()
        .unwrap()
        .clone()
        .expect("first contact");

    assert!(
        first.carried_identity,
        "the first connection carries an identity token: {first:?}"
    );
    assert_eq!(
        first.jwks_status,
        Some(200),
        "the gateway serves its keys while it connects: {first:?}"
    );
    assert!(
        first.jwks_has_keys,
        "the served key set is not empty: {first:?}"
    );

    gateway.start_kill().expect("stop gateway");
    gateway.wait().await.expect("reap gateway");
    upstream_task.abort();
}
