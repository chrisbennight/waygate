//! Exercises the `tower-http` `ServeDir` mount at `/static`.
//!
//! `dashboard_router` nests `tower_http::services::ServeDir` at `/static` to
//! ship the dashboard's CSS/JS/SVG assets. The other admin tests render HTML
//! through the askama handlers but never request a static asset, so a
//! tower-http regression — wrong content-type, body truncation, panic on
//! 404, traversal vulnerability — would not trip CI.
//!
//! This test stands up the real dashboard router, lets `ServeDir` resolve
//! the static directory exactly the way the running server does (via
//! `GATEWAY_STATIC_DIR` env override, falling back to
//! `waygate-admin/static`), and asserts:
//!
//! 1. A request for a known asset returns 200 and the asset bytes match
//!    the file on disk. We assert the invariant ("ServeDir serves the
//!    bytes pointed at by `static_dir`") rather than hardcoding asset
//!    contents — the asset files are free to change without churning
//!    this test.
//! 2. A request for a missing asset returns 404 rather than a panic or
//!    5xx, which is `ServeDir`'s documented behavior.
//!
//! Side-effect rules: no network, no DB, no real OIDC. State is built
//! through the same fakes the sibling `dashboard_render/` suite uses;
//! `DashboardAuth::Disabled` injects a synthetic principal so the route
//! goes straight to the static service without an OIDC round-trip.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

use waygate_admin::{dashboard_router, AdminState, DashboardAuth};
use waygate_upstream::pool::UpstreamPool;

async fn empty_state() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(AdminState::new(
        pool,
        None,
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

/// Resolve the static dir the same way `dashboard::router` does at runtime.
/// Reading from `GATEWAY_STATIC_DIR` (when set) lets the test track the
/// production override; falling back to `CARGO_MANIFEST_DIR/static` matches
/// the in-repo default and the `cargo test` working environment.
fn resolved_static_dir() -> PathBuf {
    std::env::var("GATEWAY_STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"))
}

#[tokio::test]
async fn serve_dir_returns_known_static_asset_with_disk_bytes() {
    let static_dir = resolved_static_dir();
    // `base.css` is one of the dashboard's load-bearing assets — every
    // template references it. If ServeDir stops finding it, every admin
    // page renders unstyled.
    let asset_rel = "css/base.css";
    let asset_path = static_dir.join(asset_rel);
    let expected_bytes =
        std::fs::read(&asset_path).expect("read static asset bytes from on-disk source of truth");

    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/static/{asset_rel}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot to /static");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /static/{asset_rel} should 200 (status was {})",
        resp.status()
    );

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/css"),
        "expected text/css content-type, got {content_type:?}"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .expect("collect response body");
    assert_eq!(
        body_bytes.as_ref(),
        expected_bytes.as_slice(),
        "ServeDir body must match the bytes of {asset_path:?}"
    );
}

#[tokio::test]
async fn serve_dir_returns_404_for_missing_asset() {
    // ServeDir's documented contract: missing files surface as 404, not as
    // a panic or 5xx. A regression that turned this into a 500 would page
    // operators every time someone mis-typed an asset URL.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static/this-file-does-not-exist.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot to /static missing");

    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "missing static asset must 404, got {}",
        resp.status()
    );
}
