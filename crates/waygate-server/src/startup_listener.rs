//! The HTTP listener, bound before the gateway finishes starting.
//!
//! Upstream servers that verify `X-MCP-Identity` fetch the gateway's keys from
//! its own `/.well-known/jwks.json` the first time they see a token. The
//! upstream pool's first connections carry such tokens, so the listener is
//! bound and serving those keys before the pool dials. Until the complete
//! application is installed, every other path answers `503 Service
//! Unavailable`, which readiness probes already treat as not ready.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use anyhow::Context as _;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use futures::future::BoxFuture;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tower::make::Shared;
use tower::{Service, ServiceExt};
use tower_http::normalize_path::NormalizePath;
use waygate_oidc::SharedIdentityKeyring;

use crate::admission::AdmissionGate;

/// The complete application the listener serves once startup is done.
pub(crate) type GatewayApp = NormalizePath<Router>;

/// What the listener serves while the gateway starts: the identity JWKS when
/// the gateway signs identity tokens, and `503` for everything else.
pub(crate) fn starting_router(keyring: Option<&SharedIdentityKeyring>) -> Router {
    let router = match keyring {
        Some(keyring) => waygate_oidc::jwks_router::<()>(keyring.clone()),
        None => Router::new(),
    };
    router.fallback(|| async { (StatusCode::SERVICE_UNAVAILABLE, "gateway is starting") })
}

/// A bound listener serving [`starting_router`] until [`Self::install`]
/// hands it the complete application.
pub(crate) struct StartupListener {
    local_addr: SocketAddr,
    app: Arc<OnceLock<GatewayApp>>,
    stop: CancellationToken,
    task: JoinHandle<std::io::Result<()>>,
}

impl StartupListener {
    /// Bind `addr` and start serving `starting` on it.
    pub(crate) async fn bind(
        addr: SocketAddr,
        starting: Router,
        admission: AdmissionGate,
    ) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind {addr}"))?;
        let local_addr = listener.local_addr().context("read the bound address")?;
        let app = Arc::new(OnceLock::new());
        let stop = CancellationToken::new();
        let service = Switch {
            app: app.clone(),
            starting,
            admission,
        };
        let server = axum::serve(listener, Shared::new(service))
            .with_graceful_shutdown(stop.clone().cancelled_owned());
        let task = tokio::spawn(async move { server.await });
        Ok(Self {
            local_addr,
            app,
            stop,
            task,
        })
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serve `app` for every request from now on. Startup installs it once.
    pub(crate) fn install(&self, app: GatewayApp) {
        if self.app.set(app).is_err() {
            unreachable!("the gateway application is installed once");
        }
    }

    /// Cancelling the returned token starts the server's graceful shutdown.
    pub(crate) fn stop_token(&self) -> CancellationToken {
        self.stop.clone()
    }

    /// The server task, which ends once graceful shutdown has drained.
    pub(crate) fn into_task(self) -> JoinHandle<std::io::Result<()>> {
        self.task
    }
}

#[derive(Clone)]
struct Switch {
    app: Arc<OnceLock<GatewayApp>>,
    starting: Router,
    admission: AdmissionGate,
}

impl Service<Request> for Switch {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let admission = self.admission.clone();
        let app = self.app.get().cloned();
        let starting = self.starting.clone();
        Box::pin(async move {
            if !admission.admits(request.method(), request.uri()).await {
                return Ok((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "gateway admission is closed",
                )
                    .into_response());
            }
            match app {
                Some(app) => Ok(app.oneshot(request).await.into_response()),
                None => starting.oneshot(request).await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tower::Layer;
    use tower_http::normalize_path::NormalizePathLayer;

    async fn get_text(addr: SocketAddr, path: &str) -> (u16, String) {
        let response = reqwest::get(format!("http://{addr}{path}"))
            .await
            .expect("request reaches the listener");
        let status = response.status().as_u16();
        (status, response.text().await.expect("response body"))
    }

    fn any_port() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn starting() -> Router {
        Router::new()
            .route("/.well-known/jwks.json", get(|| async { "keys" }))
            .fallback(|| async { (StatusCode::SERVICE_UNAVAILABLE, "gateway is starting") })
    }

    fn app() -> GatewayApp {
        NormalizePathLayer::trim_trailing_slash().layer(
            Router::new()
                .route("/.well-known/jwks.json", get(|| async { "app keys" }))
                .route("/readyz", get(|| async { "ready" })),
        )
    }

    #[tokio::test]
    async fn keys_are_served_before_the_application_is_installed() {
        let listener = StartupListener::bind(any_port(), starting(), AdmissionGate::default())
            .await
            .expect("bind");
        let addr = listener.local_addr();

        assert_eq!(
            get_text(addr, "/.well-known/jwks.json").await,
            (200, "keys".to_owned())
        );
        assert_eq!(get_text(addr, "/readyz").await.0, 503);
        assert_eq!(get_text(addr, "/mcp").await.0, 503);

        listener.stop_token().cancel();
        listener.into_task().await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_installed_application_serves_every_later_request() {
        let listener = StartupListener::bind(any_port(), starting(), AdmissionGate::default())
            .await
            .expect("bind");
        let addr = listener.local_addr();

        listener.install(app());

        assert_eq!(
            get_text(addr, "/.well-known/jwks.json").await,
            (200, "app keys".to_owned())
        );
        assert_eq!(get_text(addr, "/readyz/").await, (200, "ready".to_owned()));
        assert_eq!(get_text(addr, "/unknown").await.0, 404);

        listener.stop_token().cancel();
        listener.into_task().await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn without_identity_keys_the_starting_listener_serves_nothing() {
        let listener =
            StartupListener::bind(any_port(), starting_router(None), AdmissionGate::default())
                .await
                .expect("bind");
        let addr = listener.local_addr();

        assert_eq!(get_text(addr, "/.well-known/jwks.json").await.0, 503);

        listener.stop_token().cancel();
        listener.into_task().await.unwrap().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn admission_covers_both_routers_and_every_business_method_before_handlers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("admission");
        let hits = Arc::new(AtomicUsize::new(0));
        let guarded = || {
            let hits = hits.clone();
            Router::new()
                .route("/.well-known/jwks.json", get(|| async { "keys" }))
                .route("/healthz", get(|| async { "alive" }))
                .route("/readyz", get(|| async { "ready" }))
                .fallback(move || {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        "business handler"
                    }
                })
        };
        let listener =
            StartupListener::bind(any_port(), starting(), crate::admission::fixture(&path))
                .await
                .unwrap();
        let addr = listener.local_addr();
        let client = reqwest::Client::new();
        for installed in [false, true] {
            if installed {
                listener.install(NormalizePathLayer::trim_trailing_slash().layer(guarded()));
            }
            for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
                for safe in ["/.well-known/jwks.json", "/healthz", "/readyz"] {
                    let response = client
                        .request(method.clone(), format!("http://{addr}{safe}"))
                        .send()
                        .await
                        .unwrap();
                    let expected = if installed || safe == "/.well-known/jwks.json" {
                        200
                    } else {
                        503
                    };
                    assert_eq!(response.status(), expected);
                }
            }
            for method in [
                reqwest::Method::GET,
                reqwest::Method::POST,
                reqwest::Method::PUT,
                reqwest::Method::PATCH,
                reqwest::Method::DELETE,
                reqwest::Method::OPTIONS,
                reqwest::Method::HEAD,
                reqwest::Method::CONNECT,
                reqwest::Method::TRACE,
            ] {
                for business in [
                    "/mcp",
                    "/mcp/",
                    "/api/v1/admin",
                    "/admin/login",
                    "/v1/chat/completions",
                    "/files/upload",
                    "/oauth/token",
                    "/oauth/callback",
                    "/scim/v2/Users",
                    "/metrics",
                    "/unknown",
                ] {
                    let response = client
                        .request(method.clone(), format!("http://{addr}{business}"))
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(response.status(), 503, "{method} {business}");
                }
            }
            for safe in ["/.well-known/jwks.json", "/healthz", "/readyz"] {
                assert_eq!(
                    client
                        .post(format!("http://{addr}{safe}"))
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    503
                );
            }
            assert_eq!(hits.load(Ordering::SeqCst), 0);
        }
        listener.stop_token().cancel();
        listener.into_task().await.unwrap().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn atomic_file_replacement_controls_new_work_without_restarting_or_cancelling_inflight() {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("admission");
        let replace = |content: &[u8]| {
            let mut file = tempfile::NamedTempFile::new_in(root.path()).unwrap();
            file.write_all(content).unwrap();
            file.persist(&path).unwrap();
        };
        let entered = Arc::new(tokio::sync::Notify::new());
        let finish = Arc::new(tokio::sync::Notify::new());
        let app = Router::new().route(
            "/mcp",
            get({
                let entered = entered.clone();
                let finish = finish.clone();
                move || {
                    let entered = entered.clone();
                    let finish = finish.clone();
                    async move {
                        entered.notify_one();
                        finish.notified().await;
                        "completed"
                    }
                }
            }),
        );
        let listener =
            StartupListener::bind(any_port(), starting(), crate::admission::fixture(&path))
                .await
                .unwrap();
        listener.install(NormalizePathLayer::trim_trailing_slash().layer(app));
        let addr = listener.local_addr();
        assert_eq!(get_text(addr, "/mcp").await.0, 503);
        replace(b"open\n");
        let active = tokio::spawn(get_text(addr, "/mcp"));
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        replace(b"closed\n");
        assert_eq!(get_text(addr, "/mcp").await.0, 503);
        finish.notify_one();
        assert_eq!(active.await.unwrap(), (200, "completed".to_owned()));
        replace(b"open\n");
        finish.notify_one();
        assert_eq!(get_text(addr, "/mcp").await, (200, "completed".to_owned()));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(get_text(addr, "/mcp").await.0, 503);
        listener.stop_token().cancel();
        listener.into_task().await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_second_bind_of_the_same_address_fails_at_startup() {
        let first = StartupListener::bind(any_port(), starting(), AdmissionGate::default())
            .await
            .expect("bind");
        let taken = first.local_addr();

        let error = StartupListener::bind(taken, starting(), AdmissionGate::default())
            .await
            .err()
            .expect("the address is in use");
        assert!(error.to_string().contains(&taken.to_string()), "{error:#}");

        first.stop_token().cancel();
        first.into_task().await.unwrap().unwrap();
    }
}
