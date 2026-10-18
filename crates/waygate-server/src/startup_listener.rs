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
    pub(crate) async fn bind(addr: SocketAddr, starting: Router) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind {addr}"))?;
        let local_addr = listener.local_addr().context("read the bound address")?;
        let app = Arc::new(OnceLock::new());
        let stop = CancellationToken::new();
        let service = Switch {
            app: app.clone(),
            starting,
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
}

impl Service<Request> for Switch {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        match self.app.get() {
            Some(app) => {
                let app = app.clone();
                Box::pin(async move { Ok(app.oneshot(request).await.into_response()) })
            }
            None => {
                let starting = self.starting.clone();
                Box::pin(async move { starting.oneshot(request).await })
            }
        }
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
        let listener = StartupListener::bind(any_port(), starting())
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
        let listener = StartupListener::bind(any_port(), starting())
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
        let listener = StartupListener::bind(any_port(), starting_router(None))
            .await
            .expect("bind");
        let addr = listener.local_addr();

        assert_eq!(get_text(addr, "/.well-known/jwks.json").await.0, 503);

        listener.stop_token().cancel();
        listener.into_task().await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_second_bind_of_the_same_address_fails_at_startup() {
        let first = StartupListener::bind(any_port(), starting())
            .await
            .expect("bind");
        let taken = first.local_addr();

        let error = StartupListener::bind(taken, starting())
            .await
            .err()
            .expect("the address is in use");
        assert!(error.to_string().contains(&taken.to_string()), "{error:#}");

        first.stop_token().cancel();
        first.into_task().await.unwrap().unwrap();
    }
}
