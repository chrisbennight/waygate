//! Composes the AS routes into a single [`axum::Router<()>`] that
//! `waygate-server` nests at the top level.
//!
//! Routes:
//! * `GET /oauth/authorize` — browser entry point.
//! * `GET /oauth/callback` — upstream returns here.
//! * `POST /oauth/token` — token endpoint (auth-code + refresh grants).
//! * `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use sqlx::postgres::PgPool;
use tower_http::cors::{Any, CorsLayer};

use waygate_evidence::audit::SharedEvidence;
use waygate_oidc::{IdTokenValidator, SharedIdentityIssuer};

use crate::authorize;
use crate::callback;
use crate::cimd::CimdFetcher;
use crate::cimd_dev_host;
use crate::config::AsConfig;
use crate::consent::{PgConsentStore, SharedConsentStore};
use crate::consent_pending::{PgConsentPendingStore, SharedConsentPendingStore};
use crate::consent_screen;
use crate::metadata;
use crate::sessions::{PgUpstreamSessionStore, SharedUpstreamSessionStore};
use crate::store::OauthStore;
use crate::token;

/// Shared state handed to every `/oauth/*` handler. Cheap to clone
/// (everything inside is `Arc`-wrapped or already `Clone`).
#[derive(Clone)]
pub struct AsState {
    pub config: Arc<AsConfig>,
    pub store: OauthStore,
    pub cimd: Arc<CimdFetcher>,
    /// Shared bounded client for upstream token endpoint calls. Redirects are
    /// disabled at construction so codes and refresh tokens are never replayed
    /// to a different origin.
    pub token_http: reqwest::Client,
    pub identity_issuer: SharedIdentityIssuer,
    /// Validates the `id_token` Authentik returns at `/oauth/callback`.
    /// Audience is the gateway's upstream `client_id`; issuer is
    /// `AUTHENTIK_ISSUER`. Without this we'd be trusting unverified JWT
    /// payload claims to mint first-party bearer tokens.
    pub upstream_id_token_validator: Arc<IdTokenValidator>,
    /// Write-side recorder for `OAuthEvent`-category audit rows
    /// (`/oauth/token`, `/oauth/callback`). Always populated;
    /// `waygate-server` passes the shared `audit_sink` so every
    /// category lands in the same `audit_log` table and exporter
    /// pipeline. Tests can pass `Arc::new(waygate_evidence::audit::NullSink)`
    /// — non-required writes on `NullSink` are measured log-and-drop noops.
    pub evidence: SharedEvidence,
    /// Persistent upstream-session store (Tier-A). On every
    /// successful `/oauth/callback`, the encrypted upstream token
    /// envelope is UPSERTed here in addition to the existing
    /// `oauth_codes.upstream_tokens_ciphertext` write. This durable
    /// row is what the refresh-on-demand path and the admin session
    /// listing read; the `oauth_codes` copy is discarded unread once
    /// the code is redeemed.
    pub upstream_sessions: SharedUpstreamSessionStore,
    /// OAuth consent grant store. Written at `/oauth/callback` after
    /// id-token validation and before the gateway mints its own
    /// authorization code — records that this CIMD client has been
    /// authorized to act on behalf of this user with these scopes.
    /// The interactive consent screen and the gateway-wide
    /// `require_explicit_consent` flag layer on top of the same
    /// rows. Same `SharedConsentStore` value is also handed to
    /// `waygate-admin` so list + revoke endpoints serve from the
    /// same table.
    pub consent: SharedConsentStore,
    /// Pending-consent store backing the interactive `/oauth/consent`
    /// screen. Only consulted when `config.require_explicit_consent`
    /// is on; otherwise stays unused.
    pub consent_pending: SharedConsentPendingStore,
    /// Enterprise-Managed Authorization (EMA) dependencies for the
    /// `/oauth/token` token-exchange (ID-JAG mint) grant. `Some(_)` ⇒
    /// the grant is enabled; `None` ⇒ it returns `unsupported_grant_type`.
    pub ema: Option<crate::ema::EmaDeps>,
}

/// Build the axum router for the AS. Caller nests it at the gateway root.
pub fn build_router(
    mut config: AsConfig,
    pool: PgPool,
    token_http: reqwest::Client,
    identity_issuer: SharedIdentityIssuer,
    upstream_id_token_validator: Arc<IdTokenValidator>,
    evidence: SharedEvidence,
    ema: Option<crate::ema::EmaDeps>,
) -> Router<()> {
    let store = OauthStore::new(pool.clone());
    // Tier-A durable sessions share the same pool as the OAuth store —
    // they're peers in the gateway's own DB. Constructed alongside so
    // callback.rs can hit both inside a single request.
    let upstream_sessions: SharedUpstreamSessionStore =
        Arc::new(PgUpstreamSessionStore::new(pool.clone()));
    // Consent grants share the same pool — they're
    // peers of `oauth_codes` / `user_upstream_sessions` in
    // the AS's own DB. Constructed alongside so callback.rs
    // can UPSERT inside the same request.
    let consent: SharedConsentStore = Arc::new(PgConsentStore::new(pool.clone()));
    // Pending-consent rows share the same pool.
    let consent_pending: SharedConsentPendingStore = Arc::new(PgConsentPendingStore::new(pool));

    // Canonicalize + validate the dev-host directory at boot so misconfiguration
    // surfaces as a single WARN rather than silent 404s. Order matters: the
    // fetcher needs the canonicalized path (plus the AS's own origin) so it
    // can short-circuit same-origin CIMD fetches to a direct disk read.
    let dev_host_enabled = if let Some(dir) = config.cimd_dev_doc_dir.as_ref() {
        match cimd_dev_host::canonicalize_doc_dir(dir) {
            Some(canon) => {
                tracing::info!(path = %canon.display(), "CIMD dev-host enabled at /cimd/dev-clients/*");
                config.cimd_dev_doc_dir = Some(canon);
                true
            }
            None => {
                config.cimd_dev_doc_dir = None;
                false
            }
        }
    } else {
        false
    };

    // Parse the AS's own public URL into an `Origin` once so the fetcher can
    // do a same-origin check in O(1). If `public_url` doesn't parse we just
    // skip the shortcut — `AsConfig::validate` already rejects an empty value
    // on the startup path, so this is purely defensive.
    let self_origin = url::Url::parse(&config.public_url).ok().map(|u| u.origin());
    let cimd = CimdFetcher::new(
        config.cimd_allowed_hosts.clone(),
        self_origin,
        config.cimd_dev_doc_dir.clone(),
    );

    let state = AsState {
        config: Arc::new(config),
        store,
        cimd,
        token_http,
        identity_issuer,
        upstream_id_token_validator,
        evidence,
        upstream_sessions,
        consent,
        consent_pending,
        ema,
    };

    // CORS: the token and metadata endpoints are called from browser-based
    // MCP clients (Claude Code's web flow, MCP Inspector). `Any` origin +
    // method is standard for public OAuth endpoints — every browser already
    // treats them as opaque.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let mut router = Router::new()
        .route("/oauth/authorize", get(authorize::handler))
        .route("/oauth/callback", get(callback::handler))
        .route("/oauth/token", post(token::handler))
        // Interactive consent screen. GET
        // renders the approve/deny form for a given
        // pending token; POST consumes the user's
        // decision. Mounted unconditionally — when
        // `require_explicit_consent` is off the routes
        // exist but nothing 302s to them.
        .route(
            "/oauth/consent",
            get(consent_screen::handler_get).post(consent_screen::handler_post),
        )
        .merge(metadata::router());

    if dev_host_enabled {
        router = router.route("/cimd/dev-clients/{name}", get(cimd_dev_host::handler));
    }

    router.layer(cors).with_state(state)
}
