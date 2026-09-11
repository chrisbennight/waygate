//! axum middleware that validates `Authorization: Bearer` tokens and injects
//! the resulting [`Principal`] into the request extensions. On failure it
//! responds `401` with `WWW-Authenticate` carrying the protected-resource
//! metadata URL per RFC 9728.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use waygate_telemetry::metrics::{record_bearer_validation, BearerOutcome};

use crate::enricher::PrincipalEnricher;
use crate::header_validator::HeaderValidator;
use crate::{AuthMethod, Principal};

#[derive(Clone, Debug)]
pub enum AuthMode {
    Enforce,
    /// Accept every request with a synthetic `dev@local` principal. Intended
    /// only for local dev (no IdP configured). Emits a warning every request
    /// so it's impossible to miss in logs.
    Disabled,
}

/// Outcome facts handed to an [`AuthAttemptRecorder`] for every bearer
/// validation attempt the middleware processes. Lets `waygate-server`
/// (or any caller wiring this crate into a wider system) record an
/// `AuthAttempt`-category audit row without `waygate-oidc` taking a
/// direct dependency on `waygate-mcp::audit` (which would form a
/// cycle, since `waygate-mcp` depends on `waygate-oidc`).
#[derive(Debug)]
pub enum AuthAttemptOutcome {
    /// The Authorization header was missing entirely.
    MissingHeader,
    /// Header present but malformed (non-UTF-8 / wrong scheme / every
    /// validator returned a client-error rejection). The `reason`
    /// carries the validator's error string.
    Rejected,
    /// At least one validator hit an infra error (HTTP / JWKS /
    /// discovery) and no validator accepted. Surfaced to the caller
    /// as HTTP 503.
    InfraUnavailable,
}

/// Recorder for [`AuthAttemptOutcome`] events. Default is no-op; the
/// composition root (`waygate-server::main.rs`) wires a real recorder
/// that translates outcomes into `AuditEvent`s with
/// `EvidenceCategory::AuthAttempt`. Successful validation is *not*
/// surfaced here — every accepted request immediately produces an
/// `Invocation`-category row downstream that already carries the
/// principal, and emitting an `AuthAttemptAccepted` row per request
/// would 2× the audit-log volume with no security signal.
#[async_trait::async_trait]
pub trait AuthAttemptRecorder: Send + Sync + 'static {
    async fn record(&self, outcome: AuthAttemptOutcome, reason: String);
}

/// Axum-layer configuration. Build with [`BearerLayer::enforce`] or
/// [`BearerLayer::disabled`], then apply to a router by calling
/// `.layer(layer.into_axum_layer())`.
#[derive(Clone)]
pub struct BearerLayer {
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    validators: Vec<Arc<dyn HeaderValidator>>,
    resource_metadata_url: String,
    /// Optional `scope` parameter to include in the `WWW-Authenticate`
    /// header on 401 responses. Per MCP `2025-11-25`
    /// (`/specification/2025-11-25/basic/authorization#authorization-server-discovery`),
    /// servers SHOULD include `scope=` so clients know the minimum scopes
    /// to request during the initial authorization flow without guessing.
    /// `None` ⇒ omit the parameter (pre-2025-11-25 behaviour).
    scope_hint: Option<String>,
    mode: AuthMode,
    /// Optional `AuthAttemptRecorder` invoked for every failed bearer
    /// validation. `None` ⇒ rejection paths are still WWW-Authenticate
    /// 401/503 responses but produce no durable audit row.
    attempt_recorder: Option<Arc<dyn AuthAttemptRecorder>>,
    /// Optional [`PrincipalEnricher`] invoked after a
    /// validator accepts the token. `None` ⇒ principals reach
    /// downstream handlers without SCIM-resolved attrs (the existing
    /// behaviour). When wired, the enricher runs best-effort —
    /// failures inside it leave the principal unchanged.
    enricher: Option<Arc<dyn PrincipalEnricher>>,
}

impl BearerLayer {
    pub fn enforce(
        validator: Arc<dyn HeaderValidator>,
        resource_metadata_url: impl Into<String>,
    ) -> Self {
        Self::enforce_multi(vec![validator], resource_metadata_url)
    }

    /// Like [`Self::enforce`] but tries each validator in order. Used during
    /// the gateway-as-AS cutover: the request is accepted if *any* validator
    /// passes, so old Authentik-issued tokens and new gateway-issued tokens
    /// both work for the flip window. With the [`HeaderValidator`] trait,
    /// the chain also mixes validator *types* — e.g. JWT-backed OAuth and
    /// table-backed API keys side by side.
    pub fn enforce_multi(
        validators: Vec<Arc<dyn HeaderValidator>>,
        resource_metadata_url: impl Into<String>,
    ) -> Self {
        assert!(
            !validators.is_empty(),
            "enforce_multi requires at least one validator",
        );
        Self {
            inner: Arc::new(Inner {
                validators,
                resource_metadata_url: resource_metadata_url.into(),
                scope_hint: None,
                mode: AuthMode::Enforce,
                attempt_recorder: None,
                enricher: None,
            }),
        }
    }

    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(Inner {
                validators: Vec::new(),
                resource_metadata_url: String::new(),
                scope_hint: None,
                mode: AuthMode::Disabled,
                attempt_recorder: None,
                enricher: None,
            }),
        }
    }

    /// Set the `scope` parameter included in the `WWW-Authenticate` header
    /// on 401 responses (MCP `2025-11-25` SHOULD; see
    /// [`Inner::scope_hint`]). Typical value: a space-separated list like
    /// `"mcp:invoke mcp:read"` naming the baseline scopes a fresh client
    /// should request. Step-up flows return their own per-request scope
    /// via the 403 `insufficient_scope` challenge, not this hint.
    pub fn with_scope_hint(self, hint: impl Into<String>) -> Self {
        let hint = hint.into();
        let mut inner = Arc::try_unwrap(self.inner).unwrap_or_else(|arc| (*arc).clone());
        inner.scope_hint = if hint.is_empty() { None } else { Some(hint) };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Attach an [`AuthAttemptRecorder`] so failed bearer validations
    /// produce durable `AuthAttempt`-category audit rows in addition to
    /// the existing 401/503 response + Prometheus counter. The recorder
    /// is invoked best-effort — failures are swallowed inside the
    /// recorder, never block the HTTP response.
    pub fn with_attempt_recorder(self, recorder: Arc<dyn AuthAttemptRecorder>) -> Self {
        let mut inner = Arc::try_unwrap(self.inner).unwrap_or_else(|arc| (*arc).clone());
        inner.attempt_recorder = Some(recorder);
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Attach a [`PrincipalEnricher`] (typically the
    /// SCIM attribute resolver from `waygate-scim`). When set, every
    /// principal returned by a validator is passed through the
    /// enricher before being inserted into the request extensions.
    /// Enrichment is best-effort: if the enricher's underlying store
    /// is unreachable it must log + return the original principal so
    /// the request still proceeds (`Principal.scim` simply stays
    /// `None`).
    pub fn with_principal_enricher(self, enricher: Arc<dyn PrincipalEnricher>) -> Self {
        let mut inner = Arc::try_unwrap(self.inner).unwrap_or_else(|arc| (*arc).clone());
        inner.enricher = Some(enricher);
        Self {
            inner: Arc::new(inner),
        }
    }

    /// The raw middleware function is exposed as [`bearer_middleware`]; wire
    /// it up with `axum::middleware::from_fn_with_state(layer, bearer_middleware)`.
    pub fn resource_metadata_url(&self) -> &str {
        &self.inner.resource_metadata_url
    }
}

pub async fn bearer_middleware(
    State(layer): State<BearerLayer>,
    mut req: Request,
    next: Next,
) -> Response {
    let inner = &layer.inner;
    match &inner.mode {
        AuthMode::Disabled => {
            tracing::warn!(
                path = %req.uri().path(),
                "auth disabled — injecting synthetic dev principal"
            );
            req.extensions_mut().insert(dev_principal());
            record_bearer_validation(BearerOutcome::Disabled);
            return next.run(req).await;
        }
        AuthMode::Enforce => {}
    }

    assert!(
        !inner.validators.is_empty(),
        "validators present when enforce",
    );

    let header_val = match req.headers().get(header::AUTHORIZATION) {
        Some(v) => v,
        None => {
            record_bearer_validation(BearerOutcome::Missing);
            record_attempt(
                inner,
                AuthAttemptOutcome::MissingHeader,
                "missing Authorization header",
            )
            .await;
            return unauthorized(inner, "missing Authorization header");
        }
    };
    let header_str = match header_val.to_str() {
        Ok(s) => s,
        Err(_) => {
            record_bearer_validation(BearerOutcome::Invalid);
            record_attempt(
                inner,
                AuthAttemptOutcome::Rejected,
                "Authorization header is not valid UTF-8",
            )
            .await;
            return unauthorized(inner, "Authorization header is not valid UTF-8");
        }
    };

    // Try each validator. The chain accepts the token on the first OK. A
    // client-side error (wrong iss/aud/sig, or `UnknownKid` meaning this
    // validator doesn't know the signing key) falls through to the next:
    // chain semantics are "any validator passes". An infra failure (HTTP /
    // JSON parse / discovery missing) does NOT short-circuit either — a
    // single validator's network problem must not fail-closed when a later
    // validator might still accept the token. We surface 503 only after
    // every validator has been tried and at least one infra-errored.
    let mut last_client_error: Option<crate::validator::ValidationError> = None;
    let mut last_infra_error: Option<crate::validator::ValidationError> = None;
    for validator in &inner.validators {
        match validator.validate_header(header_str).await {
            Ok(principal) => {
                // Optional best-effort enrichment.
                // Runs *after* successful validation so authz never
                // sees a principal that the validator rejected, and
                // *before* `next.run` so handlers see the enriched
                // copy. Enricher failures stay inside the enricher
                // (by contract) and the original principal flows
                // through — never block the request.
                let principal = if let Some(enricher) = inner.enricher.as_ref() {
                    enricher.enrich(principal).await
                } else {
                    principal
                };
                // SCIM deactivation must take effect on every
                // bearer-gated surface (/mcp, /api/v1, /scim/v2),
                // not only on Cedar-gated tool calls. Cedar
                // policy 16-scim-active only fires for actions
                // the Cedar engine evaluates; admin/SCIM
                // surfaces are scope-gated, not Cedar-gated.
                // The deny lives here so a single point covers
                // all three. Cache TTL on the enricher (60s) is
                // the upper bound on deactivation latency.
                if principal.scim_blocks_request() {
                    // Pick the most-specific reason for the 403:
                    // enricher-blocked (e.g. ambiguous
                    // SCIM match) wins over scim_inactive when
                    // both could be true, because ambiguity is the
                    // higher-severity signal (operator has to
                    // reconcile rows, not just reactivate a user).
                    let reason: &str = principal
                        .enrichment_blocked
                        .as_deref()
                        .unwrap_or("scim_inactive");
                    tracing::warn!(
                        sub = %principal.sub,
                        tenant = %principal.tenant.as_str(),
                        reason = reason,
                        "principal blocked by enricher (SCIM deactivated or ambiguous match) — \
                         rejected at bearer layer",
                    );
                    record_bearer_validation(BearerOutcome::Invalid);
                    record_attempt(inner, AuthAttemptOutcome::Rejected, reason).await;
                    return enrichment_blocked_response(inner, reason);
                }
                req.extensions_mut().insert(principal);
                record_bearer_validation(BearerOutcome::Ok);
                return next.run(req).await;
            }
            Err(e) if e.is_client_error() => {
                tracing::debug!(error = %e, "bearer validator rejected; trying next");
                last_client_error = Some(e);
            }
            Err(e) => {
                tracing::warn!(error = %e, "bearer validator infra error; trying next");
                last_infra_error = Some(e);
            }
        }
    }

    // No validator accepted. If any returned an infra error, fail loud (503)
    // — we can't tell whether the token would have been valid. Otherwise
    // every validator returned a client-error rejection, which is a
    // legitimate 401.
    if let Some(e) = last_infra_error {
        tracing::error!(
            error = %e,
            "bearer validation infra error (all validators tried, none accepted)"
        );
        record_bearer_validation(BearerOutcome::Invalid);
        record_attempt(inner, AuthAttemptOutcome::InfraUnavailable, &e.to_string()).await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "auth_infrastructure_unavailable"})),
        )
            .into_response();
    }

    let detail = last_client_error
        .as_ref()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "no validator accepted the token".into());
    record_bearer_validation(BearerOutcome::Invalid);
    record_attempt(inner, AuthAttemptOutcome::Rejected, &detail).await;
    unauthorized(inner, &detail)
}

/// Thin shim: call the recorder if one is attached, otherwise a no-op.
/// Kept out of the hot path on the success branch (which doesn't record
/// per request — see [`AuthAttemptRecorder`]'s doc comment).
async fn record_attempt(inner: &Inner, outcome: AuthAttemptOutcome, reason: impl Into<String>) {
    if let Some(recorder) = inner.attempt_recorder.as_ref() {
        recorder.record(outcome, reason.into()).await;
    }
}

/// 403 response for a principal an
/// enricher refused to forward. Distinct from `unauthorized`
/// (401) because the token itself is still cryptographically
/// valid — the user is *blocked* by SCIM enforcement (either
/// `active=false` or an ambiguous SCIM match the resolver
/// can't safely reconcile). RFC 6750 §3 recommends 403 with
/// `error="invalid_token"` and `error_description` for this
/// case; clients should treat it as "re-auth won't help,
/// contact your administrator."
///
/// `reason` is the literal carried in `error_description` and
/// in the JSON body's `error` field. Common values today:
/// `scim_inactive` (user `active=false`),
/// `scim_ambiguous_match` (same `sub` matches two
/// distinct rows via different columns).
fn enrichment_blocked_response(inner: &Inner, reason: &str) -> Response {
    let www = format!(
        r#"Bearer resource_metadata="{}", error="invalid_token", error_description="{}""#,
        inner.resource_metadata_url, reason
    );
    // This map is deliberately open: any future enricher can add
    // its own reason code. `tenant_not_found` and
    // `tenant_suspended` exist so operators reading 403 bodies can
    // disambiguate "this tenant_id was never provisioned" from
    // "this tenant exists but is suspended."
    let detail = match reason {
        "scim_inactive" => "principal is provisioned via SCIM but marked active=false",
        "scim_ambiguous_match" => {
            "principal's `sub` matches multiple SCIM rows by external_id and user_name; \
             operator must reconcile"
        }
        "tenant_not_found" => {
            "principal's `tenant` claim does not match any row in the canonical tenants \
             registry — operator must provision via POST /api/v1/admin/tenants"
        }
        "tenant_suspended" => {
            "principal's tenant exists but is currently suspended (status='suspended'); \
             operator must reactivate via PATCH /api/v1/admin/tenants/{id}"
        }
        _ => "principal blocked by enrichment layer",
    };
    let mut resp = (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": reason,
            "detail": detail,
        })),
    )
        .into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&www).unwrap_or_else(|_| HeaderValue::from_static("Bearer")),
    );
    resp
}

fn unauthorized(inner: &Inner, detail: &str) -> Response {
    // Per RFC 6750 §3 + RFC 9728 §5.1: the WWW-Authenticate header on a
    // 401 carries the bearer challenge plus the resource metadata URL so
    // the client can discover the authorization server. MCP 2025-11-25
    // additionally SHOULDs the `scope` parameter so the client requests
    // the right minimum scopes on the first authorize hop instead of
    // round-tripping a separate insufficient_scope 403. The order of
    // parameters is not significant; the rendering here follows the
    // examples in the spec for readability.
    let mut www = format!(
        r#"Bearer resource_metadata="{}", error="invalid_token""#,
        inner.resource_metadata_url
    );
    if let Some(hint) = inner.scope_hint.as_deref() {
        use std::fmt::Write;
        // hint is operator-supplied + ASCII per the OAuth scope grammar
        // (RFC 6749 §3.3); we don't need to escape it.
        let _ = write!(www, r#", scope="{hint}""#);
    }
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized", "detail": detail})),
    )
        .into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&www).unwrap_or_else(|_| HeaderValue::from_static("Bearer")),
    );
    resp
}

fn dev_principal() -> Principal {
    Principal {
        sub: "dev@local".into(),
        email: Some("dev@local".into()),
        groups: vec!["mcp-admins".into()],
        issuer: "local-dev".into(),
        scopes: vec![
            "mcp:invoke".into(),
            "mcp:read".into(),
            "mcp:admin".into(),
            // Include the HITL maker scope so the dev synthetic
            // admin can exercise /api/v1/admin/change_requests under
            // GATEWAY_AUTH_MODE=disabled without an explicit override.
            "mcp:propose".into(),
            // Include SCIM scopes so the
            // dev synthetic admin can exercise /scim/v2/*
            // without an explicit-scope override.
            "scim:read".into(),
            "scim:write".into(),
        ],
        // Dev mode is single-tenant by construction;
        // the synthetic admin principal sits in the default tenant.
        tenant: waygate_core::TenantId::default(),
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        // Dev mode skips SCIM enrichment.
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

/// Extract the authenticated principal from a request extension. Returns
/// `None` for routes that weren't layered with the bearer middleware.
pub fn principal_from_req(req: &Request) -> Option<&Principal> {
    req.extensions().get::<Principal>()
}
