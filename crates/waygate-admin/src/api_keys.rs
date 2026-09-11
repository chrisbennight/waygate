//! `/admin/identities` — server-rendered API-key management panel.
//!
//! Mirror of the OAuth simulator panel pattern in [`crate::dashboard`]:
//! askama templates, htmx for partial swaps, CSRF token on every mutating
//! form. The store handle is `Option` so the page renders a "feature
//! disabled" placeholder when `GATEWAY_API_KEYS_ENABLED=false`.
//!
//! All mutating routes require the caller's session principal to carry
//! `mcp:admin` — gated by [`crate::scope`] so individual handlers stay
//! free of boilerplate. Mint is **catalog-only** —
//! when the scope/group catalog stores are wired, every requested scope
//! and group must already exist in the tenant's catalog (built-in /
//! policy / operator-registered on the Scopes & Groups pages), else the
//! mint is rejected. The operator-trust free-text path survives
//! only when no catalog store is configured (DB-less dev).
//!
//! Audit events are dual-emitted: a `tracing::info!` line for the OTel
//! pipeline (Grafana / fluentd / Datadog) and an
//! `EvidenceRecorder::record_best_effort` submission for `audit_log`, the
//! admin Activity feed, and configured exporters. The two paths carry the same
//! identity fields so persisted rows and the `noop=true` tracing signal remain
//! pivot-equivalent; bounded-queue or backing-write loss stays observable.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_apikeys::{token, ApiKeyRow, ApiKeyStore, StoreError, UsageBucket};
use waygate_core::html::escape as html_escape;
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::error::{ApiError, ApiResult};
use crate::scope::require_admin_extension;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::{format_ts_abs, format_ts_rel};

/// Top-N rows in the dashboard list. The page is intentionally a
/// single-shot render — pagination arrives only if usage warrants it.
const LIST_LIMIT: i64 = 200;

/// Sparkline window. Matches what most operators want at a glance.
const USAGE_WINDOW_DAYS: i64 = 7;

// ---- templates ------------------------------------------------------------

#[derive(Template)]
#[template(path = "api_keys.html")]
struct ApiKeysPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// Feature toggled on via `GATEWAY_API_KEYS_ENABLED`. Drives the
    /// "feature disabled" branch in the template.
    enabled: bool,
    /// Caller carries `mcp:admin`. When false, the template hides the
    /// inventory + mint form behind a "no access" message — listing
    /// keys reveals sub/email/groups/scopes which is admin-only info.
    is_admin: bool,
    allowed_scopes: Vec<String>,
    keys: Vec<KeyView>,
}

impl ApiKeysPage {
    /// Include-context delegate: the shared partial this page includes calls
    /// `self.nav_url(...)`, which must resolve on the page struct too. Pure
    /// forward to [`crate::chrome::PageChrome::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        self.chrome.nav_url(path)
    }
}

#[derive(Template)]
#[template(path = "api_keys_table.html")]
struct ApiKeysTable {
    csrf_token: String,
    keys: Vec<KeyView>,
    /// The per-row hx-get/hx-post URLs (usage sparkline, rename, revoke)
    /// must stay inside the active tenant prefix when the parent page was
    /// loaded under `/admin/t/<tenant>/identities`. Populated from the
    /// fragment-refresh handler's `Option<Extension<TenantContext>>`.
    tenant_ctx: Option<TenantContext>,
}

impl ApiKeysTable {
    /// Fragment delegate — fragments carry no full [`crate::chrome::PageChrome`];
    /// the URL logic lives in [`crate::tenant_ctx::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

#[derive(Template)]
#[template(path = "api_key_secret.html")]
struct ApiKeySecret {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// The literal `mcpgw_…` to show the operator exactly once.
    secret: String,
    name: String,
    sub: String,
    config_toml_snippet: String,
}

/// Per-key "edit grants" form (`GET /identities/api-keys/{id}/grants`),
/// prefilled with the key's current scopes + groups. The secret is never
/// re-shown — editing grants re-scopes a key in place.
#[derive(Template)]
#[template(path = "api_key_grants.html")]
struct ApiKeyGrantsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// The key being edited (path id, stamped into the form action).
    id: Uuid,
    name: String,
    sub: String,
    /// Current scopes, space-joined, prefilling the editable textbox.
    scopes: String,
    /// Current groups, comma-joined, prefilling the editable textbox.
    groups: String,
    /// Operator-visible error from a failed apply, threaded back via the
    /// `?error=` PRG query param. `None` ⇒ no banner.
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "api_keys_sparkline.html")]
struct Sparkline {
    points: String,
    width: u32,
    height: u32,
    total: i64,
}

// ---- view-model -----------------------------------------------------------

#[derive(Clone)]
struct KeyView {
    id: Uuid,
    key_prefix: String,
    name: String,
    sub: String,
    email: String,
    groups: String,
    scopes: String,
    created_at_abs: String,
    created_at_rel: String,
    last_used: String,
    expires: String,
    status: &'static str,
    status_class: &'static str,
    revoked: bool,
}

impl From<&ApiKeyRow> for KeyView {
    fn from(row: &ApiKeyRow) -> Self {
        let (status, status_class) = compute_status(row);
        KeyView {
            id: row.id,
            key_prefix: row.key_prefix.clone(),
            name: row.name.clone(),
            sub: row.sub.clone(),
            email: row.email.clone().unwrap_or_default(),
            groups: row.groups.join(", "),
            scopes: row.scopes.join(" "),
            created_at_abs: format_ts_abs(row.created_at),
            created_at_rel: format_ts_rel(row.created_at),
            last_used: row
                .last_used_at
                .map(format_ts_rel)
                .unwrap_or_else(|| "—".into()),
            expires: row
                .expires_at
                .map(format_ts_abs)
                .unwrap_or_else(|| "never".into()),
            status,
            status_class,
            revoked: row.revoked_at.is_some(),
        }
    }
}

fn compute_status(row: &ApiKeyRow) -> (&'static str, &'static str) {
    if row.revoked_at.is_some() {
        return ("revoked", "chip");
    }
    if matches!(row.expires_at, Some(exp) if exp <= OffsetDateTime::now_utc()) {
        return ("expired", "chip chip--warn");
    }
    ("active", "chip chip--ok")
}

// ---- forms ----------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MintForm {
    pub csrf: String,
    pub name: String,
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub groups: String,
    pub scopes: String,
    /// One of: `<N>d`, `<N>h`, `<N>y`, `never`. Empty → `never`.
    #[serde(default)]
    pub ttl: String,
    /// Optional profile id. When set, mint
    /// validates the requested scope set + ttl + owner/reason
    /// against the profile's bounds and refuses on overflow.
    /// When absent, the mint runs in "legacy" mode — every op
    /// can still mint by leaving this field blank, but a
    /// transitional WARN audit lets operators see who's still
    /// bypassing the profile flow.
    #[serde(default)]
    pub profile_id: Option<String>,
    /// Profile-required when the chosen profile sets
    /// `requires_owner = true`. Persisted to api_keys.owner.
    #[serde(default)]
    pub owner: Option<String>,
    /// Profile-required when the chosen profile sets
    /// `requires_reason = true`. Persisted to api_keys.reason
    /// AND the audit row's reason field.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RenameForm {
    pub csrf: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct CsrfOnlyForm {
    pub csrf: String,
}

/// Edit-grants apply body: the FULL replacement scope + group sets (a
/// replacement, not a patch). `scopes` is space-separated, `groups`
/// comma-separated — the same shapes the mint form uses.
#[derive(Debug, Deserialize)]
pub struct GrantsForm {
    pub csrf: String,
    #[serde(default)]
    pub scopes: String,
    #[serde(default)]
    pub groups: String,
}

/// Query-string state for the edit-grants form: the `?error=` PRG banner from
/// a failed apply.
#[derive(Debug, Default, Deserialize)]
pub struct GrantsQuery {
    #[serde(default)]
    pub error: Option<String>,
}

// ---- handlers -------------------------------------------------------------

async fn page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let _nav = crate::dashboard::nav("/identities", tenant_ctx.as_ref());
    let _theme = crate::dashboard::theme_from_cookie(&headers);
    let user_str = user
        .as_ref()
        .map(|Extension(p)| crate::dashboard::user_display(p));
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    // The list view exposes `sub`, `email`, `groups`, `scopes`, and
    // timestamps for every key — admin-only material. Gate the read the
    // same way the mutating handlers gate writes. Render a non-jarring
    // in-page "no access" message rather than returning JSON 403 from a
    // browser GET.
    let is_admin = user
        .as_ref()
        .map(|Extension(p)| p.has_scope(waygate_oidc::Scope::McpAdmin.as_str()))
        .unwrap_or(false);

    // Gate the dashboard surface on `api_keys_enabled`, not on
    // `api_keys.is_some()`: the store is wired whenever a DB pool
    // exists (so tenant cleanup can revoke), but a key minted while
    // the bearer-chain validator is absent cannot authenticate. Show
    // the "feature disabled" placeholder when only the store is
    // wired and the runtime auth is off.
    let (enabled, allowed_scopes, keys) = match (
        state.identity.api_keys_feature.enabled(),
        state.identity.api_keys.get(),
        is_admin,
    ) {
        (true, Some(store), true) => {
            let rows = match store.list(LIST_LIMIT).await {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!(error = %e, "api_keys: list failed");
                    return ApiError::Internal("list api keys".into()).into_response();
                }
            };
            let views = rows.iter().map(KeyView::from).collect();
            (true, default_scopes(), views)
        }
        (true, Some(_), false) => (true, Vec::new(), Vec::new()),
        _ => (false, Vec::new(), Vec::new()),
    };

    // OAuth sessions and API-key profiles each have their own page
    // (`/sessions`, `/profiles`); this page is now API keys + mint only.
    crate::dashboard::render(&ApiKeysPage {
        chrome: PageChrome::build(
            &state,
            "API keys",
            "/identities",
            &headers,
            user_str,
            tenant_ctx,
            csrf_token,
        ),
        enabled,
        is_admin,
        allowed_scopes,
        keys,
    })
}

/// Semantic inputs to [`mint_core`], decoupled from the HTTP [`MintForm`]
/// so the dashboard mint handler AND the `api_key.mint` change-request
/// executor share ONE mint path — identical validation, profile
/// enforcement, persistence, and audit. The dashboard maps its form here;
/// the executor maps the captured change-request params here.
pub(crate) struct MintParams {
    pub name: String,
    pub sub: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    /// Raw TTL token (`<N>d` / `<N>h` / `<N>y` / `never` / empty). Parsed
    /// inside `mint_core` so both callers share the same vocabulary and
    /// validation ordering.
    pub ttl_raw: String,
    pub profile_id: Option<String>,
    pub owner: Option<String>,
    pub reason: Option<String>,
}

/// A freshly minted key: the persisted [`ApiKeyRow`] plus the one-time
/// plaintext secret (`mcpgw_…`). The secret is surfaced EXACTLY once — the
/// dashboard reveal page, or the change-request burn-on-read channel — and
/// is never persisted in plaintext.
pub(crate) struct MintedKey {
    pub row: ApiKeyRow,
    pub secret: String,
}

/// Shared mint path behind the dashboard handler and the `api_key.mint`
/// executor: store-check → validate → profile enforcement → `token::mint`
/// → persist → fail-open audit. Returns the row + one-time secret.
///
/// Errors are typed via [`ApiError`] so the dashboard maps them to its HTML
/// responses (`ServiceUnavailable` → feature-disabled page, `BadRequest` →
/// inline form error) and the executor maps them to `ExecError`.
/// `tenant_id` and `created_by` are supplied by the caller (the dashboard
/// derives them from the session principal; the executor from the approved
/// change request), and `actor` attributes the audit row.
pub(crate) async fn mint_core(
    state: &AdminState,
    tenant_id: &str,
    created_by: &str,
    actor: Option<&Principal>,
    params: MintParams,
) -> Result<MintedKey, ApiError> {
    // Dual-check — refuse the mint if the runtime auth isn't on even
    // when the store is wired, since a minted key with no validator on
    // the bearer chain would 401 every request. Feature first, store
    // second, so each absence reports its own canonical message (same
    // split as `require_api_keys_runtime`).
    state.identity.api_keys_feature.require()?;
    let store = state.identity.api_keys.require()?;

    // Validation. None of these are paternalistic guardrails — they reject
    // input that would produce a broken row (per the operator-trust model
    // in identity.md). Order preserved from the original handler: name,
    // sub, scopes, then ttl.
    if params.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    if params.sub.trim().is_empty() {
        return Err(ApiError::BadRequest("sub is required".into()));
    }
    // Normalize scopes in the SHARED core so both callers get identical
    // hygiene: the dashboard form splits a single string on whitespace, but
    // the change-request executor passes a JSON array verbatim. Splitting +
    // dropping blanks here (idempotent on already-split dashboard tokens)
    // means api_key.mint can't persist blank/whitespace scope entries the
    // form could never produce.
    let scopes: Vec<String> = params
        .scopes
        .iter()
        .flat_map(|s| s.split_whitespace())
        .map(str::to_owned)
        .collect();
    if scopes.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one scope is required".into(),
        ));
    }
    // Normalize groups in the shared core too: the dashboard's
    // `split_csv` already trims + drops blanks, but the
    // change-request executor passes the JSON groups array verbatim.
    // Normalizing here means a blank / whitespace-only label can't bypass the
    // catalog check AND get persisted — the SAME normalized list is both
    // validated below and stored on the row.
    let groups: Vec<String> = params
        .groups
        .iter()
        .map(|g| g.trim())
        .filter(|g| !g.is_empty())
        .map(str::to_owned)
        .collect();
    let expires_at = parse_ttl(params.ttl_raw.trim()).map_err(ApiError::BadRequest)?;

    // Preserve caller-facing validation order, then re-check under row locks
    // in the final insert so a concurrent local-catalog delete cannot slip
    // between validation and persistence.
    let (enforce_scope_catalog, enforce_group_catalog) =
        validate_catalog_grants(state, tenant_id, &scopes, &groups).await?;

    // Profile enforcement, shared with `update_grants_core` via
    // [`enforce_profile_ceiling`] so the ceiling enforced at issue time is
    // byte-identical to the one re-checked on every grant edit — the invariant
    // that lets profiles stay immutable (a later grant edit can't widen a
    // profiled key past its `allowed_scopes`). With a profile_id, validate the
    // requested scope set + ttl + owner + reason and refuse on overflow;
    // without one (legacy), mint through with an audit-visible WARN so
    // operators can track bypasses.
    let (profile_id_for_row, rotation_due_at) =
        match params.profile_id.as_deref().filter(|s| !s.is_empty()) {
            Some(raw_id) => {
                let id = Uuid::parse_str(raw_id)
                    .map_err(|e| ApiError::BadRequest(format!("invalid profile_id: {e}")))?;
                let (pid, due) = enforce_profile_ceiling(
                    state,
                    tenant_id,
                    id,
                    &scopes,
                    expires_at,
                    params.owner.as_deref(),
                    params.reason.as_deref(),
                )
                .await?;
                (Some(pid), Some(due))
            }
            None => {
                // Legacy mint path. Audit-visible WARN so an operator scanning
                // the activity feed can spot un-attributed mints.
                tracing::warn!(
                    tenant = %tenant_id,
                    actor = %created_by,
                    "api_keys: minting via LEGACY path (no profile_id) — profile flow bypassed",
                );
                (None, None)
            }
        };

    let minted = token::mint().map_err(|e| {
        tracing::error!(error = %e, "api_keys: mint helper failed");
        ApiError::Internal("mint key".into())
    })?;
    let row = ApiKeyRow {
        id: Uuid::new_v4(),
        key_prefix: minted.key_prefix.clone(),
        key_hash: minted.key_hash.clone(),
        name: params.name.trim().to_owned(),
        sub: params.sub.trim().to_owned(),
        tenant_id: tenant_id.to_owned(),
        email: params.email.filter(|s| !s.trim().is_empty()),
        groups,
        scopes,
        created_by: created_by.to_owned(),
        created_at: OffsetDateTime::now_utc(),
        last_used_at: None,
        expires_at,
        revoked_at: None,
        profile_id: profile_id_for_row,
        owner: params
            .owner
            .as_ref()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty()),
        reason: params
            .reason
            .as_ref()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty()),
        rotation_due_at,
    };
    store
        .insert_catalog_checked(&row, enforce_scope_catalog, enforce_group_catalog)
        .await
        .map_err(|e| map_catalog_write_error(e, "minting"))?;

    // Audit-trail line. `tracing` for OTel + `record_lifecycle` for the
    // durable `audit_log` row (compliance-grade evidence), including the
    // profile-derived owner + reason so the lifecycle event captures the
    // business-justification fields the profile required.
    tracing::info!(
        action = "api_key_minted",
        api_key.id = %row.id,
        api_key.name = %row.name,
        api_key.sub = %row.sub,
        api_key.scopes = ?row.scopes,
        api_key.expires_at = ?row.expires_at,
        api_key.created_by = %row.created_by,
        "api_keys: minted",
    );
    let profile_audit_fragment = match (row.profile_id, row.owner.as_deref(), row.reason.as_deref())
    {
        (Some(pid), owner, reason) => format!(
            " profile_id={} owner={} reason={}",
            pid,
            owner.unwrap_or("<unset>"),
            reason.unwrap_or("<unset>"),
        ),
        (None, owner, reason) => {
            let mut s = String::from(" profile=legacy");
            if let Some(o) = owner {
                s.push_str(&format!(" owner={o}"));
            }
            if let Some(r) = reason {
                s.push_str(&format!(" reason={r}"));
            }
            s
        }
    };
    record_lifecycle(
        &state.evidence,
        "ApiKeyMinted",
        AuditOutcome::Success,
        format!(
            "name={} sub={} scopes=[{}] expires_at={} created_by={} id={}{}",
            row.name,
            row.sub,
            row.scopes.join(","),
            row.expires_at
                .map(|t| t.to_string())
                .unwrap_or_else(|| "never".into()),
            row.created_by,
            row.id,
            profile_audit_fragment,
        ),
        actor,
        row.sub.clone(),
    )
    .await;

    Ok(MintedKey {
        row,
        secret: minted.display,
    })
}

/// Resolve + enforce an api-key profile's ceiling for a scope set, shared by
/// [`mint_core`] (key issue) and [`update_grants_core`] (grant edit). Looks the
/// profile up in the tenant, runs [`waygate_apikeys::Profile::validate_mint`]
/// against the requested `scopes` + the key's `expires_at`/`owner`/`reason`,
/// and on success returns `(profile.id, rotation_due_at)` for the caller to
/// stamp onto a freshly minted row (the edit path ignores the tuple — a grant
/// edit never re-stamps the binding). Running the SAME validation on every
/// grant edit is what lets profiles stay immutable: without it, editing a
/// profiled key would be a hole straight past its `allowed_scopes`.
///
/// Errors are typed [`ApiError`] so both the dashboard (HTML) and the executor
/// (`ExecError`) map them: a missing store / unknown profile / scope-or-ttl
/// overflow are `BadRequest`; a store fault is `Internal`.
async fn enforce_profile_ceiling(
    state: &AdminState,
    tenant_id: &str,
    profile_id: Uuid,
    scopes: &[String],
    expires_at: Option<OffsetDateTime>,
    owner: Option<&str>,
    reason: Option<&str>,
) -> Result<(Uuid, OffsetDateTime), ApiError> {
    let Some(profile_store) = state.identity.api_key_profiles.get() else {
        return Err(ApiError::BadRequest(
            "profile store not configured — leave profile_id blank to use the legacy mint path"
                .into(),
        ));
    };
    match profile_store.get(tenant_id, profile_id).await {
        Ok(Some(p)) => {
            // Requested TTL → Duration. `None` ⇒ "never", which the profile
            // validator rejects (profiles always require a bounded TTL).
            let req_ttl = expires_at.map(|when| {
                let now = OffsetDateTime::now_utc();
                if when > now {
                    std::time::Duration::from_secs((when - now).whole_seconds().max(0) as u64)
                } else {
                    std::time::Duration::from_secs(0)
                }
            });
            p.validate_mint(scopes, req_ttl, owner, reason)
                .map_err(|v| ApiError::BadRequest(v.to_string()))?;
            let due = OffsetDateTime::now_utc() + time::Duration::seconds(p.max_ttl_seconds as i64);
            Ok((p.id, due))
        }
        Ok(None) => Err(ApiError::BadRequest(format!(
            "profile_id {profile_id} not found in tenant `{tenant_id}`"
        ))),
        Err(e) => {
            tracing::error!(error = ?e, "api_keys: profile_store lookup failed");
            Err(ApiError::Internal("profile store lookup".into()))
        }
    }
}

async fn mint(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Form(form): Form<MintForm>,
) -> Response {
    if let Err(e) = require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    if let Err(e) = require_csrf(csrf.as_ref().map(|Extension(c)| c), &form.csrf) {
        return e.into_response();
    }
    // The new key belongs to the minting principal's tenant.
    // Dashboard-mint paths without a principal (Disabled auth) land in the
    // default tenant, matching the api_keys.tenant_id NOT NULL DEFAULT.
    let tenant_id = user
        .as_ref()
        .map(|Extension(p)| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let created_by = user
        .as_ref()
        .map(|Extension(p)| p.sub.clone())
        .unwrap_or_else(|| "dashboard".into());
    // The config-snippet TOML key uses the operator's raw (untrimmed) name,
    // exactly as before; the persisted row trims it.
    let name_for_snippet = form.name.clone();
    let params = MintParams {
        name: form.name,
        sub: form.sub,
        email: form.email,
        groups: split_csv(&form.groups),
        scopes: form.scopes.split_whitespace().map(str::to_owned).collect(),
        ttl_raw: form.ttl,
        profile_id: form.profile_id,
        owner: form.owner,
        reason: form.reason,
    };
    let minted = match mint_core(
        &state,
        &tenant_id,
        &created_by,
        user.as_ref().map(|Extension(p)| p),
        params,
    )
    .await
    {
        Ok(m) => m,
        // Map the shared core's typed errors back to the dashboard's HTML
        // responses (preserving the prior behaviour exactly).
        Err(ApiError::ServiceUnavailable(_)) => return feature_disabled().into_response(),
        Err(ApiError::BadRequest(msg)) => return form_error(&msg).into_response(),
        Err(e) => return e.into_response(),
    };

    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let _nav = crate::dashboard::nav("/identities", tenant_ctx.as_ref());
    let _theme = crate::dashboard::theme_from_cookie(&headers);
    let user_str = user
        .as_ref()
        .map(|Extension(p)| crate::dashboard::user_display(p));

    let snippet = config_toml_snippet(&name_for_snippet, &minted.secret, &state.public_url);
    let mut resp = crate::dashboard::render(&ApiKeySecret {
        chrome: PageChrome::build(
            &state,
            "API key — secret shown once",
            "/identities",
            &headers,
            user_str,
            tenant_ctx,
            String::new(),
        ),
        secret: minted.secret,
        name: minted.row.name,
        sub: minted.row.sub,
        config_toml_snippet: snippet,
    });
    // The reveal page renders the literal `mcpgw_…` secret in the response
    // body. Mark it uncacheable so neither the browser back-button stack
    // nor any intermediary keeps a copy: a long-lived bearer recoverable
    // from history would undermine the "shown once" property the page
    // promises in its body copy. Per RFC 9111 §5.2.2.5,
    // `Cache-Control: no-store` is the strongest form; the other directives
    // are belt-and-braces for HTTP/1.0 caches and stale-revalidation paths.
    no_store(&mut resp);
    resp
}

/// Add the cache-busting headers we want on any response that renders a
/// secret in its body. Mutating-helper rather than a wrapper so callers
/// can use it on existing `Response`s without losing the body or status.
///
/// `pub(crate)` so the JSON SCIM-key-reveal path on POST
/// /api/v1/admin/tenants can apply the same headers the existing
/// dashboard reveal does.
pub(crate) fn no_store(resp: &mut Response) {
    let headers = resp.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
}

/// Read the api-key `{id}` capture by name and parse it. These dashboard
/// routes live in `page_routes`, which is nested under `/t/{tenant}` and
/// merged at `/`; a `Path<Uuid>` extractor 500s on the tenant-scoped
/// mount when both `tenant` and `id` captures are present. Reading
/// by name from the full capture map works on both mounts.
fn id_param(params: &HashMap<String, String>) -> ApiResult<Uuid> {
    params
        .get("id")
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
        .ok_or_else(|| ApiError::BadRequest("invalid or missing api key id".into()))
}

async fn rename(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<RenameForm>,
) -> ApiResult<Response> {
    require_admin_extension(user.as_ref().map(|Extension(p)| p))?;
    require_csrf(csrf.as_ref().map(|Extension(c)| c), &form.csrf)?;
    let id = id_param(&params)?;
    let store = require_api_keys_runtime(&state)?;
    let new_name = form.name.trim();
    if new_name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    // Look up the row first so the audit-log line matches the richness the
    // PR description promises — sub / scopes / expires_at aren't on the
    // request, they live on the row.
    let row = load_row(store, id).await?;
    let ok = store
        .rename(id, new_name)
        .await
        .map_err(|e| ApiError::Internal(format!("rename: {e}")))?;
    if !ok {
        return Err(ApiError::NotFound("api key"));
    }
    tracing::info!(
        action = "api_key_renamed",
        api_key.id = %row.id,
        api_key.old_name = %row.name,
        api_key.new_name = %new_name,
        api_key.sub = %row.sub,
        api_key.scopes = ?row.scopes,
        api_key.expires_at = ?row.expires_at,
        actor = %actor(&user),
        "api_keys: renamed",
    );
    record_lifecycle(
        &state.evidence,
        "ApiKeyRenamed",
        AuditOutcome::Success,
        format!(
            "id={} sub={} old_name={} new_name={} scopes=[{}] actor={}",
            row.id,
            row.sub,
            row.name,
            new_name,
            row.scopes.join(","),
            actor(&user),
        ),
        user.as_ref().map(|Extension(p)| p),
        row.sub.clone(),
    )
    .await;
    refresh_table(&state, csrf, tenant_ctx).await
}

async fn revoke(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<CsrfOnlyForm>,
) -> ApiResult<Response> {
    require_admin_extension(user.as_ref().map(|Extension(p)| p))?;
    require_csrf(csrf.as_ref().map(|Extension(c)| c), &form.csrf)?;
    let id = id_param(&params)?;
    // Direct-admin revoke is a global operator action (revoke by id), so no
    // tenant guard. The propose executor passes `Some(tenant)` instead.
    revoke_core(&state, user.as_ref().map(|Extension(p)| p), id, None).await?;
    refresh_table(&state, csrf, tenant_ctx).await
}

/// Outcome of [`revoke_core`]: whether a row was actually flipped to revoked,
/// plus the row's identity (for the executor's non-secret result fingerprint
/// and the audit line).
pub(crate) struct RevokeOutcome {
    pub removed: bool,
    pub row: ApiKeyRow,
}

/// Shared revoke path: runtime-check → load the row (for the audit identity and
/// the optional tenant guard) → `store.revoke` → best-effort `ApiKeyLifecycle`
/// audit. Both the dashboard revoke handler and the `api_key.revoke` propose
/// executor call this, so the store call + audit can't drift. The audit enriches
/// the reason with the row's identity (so "what got revoked" reads as "alice's
/// codex laptop key with mcp:invoke", not just a uuid).
///
/// `require_tenant`: `None` for the direct-admin dashboard path (revoke by id is
/// a global operator action, unchanged); `Some(tenant)` for the maker-initiated
/// propose path, which must be tenant-bounded — a row in another tenant returns
/// `NotFound` (404, not 403, so a maker can't probe cross-tenant key ids).
///
/// `Ok(removed = false)` is an idempotent no-op (the row exists but was already
/// revoked); a truly-unknown id is `NotFound` from `load_row`.
pub(crate) async fn revoke_core(
    state: &Arc<AdminState>,
    actor: Option<&Principal>,
    id: Uuid,
    require_tenant: Option<&str>,
) -> ApiResult<RevokeOutcome> {
    let store = require_api_keys_runtime(state)?;
    let row = load_row(store, id).await?;
    if let Some(t) = require_tenant {
        if row.tenant_id != t {
            return Err(ApiError::NotFound("api key"));
        }
    }
    let ok = store
        .revoke(id)
        .await
        .map_err(|e| ApiError::Internal(format!("revoke: {e}")))?;
    let actor_sub = actor
        .map(|p| p.sub.clone())
        .unwrap_or_else(|| "dashboard".into());
    // Same field set whether or not a row flipped; the only distinguishing
    // mark is `noop` on the tracing line and the `noop ` prefix on the reason.
    tracing::info!(
        action = "api_key_revoked",
        noop = !ok,
        api_key.id = %row.id,
        api_key.name = %row.name,
        api_key.sub = %row.sub,
        api_key.scopes = ?row.scopes,
        api_key.expires_at = ?row.expires_at,
        actor = %actor_sub,
        "api_keys: revoke",
    );
    record_lifecycle(
        &state.evidence,
        "ApiKeyRevoked",
        AuditOutcome::Success,
        format!(
            "{}id={} sub={} name={} scopes=[{}] actor={}",
            if ok { "" } else { "noop " },
            row.id,
            row.sub,
            row.name,
            row.scopes.join(","),
            actor_sub,
        ),
        actor,
        row.sub.clone(),
    )
    .await;
    Ok(RevokeOutcome { removed: ok, row })
}

/// Semantic inputs to [`update_grants_core`], decoupled from HTTP so the
/// dashboard edit-grants handler AND the `api_key.update_grants` change-request
/// executor share ONE edit path. A FULL replacement of both grant sets, not a
/// patch (mirrors `rbac.role.update`).
pub(crate) struct UpdateGrantsParams {
    pub scopes: Vec<String>,
    pub groups: Vec<String>,
}

/// Outcome of [`update_grants_core`]: the key's pre-edit identity (carrying the
/// OLD grants) plus the NEW grant sets that were applied — enough for the
/// executor's non-secret result fingerprint and the OLD→NEW audit line. Carries
/// no plaintext secret (only [`ApiKeyRow`], whose `Debug` is already used
/// across the crate), so deriving `Debug` exposes nothing new.
#[derive(Debug)]
pub(crate) struct UpdatedGrants {
    pub row: ApiKeyRow,
    pub new_scopes: Vec<String>,
    pub new_groups: Vec<String>,
}

/// Shared edit-grants path behind the dashboard handler and the
/// `api_key.update_grants` executor: runtime-check → load the row (audit
/// identity, OLD grants, profile binding, tenant guard) → normalize (identical
/// to [`mint_core`]) → catalog validation → profile re-validation against the
/// NEW scope set (the mint-time ceiling, re-applied via
/// [`enforce_profile_ceiling`] so an edit can't widen a profiled key past its
/// `allowed_scopes`) → conditional final store update that repeats catalog
/// validation under row locks (so a concurrent delete cannot win the gap) and
/// refuses to resurrect a key revoked in the load→write window → best-effort
/// lifecycle audit (OLD → NEW). The secret, sub, profile binding, and expiry
/// are never touched — editing grants re-scopes a key in place; it never
/// re-issues or rotates it.
///
/// `require_tenant`: `None` for the direct-admin dashboard path (edit by id is
/// a global operator action, like [`revoke_core`]); `Some(tenant)` for the
/// maker-initiated propose path, which must be tenant-bounded — a row in
/// another tenant is `NotFound` (404, not 403, so a maker can't probe
/// cross-tenant key ids).
pub(crate) async fn update_grants_core(
    state: &Arc<AdminState>,
    actor: Option<&Principal>,
    id: Uuid,
    require_tenant: Option<&str>,
    params: UpdateGrantsParams,
) -> ApiResult<UpdatedGrants> {
    let store = require_api_keys_runtime(state)?;
    let row = load_row(store, id).await?;
    if let Some(t) = require_tenant {
        if row.tenant_id != t {
            return Err(ApiError::NotFound("api key"));
        }
    }

    // Normalize identically to `mint_core` (scopes split on whitespace; groups
    // trimmed, blanks dropped) so the dashboard's free-text and the executor's
    // JSON array land on the same hygiene, and a blank label can't slip past the
    // catalog check then get persisted.
    let scopes: Vec<String> = params
        .scopes
        .iter()
        .flat_map(|s| s.split_whitespace())
        .map(str::to_owned)
        .collect();
    if scopes.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one scope is required".into(),
        ));
    }
    let groups: Vec<String> = params
        .groups
        .iter()
        .map(|g| g.trim())
        .filter(|g| !g.is_empty())
        .map(str::to_owned)
        .collect();

    let (enforce_scope_catalog, enforce_group_catalog) =
        validate_catalog_grants(state, &row.tenant_id, &scopes, &groups).await?;

    // Profile re-validation. A key minted under a profile carries that profile's
    // ceiling; re-running the SAME validation on every grant edit is what lets
    // profiles stay immutable — without it an edit would be a hole straight past
    // `allowed_scopes`. Uses the key's existing expiry/owner/reason (an edit
    // changes none of them). A key whose profile was deleted (the delete+recreate
    // "rotation") can't be re-validated against a ceiling that no longer exists,
    // so `enforce_profile_ceiling` refuses it — revoke + re-mint instead.
    if let Some(profile_id) = row.profile_id {
        enforce_profile_ceiling(
            state,
            &row.tenant_id,
            profile_id,
            &scopes,
            row.expires_at,
            row.owner.as_deref(),
            row.reason.as_deref(),
        )
        .await?;
    }

    // Conditional write: `revoked_at IS NULL` + the tenant guard means an edit
    // can never resurrect a key revoked in the (load → validate) window — a
    // concurrent revoke wins and we fail loud (`NotFound`) rather than silently
    // re-scoping a tombstoned row.
    let updated = store
        .update_grants_catalog_checked(
            id,
            &row.tenant_id,
            &scopes,
            &groups,
            enforce_scope_catalog,
            enforce_group_catalog,
        )
        .await
        .map_err(|e| map_catalog_write_error(e, "updating grants"))?;
    if !updated {
        return Err(ApiError::NotFound("api key"));
    }

    let actor_sub = actor
        .map(|p| p.sub.clone())
        .unwrap_or_else(|| "dashboard".into());
    tracing::info!(
        action = "api_key_grants_updated",
        api_key.id = %row.id,
        api_key.sub = %row.sub,
        api_key.old_scopes = ?row.scopes,
        api_key.new_scopes = ?scopes,
        api_key.old_groups = ?row.groups,
        api_key.new_groups = ?groups,
        actor = %actor_sub,
        "api_keys: grants updated",
    );
    record_lifecycle(
        &state.evidence,
        "ApiKeyGrantsUpdated",
        AuditOutcome::Success,
        format!(
            "id={} sub={} old_scopes=[{}] new_scopes=[{}] old_groups=[{}] new_groups=[{}] actor={}",
            row.id,
            row.sub,
            row.scopes.join(","),
            scopes.join(","),
            row.groups.join(","),
            groups.join(","),
            actor_sub,
        ),
        actor,
        row.sub.clone(),
    )
    .await;

    Ok(UpdatedGrants {
        row,
        new_scopes: scopes,
        new_groups: groups,
    })
}

/// Emit an `ApiKeyLifecycle` evidence event covering the dashboard-driven
/// api-key lifecycle mutations (mint / rename / revoke / grant edit). All use
/// `record_best_effort` — failed admission or persistence must not block the
/// lifecycle operation that just succeeded. The acting principal is
/// stamped into `principal_*` so the activity feed can pivot
/// "who-revoked-what."
async fn record_lifecycle(
    evidence: &waygate_mcp::SharedEvidence,
    action: &'static str,
    outcome: AuditOutcome,
    reason: String,
    actor: Option<&Principal>,
    // The SUBJECT of the lifecycle action — the affected key's `sub` —
    // recorded as the structured `target` column (distinct from the
    // acting principal in `principal_*`). Lets the activity feed render
    // "ApiKeyMinted · <key sub> · <operator>" so two mints of different
    // keys are distinguishable, instead of both reading as a bare
    // "ApiKeyMinted · <operator>".
    target: String,
) {
    evidence
        .record_best_effort(
            AuditEvent::new(action, outcome)
                .with_category(EvidenceCategory::ApiKeyLifecycle)
                .with_principal(actor)
                .with_reason(reason)
                .with_target(target),
        )
        .await;
}

/// Common audit-log enrichment: load the row, surface a 404 if it's gone.
/// Every admin handler that mutates or inspects api_keys via HTTP must
/// consult both the runtime feature flag (`api_keys_enabled`) AND the
/// store presence — returning the store on `api_keys.is_some()` alone
/// would let a deployment with GATEWAY_API_KEYS_ENABLED=false + DB pool
/// keep those endpoints live. The tenant-DELETE cleanup path doesn't
/// use these HTTP handlers (it calls
/// `ApiKeyStore::revoke_all_for_tenant` directly through
/// `state.identity.api_keys`), so gating these here doesn't break
/// cleanup.
fn require_api_keys_runtime(state: &AdminState) -> ApiResult<&ApiKeyStore> {
    state.identity.api_keys_feature.require()?;
    state.identity.api_keys.require()
}

fn map_catalog_write_error(error: StoreError, operation: &'static str) -> ApiError {
    match error {
        StoreError::UnknownScopes(unknown) => ApiError::BadRequest(format!(
            "unknown scope(s): {} — register them on the Scopes page first (catalog-only)",
            unknown.join(", ")
        )),
        StoreError::UnknownGroups(unknown) => ApiError::BadRequest(format!(
            "unknown group(s): {} — register them on the Groups page first (catalog-only)",
            unknown.join(", ")
        )),
        error => {
            tracing::error!(error = %error, operation, "API-key catalog-checked write failed");
            ApiError::Internal("API-key catalog write failed".into())
        }
    }
}

async fn validate_catalog_grants(
    state: &AdminState,
    tenant_id: &str,
    scopes: &[String],
    groups: &[String],
) -> ApiResult<(bool, bool)> {
    let enforce_scopes = state.identity.scopes.enabled();
    if let Some(store) = state.identity.scopes.get() {
        let unknown = store.unknown_scopes(tenant_id, scopes).await.map_err(|e| {
            tracing::error!(error = %e, tenant = %tenant_id, "API-key scope catalog check failed");
            ApiError::ServiceUnavailable("scope catalog check failed")
        })?;
        if !unknown.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "unknown scope(s): {} — register them on the Scopes page first (catalog-only)",
                unknown.join(", ")
            )));
        }
    }

    let enforce_groups = state.identity.groups.enabled();
    if let Some(store) = state.identity.groups.get() {
        let unknown = store.unknown_groups(tenant_id, groups).await.map_err(|e| {
            tracing::error!(error = %e, tenant = %tenant_id, "API-key group catalog check failed");
            ApiError::ServiceUnavailable("group catalog check failed")
        })?;
        if !unknown.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "unknown group(s): {} — register them on the Groups page first (catalog-only)",
                unknown.join(", ")
            )));
        }
    }
    Ok((enforce_scopes, enforce_groups))
}

async fn load_row(store: &ApiKeyStore, id: Uuid) -> ApiResult<ApiKeyRow> {
    store
        .find_by_id(id)
        .await
        .map_err(|e| ApiError::Internal(format!("find_by_id: {e}")))?
        .ok_or(ApiError::NotFound("api key"))
}

fn actor(user: &Option<Extension<Principal>>) -> String {
    user.as_ref()
        .map(|Extension(p)| p.sub.clone())
        .unwrap_or_else(|| "dashboard".into())
}

async fn usage(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    Path(params): Path<HashMap<String, String>>,
) -> ApiResult<Response> {
    require_admin_extension(user.as_ref().map(|Extension(p)| p))?;
    let id = id_param(&params)?;
    let store = require_api_keys_runtime(&state)?;
    let since = OffsetDateTime::now_utc() - time::Duration::days(USAGE_WINDOW_DAYS);
    let buckets = store
        .usage_since(id, since)
        .await
        .map_err(|e| ApiError::Internal(format!("usage: {e}")))?;
    Ok(render_sparkline(&buckets, since))
}

/// GET the per-key edit-grants form, prefilled with the key's current scopes
/// and groups. Admin-gated read (the form exposes the key's grants); a gone key
/// 404s. The `?error=` query param surfaces a failed apply (PRG).
async fn edit_grants_form(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Query(q): Query<GrantsQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    let id = match id_param(&params) {
        Ok(i) => i,
        Err(e) => return e.into_response(),
    };
    let store = match require_api_keys_runtime(&state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let row = match load_row(store, id).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let _nav = crate::dashboard::nav("/identities", tenant_ctx.as_ref());
    let _theme = crate::dashboard::theme_from_cookie(&headers);
    let user_str = user
        .as_ref()
        .map(|Extension(p)| crate::dashboard::user_display(p));
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    crate::dashboard::render(&ApiKeyGrantsPage {
        chrome: PageChrome::build(
            &state,
            "Edit grants",
            "/identities",
            &headers,
            user_str,
            tenant_ctx,
            csrf_token,
        ),
        id: row.id,
        name: row.name,
        sub: row.sub,
        scopes: row.scopes.join(" "),
        groups: row.groups.join(", "),
        error: q.error,
    })
}

/// Apply an edit to a key's grants, then PRG. Admin + CSRF gated; delegates to
/// the shared [`update_grants_core`] (catalog + profile re-validation + the
/// conditional write + audit). `None` tenant guard — direct-admin edit by id is
/// a global operator action, like the dashboard revoke. Success redirects to
/// the keys list; a validation error redirects back to the form with the
/// message; a vanished/revoked key redirects to the list.
async fn update_grants(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<GrantsForm>,
) -> Response {
    if let Err(e) = require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    if let Err(e) = require_csrf(csrf.as_ref().map(|Extension(c)| c), &form.csrf) {
        return e.into_response();
    }
    let id = match id_param(&params) {
        Ok(i) => i,
        Err(e) => return e.into_response(),
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);

    let core_params = UpdateGrantsParams {
        scopes: form.scopes.split_whitespace().map(str::to_owned).collect(),
        groups: split_csv(&form.groups),
    };
    match update_grants_core(
        &state,
        user.as_ref().map(|Extension(p)| p),
        id,
        None,
        core_params,
    )
    .await
    {
        Ok(_) => Redirect::to(&crate::tenant_ctx::nav_url(
            tenant_ctx.as_ref(),
            "/identities",
        ))
        .into_response(),
        Err(ApiError::ServiceUnavailable(_)) => feature_disabled(),
        // A vanished / concurrently-revoked key: nothing to edit — back to the list.
        Err(ApiError::NotFound(_)) => Redirect::to(&crate::tenant_ctx::nav_url(
            tenant_ctx.as_ref(),
            "/identities",
        ))
        .into_response(),
        // Validation rejection (unknown catalog entry, profile overflow, empty
        // scopes): back to the form with the message surfaced.
        Err(ApiError::BadRequest(msg)) => {
            let base = crate::tenant_ctx::nav_url(
                tenant_ctx.as_ref(),
                &format!("/identities/api-keys/{id}/grants"),
            );
            Redirect::to(&format!(
                "{base}?error={}",
                crate::dashboard::urlencode(&msg)
            ))
            .into_response()
        }
        Err(e) => e.into_response(),
    }
}

async fn refresh_table(
    state: &Arc<AdminState>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
) -> ApiResult<Response> {
    let store = require_api_keys_runtime(state)?;
    let rows = store
        .list(LIST_LIMIT)
        .await
        .map_err(|e| ApiError::Internal(format!("list: {e}")))?;
    let table = ApiKeysTable {
        csrf_token: csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        keys: rows.iter().map(KeyView::from).collect(),
        tenant_ctx: tenant_ctx.map(|Extension(c)| c),
    };
    let html = table
        .render()
        .map_err(|e| ApiError::Internal(format!("render: {e}")))?;
    Ok(Html(html).into_response())
}

// ---- helpers --------------------------------------------------------------

/// Inline 200×40 SVG sparkline. Each bar's height is proportional to the
/// max bucket in the window. Empty window ⇒ flat baseline + zero total.
fn render_sparkline(buckets: &[UsageBucket], since: OffsetDateTime) -> Response {
    const WIDTH: u32 = 200;
    const HEIGHT: u32 = 40;

    if buckets.is_empty() {
        return crate::dashboard::render(&Sparkline {
            points: format!("M 0 {HEIGHT} L {WIDTH} {HEIGHT}"),
            width: WIDTH,
            height: HEIGHT,
            total: 0,
        });
    }

    let now = OffsetDateTime::now_utc();
    let span = (now - since).whole_seconds().max(1) as f64;
    let max = buckets.iter().map(|b| b.request_count).max().unwrap_or(1) as f64;
    let max = max.max(1.0);

    let mut path = String::new();
    let mut total: i64 = 0;
    for b in buckets {
        total = total.saturating_add(b.request_count);
        let offset =
            ((b.bucket_start - since).whole_seconds().max(0) as f64 / span).clamp(0.0, 1.0);
        let x = (offset * f64::from(WIDTH)).round() as i32;
        let h = ((b.request_count as f64 / max) * f64::from(HEIGHT)).round() as i32;
        let y = i32::from(HEIGHT as i16) - h;
        path.push_str(&format!("M {x} {HEIGHT} L {x} {y} "));
    }
    crate::dashboard::render(&Sparkline {
        points: path.trim_end().to_owned(),
        width: WIDTH,
        height: HEIGHT,
        total,
    })
}

/// Parse the TTL field from the mint form.
///
/// * `""` / `"never"` / `"none"` / `"unlimited"` ⇒ `Ok(None)` — no expiry.
/// * `N` followed by `m`/`h`/`d`/`w`/`y` ⇒ `Ok(Some(now + N units))`.
///
/// No max cap — operator-trust model. Negative or non-numeric N ⇒ `Err`.
fn parse_ttl(raw: &str) -> Result<Option<OffsetDateTime>, String> {
    let lower = raw.to_ascii_lowercase();
    let lower = lower.trim();
    if lower.is_empty() || matches!(lower, "never" | "none" | "unlimited" | "0") {
        return Ok(None);
    }
    let (num, unit) = lower.split_at(
        lower
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("TTL `{raw}` missing unit (try `30d`)"))?,
    );
    let n: i64 = num
        .parse()
        .map_err(|_| format!("TTL `{raw}` must start with a number (e.g. `30d`)"))?;
    if n < 0 {
        return Err(format!("TTL `{raw}` must be non-negative"));
    }
    let secs: i64 = match unit.trim() {
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        "d" => n.saturating_mul(86_400),
        "w" => n.saturating_mul(7 * 86_400),
        "y" => n.saturating_mul(365 * 86_400),
        other => {
            return Err(format!(
                "TTL `{raw}`: unknown unit `{other}` (try m/h/d/w/y)"
            ))
        }
    };
    Ok(Some(
        OffsetDateTime::now_utc() + time::Duration::seconds(secs),
    ))
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn config_toml_snippet(name: &str, secret: &str, public_url: &str) -> String {
    let key = sanitize_toml_key(name);
    let url = format!("{}/mcp", public_url.trim_end_matches('/'));
    format!(
        "[mcp_servers.{key}]\nurl = \"{url}\"\n[mcp_servers.{key}.http_headers]\nAuthorization = \"Bearer {secret}\"\n",
    )
}

/// TOML-table-name-safe identifier derived from the human name. Lowercase,
/// alphanumeric, `_`/`-`. Falls back to "api_key" if everything got stripped.
fn sanitize_toml_key(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() || s.chars().all(|c| c == '_') {
        "api_key".into()
    } else {
        s
    }
}

fn require_csrf(have: Option<&CsrfToken>, submitted: &str) -> Result<(), ApiError> {
    let expected = have
        .ok_or(ApiError::Forbidden("csrf token missing from session"))?
        .0
        .as_str();
    if expected.is_empty() || expected != submitted {
        return Err(ApiError::Forbidden("csrf token mismatch"));
    }
    Ok(())
}

fn form_error(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(format!(
            "<p class=\"empty state-err\">{}</p>",
            html_escape(msg),
        )),
    )
        .into_response()
}

fn feature_disabled() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Html("<p class=\"empty\">API keys are disabled (set GATEWAY_API_KEYS_ENABLED=true to enable).</p>".to_owned()),
    )
        .into_response()
}

fn default_scopes() -> Vec<String> {
    vec![
        "mcp:invoke".into(),
        "mcp:invoke:high".into(),
        "mcp:read".into(),
        "mcp:admin".into(),
        // SCIM scopes available on the dashboard's mint-API-key
        // form so operators can tick them when issuing a
        // SCIM-purpose key for their IdP. Mutually independent —
        // typical SCIM key has scim:read + scim:write but no
        // mcp:invoke.
        "scim:read".into(),
        "scim:write".into(),
    ]
}

// ---- router ---------------------------------------------------------------

/// Returns a stateful sub-router; the caller is responsible for the final
/// `.with_state(...)`. Designed so the dashboard router can `.merge(...)`
/// us in before its own state injection so we share the same `AdminState`
/// without an extra `Arc` clone or a separate state propagation seam.
pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/identities", get(page))
        .route("/identities/api-keys/mint", post(mint))
        .route("/identities/api-keys/{id}/rename", post(rename))
        .route("/identities/api-keys/{id}/revoke", post(revoke))
        .route(
            "/identities/api-keys/{id}/grants",
            get(edit_grants_form).post(update_grants),
        )
        .route("/identities/api-keys/{id}/usage", get(usage))
        .route(
            "/identities/api-key-profiles/create",
            post(crate::api_key_profiles_section::create),
        )
        .route(
            "/identities/api-key-profiles/{id}/delete",
            post(crate::api_key_profiles_section::delete),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_write_errors_preserve_teach_through_unknown_names() {
        match map_catalog_write_error(
            StoreError::UnknownScopes(vec!["team:missing".into()]),
            "testing",
        ) {
            ApiError::BadRequest(message) => {
                assert!(message.contains("team:missing"));
                assert!(message.contains("Scopes page"));
            }
            _ => panic!("unknown scope must remain a caller-correctable bad request"),
        }
        match map_catalog_write_error(
            StoreError::UnknownGroups(vec!["missing-group".into()]),
            "testing",
        ) {
            ApiError::BadRequest(message) => {
                assert!(message.contains("missing-group"));
                assert!(message.contains("Groups page"));
            }
            _ => panic!("unknown group must remain a caller-correctable bad request"),
        }

        let json_error = serde_json::from_str::<serde_json::Value>("{").expect_err("invalid JSON");
        assert!(matches!(
            map_catalog_write_error(StoreError::Json(json_error), "testing"),
            ApiError::Internal(message) if message == "API-key catalog write failed"
        ));
    }

    #[test]
    fn parse_ttl_accepts_never_aliases() {
        for v in ["", "never", "NONE", "Unlimited", "0"] {
            assert_eq!(parse_ttl(v).unwrap(), None);
        }
    }

    #[test]
    fn parse_ttl_accepts_unit_suffixes() {
        let now = OffsetDateTime::now_utc();
        for (raw, secs) in [
            ("60m", 60 * 60),
            ("24h", 24 * 3600),
            ("30d", 30 * 86_400),
            ("1w", 7 * 86_400),
            ("1y", 365 * 86_400),
        ] {
            let parsed = parse_ttl(raw).unwrap().unwrap();
            let delta = (parsed - now).whole_seconds();
            assert!(
                (delta - secs as i64).abs() < 5,
                "{raw}: expected ~{secs}s out, got {delta}",
            );
        }
    }

    #[test]
    fn parse_ttl_rejects_garbage() {
        for v in ["abc", "10x", "-5d", "30"] {
            assert!(parse_ttl(v).is_err(), "{v} should be rejected");
        }
    }

    #[test]
    fn sanitize_toml_key_strips_unsafe() {
        assert_eq!(
            sanitize_toml_key("alice's codex laptop"),
            "alice_s_codex_laptop"
        );
        assert_eq!(sanitize_toml_key("Alice@Codex"), "alice_codex");
        assert_eq!(sanitize_toml_key(""), "api_key");
        assert_eq!(sanitize_toml_key("____"), "api_key");
    }

    #[test]
    fn split_csv_drops_empties() {
        assert_eq!(
            split_csv("mcp-users, , eng"),
            vec!["mcp-users".to_owned(), "eng".to_owned()]
        );
        assert!(split_csv("").is_empty());
        assert!(split_csv(", , ").is_empty());
    }

    #[test]
    fn config_toml_snippet_is_paste_ready() {
        let s = config_toml_snippet("alice codex", "mcpgw_AAA", "https://mcp.example.com");
        assert!(s.contains("[mcp_servers.alice_codex]"));
        assert!(s.contains("url = \"https://mcp.example.com/mcp\""));
        assert!(s.contains("Authorization = \"Bearer mcpgw_AAA\""));
    }

    #[test]
    fn config_toml_snippet_trims_trailing_slash_on_public_url() {
        let s = config_toml_snippet("k", "mcpgw_X", "https://mcp.example.com/");
        assert!(
            s.contains("url = \"https://mcp.example.com/mcp\""),
            "trailing slash on public_url must not become `//mcp`",
        );
    }

    #[test]
    fn html_escape_neutralises_attack_payload() {
        assert_eq!(
            html_escape("</script>\"<img src=x onerror=alert(1)>"),
            "&lt;/script&gt;&quot;&lt;img src=x onerror=alert(1)&gt;",
        );
    }

    /// Catalog-only mint enforcement. With the scope
    /// + group catalog stores wired, `mint_core` rejects a requested scope or
    /// group that isn't in the tenant's catalog, and accepts one that is.
    /// Skips without `AUDIT_DATABASE_URL` (CI provisions Postgres).
    #[tokio::test]
    async fn mint_core_enforces_scope_and_group_catalog() {
        use sqlx::postgres::PgPoolOptions;
        use std::collections::BTreeMap;
        use uuid::Uuid;
        use waygate_apikeys::{PgGroupStore, PgScopeStore};

        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping mint enforcement smoke: AUDIT_DATABASE_URL not set");
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect");
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let tenant = format!("test-mintenf-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
        // One known local scope + one known local group; everything else the
        // mint requests must be a built-in or it's rejected.
        sqlx::query(
            "INSERT INTO scopes (tenant_id, name, source) VALUES ($1, 'team:known', 'local')",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed scope");
        sqlx::query(
            "INSERT INTO scim_groups (tenant_id, display_name, source) VALUES ($1, 'known-grp', 'local')",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed group");

        let upstreams =
            Arc::new(waygate_upstream::pool::UpstreamPool::connect(BTreeMap::new()).await);
        let state = AdminState::new(
            upstreams,
            None,
            None,
            AdminState::null_evidence(),
            Some(ApiKeyStore::new(pool.clone())),
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_api_keys_enabled(true)
        .with_scope_store(Some(Arc::new(PgScopeStore::new(pool.clone()))))
        .with_group_store(Some(Arc::new(PgGroupStore::new(pool.clone()))));

        let mk = |scopes: &[&str], groups: &[&str]| MintParams {
            name: "k".into(),
            sub: "k@example.com".into(),
            email: None,
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            ttl_raw: "1d".into(),
            profile_id: None,
            owner: None,
            reason: None,
        };

        // Unknown scope → BadRequest naming it. (Match directly rather than
        // `unwrap_err` so the success type needn't be `Debug` — `MintedKey`
        // carries the secret and intentionally isn't.)
        match mint_core(
            &state,
            &tenant,
            "tester",
            None,
            mk(&["team:known", "bad:nope"], &[]),
        )
        .await
        {
            Err(ApiError::BadRequest(m)) => {
                assert!(m.contains("bad:nope") && m.contains("scope"), "got: {m}")
            }
            Err(other) => panic!("expected BadRequest for unknown scope, got {other:?}"),
            Ok(_) => panic!("expected an unknown scope to be rejected"),
        }

        // Unknown group → BadRequest naming it.
        match mint_core(
            &state,
            &tenant,
            "tester",
            None,
            mk(&["mcp:read"], &["no-such-grp"]),
        )
        .await
        {
            Err(ApiError::BadRequest(m)) => {
                assert!(m.contains("no-such-grp") && m.contains("group"), "got: {m}")
            }
            Err(other) => panic!("expected BadRequest for unknown group, got {other:?}"),
            Ok(_) => panic!("expected an unknown group to be rejected"),
        }

        // All-known (builtin scope + local scope + local group), plus blank
        // group labels that must be DROPPED before the check + storage →
        // succeeds.
        mint_core(
            &state,
            &tenant,
            "tester",
            None,
            mk(&["mcp:read", "team:known"], &["known-grp", "", "  "]),
        )
        .await
        .expect("mint with known catalog entries must succeed");

        // The persisted row carries only the non-blank group — the blanks
        // were normalized away, not stored.
        let stored: serde_json::Value = sqlx::query_scalar(
            "SELECT groups FROM api_keys WHERE tenant_id = $1 AND sub = 'k@example.com'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("stored row");
        assert_eq!(
            stored,
            serde_json::json!(["known-grp"]),
            "blank group labels must be dropped, not persisted",
        );
    }

    /// `update_grants_core` is the shared edit-grants path. With the catalog +
    /// profile stores wired it: (1) applies a catalog-valid new grant set in
    /// place, (2) rejects an unknown scope (the SAME catalog gate as mint),
    /// (3) re-runs the profile ceiling so an edit can't widen a profiled key
    /// past its `allowed_scopes` (even to a builtin catalog scope), and (4)
    /// refuses to resurrect a revoked key. Skips without `AUDIT_DATABASE_URL`
    /// (CI provisions Postgres).
    #[tokio::test]
    async fn update_grants_core_enforces_catalog_profile_and_revoke_guard() {
        use sqlx::postgres::PgPoolOptions;
        use std::collections::BTreeMap;
        use uuid::Uuid;
        use waygate_apikeys::{PgGroupStore, PgProfileStore, PgScopeStore, ProfileStore};

        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping update_grants_core smoke: AUDIT_DATABASE_URL not set");
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect");
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let tenant = format!("test-editgrants-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
        // Local catalog entries the edits may assign; everything else must be a
        // builtin scope / registered group or it's rejected.
        sqlx::query(
            "INSERT INTO scopes (tenant_id, name, source) VALUES ($1, 'team:known', 'local')",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed scope");
        sqlx::query(
            "INSERT INTO scim_groups (tenant_id, display_name, source) VALUES ($1, 'known-grp', 'local')",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed group");

        // A profile whose ceiling allows mcp:read + team:known but NOT mcp:admin.
        let profile = PgProfileStore::new(pool.clone())
            .create(
                &tenant,
                "limited",
                None,
                86_400,
                &["mcp:read".into(), "team:known".into()],
                None,
                None,
                false,
                false,
            )
            .await
            .expect("seed profile");

        let upstreams =
            Arc::new(waygate_upstream::pool::UpstreamPool::connect(BTreeMap::new()).await);
        let mut state = AdminState::new(
            upstreams,
            None,
            None,
            AdminState::null_evidence(),
            Some(ApiKeyStore::new(pool.clone())),
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_api_keys_enabled(true)
        .with_scope_store(Some(Arc::new(PgScopeStore::new(pool.clone()))))
        .with_group_store(Some(Arc::new(PgGroupStore::new(pool.clone()))));
        state
            .identity
            .api_key_profiles
            .set(Some(Arc::new(PgProfileStore::new(pool.clone()))));
        let state = Arc::new(state);

        // (1) legacy key (no profile): a catalog-valid edit applies in place.
        let legacy = mint_core(
            &state,
            &tenant,
            "tester",
            None,
            MintParams {
                name: "legacy".into(),
                sub: "legacy@example.com".into(),
                email: None,
                groups: vec![],
                scopes: vec!["mcp:read".into()],
                ttl_raw: "1d".into(),
                profile_id: None,
                owner: None,
                reason: None,
            },
        )
        .await
        .expect("mint legacy key");

        update_grants_core(
            &state,
            None,
            legacy.row.id,
            None,
            UpdateGrantsParams {
                scopes: vec!["mcp:read".into(), "team:known".into()],
                groups: vec!["known-grp".into()],
            },
        )
        .await
        .expect("catalog-valid edit must apply");

        let (stored_scopes, stored_groups): (serde_json::Value, serde_json::Value) =
            sqlx::query_as("SELECT scopes, groups FROM api_keys WHERE id = $1")
                .bind(legacy.row.id)
                .fetch_one(&pool)
                .await
                .expect("reload edited row");
        assert_eq!(stored_scopes, serde_json::json!(["mcp:read", "team:known"]));
        assert_eq!(stored_groups, serde_json::json!(["known-grp"]));

        // (2) an unknown scope is rejected (same gate as mint); row unchanged.
        match update_grants_core(
            &state,
            None,
            legacy.row.id,
            None,
            UpdateGrantsParams {
                scopes: vec!["bad:nope".into()],
                groups: vec![],
            },
        )
        .await
        {
            Err(ApiError::BadRequest(m)) => {
                assert!(m.contains("bad:nope") && m.contains("scope"), "got: {m}")
            }
            other => panic!("expected BadRequest for unknown scope, got {other:?}"),
        }
        let after: serde_json::Value =
            sqlx::query_scalar("SELECT scopes FROM api_keys WHERE id = $1")
                .bind(legacy.row.id)
                .fetch_one(&pool)
                .await
                .expect("reload");
        assert_eq!(
            after,
            serde_json::json!(["mcp:read", "team:known"]),
            "a rejected edit must not mutate the row",
        );

        // (3) profile re-validation: a profiled key can't be widened past its
        // allowed_scopes, even to a builtin catalog scope (mcp:admin).
        let profiled = mint_core(
            &state,
            &tenant,
            "tester",
            None,
            MintParams {
                name: "profiled".into(),
                sub: "profiled@example.com".into(),
                email: None,
                groups: vec![],
                scopes: vec!["mcp:read".into()],
                ttl_raw: "1h".into(),
                profile_id: Some(profile.id.to_string()),
                owner: None,
                reason: None,
            },
        )
        .await
        .expect("mint profiled key");
        match update_grants_core(
            &state,
            None,
            profiled.row.id,
            None,
            UpdateGrantsParams {
                scopes: vec!["mcp:admin".into()],
                groups: vec![],
            },
        )
        .await
        {
            Err(ApiError::BadRequest(m)) => {
                assert!(m.contains("mcp:admin") || m.contains("profile"), "got: {m}")
            }
            other => panic!("expected a profile-ceiling rejection, got {other:?}"),
        }

        // (4) a revoked key can't be edited (resurrection guard).
        ApiKeyStore::new(pool.clone())
            .revoke(legacy.row.id)
            .await
            .expect("revoke");
        match update_grants_core(
            &state,
            None,
            legacy.row.id,
            None,
            UpdateGrantsParams {
                scopes: vec!["mcp:read".into()],
                groups: vec![],
            },
        )
        .await
        {
            Err(ApiError::NotFound(_)) => {}
            other => panic!("expected NotFound for revoked key, got {other:?}"),
        }
    }
}
