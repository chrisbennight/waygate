//! `POST /api/v1/audit/bundle` — signed evidence-bundle
//! export for compliance auditors.
//!
//! Returns the bundle as `application/x-ndjson` with a
//! `Content-Disposition: attachment` hint so browsers and
//! CLI clients save it as a file the operator can hand over
//! to an auditor. The bundle's signature is verifiable
//! offline against the operator's published public key (no
//! live gateway access needed).
//!
//! ## Auth
//!
//! Same `require_admin` middleware as the other
//! `/api/v1/audit` handlers. Role
//! separation means the gateway DB user can `SELECT` from
//! audit_log but can't update or delete its rows; the bundle reflects
//! a point-in-time row slice. The slice can contain unchained
//! best-effort rows, and bundle format version 1 does not attest
//! chain coverage or database completeness.
//!
//! ## Audit-of-the-audit-export
//!
//! Every successful bundle export records an
//! `AdminMutation` event stamped to the target tenant's
//! chain (same pattern as `audit_retention`,
//! `audit_routing`, `audit_sweep`). The signature detects
//! changes to the signed header and row records; format
//! version 1 leaves the footer unsigned. The `AdminMutation`
//! event separately captures "operator X exported a bundle
//! for tenant Y in window Z at time T."
//! Compliance reviews of "who exported what when" pivot on
//! that event, not on unauthenticated file metadata.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::Response;
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

use waygate_core::TenantId;
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;
use waygate_storage::{build_bundle, BundleRequest};

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/audit/bundle", post(create_bundle))
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateBundleBody {
    pub tenant_id: String,
    /// Window start (inclusive). RFC3339.
    #[serde(with = "time::serde::rfc3339")]
    pub from: OffsetDateTime,
    /// Window end (inclusive). RFC3339.
    #[serde(with = "time::serde::rfc3339")]
    pub to: OffsetDateTime,
    /// Optional filter: only events for this principal.
    #[serde(default)]
    pub principal_sub: Option<String>,
    /// Optional filter: only events for this tool (matched
    /// against `audit_log.tool` exactly — operators wanting
    /// "all of server X" can iterate per-tool externally).
    #[serde(default)]
    pub tool: Option<String>,
    /// Maximum rows to include. Defaults to 10_000;
    /// hard-clamped to 100_000 by the reader. Bundles
    /// hitting the cap signal the operator to narrow the
    /// window or principal/tool filter rather than ship a
    /// partial export.
    #[serde(default)]
    pub limit: Option<i64>,
}

#[utoipa::path(
    post,
    path = "/api/v1/audit/bundle",
    tag = "audit",
    request_body = CreateBundleBody,
    responses(
        (status = 200, description = "Signed NDJSON evidence bundle", content_type = "application/x-ndjson"),
        (status = 400, description = "Invalid body (empty tenant, malformed tenant, from > to)", body = ApiErrorBody),
        (status = 503, description = "Audit reader OR bundle signing key not configured", body = ApiErrorBody),
        (status = 500, description = "Reader query or bundle assembly failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn create_bundle(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<CreateBundleBody>,
) -> ApiResult<Response<Body>> {
    if body.tenant_id.trim().is_empty() {
        return Err(ApiError::BadRequest("tenant_id is required".to_owned()));
    }
    let target_tenant = TenantId::parse(body.tenant_id.clone())
        .map_err(|e| ApiError::BadRequest(format!("invalid tenant_id: {e}")))?;
    if body.from > body.to {
        return Err(ApiError::BadRequest(
            "from must be <= to (RFC3339 inclusive window)".to_owned(),
        ));
    }

    let reader = state.observability.audit.require()?;
    let bundle_signer = state.observability.bundle_signer.require()?;

    let limit = body.limit.unwrap_or(10_000);
    let (rows, has_more) = reader
        .fetch_events_for_bundle(
            &body.tenant_id,
            body.from,
            body.to,
            body.principal_sub.as_deref(),
            body.tool.as_deref(),
            limit,
        )
        .await
        .map_err(|e| ApiError::Internal(format!("bundle reader: {e}")))?;
    // Never knowingly sign a server-truncated query result. The v1 signature
    // authenticates the selected bytes and row_count, but it does not prove
    // database completeness to an offline auditor. Refusing `has_more` still
    // prevents this endpoint from silently dropping rows it knows matched.
    // 413 plus narrow-window guidance is the correct disposition.
    if has_more {
        return Err(ApiError::PayloadTooLarge(format!(
            "result exceeds bundle cap of {limit} rows; narrow the window (from/to), \
             principal_sub, or tool filter and retry. Server-side reader hard-clamps at \
             100_000 rows per bundle."
        )));
    }
    let row_count = rows.len();

    let req = BundleRequest {
        tenant_id: body.tenant_id.clone(),
        from: body.from,
        to: body.to,
        principal_sub: body.principal_sub.clone(),
        tool: body.tool.clone(),
    };
    let bytes = build_bundle(
        &req,
        &rows,
        &bundle_signer.signing_key_id,
        env!("CARGO_PKG_VERSION"),
        &bundle_signer.signing_key,
    )
    .map_err(|e| ApiError::Internal(format!("bundle build: {e}")))?;

    // AdminMutation for the export
    // itself lands in the target tenant's chain. Compliance
    // pivot "who exported what when" reads this row, not the
    // bundle file metadata. Post-export file metadata is not authenticated.
    // The append-only trigger prevents the ordinary runtime DB role from
    // updating or deleting the required-write audit row.
    let actor = principal.as_ref().map(|Extension(p)| p);
    state
        .evidence
        .record_required(
            AuditEvent::new("audit_bundle.export", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(actor)
                .with_tenant(target_tenant)
                .with_reason(format!(
                    "bundle export tenant={} from={} to={} principal={} tool={} rows={} key_id={}",
                    body.tenant_id,
                    body.from,
                    body.to,
                    body.principal_sub.as_deref().unwrap_or("*"),
                    body.tool.as_deref().unwrap_or("*"),
                    row_count,
                    bundle_signer.signing_key_id,
                )),
        )
        .await
        .map_err(|e| {
            ApiError::Internal(format!(
                "bundle export prepared but not sent because required audit recording failed; retry: {e}"
            ))
        })?;

    // Filename hint: `<tenant>-<from-date>-<to-date>.ndjson`,
    // with safe-character replacement so the operator gets
    // a sensible save dialog default.
    let filename = format!(
        "{}-{}-{}.ndjson",
        sanitize_for_filename(&body.tenant_id),
        body.from.date(),
        body.to.date(),
    );
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-ndjson")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(bytes))
        .map_err(|e| ApiError::Internal(format!("response build: {e}")))?;
    Ok(resp)
}

/// Strip everything except `[A-Za-z0-9._-]` from the tenant
/// id so a path-traversal-shaped tenant string can't end up
/// in the Content-Disposition filename header. Empty result
/// falls back to literal `tenant` so the format string still
/// produces a sensible filename.
fn sanitize_for_filename(s: &str) -> String {
    let out: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .collect();
    if out.is_empty() {
        "tenant".to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_for_filename;

    #[test]
    fn sanitize_strips_unsafe_filename_chars() {
        assert_eq!(sanitize_for_filename("acme"), "acme");
        assert_eq!(sanitize_for_filename("acme-corp_2026"), "acme-corp_2026");
        // path-traversal attempts
        assert_eq!(sanitize_for_filename("../../etc/passwd"), "....etcpasswd");
        // unicode
        assert_eq!(sanitize_for_filename("tëñânt"), "tnt");
        // empty fallback
        assert_eq!(sanitize_for_filename(""), "tenant");
        assert_eq!(sanitize_for_filename("///"), "tenant");
    }
}
