//! Admin API error shape. Converting everything through a single type means
//! clients see a consistent JSON envelope and we never accidentally leak an
//! internal `Debug` formatting through `IntoResponse`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;

/// OpenAPI schema for the JSON envelope returned by [`ApiError`]. Kept as a
/// distinct type (rather than inlining `serde_json::Value`) so the generated
/// spec documents the `error` / `detail` shape every caller can expect.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiErrorBody {
    /// Short machine-readable code: `not_found`, `unauthorized`,
    /// `forbidden`, `service_unavailable`, `bad_request`, `internal_error`.
    pub error: String,
    /// Human-readable detail. Internal errors collapse to `"internal error"`
    /// to avoid leaking implementation detail.
    pub detail: String,
}

#[derive(Debug)]
pub enum ApiError {
    NotFound(&'static str),
    /// Same as [`Self::NotFound`] but the
    /// detail message is constructed at runtime (e.g.
    /// `"role <uuid>"`). Old static-detail call sites stay
    /// on `NotFound`; new handlers that want to name the
    /// missing resource use this. Both render as HTTP 404
    /// with `error: "not_found"`.
    NotFoundDyn(String),
    Unauthorized(&'static str),
    Forbidden(&'static str),
    /// Same as [`Self::Forbidden`] but the detail is built at runtime —
    /// the policy-editing gate names *why* a write was refused (the flag is
    /// off, or the policies dir isn't writable), and that reason is
    /// operator-actionable, not a fixed string. Renders as HTTP 403 with
    /// `error: "forbidden"`, like [`Self::Forbidden`].
    ForbiddenDyn(String),
    /// HTTP 409. Used when a request is well-formed and authorized but
    /// rejected by a policy precondition (e.g. two-approver mode refuses
    /// the same actor from approving twice — the request is valid in
    /// isolation but conflicts with prior state).
    Conflict(String),
    ServiceUnavailable(&'static str),
    BadGateway(String),
    BadRequest(String),
    /// HTTP 422 for well-formed requests
    /// that reference a non-existent parent (e.g. RBAC admin
    /// trying to create an assignment for a role_id that
    /// doesn't exist in this tenant). Distinct from
    /// `NotFound` (404, the *requested* resource doesn't
    /// exist) and from `Conflict` (409, the requested
    /// resource exists but the operation violates an
    /// invariant against existing state).
    UnprocessableEntity(String),
    /// HTTP 500 carrying the actual detail string to the
    /// client — distinct from `Internal(String)` which deliberately collapses
    /// the detail to "internal error" to avoid leaking
    /// implementation specifics. Used for operator-actionable
    /// 500s like "audit-of-record persistence failed; verify
    /// via the matching list endpoint" where the detail is
    /// operator-supplied and intentionally surface-able.
    InternalOperatorVisible(String),
    /// HTTP 413. The request is well-formed and authorised
    /// but the response would exceed a hard cap (e.g. the
    /// bundle export refuses to sign a result that
    /// hit `limit + 1` rows — partial bundles would mislead
    /// the auditor).
    PayloadTooLarge(String),
    Internal(String),
}

impl ApiError {
    /// The human-readable detail string, for surfaces that render the error
    /// OUTSIDE the JSON `IntoResponse` body — e.g. the dashboard PRG flash that
    /// shows WHY a policy publish was rejected (a failing-test gate 422, a
    /// not-a-draft 409, …) when it routes through a shared `ApiResult` core.
    /// `Internal` collapses to a generic message, matching `IntoResponse`'s
    /// deliberate non-leak posture.
    pub fn detail(&self) -> String {
        match self {
            ApiError::NotFound(d)
            | ApiError::Unauthorized(d)
            | ApiError::Forbidden(d)
            | ApiError::ServiceUnavailable(d) => (*d).to_owned(),
            ApiError::NotFoundDyn(d)
            | ApiError::ForbiddenDyn(d)
            | ApiError::Conflict(d)
            | ApiError::BadGateway(d)
            | ApiError::BadRequest(d)
            | ApiError::UnprocessableEntity(d)
            | ApiError::InternalOperatorVisible(d)
            | ApiError::PayloadTooLarge(d) => d.clone(),
            // Match `IntoResponse`: never surface the internal detail.
            ApiError::Internal(_) => "internal error".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, detail) = match self {
            ApiError::NotFound(d) => (StatusCode::NOT_FOUND, "not_found", d.to_owned()),
            ApiError::NotFoundDyn(d) => (StatusCode::NOT_FOUND, "not_found", d),
            ApiError::Unauthorized(d) => (StatusCode::UNAUTHORIZED, "unauthorized", d.to_owned()),
            ApiError::Forbidden(d) => (StatusCode::FORBIDDEN, "forbidden", d.to_owned()),
            ApiError::ForbiddenDyn(d) => (StatusCode::FORBIDDEN, "forbidden", d),
            ApiError::Conflict(d) => (StatusCode::CONFLICT, "conflict", d),
            ApiError::ServiceUnavailable(d) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                d.to_owned(),
            ),
            ApiError::BadGateway(d) => (StatusCode::BAD_GATEWAY, "bad_gateway", d),
            ApiError::BadRequest(d) => (StatusCode::BAD_REQUEST, "bad_request", d),
            ApiError::UnprocessableEntity(d) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "invalid_reference", d)
            }
            ApiError::InternalOperatorVisible(d) => {
                // 500 with the detail surfaced — for operator-
                // actionable failures like "audit didn't persist,
                // verify via list" where the detail is
                // operator-supplied and intentionally safe to
                // expose.
                tracing::error!(detail = %d, "admin api operator-visible 500");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", d)
            }
            ApiError::PayloadTooLarge(d) => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", d),
            ApiError::Internal(d) => {
                tracing::error!(detail = %d, "admin api internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal error".to_owned(),
                )
            }
        };
        (status, Json(json!({"error": code, "detail": detail}))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
