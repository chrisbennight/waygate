//! `/api/v1/admin/confidential-clients` — EMA confidential OAuth client registry.
//!
//! Operators register the confidential clients allowed to redeem ID-JAGs at
//! the Resource-AS `jwt-bearer` grant
//! (draft-ietf-oauth-identity-assertion-authz-grant §4.4 / §9.1 — confidential
//! clients only). A client authenticates by `client_secret` (minted here,
//! argon2id-hashed, shown once) and/or `private_key_jwt` (its public JWKS,
//! stored here and used to verify a `client_assertion`).
//!
//! These rows are operator-managed AS infrastructure (the apps allowed to
//! redeem), not per-end-user state, so they are NOT tenant-scoped — a redeemed
//! token's tenant comes from the ID-JAG subject, not the client. Every
//! mutating handler requires `mcp:admin` and emits a fail-closed `AdminMutation`
//! evidence row.
//!
//! The registry + the redeem-side verification live in `waygate-as`
//! (`clients` / `client_auth`); this module is only the admin CRUD surface.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use utoipa::ToSchema;

use waygate_as::ConfidentialClient;
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;
use waygate_core::fmt::format_ts_rfc3339;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/confidential-clients",
            get(list_clients).post(create_client).delete(delete_client),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

// --- DTOs --------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateClientRequest {
    /// OAuth `client_id` — what the redeeming client authenticates as and what
    /// the ID-JAG's `client_id` claim must equal. For CIMD-style clients this
    /// is the metadata-document URL; opaque identifiers are also accepted.
    pub client_id: String,
    /// Mint a `client_secret` for `client_secret`-based auth (returned ONCE in
    /// the response). Defaults to `false`.
    #[serde(default)]
    pub generate_secret: bool,
    /// The client's public JWKS for `private_key_jwt` (`client_assertion`)
    /// auth. Optional. At least one of `generate_secret` / `jwks` must be set.
    #[serde(default)]
    pub jwks: Option<JsonValue>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateClientResponse {
    pub client_id: String,
    /// The minted `client_secret`, present only when `generate_secret` was set.
    /// Shown ONCE — it is argon2id-hashed at rest and cannot be recovered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// The auth methods now configured for this client.
    pub auth_methods: Vec<&'static str>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSummary {
    pub client_id: String,
    /// Whether a `client_secret` is configured (the hash is never returned).
    pub has_secret: bool,
    /// Whether a JWKS (private_key_jwt) is configured.
    pub has_jwks: bool,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
}

impl From<ConfidentialClient> for ClientSummary {
    fn from(c: ConfidentialClient) -> Self {
        Self {
            client_id: c.client_id,
            has_secret: c.secret_hash.is_some(),
            has_jwks: c.jwks.is_some(),
            created_at: format_ts_rfc3339(c.created_at),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientListResponse {
    pub clients: Vec<ClientSummary>,
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct DeleteQuery {
    /// The `client_id` to delete. Passed as a query parameter because client
    /// ids are often URLs (awkward as a path segment).
    pub client_id: String,
}

// --- Validation --------------------------------------------------

const CLIENT_ID_MAX: usize = 2048;

/// Trim + length-check the client_id; return the normalized form (so a list /
/// redeem lookup can't silently miss a `" id "` registration).
fn validate_client_id(client_id: &str) -> Result<String, ApiError> {
    let trimmed = client_id.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("client_id must be non-empty".into()));
    }
    if client_id.len() > CLIENT_ID_MAX {
        return Err(ApiError::BadRequest(format!(
            "client_id must be ≤{CLIENT_ID_MAX} chars"
        )));
    }
    Ok(trimmed.to_owned())
}

/// A JWKS must be an object carrying a non-empty `keys` array — reject obvious
/// garbage at registration rather than storing an un-verifiable key set the
/// redeem path would only reject later.
fn validate_jwks(jwks: &JsonValue) -> Result<(), ApiError> {
    let keys = jwks
        .get("keys")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| ApiError::BadRequest("jwks must be an object with a `keys` array".into()))?;
    if keys.is_empty() {
        return Err(ApiError::BadRequest("jwks.keys must be non-empty".into()));
    }
    Ok(())
}

// --- Handlers ----------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/admin/confidential-clients",
    tag = "confidential_clients",
    request_body = CreateClientRequest,
    responses(
        (status = 201, description = "Client registered", body = CreateClientResponse),
        (status = 400, description = "Invalid fields, or no credential requested", body = ApiErrorBody),
        (status = 409, description = "client_id already registered", body = ApiErrorBody),
        (status = 503, description = "Confidential-client store not configured", body = ApiErrorBody),
        (status = 500, description = "Store error", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn create_client(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Json(body): Json<CreateClientRequest>,
) -> ApiResult<(StatusCode, Json<CreateClientResponse>)> {
    let store = state.identity.confidential_clients.require()?;

    let client_id = validate_client_id(&body.client_id)?;
    if !body.generate_secret && body.jwks.is_none() {
        return Err(ApiError::BadRequest(
            "at least one of `generate_secret` or `jwks` must be provided".into(),
        ));
    }
    if let Some(jwks) = body.jwks.as_ref() {
        validate_jwks(jwks)?;
    }

    // Mint + hash the secret if requested. The plaintext is returned once and
    // never stored.
    let (secret_plain, secret_hash) = if body.generate_secret {
        let secret = format!("cs_{}", waygate_oidc::pkce::new_random_token());
        let hash = waygate_apikeys::token::hash_secret(&secret)
            .map_err(|e| ApiError::Internal(format!("hash client secret: {e}")))?;
        (Some(secret), Some(hash))
    } else {
        (None, None)
    };

    // Atomic insert: refuse to silently overwrite an existing registration
    // (which would rotate its secret / replace its keys). `insert` returns
    // `false` on conflict with no read-then-write race, so two concurrent POSTs
    // can't both pass a precheck and clobber each other. To rotate, operators
    // DELETE then re-create.
    let inserted = store
        .insert(&client_id, secret_hash.as_deref(), body.jwks.as_ref())
        .await
        .map_err(|e| ApiError::Internal(format!("confidential-client store: {e}")))?;
    if !inserted {
        return Err(ApiError::Conflict(format!(
            "confidential client `{client_id}` is already registered"
        )));
    }

    let mut auth_methods = Vec::new();
    if secret_hash.is_some() {
        auth_methods.push("client_secret");
    }
    if body.jwks.is_some() {
        auth_methods.push("private_key_jwt");
    }

    crate::admin_mutation::record_admin_mutation(
        &state,
        "confidential_clients",
        "GET /api/v1/admin/confidential-clients",
        actor.tenant.as_str(),
        Some(&actor),
        "ConfidentialClientRegistered",
        // No secret/jwks material in the reason — just identity + which methods.
        format!(
            "registered confidential client client_id={client_id} methods={}",
            auth_methods.join("+"),
        ),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateClientResponse {
            client_id,
            client_secret: secret_plain,
            auth_methods,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/confidential-clients",
    tag = "confidential_clients",
    responses(
        (status = 200, description = "Registered confidential clients (no secrets)", body = ClientListResponse),
        (status = 503, description = "Confidential-client store not configured", body = ApiErrorBody),
        (status = 500, description = "Store error", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_clients(State(state): State<Arc<AdminState>>) -> ApiResult<Json<ClientListResponse>> {
    let store = state.identity.confidential_clients.require()?;
    let clients = store
        .list()
        .await
        .map_err(|e| ApiError::Internal(format!("confidential-client store: {e}")))?
        .into_iter()
        .map(ClientSummary::from)
        .collect();
    Ok(Json(ClientListResponse { clients }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/confidential-clients",
    tag = "confidential_clients",
    params(DeleteQuery),
    responses(
        (status = 204, description = "Client deleted"),
        (status = 404, description = "No such confidential client", body = ApiErrorBody),
        (status = 503, description = "Confidential-client store not configured", body = ApiErrorBody),
        (status = 500, description = "Store error", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn delete_client(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<DeleteQuery>,
) -> ApiResult<StatusCode> {
    let store = state.identity.confidential_clients.require()?;
    let client_id = validate_client_id(&q.client_id)?;
    let removed = store
        .delete(&client_id)
        .await
        .map_err(|e| ApiError::Internal(format!("confidential-client store: {e}")))?;
    if !removed {
        return Err(ApiError::NotFound("confidential client"));
    }
    crate::admin_mutation::record_admin_mutation(
        &state,
        "confidential_clients",
        "GET /api/v1/admin/confidential-clients",
        actor.tenant.as_str(),
        Some(&actor),
        "ConfidentialClientDeleted",
        format!("deleted confidential client client_id={client_id}"),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_client_id_trims_and_rejects_empty() {
        assert_eq!(
            validate_client_id("  https://app/c.json  ").unwrap(),
            "https://app/c.json",
        );
        assert!(matches!(
            validate_client_id("   "),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn validate_client_id_rejects_over_length() {
        let long = "x".repeat(CLIENT_ID_MAX + 1);
        assert!(matches!(
            validate_client_id(&long),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn validate_jwks_requires_nonempty_keys() {
        assert!(validate_jwks(&json!({"keys": [{"kty": "OKP"}]})).is_ok());
        assert!(matches!(
            validate_jwks(&json!({"keys": []})),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            validate_jwks(&json!({"not_keys": 1})),
            Err(ApiError::BadRequest(_))
        ));
    }
}
