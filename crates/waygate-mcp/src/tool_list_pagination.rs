//! Authorization- and catalog-bound pagination for the downstream tool list.
//!
//! MCP cursors are opaque continuation values, not authorization grants. Each
//! page rebuilds and reauthorizes the complete canonical view, then accepts a
//! continuation only when it names that same principal context and exact wire
//! catalog. A change therefore fails with `InvalidParams` and asks the client
//! to restart instead of combining pages from different views.

use std::io;
use std::sync::{Arc, OnceLock};

use blake3::Hasher;
use rmcp::model::Tool;
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use waygate_oidc::session::{self, HasExp, SessionKey};
use waygate_oidc::Principal;

/// Full tool declarations can be schema-heavy. The protocol deliberately
/// leaves page size to the server, so keep one response bounded without
/// making clients depend on a caller-selectable size.
pub(crate) const TOOL_LIST_PAGE_SIZE: usize = 50;

const CURSOR_PREFIX: &str = "tl1";
const CURSOR_MAX_BYTES: usize = 320;
const CURSOR_LIFETIME_SECONDS: i64 = 5 * 60;

/// Authenticated, deployment-scoped protection for stateless list cursors.
///
/// The token carries no authority: every page still rebuilds and reauthorizes
/// the catalog. Sealing makes the continuation genuinely opaque and prevents
/// a caller from rewriting the server-selected position or expiry.
#[derive(Clone)]
pub struct ToolListCursorSealer {
    key: SessionKey,
}

impl ToolListCursorSealer {
    pub fn new(key: SessionKey) -> Self {
        Self { key }
    }

    /// Process-local fallback for embedders that do not supply a deployment
    /// continuation key. A single [`GatewayServer`](crate::GatewayServer)
    /// keeps this sealer across clones; the production factory overrides it
    /// with one shared across every request and, when configured, replica.
    pub fn process_local() -> Self {
        let key = SessionKey::from_encoded(&waygate_oidc::new_random_token())
            .expect("a generated 32-byte token is a valid session key");
        Self::new(key)
    }

    fn seal(&self, claims: &CursorClaims) -> Result<String, McpError> {
        session::encrypt(&self.key, claims).map_err(|_| cursor_encoding_error())
    }

    fn open(&self, cursor: &str) -> Result<CursorClaims, McpError> {
        if cursor.len() > CURSOR_MAX_BYTES {
            return Err(invalid_cursor("list"));
        }
        session::decrypt(&self.key, cursor).map_err(|_| invalid_cursor("list"))
    }
}

pub type SharedToolListCursorSealer = Arc<ToolListCursorSealer>;

pub(crate) fn shared_process_local_sealer() -> SharedToolListCursorSealer {
    static SEALER: OnceLock<SharedToolListCursorSealer> = OnceLock::new();
    SEALER
        .get_or_init(|| Arc::new(ToolListCursorSealer::process_local()))
        .clone()
}

#[derive(Serialize, Deserialize)]
struct CursorClaims {
    kind: String,
    exp: i64,
    offset: u64,
    principal: String,
    view: String,
}

impl HasExp for CursorClaims {
    fn exp(&self) -> i64 {
        self.exp
    }
}

pub(crate) struct ToolListPage {
    pub tools: Vec<Tool>,
    pub next_cursor: Option<String>,
}

#[derive(Debug)]
pub(crate) struct BoundListPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct BoundListDomain {
    page_size: usize,
    cursor_kind: &'static str,
    view_domain: &'static [u8],
    operation: &'static str,
}

impl BoundListDomain {
    pub(crate) const fn new(
        page_size: usize,
        cursor_kind: &'static str,
        view_domain: &'static [u8],
        operation: &'static str,
    ) -> Self {
        Self {
            page_size,
            cursor_kind,
            view_domain,
            operation,
        }
    }
}

const TOOL_LIST_DOMAIN: BoundListDomain = BoundListDomain::new(
    TOOL_LIST_PAGE_SIZE,
    CURSOR_PREFIX,
    b"tool-list-view-v1\0",
    "tools/list",
);

pub(crate) fn paginate(
    tools: Vec<Tool>,
    cursor: Option<&str>,
    principal: Option<&Principal>,
    sealer: &ToolListCursorSealer,
) -> Result<ToolListPage, McpError> {
    let page = paginate_bound_at(
        tools,
        cursor,
        principal_binding(principal)?,
        OffsetDateTime::now_utc().unix_timestamp(),
        sealer,
        TOOL_LIST_DOMAIN,
    )?;
    Ok(ToolListPage {
        tools: page.items,
        next_cursor: page.next_cursor,
    })
}

/// Paginate a canonical serializable view with an authenticated cursor bound
/// to the caller and exact view. Custom extension lists reuse the same cursor
/// protection as `tools/list` without sharing cursor namespaces.
pub(crate) fn paginate_bound<T: Serialize>(
    items: Vec<T>,
    cursor: Option<&str>,
    principal: Option<&Principal>,
    sealer: &ToolListCursorSealer,
    domain: BoundListDomain,
) -> Result<BoundListPage<T>, McpError> {
    paginate_bound_at(
        items,
        cursor,
        principal_binding(principal)?,
        OffsetDateTime::now_utc().unix_timestamp(),
        sealer,
        domain,
    )
}

#[cfg(test)]
fn paginate_at(
    tools: Vec<Tool>,
    cursor: Option<&str>,
    principal_binding: String,
    now: i64,
    page_size: usize,
    sealer: &ToolListCursorSealer,
) -> Result<ToolListPage, McpError> {
    let domain = BoundListDomain {
        page_size,
        ..TOOL_LIST_DOMAIN
    };
    let page = paginate_bound_at(tools, cursor, principal_binding, now, sealer, domain)?;
    Ok(ToolListPage {
        tools: page.items,
        next_cursor: page.next_cursor,
    })
}

fn paginate_bound_at<T: Serialize>(
    items: Vec<T>,
    cursor: Option<&str>,
    principal_binding: String,
    now: i64,
    sealer: &ToolListCursorSealer,
    domain: BoundListDomain,
) -> Result<BoundListPage<T>, McpError> {
    debug_assert!(domain.page_size > 0);
    let view_binding = catalog_binding(&items, domain.view_domain)?;
    // The 2026 specification explicitly says an empty cursor is a valid
    // cursor value. This server uses it as the first-page continuation rather
    // than rejecting it for being falsey.
    let start = match cursor {
        None | Some("") => 0,
        Some(cursor) => decode_cursor(
            cursor,
            &principal_binding,
            &view_binding,
            items.len(),
            sealer,
            domain.cursor_kind,
            domain.operation,
        )?,
    };
    let end = start.saturating_add(domain.page_size).min(items.len());
    let has_more = end < items.len();
    let page = items.into_iter().skip(start).take(end - start).collect();
    let next_cursor = has_more
        .then(|| {
            encode_cursor(
                end,
                now.saturating_add(CURSOR_LIFETIME_SECONDS),
                &principal_binding,
                &view_binding,
                sealer,
                domain.cursor_kind,
            )
        })
        .transpose()?;
    Ok(BoundListPage {
        items: page,
        next_cursor,
    })
}

fn encode_cursor(
    offset: usize,
    expires_at: i64,
    principal: &str,
    view: &str,
    sealer: &ToolListCursorSealer,
    cursor_kind: &str,
) -> Result<String, McpError> {
    let offset = u64::try_from(offset).map_err(|_| cursor_encoding_error())?;
    sealer.seal(&CursorClaims {
        kind: cursor_kind.to_owned(),
        exp: expires_at,
        offset,
        principal: principal.to_owned(),
        view: view.to_owned(),
    })
}

fn decode_cursor(
    cursor: &str,
    expected_principal: &str,
    expected_view: &str,
    item_count: usize,
    sealer: &ToolListCursorSealer,
    expected_kind: &str,
    operation: &str,
) -> Result<usize, McpError> {
    let claims = sealer.open(cursor).map_err(|_| invalid_cursor(operation))?;
    let offset = usize::try_from(claims.offset).map_err(|_| invalid_cursor(operation))?;
    if claims.kind != expected_kind
        || claims.principal != expected_principal
        || claims.view != expected_view
        // A cursor is emitted only when at least one later item exists.
        || offset == 0
        || offset >= item_count
    {
        return Err(invalid_cursor(operation));
    }
    Ok(offset)
}

fn principal_binding(principal: Option<&Principal>) -> Result<String, McpError> {
    let mut hasher = Hasher::new();
    hasher.update(b"tool-list-principal-v1\0");
    match principal {
        Some(principal) => {
            // Principal's serde contract excludes the raw bearer token while
            // retaining every authorization-bearing claim and resolved
            // profile restriction. Bind that complete safe projection so a
            // same-subject scope, role, group, SCIM, email, or profile change
            // cannot continue an earlier authorization context.
            serde_json::to_writer(HashWriter(&mut hasher), principal)
                .map_err(|_| cursor_encoding_error())?;
        }
        None => hash_field(&mut hasher, b"disabled-auth"),
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn catalog_binding<T: Serialize>(items: &[T], domain: &[u8]) -> Result<String, McpError> {
    let mut hasher = Hasher::new();
    hasher.update(domain);
    hash_field(&mut hasher, &items.len().to_be_bytes());
    {
        let mut writer = HashWriter(&mut hasher);
        for item in items {
            serde_json::to_writer(&mut writer, item).map_err(|_| cursor_encoding_error())?;
            writer.0.update(&[0]);
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn hash_field(hasher: &mut Hasher, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("in-memory field length fits u64");
    hasher.update(&length.to_be_bytes());
    hasher.update(value);
}

struct HashWriter<'a>(&'a mut Hasher);

impl io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invalid_cursor(operation: &str) -> McpError {
    McpError::invalid_params(
        format!("invalid {operation} cursor; restart listing from the first page"),
        None,
    )
}

fn cursor_encoding_error() -> McpError {
    McpError::internal_error("failed to bind the tools/list catalog view", None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ErrorCode;
    use serde_json::json;
    use std::sync::Arc;
    use waygate_oidc::{ApiKeyProfileRestrictions, AuthMethod, ScimGroupRef, ScimPrincipalAttrs};

    fn tools(names: &[&str]) -> Vec<Tool> {
        names
            .iter()
            .map(|name| {
                Tool::new(
                    (*name).to_owned(),
                    format!("{name} description"),
                    Arc::new(json!({"type": "object"}).as_object().unwrap().clone()),
                )
            })
            .collect()
    }

    fn assert_invalid(result: Result<ToolListPage, McpError>) {
        let error = result.err().expect("cursor must be rejected");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    fn sealer() -> ToolListCursorSealer {
        ToolListCursorSealer::new(SessionKey::from_bytes([7; 32]))
    }

    fn principal() -> Principal {
        Principal {
            sub: "caller".to_owned(),
            email: Some("caller@example.test".to_owned()),
            groups: vec!["operators".to_owned()],
            issuer: "https://issuer.example.test".to_owned(),
            scopes: vec!["mcp:invoke".to_owned()],
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: Some("credential-value-a".to_owned()),
            scim: None,
            enrichment_blocked: None,
            roles: vec!["reader".to_owned()],
            api_key_profile_restrictions: None,
        }
    }

    #[test]
    fn walks_one_bound_view_and_accepts_empty_first_cursor() {
        let sealer = sealer();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = paginate_at(
            tools(&["a", "b", "c"]),
            Some(""),
            "p".into(),
            now,
            2,
            &sealer,
        )
        .expect("empty cursor starts the listing");
        assert_eq!(
            first
                .tools
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        let second = paginate_at(
            tools(&["a", "b", "c"]),
            first.next_cursor.as_deref(),
            "p".into(),
            now,
            2,
            &sealer,
        )
        .expect("cursor continues the same view");
        assert_eq!(
            second
                .tools
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            ["c"]
        );
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn rejects_malformed_expired_cross_context_and_stale_cursors() {
        let sealer = sealer();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = paginate_at(
            tools(&["a", "b"]),
            None,
            "principal-a".into(),
            now,
            1,
            &sealer,
        )
        .expect("first page");
        let cursor = first.next_cursor.expect("continuation");

        assert_invalid(paginate_at(
            tools(&["a", "b"]),
            Some("resource-list:cursor"),
            "principal-a".into(),
            now,
            1,
            &sealer,
        ));
        assert_invalid(paginate_at(
            tools(&["a", "b"]),
            Some(&cursor),
            "principal-b".into(),
            now,
            1,
            &sealer,
        ));
        assert_invalid(paginate_at(
            tools(&["a", "changed"]),
            Some(&cursor),
            "principal-a".into(),
            now,
            1,
            &sealer,
        ));
        let expired = paginate_at(
            tools(&["a", "b"]),
            None,
            "principal-a".into(),
            now - CURSOR_LIFETIME_SECONDS - 1,
            1,
            &sealer,
        )
        .expect("an expired claim can be minted for the verifier test")
        .next_cursor
        .expect("expired continuation");
        assert_invalid(paginate_at(
            tools(&["a", "b"]),
            Some(&expired),
            "principal-a".into(),
            now,
            1,
            &sealer,
        ));
    }

    #[test]
    fn description_and_schema_changes_invalidate_a_continuation() {
        let sealer = sealer();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first =
            paginate_at(tools(&["a", "b"]), None, "p".into(), now, 1, &sealer).expect("first page");
        let cursor = first.next_cursor.expect("continuation");

        let mut changed_description = tools(&["a", "b"]);
        changed_description[1].description = Some("new contract".into());
        assert_invalid(paginate_at(
            changed_description,
            Some(&cursor),
            "p".into(),
            now,
            1,
            &sealer,
        ));

        let mut changed_schema = tools(&["a", "b"]);
        changed_schema[1].input_schema = Arc::new(
            json!({"type": "object", "properties": {"q": {"type": "string"}}})
                .as_object()
                .unwrap()
                .clone(),
        );
        assert_invalid(paginate_at(
            changed_schema,
            Some(&cursor),
            "p".into(),
            now,
            1,
            &sealer,
        ));
    }

    #[test]
    fn refuses_tampered_position_and_expiry() {
        let sealer = sealer();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first =
            paginate_at(tools(&["a", "b"]), None, "p".into(), now, 1, &sealer).expect("first page");
        let cursor = first.next_cursor.expect("continuation");

        for index in [cursor.len() / 3, cursor.len() / 2] {
            let mut tampered = cursor.clone().into_bytes();
            tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
            let tampered = String::from_utf8(tampered).expect("cursor remains UTF-8");
            assert_invalid(paginate_at(
                tools(&["a", "b"]),
                Some(&tampered),
                "p".into(),
                now,
                1,
                &sealer,
            ));
        }
    }

    #[test]
    fn binds_authorization_claims_but_never_the_raw_credential() {
        let base = principal();
        let binding = principal_binding(Some(&base)).expect("principal binding");
        let mut changed = Vec::new();

        let mut email = base.clone();
        email.email = Some("other@example.test".to_owned());
        changed.push(email);
        let mut groups = base.clone();
        groups.groups.push("admins".to_owned());
        changed.push(groups);
        let mut scopes = base.clone();
        scopes.scopes.push("mcp:admin".to_owned());
        changed.push(scopes);
        let mut roles = base.clone();
        roles.roles.push("tenant_admin".to_owned());
        changed.push(roles);
        let mut scim = base.clone();
        scim.scim = Some(ScimPrincipalAttrs {
            user_id: "user-id".to_owned(),
            user_name: "caller".to_owned(),
            external_id: None,
            active: true,
            attrs: serde_json::json!({"department": "operations"}),
            groups: vec![ScimGroupRef {
                id: "group-id".to_owned(),
                display_name: "operations".to_owned(),
            }],
        });
        changed.push(scim);
        let mut profile = base.clone();
        profile.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
            profile_id: "profile-id".to_owned(),
            profile_name: "bounded".to_owned(),
            allowed_servers: Some(vec!["server-a".to_owned()]),
            allowed_tools: None,
        });
        changed.push(profile);

        for principal in changed {
            assert_ne!(
                principal_binding(Some(&principal)).expect("changed binding"),
                binding
            );
        }

        let mut credential_only = base;
        credential_only.raw_token = Some("credential-value-b".to_owned());
        assert_eq!(
            principal_binding(Some(&credential_only)).expect("credential-safe binding"),
            binding,
            "the raw bearer credential is excluded from Principal's serde projection"
        );
    }
}
