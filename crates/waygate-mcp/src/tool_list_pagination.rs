//! Authorization- and catalog-bound pagination for the downstream tool list.
//!
//! MCP cursors are opaque continuation values, not authorization grants. A
//! traversal pages exactly one view: the complete authorized list built for
//! its first page. That page captures the list for a short, bounded window,
//! and a continuation from the same principal context and presentation is
//! served from the captured list, so the traversal completes consistently
//! while the live
//! catalog changes. The client therefore receives what a single unpaginated
//! response would have returned when the traversal began; every call is still
//! resolved and authorized at invocation.
//!
//! When the captured list is no longer held (expired, evicted, or captured by
//! another process), the continuation rebuilds and reauthorizes the live view
//! and accepts the cursor only when it names that same principal context and
//! exact wire catalog. A change then fails with `InvalidParams` and asks the
//! client to restart instead of combining pages from different views.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

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
/// How long a first-page view serves its traversal's continuations. This
/// bounds how stale a continuation page can be; a slower traversal falls back
/// to rebuilding the live view.
const CAPTURED_VIEW_RETENTION_SECONDS: i64 = 60;
/// Captured views held at once. Each is a complete authorized tool list, so
/// the bound limits memory; an evicted view falls back like an expired one.
const CAPTURED_VIEW_CAPACITY: usize = 16;

/// Authenticated, deployment-scoped protection for stateless list cursors.
///
/// The token carries no authority: a continuation is served only from a view
/// built and authorized for the same principal context. Sealing makes the
/// continuation genuinely opaque and prevents a caller from rewriting the
/// server-selected position or expiry. Clones share the captured tool-list
/// views, so one sealer serves every request in a process.
#[derive(Clone)]
pub struct ToolListCursorSealer {
    key: SessionKey,
    captured: Arc<Mutex<CapturedViews>>,
}

impl ToolListCursorSealer {
    pub fn new(key: SessionKey) -> Self {
        Self {
            key,
            captured: Arc::default(),
        }
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

    fn open(&self, cursor: &str) -> Result<CursorClaims, CursorRejection> {
        if cursor.len() > CURSOR_MAX_BYTES {
            return Err(CursorRejection::Unreadable);
        }
        session::decrypt(&self.key, cursor).map_err(|error| match error {
            session::SessionError::Expired => CursorRejection::Expired,
            _ => CursorRejection::Unreadable,
        })
    }

    fn capture(&self, view: CapturedView) {
        self.captured
            .lock()
            .expect(
                "captured tool-list views mutex poisoned — a prior panic corrupted shared state",
            )
            .insert(view);
    }

    fn captured_view(
        &self,
        principal: &str,
        presentation: ToolListPresentation,
        view: &str,
        now: i64,
    ) -> Option<Arc<[Tool]>> {
        self.captured
            .lock()
            .expect(
                "captured tool-list views mutex poisoned — a prior panic corrupted shared state",
            )
            .get(principal, presentation, view, now)
    }
}

/// What a client is shown of its authorized catalog: the projection, its
/// ordering, and whether presentation-only schema adaptation applies. A
/// captured view serves only continuations requesting the same presentation,
/// so pages from different presentations are never combined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ToolListPresentation {
    pub(crate) projection: &'static str,
    pub(crate) canonical_order: bool,
    pub(crate) schema_adapted: bool,
}

/// First-page tool lists still serving their traversals, oldest first.
#[derive(Default)]
struct CapturedViews {
    entries: VecDeque<CapturedView>,
}

struct CapturedView {
    principal: String,
    presentation: ToolListPresentation,
    view: String,
    captured_at: i64,
    tools: Arc<[Tool]>,
}

impl CapturedView {
    fn serves(&self, principal: &str, presentation: ToolListPresentation, view: &str) -> bool {
        self.principal == principal && self.presentation == presentation && self.view == view
    }
}

impl CapturedViews {
    /// Hold `view`, dropping expired entries and any entry for the same
    /// principal, presentation, and view, and evicting the oldest entries
    /// beyond capacity.
    fn insert(&mut self, view: CapturedView) {
        self.entries.retain(|held| {
            view.captured_at.saturating_sub(held.captured_at) <= CAPTURED_VIEW_RETENTION_SECONDS
                && !held.serves(&view.principal, view.presentation, &view.view)
        });
        while self.entries.len() >= CAPTURED_VIEW_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(view);
    }

    fn get(
        &mut self,
        principal: &str,
        presentation: ToolListPresentation,
        view: &str,
        now: i64,
    ) -> Option<Arc<[Tool]>> {
        self.entries
            .retain(|held| now.saturating_sub(held.captured_at) <= CAPTURED_VIEW_RETENTION_SECONDS);
        self.entries
            .iter()
            .find(|held| held.serves(principal, presentation, view))
            .map(|held| Arc::clone(&held.tools))
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

/// Page a freshly built and authorized tool view. A continuation is accepted
/// only when it names exactly this view. A page that issues a continuation
/// captures the view, so [`resume_captured`] can serve the rest of the
/// traversal without rebuilding the catalog.
pub(crate) fn paginate(
    tools: Vec<Tool>,
    cursor: Option<&str>,
    principal: Option<&Principal>,
    presentation: ToolListPresentation,
    sealer: &ToolListCursorSealer,
) -> Result<ToolListPage, McpError> {
    paginate_tools_at(
        tools,
        cursor,
        principal_binding(principal)?,
        presentation,
        OffsetDateTime::now_utc().unix_timestamp(),
        TOOL_LIST_PAGE_SIZE,
        sealer,
    )
}

/// Serve a continuation from the view its traversal captured for the same
/// principal context and presentation. Returns `Ok(None)` for a first-page
/// request or when no such view is held here; the caller then builds the live
/// view and calls [`paginate`], which accepts the cursor only if the view is
/// unchanged.
pub(crate) fn resume_captured(
    cursor: Option<&str>,
    principal: Option<&Principal>,
    presentation: ToolListPresentation,
    sealer: &ToolListCursorSealer,
) -> Result<Option<ToolListPage>, McpError> {
    let Some(cursor) = cursor.filter(|cursor| !cursor.is_empty()) else {
        return Ok(None);
    };
    resume_captured_at(
        cursor,
        &principal_binding(principal)?,
        presentation,
        OffsetDateTime::now_utc().unix_timestamp(),
        TOOL_LIST_PAGE_SIZE,
        sealer,
    )
}

fn paginate_tools_at(
    tools: Vec<Tool>,
    cursor: Option<&str>,
    principal_binding: String,
    presentation: ToolListPresentation,
    now: i64,
    page_size: usize,
    sealer: &ToolListCursorSealer,
) -> Result<ToolListPage, McpError> {
    let view = catalog_binding(&tools, TOOL_LIST_DOMAIN.view_domain)?;
    let start = match cursor {
        None | Some("") => 0,
        Some(cursor) => decode_cursor(
            cursor,
            &principal_binding,
            &view,
            tools.len(),
            sealer,
            TOOL_LIST_DOMAIN.cursor_kind,
            TOOL_LIST_DOMAIN.operation,
        )?,
    };
    let tools: Arc<[Tool]> = tools.into();
    let page = tool_page(
        &tools,
        start,
        page_size,
        now,
        &principal_binding,
        &view,
        sealer,
    )?;
    if page.next_cursor.is_some() {
        sealer.capture(CapturedView {
            principal: principal_binding,
            presentation,
            view,
            captured_at: now,
            tools,
        });
    }
    Ok(page)
}

fn resume_captured_at(
    cursor: &str,
    principal_binding: &str,
    presentation: ToolListPresentation,
    now: i64,
    page_size: usize,
    sealer: &ToolListCursorSealer,
) -> Result<Option<ToolListPage>, McpError> {
    let operation = TOOL_LIST_DOMAIN.operation;
    let claims = open_cursor(
        cursor,
        principal_binding,
        sealer,
        TOOL_LIST_DOMAIN.cursor_kind,
        operation,
    )?;
    let Some(tools) = sealer.captured_view(principal_binding, presentation, &claims.view, now)
    else {
        return Ok(None);
    };
    let start =
        checked_offset(claims.offset, tools.len()).map_err(|reason| reject(operation, reason))?;
    tool_page(
        &tools,
        start,
        page_size,
        now,
        principal_binding,
        &claims.view,
        sealer,
    )
    .map(Some)
}

fn tool_page(
    tools: &[Tool],
    start: usize,
    page_size: usize,
    now: i64,
    principal_binding: &str,
    view: &str,
    sealer: &ToolListCursorSealer,
) -> Result<ToolListPage, McpError> {
    debug_assert!(page_size > 0);
    let end = start.saturating_add(page_size).min(tools.len());
    let next_cursor = (end < tools.len())
        .then(|| {
            encode_cursor(
                end,
                now.saturating_add(CURSOR_LIFETIME_SECONDS),
                principal_binding,
                view,
                sealer,
                TOOL_LIST_DOMAIN.cursor_kind,
            )
        })
        .transpose()?;
    Ok(ToolListPage {
        tools: tools[start..end].to_vec(),
        next_cursor,
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
    paginate_tools_at(
        tools,
        cursor,
        principal_binding,
        TEST_PRESENTATION,
        now,
        page_size,
        sealer,
    )
}

#[cfg(test)]
const TEST_PRESENTATION: ToolListPresentation = ToolListPresentation {
    projection: "full",
    canonical_order: true,
    schema_adapted: false,
};

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
    let claims = open_cursor(cursor, expected_principal, sealer, expected_kind, operation)?;
    if claims.view != expected_view {
        return Err(reject(operation, CursorRejection::ChangedView));
    }
    checked_offset(claims.offset, item_count).map_err(|reason| reject(operation, reason))
}

/// Open a continuation minted for this list kind and principal context.
fn open_cursor(
    cursor: &str,
    expected_principal: &str,
    sealer: &ToolListCursorSealer,
    expected_kind: &str,
    operation: &str,
) -> Result<CursorClaims, McpError> {
    let claims = sealer
        .open(cursor)
        .map_err(|reason| reject(operation, reason))?;
    if claims.kind != expected_kind {
        return Err(reject(operation, CursorRejection::OtherList));
    }
    if claims.principal != expected_principal {
        return Err(reject(operation, CursorRejection::OtherCaller));
    }
    Ok(claims)
}

/// A cursor is emitted only when at least one later item exists.
fn checked_offset(offset: u64, item_count: usize) -> Result<usize, CursorRejection> {
    let offset = usize::try_from(offset).map_err(|_| CursorRejection::PositionOutOfRange)?;
    if offset == 0 || offset >= item_count {
        return Err(CursorRejection::PositionOutOfRange);
    }
    Ok(offset)
}

/// The check a rejected continuation failed. Only `ChangedView` is expected
/// in normal operation, when the live catalog changed and the traversal's
/// captured view was no longer held.
#[derive(Clone, Copy)]
enum CursorRejection {
    Unreadable,
    Expired,
    OtherList,
    OtherCaller,
    ChangedView,
    PositionOutOfRange,
}

impl CursorRejection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::Expired => "expired",
            Self::OtherList => "other_list",
            Self::OtherCaller => "other_caller",
            Self::ChangedView => "changed_view",
            Self::PositionOutOfRange => "position_out_of_range",
        }
    }
}

/// Reject a continuation and record which check failed, so operators can
/// tell a catalog change from a stale, foreign, or damaged cursor. The
/// cursor and its bindings are not logged.
fn reject(operation: &str, reason: CursorRejection) -> McpError {
    tracing::info!(
        operation,
        reason = reason.as_str(),
        "rejected list continuation cursor"
    );
    invalid_cursor(operation)
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

    fn names(page: &ToolListPage) -> Vec<&str> {
        page.tools.iter().map(|tool| tool.name.as_ref()).collect()
    }

    fn resumed(
        cursor: &str,
        principal: &str,
        now: i64,
        sealer: &ToolListCursorSealer,
    ) -> Result<Option<ToolListPage>, McpError> {
        resume_captured_at(cursor, principal, TEST_PRESENTATION, now, 2, sealer)
    }

    #[test]
    fn a_traversal_completes_on_its_captured_view_while_the_catalog_changes() {
        let sealer = sealer();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let captured = ["a", "b", "c", "d", "e"];
        let first = paginate_at(tools(&captured), None, "p".into(), now, 2, &sealer)
            .expect("first page captures the view");
        let mut walked = names(&first)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();

        // The live catalog changes after the first page. The live check
        // rejects the old continuation, but the captured view serves it.
        assert_invalid(paginate_at(
            tools(&["a", "b", "changed", "d", "e"]),
            first.next_cursor.as_deref(),
            "p".into(),
            now,
            2,
            &sealer,
        ));
        let mut cursor = first.next_cursor;
        while let Some(next) = cursor {
            let page = resumed(&next, "p", now, &sealer)
                .expect("continuation accepted")
                .expect("captured view is held");
            walked.extend(names(&page).into_iter().map(str::to_owned));
            cursor = page.next_cursor;
        }
        assert_eq!(
            walked, captured,
            "pages concatenate to the captured view in order, each tool exactly once"
        );
    }

    #[test]
    fn a_captured_view_serves_only_its_principal_context() {
        let sealer = sealer();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = paginate_at(tools(&["a", "b", "c"]), None, "p".into(), now, 2, &sealer)
            .expect("first page");
        let cursor = first.next_cursor.expect("continuation");

        let error = resumed(&cursor, "other", now, &sealer)
            .err()
            .expect("another principal context is refused, not sent to the live check");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
        assert!(resumed("resource-list:cursor", "p", now, &sealer).is_err());
    }

    #[test]
    fn an_unheld_view_falls_back_to_the_live_check() {
        let sealer = sealer();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = paginate_at(tools(&["a", "b", "c"]), None, "p".into(), now, 2, &sealer)
            .expect("first page");
        let cursor = first.next_cursor.expect("continuation");

        let later = now + CAPTURED_VIEW_RETENTION_SECONDS + 1;
        assert!(
            resumed(&cursor, "p", later, &sealer)
                .expect("an unheld view is not an error")
                .is_none(),
            "a view past its retention window is no longer served"
        );
        let other_process = ToolListCursorSealer {
            key: sealer.key.clone(),
            captured: Arc::default(),
        };
        assert!(
            resumed(&cursor, "p", now, &other_process)
                .expect("a view held elsewhere is not an error")
                .is_none(),
            "a process that did not capture the view cannot serve it"
        );

        assert_invalid(paginate_at(
            tools(&["a", "b", "changed"]),
            Some(&cursor),
            "p".into(),
            later,
            2,
            &other_process,
        ));
        let live = paginate_at(
            tools(&["a", "b", "c"]),
            Some(&cursor),
            "p".into(),
            later,
            2,
            &other_process,
        )
        .expect("an unchanged live view accepts the continuation");
        assert_eq!(names(&live), ["c"]);
    }

    #[test]
    fn capacity_evicts_the_oldest_captured_view() {
        let sealer = sealer();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let cursors = (0..=CAPTURED_VIEW_CAPACITY)
            .map(|index| {
                paginate_at(
                    tools(&["a", "b", "c"]),
                    None,
                    format!("p{index}"),
                    now,
                    2,
                    &sealer,
                )
                .expect("first page")
                .next_cursor
                .expect("continuation")
            })
            .collect::<Vec<_>>();

        assert!(resumed(&cursors[0], "p0", now, &sealer)
            .expect("evicted view falls back")
            .is_none());
        let newest = CAPTURED_VIEW_CAPACITY;
        assert!(
            resumed(&cursors[newest], &format!("p{newest}"), now, &sealer)
                .expect("newest view is held")
                .is_some()
        );
    }

    #[test]
    fn a_first_page_never_reads_a_captured_view() {
        let sealer = sealer();
        let principal = principal();
        assert!(
            resume_captured(None, Some(&principal), TEST_PRESENTATION, &sealer)
                .expect("no cursor")
                .is_none()
        );
        assert!(
            resume_captured(Some(""), Some(&principal), TEST_PRESENTATION, &sealer)
                .expect("empty first-page cursor")
                .is_none()
        );
    }

    #[test]
    fn a_captured_view_serves_only_its_presentation() {
        let sealer = sealer();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = paginate_at(tools(&["a", "b", "c"]), None, "p".into(), now, 2, &sealer)
            .expect("first page");
        let cursor = first.next_cursor.expect("continuation");

        let adapted = ToolListPresentation {
            schema_adapted: true,
            ..TEST_PRESENTATION
        };
        let builtins_only = ToolListPresentation {
            projection: "builtins_only",
            ..TEST_PRESENTATION
        };
        for other in [adapted, builtins_only] {
            assert!(
                resume_captured_at(&cursor, "p", other, now, 2, &sealer)
                    .expect("another presentation is sent to the live check")
                    .is_none(),
                "{other:?} must not continue a view captured for another presentation"
            );
        }
        assert!(resumed(&cursor, "p", now, &sealer)
            .expect("same presentation")
            .is_some());
    }
}
