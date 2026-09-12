//! Placeholders, Settings, auth middleware, tenant prefix, palette, sidebar
//! — split from the monolithic `dashboard_render.rs`; bodies verbatim, cut
//! at the file's own section markers.

use crate::common::*;
use crate::try_profiles::state_with_profile_store;
use crate::try_profiles::InMemoryProfileStore;
use std::time::{SystemTime, UNIX_EPOCH};
use waygate_oidc::{session_decrypt, LoginState, LOGIN_STATE_COOKIE};

// ---- placeholders ---------------------------------------------------------

#[tokio::test]
pub(crate) async fn identities_placeholder_renders() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/identities").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Identities"));
    assert!(body.contains(r#"href="/admin/identities""#));
}

/// API-key profiles section renders on the Profiles page (split off
/// the API Keys page). empty_state has no api_key_profiles store
/// wired → the section renders its disabled-state card, not a table.
#[tokio::test]
pub(crate) async fn profiles_page_renders_api_key_profiles_section_disabled_state() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/profiles").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("API-key profiles"),
        "API-key profiles section heading missing",
    );
    assert!(
        body.contains("API-key profiles store not configured"),
        "expected profiles-section disabled-state copy",
    );
    // Disabled state uses the shared empty-state component.
    assert!(
        body.contains(r#"class="empty-state""#),
        "profiles disabled state should use the shared .empty-state component",
    );
}

/// The OAuth-sessions inventory has its own `/sessions` page. With
/// the AS disabled (empty_state wires no OAuth store), the section renders
/// nothing, so the page shows the explicit AS-disabled empty-state card
/// rather than a bare title. Renders at both mounts.
#[tokio::test]
pub(crate) async fn sessions_page_renders_disabled_state_when_as_off() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/sessions", "/t/default/sessions"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "sessions page failed at {path}");
        assert!(
            body.contains(r#"<h1 class="page-title">Sessions</h1>"#),
            "Sessions page heading missing at {path}",
        );
        assert!(
            body.contains("OAuth sessions unavailable"),
            "expected the AS-disabled empty-state card at {path}",
        );
    }
}

/// The API Keys page (`/identities`) no longer carries the
/// OAuth-sessions or API-key-profiles sections — they moved to their own
/// pages. Wire the profile store (which on the old page would have
/// rendered the "API-key profiles" section) and confirm neither section
/// heading appears, while the API Keys heading still does.
#[tokio::test]
pub(crate) async fn api_keys_page_no_longer_shows_sessions_or_profiles() {
    let store = Arc::new(InMemoryProfileStore::default());
    let app = dashboard_router(
        state_with_profile_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/identities").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"<h1 class="page-title">API keys</h1>"#),
        "the API Keys page heading should be present",
    );
    assert!(
        !body.contains("API-key profiles"),
        "the profiles section must have moved off the API Keys page",
    );
    assert!(
        !body.contains("OAuth sessions"),
        "the OAuth-sessions section must have moved off the API Keys page",
    );
}

/// The Identities destination's tab bar carries the split-out
/// Sessions + Profiles pages (and the renamed "API Keys" tab). On
/// /sessions the Identities destination is current and the Sessions tab
/// carries aria-current.
#[tokio::test]
pub(crate) async fn sessions_page_marks_identity_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/sessions").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/identities" aria-current="page""#),
        "the Identities destination should be current on /sessions",
    );
    assert!(
        body.contains(r#"href="/admin/sessions" aria-current="page""#),
        "the Sessions tab should be current on /sessions",
    );
    // The Profiles tab is wired into the same destination's tab bar.
    assert!(
        body.contains(r#"href="/admin/profiles""#),
        "the Profiles tab should be present in the Identities tab bar",
    );
}

// ---- Settings page --------------------------------------------------------

/// Settings page renders at both mounts (legacy and tenant-prefixed).
/// `empty_state` boots with `SystemInfo::unknown()`, so the JWKS and
/// introspection sections render their not-configured empty-state cards.
#[tokio::test]
pub(crate) async fn settings_page_renders_at_both_mounts() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/settings", "/t/default/settings"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "settings page failed at {path}");
        assert!(body.contains("Settings"), "page title missing at {path}");
        assert!(
            body.contains("No identity keyring configured"),
            "expected JWKS-unwired copy at {path}",
        );
        assert!(
            body.contains("Token introspection not configured"),
            "expected introspection-unwired copy at {path}",
        );
        assert!(
            body.contains("Capabilities"),
            "capability grid missing at {path}",
        );
    }
}

/// System sidebar group force-opens on /settings
/// (contains_active behavior).
#[tokio::test]
pub(crate) async fn settings_page_marks_system_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/settings").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/settings" aria-current="page""#),
        "the Settings destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/settings" aria-current="page""#),
        "Settings nav link missing aria-current on legacy mount",
    );
}

/// Palette finds Settings in its catalogue.
#[tokio::test]
pub(crate) async fn settings_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=settings").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Settings""#),
        "Settings missing from palette search results: {body}",
    );
}

#[tokio::test]
pub(crate) async fn palette_offers_per_server_tools_jump() {
    // Each upstream gets a read-only "Tools: <server>" entry that navigates to
    // the filtered Tools console.
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=example-messages").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Tools: example-messages""#),
        "per-server palette entry missing: {body}",
    );
    assert!(
        body.contains("server=example-messages"),
        "filtered Tools href missing: {body}",
    );
}

// ---- auth middleware ------------------------------------------------------

#[tokio::test]
pub(crate) async fn simulate_rejects_missing_csrf_in_dev_mode() {
    // Disabled-mode middleware still injects a `dev-csrf` token, so a POST
    // with no csrf field must 403 — protects the form from trivial CSRF
    // even in the dev profile.
    let app = dashboard_router(state_with_cedar().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policies/simulate")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "sub=alice&action=search_tools&resource_type=server&server=example-messages",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn simulate_rejects_wrong_csrf_token() {
    let app = dashboard_router(state_with_cedar().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policies/simulate")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "csrf=not-the-right-one&sub=alice&action=search_tools&resource_type=server&server=x",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn dev_mode_injects_synthetic_user_into_topbar() {
    // Disabled auth ⇒ middleware injects dev@local; topbar should show it.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("dev@local"),
        "dev principal missing from topbar"
    );
    // Sign-out form should render for any non-None user.
    assert!(body.contains("Sign out"));
}

/// Build an Enforce-mode `DashboardAuth` using local-only primitives — no
/// real IdP is ever contacted. Suitable only for asserting the middleware's
/// redirect behavior; any route that would actually exchange a code or
/// validate an ID token needs the real thing.
pub(crate) fn stub_enforce_auth() -> DashboardAuth {
    let issuer = "https://auth.test.invalid";
    // Empty JWKS is fine — we never reach the validator in these tests.
    let jwks = Arc::new(JwksProvider::from_preloaded(issuer, r#"{"keys": []}"#).unwrap());
    let id_validator = Arc::new(IdTokenValidator::new(jwks, issuer, "test-client"));
    let endpoints = OidcEndpoints {
        authorization_endpoint: "https://auth.test.invalid/authorize".into(),
        token_endpoint: "https://auth.test.invalid/token".into(),
        jwks_uri: "https://auth.test.invalid/jwks".into(),
        userinfo_endpoint: None,
        issuer: issuer.into(),
    };
    let cfg = DashboardOidcConfig {
        client_id: "test-client".into(),
        client_secret: "test-secret".into(),
        redirect_uri: "https://gw.test.invalid/admin/auth/callback".into(),
        endpoints,
        token_http: waygate_core::http_client::client(waygate_core::http_client::Profile::Standard)
            .unwrap(),
        id_token_validator: id_validator,
        session_key: SessionKey::from_bytes([9u8; 32]),
        secure_cookies: false,
        session_ttl: 3600,
        login_state_ttl: 600,
        scopes: vec!["openid".into()],
        allowed_step_up_scopes: vec!["mcp:invoke:high".into()],
    };
    DashboardAuth::Enforce {
        cfg: Arc::new(cfg),
        enricher: None,
    }
}

#[tokio::test]
pub(crate) async fn enforce_mode_redirects_unauthenticated_to_login() {
    let app = dashboard_router(empty_state().await, stub_enforce_auth());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/servers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        loc.starts_with("/admin/login"),
        "unexpected redirect: {loc}"
    );
    // `/` is kept unencoded in the next-path so operators can read the
    // redirect target at a glance in server logs. The `next=` value
    // re-prefixes `/admin` so the post-login `sanitize_next` accepts it
    // (the fix lives in `redirect_to_login`). Without that prefix, the
    // callback would treat it as default-home and substitute the
    // tenant-scoped home, losing the original deep-link target.
    assert!(
        loc.contains("next=/admin/servers"),
        "next param missing or un-prefixed: {loc}",
    );
}

#[tokio::test]
pub(crate) async fn enforce_mode_login_redirects_to_idp_with_pkce() {
    let app = dashboard_router(empty_state().await, stub_enforce_auth());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        loc.starts_with("https://auth.test.invalid/authorize?"),
        "should redirect to IdP authorize endpoint: {loc}"
    );
    assert!(loc.contains("code_challenge_method=S256"));
    assert!(loc.contains("client_id=test-client"));
    // Login-state cookie must be set, scoped to /admin and HttpOnly.
    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cookie.starts_with("mcp-gw-login="),
        "login cookie missing: {cookie}"
    );
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("Path=/admin"));
}

#[tokio::test]
pub(crate) async fn enforce_mode_login_adds_scope_without_requesting_mfa() {
    // Step-up UX: when the simulator (or an MCP client) bounces a user to
    // /admin/login?step_up_scope=mcp:invoke:high, the authorize URL must
    // (a) include the extra scope and (b) force a fresh IdP login. The
    // gateway must not impose an MFA ACR; authenticator policy belongs to the
    // IdP.
    let app = dashboard_router(empty_state().await, stub_enforce_auth());
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login?step_up_scope=mcp:invoke:high&next=/admin/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        loc.contains("scope=openid%20mcp%3Ainvoke%3Ahigh"),
        "step-up scope missing from authorize URL: {loc}"
    );
    assert!(
        loc.contains("prompt=login"),
        "step-up flow must force re-auth: {loc}"
    );
    assert!(!loc.contains("acr_values"), "gateway requested MFA: {loc}");

    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("login-state cookie");
    let encrypted = cookie
        .strip_prefix(&format!("{LOGIN_STATE_COOKIE}="))
        .and_then(|value| value.split(';').next())
        .expect("encrypted login-state cookie value");
    let login_state = session_decrypt::<LoginState>(&SessionKey::from_bytes([9u8; 32]), encrypted)
        .expect("login-state cookie decrypts");
    assert!(
        (before + 600..=after + 600).contains(&login_state.exp),
        "login-state expiry must preserve the configured ten-minute TTL",
    );
}

#[tokio::test]
pub(crate) async fn enforce_mode_login_ignores_unlisted_step_up_scope() {
    // A crafted link that asks for an arbitrary scope (e.g. `mcp:admin`)
    // must be ignored silently — the login still works but as a normal flow.
    // This is the defense against step-up-URL abuse where an attacker tries
    // to trick a user into granting themselves elevated scopes.
    let app = dashboard_router(empty_state().await, stub_enforce_auth());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login?step_up_scope=mcp:admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        !loc.contains("mcp%3Aadmin"),
        "unlisted scope leaked into authorize URL: {loc}"
    );
    assert!(
        !loc.contains("prompt=login"),
        "non-whitelisted request must not force re-auth: {loc}"
    );
    assert!(
        !loc.contains("acr_values"),
        "non-whitelisted request must not request MFA: {loc}"
    );
}

#[tokio::test]
pub(crate) async fn simulate_step_up_renders_reauthenticate_link() {
    // Policy simulator must surface the step-up affordance so operators can
    // click through to re-auth. The retry loop is: caller hits forbidden
    // step-up on `delete_dataset` (the lone step-up canary now that step-up
    // is decoupled from risk tier) → simulator shows STEP_UP chip + re-auth
    // link → link hits /admin/login with the right step_up_scope → IdP
    // re-authenticates and grants mcp:invoke:high → next call succeeds. The
    // CedarGate → MCP wire plumbing for the retry is
    // already covered end-to-end in waygate-authz/tests/authz_e2e.rs;
    // this test pins the dashboard UX.
    let app = dashboard_router(state_with_step_up_policy().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policies/simulate")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    // Admin principal against `delete_dataset` w/o mcp:invoke:high —
                    // the one shape 30-step-up.cedar still forbids. A generic
                    // high-risk tool (e.g. send_message) no longer steps up:
                    // step-up is decoupled from the risk tier.
                    "csrf=dev-csrf&sub=alice&groups=mcp-admins&scopes=mcp:invoke\
                     &action=call_tool&tool_name=delete_dataset&risk=high\
                     &resource_type=tool&server=example-memory-assistant&tool=delete_dataset",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(
        body.contains("STEP_UP"),
        "simulator missed step-up chip: {body}"
    );
    assert!(
        body.contains("/admin/login?step_up_scope=mcp:invoke:high"),
        "missing re-auth link: {body}"
    );
    assert!(body.contains("Re-authenticate"));
    assert!(body.contains("next=/admin/policies"));
}

/// State with the real three-layer policy set loaded. The simulator test
/// relies on `30-step-up.cedar` producing a step-up decision for an admin
/// hitting `delete_dataset` (the lone step-up canary) without the elevated scope;
/// the fabricated DENY_ALL_POLICY won't do that.
pub(crate) async fn state_with_step_up_policy() -> Arc<AdminState> {
    let policies_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("crates/waygate-authz/tests/fixtures/policies");
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::load_dir(&policies_dir).expect("load workspace policies/"),
    ));
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(AdminState::new(
        pool,
        Some(engine),
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

// ---- Tenant URL prefix ------------------------------------------------------

// Test URIs use the no-trailing-slash form (`/t/default`) because axum 0.8's
// `.nest("/t/{tenant}", router)` matches the nested router's `/` route at
// `/t/default` but 404s on `/t/default/` (same gotcha that
// `admin_trailing_slash_reaches_overview` documents for `/admin/`).
// waygate-server's `NormalizePathLayer::trim_trailing_slash()` is what makes
// the canonical `/admin/t/default/` URL work in production. One test below
// (`tenant_prefix_trailing_slash_requires_normalize_layer`) pins that
// dependency so an accidental removal fails loudly.

/// Pages live at both the legacy un-prefixed path AND the new
/// `/t/{tenant}/...` prefix. The new prefix is the canonical shape
/// each page migrates to.
#[tokio::test]
pub(crate) async fn tenant_prefix_overview_renders() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("<!doctype html>"));
    // Tenant selector chip should render the active slug since no
    // tenants store is wired (Disabled mode + None tenants store).
    assert!(
        body.contains("sidebar__tenant-chip"),
        "tenant selector chip missing from tenant-prefixed overview",
    );
    assert!(
        body.contains("<code>default</code>"),
        "active tenant slug not rendered",
    );
}

/// Regression: the canonical home URL (`/admin/t/<tenant>/`, trailing
/// slash) only works when `NormalizePathLayer::trim_trailing_slash()` is
/// applied at the outer level — same pattern as the existing
/// `admin_trailing_slash_reaches_overview` test, but for the new nested
/// `/t/{tenant}` mount. Without this, post-login redirects from
/// `auth::callback_get` (which uses `home_url()` → `/admin/t/<tenant>/`)
/// would 404 in production.
#[tokio::test]
pub(crate) async fn tenant_prefix_trailing_slash_requires_normalize_layer() {
    use tower::Layer;
    use tower_http::normalize_path::NormalizePathLayer;

    let dashboard = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let nested: axum::Router<()> = axum::Router::new().merge(dashboard);
    let app = NormalizePathLayer::trim_trailing_slash().layer(nested);

    for path in ["/t/default", "/t/default/"] {
        let resp = tower::ServiceExt::oneshot(
            app.clone(),
            Request::builder().uri(path).body(Body::empty()).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "unexpected status for {path}",
        );
    }
}

/// Sidebar nav links must carry the tenant prefix when the page is
/// rendered under `/t/{tenant}/...`, otherwise clicking the sidebar
/// would silently drop the operator out of the tenant scope.
#[tokio::test]
pub(crate) async fn tenant_prefix_nav_links_carry_prefix() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"class="topbar__brand" href="/admin/t/default/""#),
        "the brand home link must preserve the selected tenant",
    );
    assert!(
        body.contains(r#"href="/admin/t/default/servers""#),
        "Servers sidebar link missing tenant prefix",
    );
    assert!(
        body.contains(r#"href="/admin/t/default/policies""#),
        "Policies sidebar link missing tenant prefix",
    );
    assert!(
        body.contains(r#"href="/admin/t/default/identities""#),
        "Identities sidebar link missing tenant prefix",
    );
}

/// Legacy un-prefixed paths still render — the URL refactor is
/// additive (per-page migration is incremental), so existing
/// bookmarks must not 404.
#[tokio::test]
pub(crate) async fn legacy_routes_still_render() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in [
        "/",
        "/servers",
        "/tools",
        "/policies",
        "/activity",
        "/settings",
    ] {
        let (status, _body) = body_of(app.clone(), path).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "legacy route {path} regressed during the tenant URL prefix refactor",
        );
    }
}

/// Tenant-prefixed nav vs legacy nav must both correctly mark the
/// active page — same `active_suffix` comparison either way.
#[tokio::test]
pub(crate) async fn tenant_prefix_marks_active_page() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/servers").await;
    assert_eq!(status, StatusCode::OK);
    // The Servers nav item's <a> should carry BOTH the tenant-prefixed
    // href AND aria-current="page" — the layout.html template renders
    // them on the same opening tag, so the joined fragment must appear
    // verbatim.
    assert!(
        body.contains(r#"href="/admin/t/default/servers" aria-current="page""#),
        "Servers nav <a> missing tenant-prefixed href + aria-current pair",
    );
}

/// Malformed slug ⇒ 404 (TenantId::parse refuses it). Guards against
/// SQL lookup on input that couldn't possibly match.
#[tokio::test]
pub(crate) async fn tenant_prefix_rejects_malformed_slug() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, _body) = body_of(app, "/t/Has%20Spaces%20And%20UpperCase").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "malformed tenant slug must 404, not pass through to handler",
    );
}

/// Cross-tenant banner only appears in Enforce mode against a tenant
/// slug that differs from `principal.tenant`. In Disabled mode
/// `dev_principal()` has `TenantId::default()`, so a URL like
/// `/t/acme/` triggers the banner (acme != default). Verifies the
/// banner markup is present.
#[tokio::test]
pub(crate) async fn cross_tenant_banner_appears_when_url_differs_from_principal() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/acme").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("banner--cross-tenant"),
        "cross-tenant banner missing when URL tenant != principal tenant",
    );
    assert!(
        body.contains(r#"<code>acme</code>"#),
        "banner should name the URL tenant",
    );
    assert!(
        body.contains(r#"<code>default</code>"#),
        "banner should name the principal's home tenant",
    );
}

/// Same-tenant URL (matches `principal.tenant`) should NOT render the
/// cross-tenant banner — false positives would train operators to
/// ignore it during real cross-tenant work.
#[tokio::test]
pub(crate) async fn same_tenant_url_omits_cross_tenant_banner() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("banner--cross-tenant"),
        "cross-tenant banner should not appear when URL tenant matches principal",
    );
}

/// Static assets stay at `/static/...`, NOT under the tenant prefix —
/// avoids hash-cache busting on tenant switch and matches what
/// templates render via absolute `/admin/static/...` paths.
#[tokio::test]
pub(crate) async fn static_assets_not_tenant_scoped() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    // The static dir is resolved at runtime; we just need to confirm
    // the route exists (404 is fine if the file isn't found — what
    // matters is that the static-route mount isn't shadowed).
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static/css/base.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 200 (file served) or 404 (no static dir in test fs) both
    // indicate the mount exists; 405 / route-not-found would mean
    // the static mount got broken by a router rewrite.
    assert!(
        matches!(resp.status(), StatusCode::OK | StatusCode::NOT_FOUND),
        "/static unexpectedly returned {}",
        resp.status(),
    );
}

/// Regression: when an existing page is loaded under the tenant prefix,
/// its in-page links / htmx targets / form actions must carry the prefix
/// too — otherwise clicking out drops the tenant context silently. Walks
/// each layout-extending page and asserts a canonical sample per page.
#[tokio::test]
pub(crate) async fn in_page_links_carry_tenant_prefix() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);

    // Overview: refresh link, server row link, "See all activity →".
    let (status, body) = body_of(app.clone(), "/t/default").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/t/default/""#),
        "overview refresh link missing tenant prefix",
    );
    assert!(
        body.contains(r#"href="/admin/t/default/activity""#),
        "overview \"see all activity\" link missing tenant prefix",
    );
}

#[tokio::test]
pub(crate) async fn activity_htmx_targets_carry_tenant_prefix() {
    // The activity-page tenant-prefixed URLs only render when an
    // audit store is wired (otherwise the "audit not configured"
    // branch wins and there's no filter form / drawer to prefix).
    // Use state_with_audit — the same helper the deny-rate / drawer
    // tests use.
    //
    // The filter form is a plain GET against the parent page
    // (full-page reload keeps facets + chips + rows consistent with
    // the URL); the htmx surface on the page is just the drawer +
    // load-more pagination, both of which still need the tenant
    // prefix to avoid escaping the active tenant scope.
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"action="/admin/t/default/activity""#),
        "activity filter form action missing tenant prefix",
    );
    assert!(
        body.contains(r#"data-drawer-url-base="/admin/t/default/activity/""#),
        "activity drawer-url-base missing tenant prefix (JS would fall back to legacy)",
    );
    // The facet sidebar's per-value hrefs also need to thread the
    // tenant prefix — otherwise a click would escape into the
    // legacy /admin/activity URL and lose the tenant scope. Pick
    // one of the seeded facet values from `state_with_audit` and
    // assert its href.
    assert!(
        body.contains(r#"href="/admin/t/default/activity?outcome=denied""#),
        "facet sidebar link missing tenant prefix",
    );
}

#[tokio::test]
pub(crate) async fn policies_simulator_post_target_carries_tenant_prefix() {
    use std::path::PathBuf;
    let policies_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("crates/waygate-authz/tests/fixtures/policies");
    let engine = std::sync::Arc::new(ReloadableCedar::new(
        CedarEngine::load_dir(&policies_dir).expect("load workspace policies/"),
    ));
    let pool = std::sync::Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let state = std::sync::Arc::new(AdminState::new(
        pool,
        Some(engine),
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/policies").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"hx-post="/admin/t/default/policies/simulate""#),
        "simulator hx-post missing tenant prefix",
    );
}

#[tokio::test]
pub(crate) async fn identities_mint_form_action_carries_tenant_prefix() {
    // Identities page branches: when api_keys store is unwired AND the
    // feature flag is off, the page renders the "feature disabled"
    // message (no URL to prefix). When the caller lacks mcp:admin (or
    // store is wired but flag off), it renders a re-auth link with a
    // `next=` query param. Both shapes must carry the tenant prefix
    // wherever a URL appears. empty_state() has neither store + flag,
    // so the body just shows the disabled message — assertion checks
    // both possible URL shapes; if neither matches that's the bug.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/identities").await;
    assert_eq!(status, StatusCode::OK);
    // The "API keys are disabled" branch has no in-page URLs to
    // prefix, so the absence is correct. Verify the BODY contains
    // either the disabled-message OR a prefixed URL — both shapes
    // are consistent with the URL-prefix invariant.
    assert!(
        body.contains("API keys are disabled")
            || body.contains(r#"action="/admin/t/default/identities/api-keys/mint""#)
            || body.contains(r#"next=/admin/t/default/identities"#),
        "identities page rendered neither the disabled-message nor a \
         tenant-prefixed URL; one of the three branches should match",
    );
    // What the page MUST NOT contain on a tenant-prefixed URL: a
    // legacy un-prefixed in-page URL that would drop tenant context.
    // (Static assets and /admin/login / /admin/logout / /admin/static/
    // are cross-cutting and stay legacy by design.)
    let suspect_legacy = [
        r#"action="/admin/identities/api-keys/mint""#,
        r#"next=/admin/identities""#,
    ];
    for sus in suspect_legacy {
        assert!(
            !body.contains(sus),
            "identities page on tenant prefix renders legacy URL `{sus}` \
             — would drop tenant context on click",
        );
    }
}

/// Legacy un-prefixed pages keep their legacy in-page URLs — confirms the
/// `nav_url` helper falls back to `/admin/...` when `tenant_ctx` is `None`.
#[tokio::test]
pub(crate) async fn legacy_pages_keep_legacy_in_page_urls() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/""#),
        "legacy overview refresh link should stay at /admin/",
    );
    assert!(
        body.contains(r#"href="/admin/activity""#),
        "legacy overview activity link should stay at /admin/activity",
    );
    // Must NOT contain a tenant-prefixed URL on the legacy page.
    assert!(
        !body.contains("/admin/t/"),
        "legacy page should not render any tenant-prefixed URLs",
    );
}

/// `/admin/tenant-switch?tenant_slug=<slug>` is the server-side target
/// the sidebar selector form posts to. Valid slug ⇒ 3xx to
/// `/admin/t/<slug>/`. Pinned at the route level so the no-JS
/// `<noscript>` Switch button keeps working if the dashboard router is
/// refactored.
#[tokio::test]
pub(crate) async fn tenant_switch_redirects_to_canonical_home() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/tenant-switch?tenant_slug=acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_redirection(),
        "tenant-switch should 3xx, got {}",
        resp.status(),
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/admin/t/acme/");
}

/// Sidebar selector renders the form action pointing at the
/// server-side `/admin/tenant-switch` endpoint (NOT the old
/// `__placeholder__` route that relied on inline JS).
#[tokio::test]
pub(crate) async fn selector_form_targets_server_side_switch_endpoint() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default").await;
    assert_eq!(status, StatusCode::OK);
    // The form action should not contain the placeholder route.
    assert!(
        !body.contains("__placeholder__"),
        "selector form must not target the placeholder route",
    );
    // When a tenant registry is wired the form action is rendered;
    // here the Disabled-auth state has no registry so the static
    // chip path is taken — confirm the chip falls back gracefully
    // (no broken form).
    assert!(
        body.contains("sidebar__tenant-chip") || body.contains("/admin/tenant-switch"),
        "either the chip fallback (no registry) or the form action \
         must be present",
    );
}

// ---- Cmd-K palette ----------------------------------------------------------

/// The palette overlay HTML is in the layout, so every page renders
/// it. Confirms the input element, results list, and the script tag
/// pulling palette.js are all present.
#[tokio::test]
pub(crate) async fn palette_overlay_and_script_present_on_every_page() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"id="palette-overlay""#),
        "palette overlay missing",
    );
    assert!(body.contains("data-palette-input"), "palette input missing",);
    assert!(
        body.contains("data-palette-results"),
        "palette results list missing",
    );
    assert!(
        body.contains(r#"src="/admin/static/js/palette.js""#),
        "palette.js script tag missing",
    );
    // Cmd-K opener button in the topbar — discoverability hook.
    assert!(
        body.contains("topbar__palette"),
        "Ctrl-K opener button missing from topbar",
    );
}

/// The body's `data-tenant-slug` attribute is what the palette JS
/// reads to compose the `/admin/t/<slug>/search` URL. On a
/// tenant-prefixed page, the slug must be present; on a legacy page,
/// it must NOT be (or the JS would route the search through a stale
/// prefix).
#[tokio::test]
pub(crate) async fn palette_body_data_tenant_slug_matches_url() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);

    // Legacy page: no tenant slug attribute.
    let (_status, body) = body_of(app.clone(), "/").await;
    assert!(
        !body.contains("data-tenant-slug"),
        "legacy page must not carry data-tenant-slug",
    );

    // Tenant-prefixed page: slug attribute matches the URL.
    let (_status, body) = body_of(app, "/t/default").await;
    assert!(
        body.contains(r#"data-tenant-slug="default""#),
        "tenant-prefixed page missing data-tenant-slug=default",
    );
}

/// `/search?q=` (empty query) returns the full catalogue of page
/// items, with tenant-prefixed hrefs when the request comes via the
/// `/t/{tenant}/search` mount.
#[tokio::test]
pub(crate) async fn search_empty_query_returns_pages_tenant_aware() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);

    // Tenant-prefixed search: hrefs carry the prefix.
    let (status, body) = body_of(app.clone(), "/t/default/search?q=").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#""query":"""#));
    assert!(
        body.contains(r#""href":"/admin/t/default/servers""#),
        "search items should carry tenant prefix: {body}",
    );
    assert!(
        body.contains(r#""category":"page""#),
        "page items missing category",
    );

    // Legacy search: hrefs stay un-prefixed.
    let (status, body) = body_of(app, "/search?q=").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""href":"/admin/servers""#),
        "legacy search items should keep legacy hrefs: {body}",
    );
}

/// Substring match is case-insensitive and only returns the items
/// whose label contains the needle.
#[tokio::test]
pub(crate) async fn search_filters_by_substring() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=act").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Activity""#),
        "Activity should match `act`: {body}",
    );
    assert!(
        !body.contains(r#""label":"Settings""#),
        "Settings should not match `act`: {body}",
    );
}

#[tokio::test]
pub(crate) async fn search_oversized_query_returns_400_with_empty_items() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let huge = "x".repeat(500);
    let uri = format!("/search?q={huge}");
    let (status, body) = body_of(app, &uri).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Body still parses as JSON (palette JS expects JSON on every
    // status code) — items list is empty.
    assert!(
        body.contains(r#""items":[]"#),
        "400 response should still be JSON with empty items: {body}",
    );
}

// ---- sidebar sections ------------------------------------------------------

/// Sidebar nav renders its destinations grouped under three section
/// headers: Common, MCP Gateway, and LLM Gateway.
#[tokio::test]
pub(crate) async fn sidebar_renders_destinations() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    // Each section exposes its task-oriented destinations.
    for expected in [
        // Common
        "Overview",
        "Activity",
        "Identities",
        "Access Control",
        "Policy",
        "Decisions",
        // MCP Gateway
        "Servers",
        "Tools",
        "Federation",
        "Connect",
        // LLM Gateway
        "Models",
        "Credentials",
        // Pinned foot
        "Settings",
    ] {
        assert!(
            body.contains(&format!(r#"<span class="sidebar-label">{expected}</span>"#)),
            "sidebar missing destination `{expected}`",
        );
    }
    // The three section headers render.
    for section in ["Common", "MCP Gateway", "LLM Gateway"] {
        assert!(
            body.contains(&format!(
                r#"<li class="sidebar__section" role="heading" aria-level="2">{section}</li>"#
            )),
            "sidebar missing section header `{section}`",
        );
    }
    assert!(
        !body.contains("sidebar__group-details"),
        "the <details> group tree should be gone",
    );
}

/// Regression for the section reorg: the LLM surfaces moved out of the
/// MCP "Tools" tab bar into their own "LLM Gateway" section. On /tools the
/// tab bar holds only Tools + Catalog (no LLM tabs); Models/Credentials
/// are their own single-page destinations whose sidebar link is current
/// and which render under the LLM Gateway section header.
#[tokio::test]
pub(crate) async fn llm_surfaces_live_in_llm_section_not_tools_tabs() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);

    // /tools still renders its tab bar (Tools + Catalog) but no LLM tabs.
    // Scope the check to the tab-bar region — the LLM pages still appear in
    // the sidebar (every destination does), just not as Tools tabs.
    let (status, body) = body_of(app.clone(), "/tools").await;
    assert_eq!(status, StatusCode::OK);
    let tab_bar = body
        .split(r#"class="tab-bar""#)
        .nth(1)
        .and_then(|s| s.split("</nav>").next())
        .expect("the active Tools destination should render a tab bar");
    assert!(
        tab_bar.contains(r#"href="/admin/tools""#) && tab_bar.contains(r#"href="/admin/catalog""#),
        "Tools tab bar should still carry the Tools + Catalog tabs",
    );
    assert!(
        !tab_bar.contains("/admin/llm_models") && !tab_bar.contains("/admin/llm_credentials"),
        "LLM tabs must no longer render in the Tools tab bar",
    );

    // Each LLM page is its own destination, current under the LLM section.
    for (suffix, label) in [
        ("/llm_models", "Models"),
        ("/llm_credentials", "Credentials"),
    ] {
        let (status, body) = body_of(app.clone(), suffix).await;
        assert_eq!(status, StatusCode::OK, "{suffix} should render");
        assert!(
            body.contains(&format!(r#"href="/admin{suffix}" aria-current="page""#)),
            "{label} destination link should be current on {suffix}",
        );
        assert!(
            body.contains(
                r#"<li class="sidebar__section" role="heading" aria-level="2">LLM Gateway</li>"#
            ),
            "LLM Gateway section header should render on {suffix}",
        );
    }
}

/// Every icon the sidebar nav references via `<use href="…#icon"/>` must
/// have a matching `<symbol id="icon">` in the spritesheet — otherwise the
/// `<use>` renders nothing and a destination silently loses its icon. The
/// section reorg added the network / cpu / key icons for Federation /
/// Models / Credentials; this guards that they (and every other
/// destination icon) actually resolve.
#[tokio::test]
pub(crate) async fn every_sidebar_icon_resolves_in_spritesheet() {
    use std::path::PathBuf;
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    let sprite = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static/lucide.svg"),
    )
    .expect("static/lucide.svg should be readable from CARGO_MANIFEST_DIR");

    // Scope to the sidebar nav <ul> so we check destination icons, not
    // unrelated topbar / palette chrome.
    let nav = body
        .split(r#"class="sidebar__nav""#)
        .nth(1)
        .and_then(|s| s.split("</ul>").next())
        .expect("sidebar nav <ul> should render");

    let marker = "/admin/static/lucide.svg#";
    let mut icons: Vec<&str> = nav
        .match_indices(marker)
        .map(|(i, _)| {
            let rest = &nav[i + marker.len()..];
            let end = rest.find(['"', '\'']).unwrap_or(rest.len());
            &rest[..end]
        })
        .collect();
    icons.sort_unstable();
    icons.dedup();
    assert!(!icons.is_empty(), "no sidebar icons found in rendered nav");
    for icon in icons {
        assert!(
            sprite.contains(&format!(r#"id="{icon}""#)),
            "sidebar references lucide icon `{icon}` with no matching <symbol> in static/lucide.svg",
        );
    }
}

/// Broader sibling of `every_sidebar_icon_resolves_in_spritesheet`: EVERY
/// `<use href="…#icon"/>` anywhere in the rendered page chrome — topbar,
/// sidebar, AND the docked assistant drawer — must resolve to a `<symbol>` in
/// the spritesheet. The sidebar-scoped guard above only checks the nav `<ul>`,
/// so a dangling icon in the layout chrome slips past it — which is exactly how
/// the assistant panel's close button shipped pointing at a non-existent `#x`
/// symbol (the sprite has `x-circle`, not `x`), rendering a blank, invisible
/// "close" control with no way to collapse the panel. This guards the whole
/// class: any `#icon` reference in the full body that the sprite can't satisfy.
#[tokio::test]
pub(crate) async fn every_rendered_icon_resolves_in_spritesheet() {
    use std::path::PathBuf;
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    let sprite = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static/lucide.svg"),
    )
    .expect("static/lucide.svg should be readable from CARGO_MANIFEST_DIR");

    let marker = "/admin/static/lucide.svg#";
    let mut icons: Vec<&str> = body
        .match_indices(marker)
        .map(|(i, _)| {
            let rest = &body[i + marker.len()..];
            let end = rest.find(['"', '\'']).unwrap_or(rest.len());
            &rest[..end]
        })
        .collect();
    icons.sort_unstable();
    icons.dedup();
    assert!(!icons.is_empty(), "no lucide icons found in rendered page");
    // The docked assistant drawer is part of the layout chrome, so its close
    // icon is in this set — its presence proves the scan covers the panel.
    assert!(
        body.contains(r#"id="gw-assist-panel""#),
        "assistant drawer should be in the rendered chrome this scan covers",
    );
    for icon in icons {
        assert!(
            sprite.contains(&format!(r#"id="{icon}""#)),
            "rendered page references lucide icon `{icon}` with no matching <symbol> in static/lucide.svg",
        );
    }
}

/// The active destination's second-level pages render as an in-page
/// tab bar, with the active tab marked. A destination the page does
/// not belong to must not render its tabs.
#[tokio::test]
pub(crate) async fn active_destination_renders_tab_bar() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);

    // /activity belongs to the Activity destination; its tab bar
    // renders with the Activity tab current and the Evidence
    // pipeline tab present.
    let (_status, body) = body_of(app.clone(), "/activity").await;
    assert!(
        body.contains(r#"class="tab tab--active" href="/admin/activity" aria-current="page""#),
        "Activity tab should be active on /activity",
    );
    assert!(
        body.contains(r#"href="/admin/evidence""#),
        "Evidence pipeline tab should render in the Activity tab bar",
    );
    // No Policy tabs on an Activity page.
    assert!(
        !body.contains(r#"href="/admin/playground""#),
        "Policy tabs must not render on /activity",
    );

    // Single-page destinations render no tab bar at all.
    let (_status, body) = body_of(app, "/").await;
    assert!(
        !body.contains(r#"class="tab-bar""#),
        "Overview has no second-level pages — no tab bar",
    );
}

/// The `chevron-right` icon referenced by the group `<summary>` must
/// actually exist in the Lucide spritesheet, otherwise
/// `<use href="…#chevron-right"/>` renders nothing and operators lose
/// the expand/collapse affordance.
#[tokio::test]
pub(crate) async fn sidebar_chevron_icon_exists_in_spritesheet() {
    use std::path::PathBuf;
    let sprite = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static/lucide.svg");
    let body = std::fs::read_to_string(&sprite)
        .expect("static/lucide.svg should be readable from CARGO_MANIFEST_DIR");
    assert!(
        body.contains(r#"id="chevron-right""#),
        "lucide.svg missing the chevron-right symbol referenced by the sidebar group <summary>",
    );
}

/// The Decisions badge script must load, and its sidebar entry must carry the
/// data-badge-src hook it reads.
#[tokio::test]
pub(crate) async fn decisions_badge_hook_present() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (_status, body) = body_of(app, "/").await;
    assert!(
        body.contains(r#"src="/admin/static/js/badge.js""#),
        "badge.js script tag missing",
    );
    assert!(
        body.contains(r#"data-badge-src="/admin/badge/decisions""#),
        "Decisions nav entry missing its badge hook",
    );
}

/// Active nav-item marker must still appear inside its group. This is
/// the cross-check on `tenant_prefix_marks_active_page` after nav items
/// moved into nested `<ul>`s.
#[tokio::test]
pub(crate) async fn sidebar_active_item_still_marked_inside_group() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (_status, body) = body_of(app, "/servers").await;
    assert!(
        body.contains(r#"href="/admin/servers" aria-current="page""#),
        "Servers active link should still carry aria-current after group refactor",
    );
}
