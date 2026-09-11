//! Tools page — one of the router-per-domain modules `dashboard.rs`
//! delegates to. Routes stay mounted by `dashboard::page_routes`.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde::Deserialize;
use waygate_mcp::catalog::UpstreamCatalog;
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::Principal;

use super::dashboard::*;
use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

#[derive(Template)]
#[template(path = "tools.html")]
struct ToolsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// Echoed filter state so the form re-renders with the operator's
    /// current selection. Plain-GET, so the URL stays the source of truth
    /// — same pattern the Activity page follows.
    filters: ToolFilters,
    /// Distinct servers + their tool counts, for the server `<select>`.
    servers: Vec<(String, usize)>,
    /// Filtered + capped rows.
    tools: Vec<ToolRow>,
    /// Total matched before the cap.
    total: usize,
    /// `true` when `total` exceeded [`TOOLS_PAGE_CAP`] and the list was
    /// truncated — the fragment renders a "refine your filter" hint.
    truncated: bool,
}

struct ToolRow {
    server: String,
    name: String,
    risk: &'static str,
    side_effects: bool,
    pii: bool,
    description: Option<String>,
}

/// Plain-GET filters for the Tools console. Empty strings normalise to
/// `None` via [`ToolFilters::cleaned`].
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ToolFilters {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    risk: Option<String>,
    #[serde(default)]
    side_effects: Option<String>,
    #[serde(default)]
    pii: Option<String>,
}

impl ToolFilters {
    fn cleaned(mut self) -> Self {
        fn norm(o: Option<String>) -> Option<String> {
            o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        }
        // Drop values the `<select>` can't represent so an out-of-band URL
        // (e.g. `?risk=garbage`) can't filter the rows while the control
        // still shows "Any" — the control and the result must agree.
        fn one_of(o: Option<String>, allowed: &[&str]) -> Option<String> {
            norm(o).filter(|s| allowed.contains(&s.as_str()))
        }
        self.q = norm(self.q);
        self.server = norm(self.server);
        self.risk = one_of(self.risk, &["high", "medium", "low"]);
        self.side_effects = one_of(self.side_effects, &["yes", "no"]);
        self.pii = one_of(self.pii, &["yes", "no"]);
        self
    }

    fn matches(&self, t: &ToolRow) -> bool {
        if let Some(q) = &self.q {
            let q = q.to_ascii_lowercase();
            let hit = t.name.to_ascii_lowercase().contains(&q)
                || t.server.to_ascii_lowercase().contains(&q)
                || t.description
                    .as_deref()
                    .map(|d| d.to_ascii_lowercase().contains(&q))
                    .unwrap_or(false);
            if !hit {
                return false;
            }
        }
        if let Some(s) = &self.server {
            if &t.server != s {
                return false;
            }
        }
        if let Some(r) = &self.risk {
            if t.risk != r.as_str() {
                return false;
            }
        }
        if let Some(se) = &self.side_effects {
            if t.side_effects != (se == "yes") {
                return false;
            }
        }
        if let Some(p) = &self.pii {
            if t.pii != (p == "yes") {
                return false;
            }
        }
        true
    }

    // Selected-state helpers for the template's `<option>`s + search box.
    fn q_value(&self) -> &str {
        self.q.as_deref().unwrap_or("")
    }
    fn is_server(&self, s: &str) -> bool {
        self.server.as_deref() == Some(s)
    }
    fn is_risk(&self, s: &str) -> bool {
        self.risk.as_deref() == Some(s)
    }
    fn is_side_effects(&self, s: &str) -> bool {
        self.side_effects.as_deref() == Some(s)
    }
    fn is_pii(&self, s: &str) -> bool {
        self.pii.as_deref() == Some(s)
    }
}

/// Cap on rendered rows. A wider result set is a signal to refine the
/// filter, not to ship a megabyte of table — mirrors the palette cap.
const TOOLS_PAGE_CAP: usize = 200;

/// Assemble the full tool catalogue across every upstream: live tools from
/// connected upstreams, manifest-only rows for disconnected ones.
async fn collect_tool_rows(state: &Arc<AdminState>) -> Vec<ToolRow> {
    let mut tools = Vec::new();
    for m in state.upstreams.manifests() {
        let live = state
            .upstreams
            .list_tools(&m.name)
            .await
            .unwrap_or_default();
        if live.is_empty() {
            for c in &m.tools {
                tools.push(ToolRow {
                    server: m.name.clone(),
                    name: c.name.clone(),
                    risk: risk_str(c.risk),
                    side_effects: c.side_effects,
                    pii: c.pii,
                    description: None,
                });
            }
        } else {
            for t in live {
                let facts = state.upstreams.tool_facts(&m.name, &t.name);
                tools.push(ToolRow {
                    server: m.name.clone(),
                    name: t.name.to_string(),
                    risk: risk_str(facts.risk),
                    side_effects: facts.side_effects,
                    pii: facts.pii,
                    description: t.description.as_ref().map(|d| d.to_string()),
                });
            }
        }
    }
    tools
}

/// Distinct servers + tool counts, sorted by name — drives the server
/// `<select>` options. Computed from the unfiltered catalogue so the counts
/// stay stable as filters change.
fn build_server_facets(rows: &[ToolRow]) -> Vec<(String, usize)> {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for r in rows {
        *counts.entry(r.server.clone()).or_default() += 1;
    }
    counts.into_iter().collect()
}

/// Filter + sort + cap the catalogue. Returns `(rows, total_matched, truncated)`.
fn filter_tool_rows(all: Vec<ToolRow>, filters: &ToolFilters) -> (Vec<ToolRow>, usize, bool) {
    let mut matched: Vec<ToolRow> = all.into_iter().filter(|t| filters.matches(t)).collect();
    matched.sort_by(|a, b| a.server.cmp(&b.server).then_with(|| a.name.cmp(&b.name)));
    let total = matched.len();
    let truncated = total > TOOLS_PAGE_CAP;
    matched.truncate(TOOLS_PAGE_CAP);
    (matched, total, truncated)
}

pub(crate) async fn tools_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<ToolFilters>,
) -> Response {
    let mut filters = q.cleaned();
    let all = collect_tool_rows(&state).await;
    let servers = build_server_facets(&all);
    // Drop an unknown server so the `<select>` (which would render "All
    // servers" for an unrepresentable value) can't disagree with a 0-row
    // result.
    if let Some(s) = &filters.server {
        if !servers.iter().any(|(name, _)| name == s) {
            filters.server = None;
        }
    }
    let (tools, total, truncated) = filter_tool_rows(all, &filters);
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    render(&ToolsPage {
        chrome: PageChrome::build(
            &state,
            "Tools",
            "/tools",
            &headers,
            user.map(|Extension(p)| user_display(&p)),
            tenant_ctx,
            String::new(),
        ),
        filters,
        servers,
        tools,
        total,
        truncated,
    })
}

/// Query for the tool-detail drawer: `GET /tools/drawer?server=&tool=`.
/// Server + tool are passed as query params (not path segments) so tool
/// names containing `/` or other path-hostile characters round-trip cleanly.
#[derive(Debug, Deserialize)]
pub(crate) struct ToolDrawerQuery {
    #[serde(default)]
    server: String,
    #[serde(default)]
    tool: String,
}

/// One row of the parameter table rendered in the tool drawer.
struct ToolParam {
    name: String,
    ty: String,
    required: bool,
    description: Option<String>,
    enum_vals: Option<String>,
}

#[derive(Template)]
#[template(path = "tools_drawer.html")]
struct ToolDrawer {
    server: String,
    name: String,
    /// `true` when the live upstream returned this tool (so we have a
    /// schema). `false` ⇒ upstream down / tool gone — the overview still
    /// renders from the manifest-backed `ToolFacts`, but the parameter
    /// table + raw schema are unavailable.
    found: bool,
    description: Option<String>,
    risk: &'static str,
    side_effects: bool,
    pii: bool,
    params: Vec<ToolParam>,
    has_schema: bool,
    schema_json: String,
    /// The same schema, encoded for safe embedding inside the
    /// `<script type="application/json">` the try-it island reads. Askama's
    /// default HTML escaping turns `"` into `&quot;` — fine for the visible
    /// `<pre>`, but `<script>` content is *raw text*, so an HTML-escaped body
    /// is not valid JSON and `JSON.parse` would fail. We instead disable HTML
    /// escaping for the script (`{{ ... | safe }}`) and pre-escape `<` to its
    /// JSON unicode form `<`, which round-trips to identical data while
    /// making a literal `</script>` impossible to emit. Empty when no schema.
    schema_json_js: String,
    /// `true` when the try-it form should render — admin viewer (the
    /// `mcp:admin` extension), the tool was found live (so we have a schema
    /// to drive the inputs), and the deployment wired an invocation
    /// pipeline (`try_invocation`). Non-admins / unwired deployments get
    /// the read-only drawer with no form.
    try_enabled: bool,
    /// `true` when the tool is high-risk or has side effects, so the
    /// form must require an explicit confirmation checkbox before it will
    /// run the call for real (default-off guard). Re-checked server-side
    /// in `tools_try` — never trusted from the client.
    requires_confirm: bool,
    /// CSRF token for the try-it POST. Empty when no token is
    /// injected (the form is hidden in that case anyway).
    csrf_token: String,
    /// Tenant context so the try-it form posts to the correctly
    /// prefixed route via `{{ self.nav_url("/tools/try") }}`.
    tenant_ctx: Option<TenantContext>,
}

impl ToolDrawer {
    /// Fragment delegate — fragments carry no full [`crate::chrome::PageChrome`];
    /// the URL logic lives in [`crate::tenant_ctx::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

/// Project a JSON-Schema object into a flat parameter list + a
/// pretty-printed copy of the raw schema. Read-only; no JS island —
/// per `docs/agents/dashboard-ui.md`, schema *viewing* is a server-side
/// `serde_json::to_string_pretty` into an HTML-escaped `<pre>`.
fn build_tool_params(
    schema: &serde_json::Map<String, serde_json::Value>,
) -> (Vec<ToolParam>, bool, String) {
    use serde_json::Value;
    let required: std::collections::HashSet<&str> = schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    let mut params = Vec::new();
    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        for (name, spec) in props {
            let ty = spec
                .get("type")
                .and_then(|t| match t {
                    Value::String(s) => Some(s.clone()),
                    Value::Array(a) => Some(
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(" | "),
                    ),
                    _ => None,
                })
                .unwrap_or_else(|| "—".to_string());
            let description = spec
                .get("description")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string());
            let enum_vals = spec.get("enum").and_then(|e| e.as_array()).map(|a| {
                a.iter()
                    .map(|x| match x {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            });
            params.push(ToolParam {
                required: required.contains(name.as_str()),
                name: name.clone(),
                ty,
                description,
                enum_vals,
            });
        }
    }
    // Required params first, then alphabetical — the order an operator
    // reads a contract in.
    params.sort_by(|a, b| {
        b.required
            .cmp(&a.required)
            .then_with(|| a.name.cmp(&b.name))
    });
    let has_schema = !schema.is_empty();
    let schema_json =
        serde_json::to_string_pretty(&Value::Object(schema.clone())).unwrap_or_default();
    (params, has_schema, schema_json)
}

/// `GET /tools/drawer?server=&tool=` — htmx-loaded tool-detail drawer.
/// Re-fetches the live tool so the operator sees the upstream's current
/// `input_schema` (the same data `searchTools` `mode=types` returns over
/// the wire), then renders name / description / risk / side-effects / PII
/// plus a parameter table and the raw schema. Read-only GET, no CSRF —
/// matches the activity drawer and the palette read-only contract.
pub(crate) async fn tools_drawer(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<ToolDrawerQuery>,
) -> Response {
    // Resolve facts via the same governed-catalog path the invocation
    // pipeline uses, so the displayed risk chips AND the try-it confirm
    // hint match what `tools_try` will actually enforce (no manifest-vs-
    // catalog drift in either direction).
    let (risk, side_effects, pii) =
        resolve_pipeline_facts(&state, principal_tenant(user.as_ref()), &q.server, &q.tool).await;
    let live = state
        .upstreams
        .list_tools(&q.server)
        .await
        .unwrap_or_default();
    let found_tool = live
        .into_iter()
        .find(|t| t.name.as_ref() == q.tool.as_str());
    let (found, description, params, has_schema, schema_json) = match found_tool {
        Some(t) => {
            let (params, has_schema, schema_json) = build_tool_params(&t.input_schema);
            (
                true,
                t.description.as_ref().map(|d| d.to_string()),
                params,
                has_schema,
                schema_json,
            )
        }
        None => (false, None, Vec::new(), false, String::new()),
    };
    // Gate the governed try-it form. Admin viewer + tool found live
    // (so we can drive inputs from its schema) + an invocation pipeline
    // wired in this deployment. The high-risk / side-effecting confirm
    // guard is re-checked server-side in `tools_try`.
    let is_admin =
        crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)).is_ok();
    let try_enabled = is_admin && found && state.dashboard.try_invocation.is_some();
    let requires_confirm = matches!(risk, RiskTier::High) || side_effects;
    let schema_json_js = json_for_script_tag(&schema_json);
    render(&ToolDrawer {
        server: q.server,
        name: q.tool,
        found,
        description,
        risk: risk_str(risk),
        side_effects,
        pii,
        params,
        has_schema,
        schema_json,
        schema_json_js,
        try_enabled,
        requires_confirm,
        csrf_token: csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        tenant_ctx: tenant_ctx.map(|Extension(c)| c),
    })
}

// ---- governed "try this tool" ----------------------------------------------

/// Form body for `POST /tools/try`. `arguments` is the JSON object the
/// drawer's vanilla-JS island assembles from the typed inputs (empty ⇒
/// an argument-less call). `confirm` is the high-risk acknowledgement
/// checkbox (`"on"` when ticked, absent otherwise) — re-validated
/// server-side against the tool's freshly-resolved facts.
#[derive(serde::Deserialize)]
pub(crate) struct ToolTryForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    tool: String,
    #[serde(default)]
    arguments: String,
    #[serde(default)]
    confirm: Option<String>,
}

/// Result fragment swapped into the drawer after a try-it call. One
/// template renders every outcome (success, policy denial, step-up,
/// invalid args, confirmation-required, unavailable, upstream error);
/// `ok` only drives the success styling.
#[derive(Template)]
#[template(path = "tools_try_result.html")]
struct TryResult {
    ok: bool,
    heading: &'static str,
    message: String,
    /// Pretty-printed JSON of a successful `CallToolResult`, escaped into
    /// a `<pre>` by askama. `None` for every non-success outcome.
    body_json: Option<String>,
    /// Populated for `StepUpRequired` so the operator sees which scope the
    /// tool's risk class demands.
    required_scope: Option<String>,
    /// Cedar per-policy reason strings for a `Forbidden` verdict — the
    /// same "explain this denial" detail the wire surfaces.
    policy_reasons: Vec<String>,
}

impl TryResult {
    fn err(heading: &'static str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            heading,
            message: message.into(),
            body_json: None,
            required_scope: None,
            policy_reasons: Vec::new(),
        }
    }
}

/// `POST /tools/try` — run one real, governed tool call from the
/// dashboard. The call routes through the *same*
/// `waygate_mcp::SharedInvocation` handle the per-session MCP dispatch
/// path uses (`AdminState::try_invocation`, built by the shared
/// `build_default_invocation_service`), so it runs the identical
/// `authorize → step-up → quota → HITL → audit → redact` pipeline a real
/// client hits — it is **not** a bypass.
///
/// Every precondition is checked *before* the (irreversible) invoke:
/// admin scope, CSRF, an invocation pipeline being wired, the tool
/// existing on its server, the arguments parsing as a JSON object, and —
/// for high-risk / side-effecting tools — an explicit confirmation. Only
/// then does the call reach `invoke`, whose own stages enforce policy and
/// audit independently.
pub(crate) async fn tools_try(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Form(form): Form<ToolTryForm>,
) -> Response {
    // 1. Admin scope. Mutating/side-effecting surface ⇒ admin-gated, same
    //    as the servers/catalog/tenant mutation handlers.
    if let Err(e) = crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    // 2. CSRF. The form carries the injected token; reject on mismatch.
    if !activity_csrf_ok(csrf.as_ref(), &form.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    // 3. Invocation pipeline wired? The production server always wires it
    //    (try-it is not DB-gated); this guards the defensive case where a
    //    composition omits `with_try_invocation` (e.g. tests) — render an
    //    explanatory fragment rather than 500.
    let Some(invocation) = state.dashboard.try_invocation.as_ref() else {
        return render(&TryResult::err(
            "Try-it unavailable",
            "The try-it surface isn't wired in this deployment, so tools \
             can't be run from the dashboard.",
        ));
    };

    // 4. Tool-exists check (side-effect-free). A populated live list that
    //    omits the tool is a positive "no such tool" signal; an empty list
    //    (upstream transiently down) is NOT treated as proof of absence —
    //    `invoke` resolves from the catalog and is the final authority, so
    //    we avoid a false negative that would block a valid call.
    let live = state
        .upstreams
        .list_tools(&form.server)
        .await
        .unwrap_or_default();
    if !live.is_empty() && !live.iter().any(|t| t.name.as_ref() == form.tool.as_str()) {
        return render(&TryResult::err(
            "Unknown tool",
            format!("`{}` is not a tool on server `{}`.", form.tool, form.server),
        ));
    }

    // 5. Parse arguments → JSON object (before invoke). Blank ⇒ an
    //    argument-less call (the MCP wire convention).
    let arguments = match parse_try_arguments(&form.arguments) {
        Ok(args) => args,
        Err(msg) => return render(&TryResult::err("Invalid arguments", msg)),
    };

    // 6. High-risk / side-effecting guard (default-off). Facts are
    //    re-resolved server-side here via the SAME governed-catalog path the
    //    invocation pipeline uses (`resolve_pipeline_facts`), keyed on the
    //    principal's tenant — NOT the manifest-only `tool_facts`. Keying off
    //    the manifest would let a catalog-classified high-risk tool through
    //    without the confirmation the pipeline's risk class demands.
    //    The drawer's `requires_confirm` is a UI hint only.
    let (risk, side_effects, _pii) = resolve_pipeline_facts(
        &state,
        principal_tenant(user.as_ref()),
        &form.server,
        &form.tool,
    )
    .await;
    let requires_confirm = matches!(risk, RiskTier::High) || side_effects;
    let confirmed = form
        .confirm
        .as_deref()
        .is_some_and(|v| v == "on" || v == "true");
    if requires_confirm && !confirmed {
        return render(&TryResult::err(
            "Confirmation required",
            "This tool is high-risk or has side effects. Tick the \
             confirmation box to run it for real — the call goes through \
             the live policy + audit pipeline exactly as a client's would.",
        ));
    }

    // 7. Irreversible call. Same governed pipeline as a real MCP client.
    let principal = user.as_ref().map(|Extension(p)| p);
    let req = waygate_mcp::InvocationRequest::new(form.server.clone(), form.tool.clone())
        .with_arguments(arguments);
    let outcome = invocation.invoke(principal, req).await;

    // 8. Best-effort admin-surface evidence (who ran try-it, and how it
    //    resolved). The authoritative tool-call audit row is emitted by
    //    the invoke pipeline itself; this row attributes the *dashboard*
    //    action on top of it.
    let outcome_label = match &outcome {
        Ok(_) => "success".to_string(),
        Err(e) => format!("error:{}", invocation_error_kind(e)),
    };
    record_server_action(
        &state,
        principal,
        "dashboard.tool.try",
        format!(
            "server={}; tool={}; outcome={}",
            form.server, form.tool, outcome_label
        ),
    )
    .await;

    // Render the outcome. The success arm serialises the `CallToolResult`
    // inline (its type is inferred from `invoke`'s return), so this crate
    // never has to name the `rmcp` wire type directly.
    let rendered = match outcome {
        // Tool calls return a unary result; serialise it for the panel.
        Ok(waygate_mcp::InvocationResponse::Unary(result)) => {
            let body = serde_json::to_string_pretty(&result).unwrap_or_default();
            TryResult {
                ok: true,
                heading: "Success",
                message: String::new(),
                body_json: Some(body),
                required_scope: None,
                policy_reasons: Vec::new(),
            }
        }
        // A raw-JSON (LLM) unary response carries a renderable body; pretty-
        // print it the same way as a tool result.
        Ok(waygate_mcp::InvocationResponse::UnaryValue(value)) => {
            let body = serde_json::to_string_pretty(&value).unwrap_or_default();
            TryResult {
                ok: true,
                heading: "Success",
                message: String::new(),
                body_json: Some(body),
                required_scope: None,
                policy_reasons: Vec::new(),
            }
        }
        // Streaming responses originate only from the inference plane, which
        // has its own client path — the dashboard try-it surface doesn't
        // render them.
        Ok(waygate_mcp::InvocationResponse::Stream(_)) => TryResult::err(
            "Unsupported",
            "This tool returned a streaming response, which the dashboard \
             try-it surface does not render. Streaming is an inference-plane \
             feature with its own client path.",
        ),
        // Try-it declares no input capabilities, so the pipeline fails an
        // MRTR pause closed before it can surface here; render defensively.
        Ok(waygate_mcp::InvocationResponse::InputRequired(_)) => TryResult::err(
            "Unsupported",
            "This tool paused for interactive input, which the dashboard \
             try-it surface cannot provide.",
        ),
        Err(e) => try_result_for_err(e),
    };
    render(&rendered)
}

/// Parse the island's `arguments` field into the `Option<Map>` shape
/// `InvocationRequest::with_arguments` expects. Blank ⇒ `None`. A non-
/// object JSON value (array, string, number) is rejected: MCP tool
/// arguments are always a key/value object.
fn parse_try_arguments(
    raw: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::Object(map)) => Ok(Some(map)),
        Ok(_) => Err("Arguments must be a JSON object (e.g. {\"key\": \"value\"}).".to_string()),
        Err(e) => Err(format!("Arguments are not valid JSON: {e}")),
    }
}

/// Short stable kind label for a typed invocation error — used only for
/// the admin-surface evidence `outcome=` field, not shown to the user.
fn invocation_error_kind(e: &waygate_mcp::InvocationError) -> &'static str {
    use waygate_mcp::InvocationError as E;
    match e {
        E::InvalidArguments(_) => "invalid_arguments",
        E::Forbidden { .. } => "forbidden",
        E::StepUpRequired { .. } => "step_up_required",
        E::Upstream(_) => "upstream",
        E::AuditUnavailable(_) => "audit_unavailable",
        E::ApprovalRequired { .. } => "approval_required",
        _ => "other",
    }
}

/// Map a typed invocation *error* to the rendered result fragment. Each
/// variant with bespoke UI (policy denial, step-up, approval) gets an
/// operator-readable heading; the `Display` string carries the detail for
/// everything else. The success case is handled inline at the call site
/// so this crate never names the `rmcp` `CallToolResult` type.
fn try_result_for_err(e: waygate_mcp::InvocationError) -> TryResult {
    use waygate_mcp::InvocationError as E;
    match e {
        E::Forbidden {
            reason, reasons, ..
        } => TryResult {
            ok: false,
            heading: "Denied by policy",
            message: reason,
            body_json: None,
            required_scope: None,
            policy_reasons: reasons,
        },
        E::StepUpRequired {
            required_scope,
            reason,
        } => TryResult {
            ok: false,
            heading: "Step-up required",
            message: reason,
            body_json: None,
            required_scope: Some(required_scope),
            policy_reasons: Vec::new(),
        },
        E::ApprovalRequired { reason, .. } => TryResult::err("Approval required", reason),
        E::InvalidArguments(msg) => TryResult::err("Invalid arguments", msg),
        other => TryResult::err("Call failed", other.to_string()),
    }
}

// ---- connect (client onboarding) ------------------------------------------
