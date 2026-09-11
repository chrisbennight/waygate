//! Policies page — one of the router-per-domain modules `dashboard.rs`
//! delegates to. Routes stay mounted by `dashboard::page_routes`.

use std::sync::Arc;
use waygate_authz::{
    Action as AuthzAction, AuthzEngine, AuthzResult, Decision, PolicySnapshot, ResourceSpec,
    ToolSpec,
};

use askama::Template;
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde::Deserialize;
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::Principal;

use super::dashboard::*;
use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

#[derive(Template)]
#[template(path = "policies.html")]
struct PoliciesPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    policy_groups: Vec<PolicyGroup>,
    cedar_configured: bool,
    /// JSON array of `{server, tool, risk, side_effects, pii}` from the loaded
    /// manifests, embedded in the page so the simulator's server/tool inputs
    /// get typeahead and the risk/side_effects/pii fields autofill on pick.
    /// `[]` when no upstreams are configured.
    tool_catalog_json: String,
    /// Whether the dashboard principal can edit policies (`mcp:admin`,
    /// non-peer). Gates the per-policy "Edit" deep-link on each policy card so a
    /// read-only viewer isn't offered an affordance that just bounces off the
    /// editor's own insufficient-scope gate.
    can_edit: bool,
    /// When policy editing is DISABLED for the deployment (flag off, or the
    /// policies dir isn't writable), the reason to show admins — so a read-only
    /// page isn't mysterious. `None` when editing is enabled (or the viewer isn't
    /// an admin, in which case `can_edit` is already false for other reasons).
    policy_editing_off_reason: Option<String>,
}

/// One tool in the simulator's typeahead catalog, sourced from the loaded
/// upstream manifests so a dry-run reflects the tool's real classification.
#[derive(serde::Serialize)]
struct ToolCatalogEntry {
    server: String,
    tool: String,
    risk: &'static str,
    side_effects: bool,
    pii: bool,
}

/// One evaluation layer (a `@layer` annotation value) with its policies. The
/// layered stack is the "what is happening" story the old flat list hid.
struct PolicyGroup {
    /// `@layer` slug (or `ungrouped`); used as the filter data attribute.
    layer_id: String,
    /// Human display name for the layer.
    title: String,
    /// One-line description of what this layer does in the evaluation stack.
    blurb: String,
    /// `permit` | `forbid` | `mixed`, derived from the group's policies.
    effect: &'static str,
    policies: Vec<PolicyView>,
}

struct PolicyView {
    id: String,
    /// URL-encoded `id` for the "View recent decisions" cross-link to the
    /// Decision Log (`/decisions-log?policy_id=<id_qs>`). Pre-encoded in Rust
    /// (the established `*_qs` pattern) so an operator-authored `@id` with
    /// reserved chars doesn't break the link.
    id_qs: String,
    effect: String,
    /// `@description` text, or empty when the policy has none.
    description: String,
    tags: Vec<String>,
    /// `@reason` text (surfaced to denied callers), or empty when absent.
    reason: String,
    /// Lowercased `id + effect + tags + description + reason + source`, used by
    /// the client-side search box to show/hide this item.
    search: String,
    highlighted: String,
    /// The policy's EXACT source statement (byte-faithful, from the
    /// segmenter over the active bundle), for the inline per-policy editor.
    /// `None` when the policy isn't per-policy addressable (no `@id`, or the
    /// active bundle isn't cleanly segmentable) — the card then falls back to a
    /// deep-link into the whole-bundle editor instead of an inline editor.
    editable_source: Option<String>,
}

pub(crate) async fn policies_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    // Build the simulator typeahead catalog so the server/tool inputs
    // autocomplete and risk/side_effects/pii autofill on pick. Resolve each
    // tool's facts the SAME way the invocation pipeline does — the tenant-aware
    // governed catalog with manifest fallback (`resolve_pipeline_facts`) — so a
    // catalog-enabled deployment's autofill can't drift from the live gate.
    // Deployments with no catalog get the manifest facts
    // cheaply. Resolves run concurrently; an empty pool ⇒ `[]` (free text).
    let tenant = principal_tenant(user.as_ref()).to_owned();
    // Editing is offered only when it can actually deliver — the
    // principal is an admin AND the tenant has an ACTIVE (published) bundle. A
    // wired store with no published bundle (e.g. policies loaded from disk but
    // never imported into the ledger) would dead-end on an empty editor, so we
    // fetch the active bundle's content up front (admin-only, so a read-only
    // viewer never pays the read). That content is then segmented into the
    // per-policy exact source for the INLINE editor; `can_edit` is simply
    // "an active bundle exists".
    let active_content: Option<String> =
        if overview_break_glass_admin(user.as_ref().map(|Extension(p)| p)) {
            match state.policy.policy_store.get() {
                Some(store) => store.active_bundle(&tenant).await.ok().map(|b| b.content),
                None => None,
            }
        } else {
            None
        };
    // Editing also requires the GATEWAY_POLICY_EDITING flag + a writable
    // policies dir (folded into `policy_editing_enabled`). When off, the inline
    // editors are hidden and `policy_editing_off_reason` is shown so the operator
    // sees WHY (flag off, or dir not writable) instead of a silently bare page.
    let can_edit = active_content.is_some() && state.policy.policy_editing.enabled();
    // Show the "why editing is off" note only to a viewer who would otherwise be
    // offered editing (admin + an active bundle present, i.e. `active_content`).
    let policy_editing_off_reason = if active_content.is_some() {
        state.policy.policy_editing.off_reason().map(str::to_owned)
    } else {
        None
    };
    // Map each policy's `@id` to its EXACT source statement, byte-faithful,
    // for the inline editor's pre-fill. A bundle the segmenter can't address
    // cleanly (duplicate `@id`, unparseable — neither should reach the active
    // slot, but be defensive) yields an empty map, so cards degrade to the
    // whole-bundle editor deep-link rather than offering a broken inline edit.
    let editable: std::collections::HashMap<String, String> = {
        let mut m = std::collections::HashMap::new();
        if let Some(content) = active_content.as_deref() {
            if let Ok(frags) = waygate_authz::segment_verified(content) {
                for f in frags {
                    if let Some(id) = f.id {
                        m.insert(id, content[f.statement].to_string());
                    }
                }
            }
        }
        m
    };
    let (policy_groups, cedar_configured) = match state.policy.cedar.get() {
        Some(engine) => (
            group_policies(engine.list_policies_for_tenant(&tenant), &editable),
            true,
        ),
        None => (Vec::new(), false),
    };
    let pairs: Vec<(String, String)> = state
        .upstreams
        .manifests()
        .into_iter()
        .flat_map(|m| {
            let server = m.name;
            m.tools.into_iter().map(move |t| (server.clone(), t.name))
        })
        .collect();
    let tool_catalog: Vec<ToolCatalogEntry> =
        futures_util::future::join_all(pairs.into_iter().map(|(server, tool)| {
            let state = state.clone();
            let tenant = tenant.clone();
            async move {
                let (risk, side_effects, pii) =
                    resolve_pipeline_facts(&state, &tenant, &server, &tool).await;
                ToolCatalogEntry {
                    server,
                    tool,
                    risk: risk_str(risk),
                    side_effects,
                    pii,
                }
            }
        }))
        .await;
    // Encode for safe `<script type="application/json">` embedding via the
    // module's hardened helper (escapes every `<` to the JSON unicode escape
    // `\u003c`, with a unit invariant) rather than an ad-hoc `</` replacement.
    let raw_catalog = serde_json::to_string(&tool_catalog).unwrap_or_else(|_| "[]".into());
    let tool_catalog_json = json_for_script_tag(&raw_catalog);
    render(&PoliciesPage {
        chrome: PageChrome::build(
            &state,
            "Policies",
            "/policies",
            &headers,
            user.map(|Extension(p)| user_display(&p)),
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        policy_groups,
        cedar_configured,
        tool_catalog_json,
        can_edit,
        policy_editing_off_reason,
    })
}

/// Group loaded policies by their `@layer` annotation into the canonical
/// evaluation-layer stack (baseline → overlays → per-service grants →
/// step-up). Policies without a `@layer` (dev fragments, legacy
/// bundles) fall into an "Ungrouped" group, always rendered last.
fn group_policies(
    snapshots: Vec<PolicySnapshot>,
    editable: &std::collections::HashMap<String, String>,
) -> Vec<PolicyGroup> {
    let mut buckets: std::collections::BTreeMap<String, Vec<PolicyView>> =
        std::collections::BTreeMap::new();
    for p in snapshots {
        let layer_id = p
            .layer
            .clone()
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| "ungrouped".to_string());
        let editable_source = editable.get(&p.id).cloned();
        let view = PolicyView {
            search: policy_search_blob(&p),
            highlighted: highlight_cedar(&p.source),
            id_qs: urlencode(&p.id),
            id: p.id,
            effect: p.effect,
            description: p.description.unwrap_or_default(),
            tags: p.tags,
            reason: p.reason.unwrap_or_default(),
            editable_source,
        };
        buckets.entry(layer_id).or_default().push(view);
    }

    let mut groups: Vec<PolicyGroup> = buckets
        .into_iter()
        .map(|(layer_id, mut policies)| {
            // Stable, human-meaningful order within a layer.
            policies.sort_by(|a, b| a.id.cmp(&b.id));
            let (_, title, blurb) = layer_meta(&layer_id);
            let effect = group_effect(&policies);
            PolicyGroup {
                layer_id,
                title,
                blurb,
                effect,
                policies,
            }
        })
        .collect();
    // Canonical evaluation order; unknown layers after the known stack,
    // "ungrouped" last (see `layer_meta`).
    groups.sort_by_key(|g| layer_meta(&g.layer_id).0);
    groups
}

/// `(sort_order, title, blurb)` for a `@layer` slug. Unknown layers sort after
/// the known stack but before `ungrouped`, which is always last. `pub(crate)`
/// so the simulator trace (`crate::policies::build_trace`) shares the same
/// layer ordering + display names as the layered Policies pane.
pub(crate) fn layer_meta(layer_id: &str) -> (u32, String, String) {
    let (order, title, blurb): (u32, &str, &str) = match layer_id {
        "deny-default" => (
            0,
            "Deny by default",
            "Cedar's floor — any request that no permit matches is denied.",
        ),
        "baseline" => (
            1,
            "Baseline permits",
            "Role-wide grants every authenticated principal builds on.",
        ),
        "pii-overlay" => (
            2,
            "PII overlay",
            "Forbids that restrict access to PII-tagged tools.",
        ),
        "scim-overlay" => (
            3,
            "SCIM overlay",
            "Forbids principals deactivated in the directory (SCIM).",
        ),
        "service-grants" => (
            4,
            "Per-service grants",
            "Group-scoped permits and confinements for individual upstreams.",
        ),
        "step-up-overlay" => (
            5,
            "Step-up overlay",
            "Forbids requiring a fresh step-up scope.",
        ),
        "ungrouped" => (99, "Ungrouped", "Policies with no @layer annotation."),
        other => return (50, titleize(other), "Custom layer.".to_string()),
    };
    (order, title.to_string(), blurb.to_string())
}

/// `permit` / `forbid` / `mixed` for a layer, derived from its policies.
fn group_effect(policies: &[PolicyView]) -> &'static str {
    let any_permit = policies.iter().any(|p| p.effect == "permit");
    let any_forbid = policies.iter().any(|p| p.effect == "forbid");
    match (any_permit, any_forbid) {
        (true, false) => "permit",
        (false, true) => "forbid",
        _ => "mixed",
    }
}

/// Title-case an unknown layer slug for display (`my-layer` → `My layer`).
fn titleize(slug: &str) -> String {
    let spaced = slug.replace(['-', '_'], " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => spaced,
    }
}

/// Lowercased haystack the client-side search box matches a policy against.
fn policy_search_blob(p: &PolicySnapshot) -> String {
    let mut s = format!("{} {} {}", p.id, p.effect, p.tags.join(" "));
    if let Some(d) = &p.description {
        s.push(' ');
        s.push_str(d);
    }
    if let Some(r) = &p.reason {
        s.push(' ');
        s.push_str(r);
    }
    s.push(' ');
    s.push_str(&p.source);
    s.to_lowercase()
}

/// Minimal Cedar syntax highlighter. We don't want a full parser here —
/// Cedar already validated the source; this is pure cosmetic markup.
/// Keywords get `.kw`, quoted strings `.str`, line comments `.cmt`.
///
/// Tokenizes the RAW source and escapes each segment on output (via the
/// shared `waygate_core::html::escape`). Escape-then-tokenize would break
/// string detection: the escaper rewrites `"` to `&quot;`, so the
/// tokenizer's quote scan must see the raw text.
fn highlight_cedar(src: &str) -> String {
    let mut out = String::with_capacity(src.len() + 64);
    for line in src.split_inclusive('\n') {
        // Comment wins if it's on the line — match Cedar's `//` and `#`.
        if let Some(ix) = line.find("//") {
            out.push_str(&highlight_tokens(&line[..ix]));
            out.push_str("<span class=\"cmt\">");
            out.push_str(&waygate_core::html::escape(&line[ix..]));
            out.push_str("</span>");
        } else {
            out.push_str(&highlight_tokens(line));
        }
    }
    out
}

fn highlight_tokens(s: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "permit",
        "forbid",
        "when",
        "unless",
        "if",
        "then",
        "else",
        "in",
        "has",
        "like",
        "principal",
        "action",
        "resource",
        "context",
        "true",
        "false",
    ];
    fn flush_plain(out: &mut String, s: &str, from: usize, to: usize) {
        if from < to {
            out.push_str(&waygate_core::html::escape(&s[from..to]));
        }
    }
    let mut out = String::with_capacity(s.len());
    // Start of the pending not-yet-emitted plain run (escaped on flush).
    let mut plain_start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '"' {
            flush_plain(&mut out, s, plain_start, i);
            // Consume until next unescaped quote (or end of line).
            let start = i;
            let mut end = s.len();
            while let Some((j, cc)) = chars.next() {
                if cc == '"' {
                    end = j + 1;
                    break;
                }
                if cc == '\\' {
                    chars.next();
                }
            }
            out.push_str("<span class=\"str\">");
            out.push_str(&waygate_core::html::escape(&s[start..end]));
            out.push_str("</span>");
            plain_start = end;
        } else if c.is_ascii_alphabetic() || c == '_' {
            flush_plain(&mut out, s, plain_start, i);
            let start = i;
            let mut end = i + c.len_utf8();
            while let Some(&(j, cc)) = chars.peek() {
                if cc.is_ascii_alphanumeric() || cc == '_' {
                    end = j + cc.len_utf8();
                    chars.next();
                } else {
                    break;
                }
            }
            let word = &s[start..end];
            if KEYWORDS.contains(&word) {
                out.push_str("<span class=\"kw\">");
                out.push_str(word);
                out.push_str("</span>");
            } else {
                out.push_str(word);
            }
            plain_start = end;
        }
    }
    flush_plain(&mut out, s, plain_start, s.len());
    out
}

// --- simulator form handling ---

/// Flat form payload from the Policies page simulator. The action/resource
/// split is reconstructed from the `action` + `resource_type` discriminators;
/// unused fields ride along as empty strings because HTML forms always send
/// every named input.
#[derive(Debug, Deserialize)]
pub(crate) struct SimulateForm {
    /// Session-bound CSRF token copied from the rendered Policies page.
    /// The handler compares this in constant time against the token in the
    /// caller's session cookie — mismatch ⇒ 403.
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    groups: String,
    #[serde(default)]
    scopes: String,
    #[serde(default)]
    action: String,
    /// Originating channel for the simulated call — `direct` (default) or
    /// `codemode` — so operators can dry-run channel-conditioned overlays
    /// like the Code Mode approval policy.
    #[serde(default)]
    channel: String,
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    risk: String,
    #[serde(default)]
    resource_type: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    tool: String,
    /// Whether the simulated tool returns/accepts PII. HTML form posts
    /// this as `pii=on` from a checkbox; `#[serde(default)]` plus a
    /// string-typed deserializer treats absence (checkbox unchecked) as
    /// `false`. Drives the `pii` attribute on the simulated `Tool`
    /// entity so operators can dry-run PII-aware policies.
    #[serde(default, deserialize_with = "deserialize_html_checkbox")]
    pii: bool,
    /// Whether the simulated tool has side effects. Posted as `side_effects=on`
    /// from a checkbox (absence ⇒ `false`). Drives the `side_effects` attribute
    /// on the simulated `Tool` so operators can dry-run rules that gate on it —
    /// notably the baseline read-only grant (`risk:low && !side_effects`).
    #[serde(default, deserialize_with = "deserialize_html_checkbox")]
    side_effects: bool,
    /// Simulated principal's `auth_method` — `"oauth"` or `"api_key"`.
    /// Empty/unknown defaults to OAuth. Lets operators dry-run rules
    /// like the default PII forbid (`crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar`)
    /// that gate on `principal.auth_method == "api_key"`.
    #[serde(default)]
    auth_method: String,
}

/// HTML `<input type="checkbox">` posts the literal string `"on"` when
/// checked and omits the field when unchecked. serde's default `bool`
/// expects `true`/`false`; this adapter accepts `on`/`off`/`true`/`false`
/// so the form-level UX maps cleanly to a Rust bool.
fn deserialize_html_checkbox<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = serde::Deserialize::deserialize(deserializer)?;
    Ok(matches!(
        s.as_deref().map(str::to_ascii_lowercase).as_deref(),
        Some("on" | "true" | "1" | "yes" | "checked")
    ))
}

#[derive(Template)]
#[template(path = "policy_result.html")]
struct PolicyResult {
    /// The step-up re-auth link in this
    /// fragment carries a `next=` query param that must point back to
    /// the tenant-prefixed `/admin/t/<tenant>/policies` (not the
    /// legacy path) when the parent page was loaded under a tenant
    /// prefix. Populated by `policies_simulate`.
    tenant_ctx: Option<TenantContext>,
    decision: &'static str,
    reasons: Vec<String>,
    /// When `decision == "step_up"`, the scope the caller would need to add
    /// to their session via `/admin/login?step_up_scope=…` before the action
    /// would be allowed. `None` for allow/deny — the template hides the
    /// step-up affordance in those cases.
    step_up_scope: Option<String>,
    /// The fired policies joined to layer/description/reason metadata,
    /// ordered by evaluation layer — the structured "why" of the decision.
    trace: Vec<crate::policies::SimTraceEntry>,
    /// The single policy that decided the outcome (highlighted in the
    /// trace). `None` for a default deny.
    determinative_policy_id: Option<String>,
}

impl PolicyResult {
    /// Fragment delegate — fragments carry no full [`crate::chrome::PageChrome`];
    /// the URL logic lives in [`crate::tenant_ctx::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

/// 503 fragment used when the simulator is hit with no Cedar engine wired up
/// (dev-mode auth-disabled). Inline HTML — the view is a single paragraph and
/// duplicating the `#sim-result` wrapper keeps htmx's `outerHTML` swap valid.
const SIMULATE_UNAVAILABLE: &str = r#"<div id="sim-result" aria-live="polite" style="margin-top: 12px">
  <p class="sim-note state-err">Cedar engine is not configured — simulator unavailable.</p>
</div>"#;

pub(crate) async fn policies_simulate(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<SimulateForm>,
) -> Response {
    // CSRF: the rendered page stamped the session's csrf token into a hidden
    // input. Require a match before doing any work. Constant-time compare so
    // a careless equality doesn't leak byte timings.
    if let Some(Extension(ct)) = csrf.as_ref() {
        if !csrf_matches(&ct.0, &form.csrf) {
            tracing::warn!("simulator CSRF token mismatch; rejecting");
            return (
                StatusCode::FORBIDDEN,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                "<div id=\"sim-result\" aria-live=\"polite\" style=\"margin-top: 12px\">\
                 <p class=\"sim-note state-err\">Session expired. Refresh the page and try again.</p>\
                 </div>",
            )
                .into_response();
        }
    }

    let Some(engine) = state.policy.cedar.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            SIMULATE_UNAVAILABLE,
        )
            .into_response();
    };

    // Map the form's `auth_method=oauth|api_key` radio to the runtime
    // enum so operators can dry-run policies that branch on
    // `principal.auth_method` — notably `crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar`
    // which forbids API-key callers on PII tools. Empty or unknown
    // defaults to OAuth (the most-common interactive path).
    let auth_method = match form.auth_method.as_str() {
        "api_key" => waygate_oidc::AuthMethod::ApiKey,
        _ => waygate_oidc::AuthMethod::Oauth,
    };
    let tenant = waygate_core::TenantId::parse(principal_tenant(user.as_ref()))
        .expect("authenticated principal tenant must be valid");
    let principal = Principal {
        sub: if form.sub.is_empty() {
            "anonymous".into()
        } else {
            form.sub
        },
        email: None,
        groups: split_csv(&form.groups),
        issuer: "simulation".into(),
        scopes: split_csv(&form.scopes),
        tenant: tenant.clone(),
        auth_method,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    };
    let risk = parse_risk(&form.risk);
    let action = match form.action.as_str() {
        "list_tools" => AuthzAction::ListTools,
        "search_tools" => AuthzAction::SearchTools,
        "call_tool" => AuthzAction::CallTool {
            name: form.tool_name.clone(),
            risk,
        },
        "admin_manage_policies" => AuthzAction::AdminManagePolicies,
        "admin_manage_servers" => AuthzAction::AdminManageServers,
        "admin_view_telemetry" => AuthzAction::AdminViewTelemetry,
        "grant_cross_app_access" => AuthzAction::GrantCrossAppAccess,
        _ => AuthzAction::SearchTools,
    };
    let resource = match form.resource_type.as_str() {
        "tool" => ResourceSpec::Tool(ToolSpec {
            operation: None,
            server: form.server.clone(),
            name: if form.tool.is_empty() {
                form.tool_name
            } else {
                form.tool
            },
            risk,
            side_effects: form.side_effects,
            pii: form.pii,
        }),
        _ => ResourceSpec::Server { name: form.server },
    };

    // Pin ONE engine snapshot for both the decision and the trace metadata, so
    // a SIGHUP reload between `evaluate` and `list_policies` can't join the
    // fired policy_ids to a different policy set.
    let snap = engine.snapshot_for_tenant(tenant.as_str());
    let mut facts = waygate_authz::simulation_facts(&principal, &action, &resource);
    // The form's channel select maps onto the same gateway-stamped fact the
    // live pipeline sets, so a codemode dry-run exercises the approval
    // overlay exactly as a real Code Mode dispatch would.
    if form.channel == "codemode" {
        facts.context.channel = waygate_core::InvocationChannelFact::CodeMode;
    }
    let result: AuthzResult = AuthzEngine::evaluate_facts(snap.as_ref(), &facts);
    let decision = match result.decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::StepUpRequired => "step_up",
        Decision::ApprovalRequired => "approval_required",
    };
    // Mirror the same risk → scope mapping the live CedarGate uses; surfacing
    // it here keeps the simulator UX consistent with what an MCP caller would
    // actually have to re-authorize for.
    let step_up_scope = match result.decision {
        Decision::StepUpRequired => Some(step_up_scope_for_risk(risk)),
        _ => None,
    };
    // Build the structured trace from the SAME pinned snapshot before moving
    // the result's fields out.
    let (trace, determinative_policy_id) =
        crate::policies::build_trace(&result, &snap.list_policies());
    render(&PolicyResult {
        tenant_ctx: tenant_ctx.map(|Extension(c)| c),
        decision,
        reasons: result.reasons,
        step_up_scope,
        trace,
        determinative_policy_id,
    })
}

fn step_up_scope_for_risk(risk: RiskTier) -> String {
    // Single source of truth (`waygate_mcp::authz::required_scope_for`). Low
    // has no required scope canonically, so the playground's advisory step-up
    // scope falls back to the base `mcp:invoke` (preserving prior behavior).
    waygate_mcp::authz::required_scope_for(risk)
        .unwrap_or("mcp:invoke")
        .to_owned()
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_owned())
        .collect()
}

fn parse_risk(s: &str) -> RiskTier {
    match s {
        "high" => RiskTier::High,
        "medium" => RiskTier::Medium,
        _ => RiskTier::Low,
    }
}

// ---- activity (full page + htmx fragments) --------------------------------

#[cfg(test)]
mod highlight_tests {
    use super::{highlight_cedar, highlight_tokens};

    // Regression guard: the shared escaper rewrites `"` to `&quot;`, so
    // string-literal detection must run on the raw source. An
    // escape-then-tokenize ordering silently drops every `.str` span.
    #[test]
    fn string_literals_keep_their_span_and_are_escaped() {
        let out = highlight_cedar(r#"permit(principal == User::"alice");"#);
        assert!(
            out.contains(r#"<span class="str">&quot;alice&quot;</span>"#),
            "string literal must be span-wrapped and quote-escaped, got: {out}"
        );
        assert!(out.contains(r#"<span class="kw">permit</span>"#));
    }

    #[test]
    fn comments_are_escaped_inside_their_span() {
        // split_inclusive keeps the trailing newline inside the comment span.
        let out = highlight_cedar("permit(); // a <b> & \"c\"\n");
        assert!(
            out.contains("<span class=\"cmt\">// a &lt;b&gt; &amp; &quot;c&quot;\n</span>"),
            "comment body must be escaped, got: {out}"
        );
    }

    #[test]
    fn plain_segments_are_escaped() {
        // `<` and `&&` appear outside strings/comments in real Cedar.
        let out = highlight_tokens("a < 3 && b");
        assert!(out.contains("&lt;"), "got: {out}");
        assert!(out.contains("&amp;&amp;"), "got: {out}");
    }
}
