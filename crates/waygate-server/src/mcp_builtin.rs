//! Built-in `gateway-admin` MCP namespace — the maker's propose/poll surface
//! over the MCP wire for the HITL control plane.
//!
//! An automated maker (Claude over MCP) holding `mcp:propose` can QUEUE a
//! privileged control-plane change and poll its decision without ever holding
//! admin — the same CIBA-shaped flow the REST surface exposes
//! ([`waygate_admin::change_requests`]), reachable as MCP tools so an agent
//! doesn't have to shell out to `curl`. Implements
//! [`waygate_mcp::BuiltinTools`]; `GatewayServer` routes `gateway-admin.<tool>`
//! calls here.
//!
//! ## Why this lives in `waygate-server`, not `waygate-admin`
//!
//! The propose/poll/list LOGIC is the same `*_core` functions the REST
//! handlers call — [`waygate_admin::change_requests::propose_core`] /
//! `status_core` / `list_core` — so the MCP and REST surfaces can't drift
//! (same validation, fail-closed audit, maker-only scoping, binding code,
//! approval URL). But *producing* the rmcp `CallToolResult` / `Tool` wire
//! types is MCP-wire work, and `waygate-admin` deliberately keeps `rmcp` a
//! dev-only dependency (it's the REST + dashboard crate). So the rmcp-typed
//! adapter lives here in the composition root, which already bridges
//! `waygate-admin` (the cores) and `waygate-mcp` (the [`BuiltinTools`] trait).
//!
//! Tools, all requiring `mcp:propose`:
//! - `propose_change` — capture an intent as a pending change; returns the
//!   binding code + approval URL the agent surfaces in the transcript.
//! - `describe_action` — list the proposable actions, each with its params
//!   JSON Schema (so a maker builds a valid `propose_change.params` from the
//!   wire surface alone).
//! - `get_action_context` — read the current operator-authored policy/manifest
//!   state an action needs before a maker constructs its params, without
//!   resolving governed secret references.
//! - `preview_change` — dry-run an action's params against its schema and
//!   current gateway state, including the existing policy/manifest effect
//!   preview when applicable, WITHOUT queuing — validate before consuming a
//!   human approval slot.
//! - `get_change_status` — poll one change (the CIBA `auth_req_id`).
//! - `get_change_secret` — retrieve the one-time secret an executed,
//!   secret-producing change left behind (e.g. the plaintext `mcpgw_…` key
//!   from an approved `api_key.mint`). Single-use burn-on-read, delegating to
//!   the same [`waygate_admin::change_requests::retrieve_secret_core`] the REST
//!   reveal endpoint uses — so the maker no longer has to shell out to `curl`
//!   for the one thing the poll deliberately withholds (the poll carries only a
//!   `secret_available: true` fingerprint, never the plaintext).
//! - `list_my_changes` — the maker's own queue.
//!
//! A caller without `mcp:propose` sees none of these tools in `tools/list`
//! AND is refused at `call` (defense in depth — hiding them in the listing is
//! UX, the `call` check is the boundary).
//!
//! ## Elicitation: URL-mode wired, form-mode deferred
//!
//! The design's optional accelerator uses the MCP `elicitation/create` request,
//! which rmcp 1.8 exposes via `Peer<RoleServer>::create_elicitation`. URL-mode
//! is now wired in the server's `tools/call` handler (see
//! `waygate_mcp::server`'s `approval_elicitation`): when a `propose_change`
//! queues a change and the client negotiated the elicitation capability, the
//! gateway sends the present operator straight to the approval page. It's
//! best-effort and fire-and-forget — the always-on fallback below is unchanged
//! and remains the contract: `propose_change` returns the binding code +
//! approval URL in the tool-result text, which the agent repeats in the
//! transcript ("Queued change … — code AMBER-OTTER — approve: <url>"), so a
//! client without elicitation (or one that declines) loses nothing. Form-mode
//! elicitation (collecting missing params in-session for a `confirm` tier) is
//! deliberately NOT wired: propose-time params validation and
//! `describe_action` already validate and teach the params shape.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use rmcp::model::{
    CallToolResult, ContentBlock as Content, ErrorCode, JsonObject, Tool, ToolAnnotations,
};
use rmcp::ErrorData as McpError;
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use waygate_admin::change_executor::registry;
use waygate_admin::change_notify::SharedChangeNotifier;
use waygate_admin::change_requests::{
    capture_target_etag, list_core, propose_core, resolve_submission_files, retrieve_secret_core,
    status_core, validate_propose_params_size, ListResponse, ProposeRequest, ProposeResponse,
    SecretResponse, StatusResponse, SubmissionContext,
};
use waygate_admin::error::ApiError;
use waygate_admin::param_files::engages_the_file_plane;
use waygate_admin::AdminState;
use waygate_changeset::SharedChangeRequestStore;
use waygate_core::RiskTier;
use waygate_mcp::{
    BuiltinCatalog, BuiltinSurfaceDescriptor, BuiltinTools, CatalogTool, SharedEvidence,
};
use waygate_oidc::{AuthMethod, Principal, Scope};

#[path = "mcp_action_context.rs"]
mod action_context;

/// The reserved namespace this handler answers. The dispatcher intercepts
/// this prefix before the `<server>.<tool>` split, so it takes precedence
/// over any upstream of the same name. That collision can't arise:
/// `waygate_upstream::validate_manifest_invariants` rejects an upstream
/// registered under this name at load. Aliased to the cross-crate
/// [`waygate_core::RESERVED_BUILTIN_NAMESPACE`] so the dispatch side and the
/// load-time guard share one source of truth.
pub const NAMESPACE: &str = waygate_core::RESERVED_BUILTIN_NAMESPACE;

/// Built-in MCP tools backing the HITL maker surface. Holds the minimal
/// pieces the `*_core` functions need — the same store Arc the REST surface
/// uses (one Arc, two consumers), the audit sink, the public URL for the
/// approval / poll links, and the same out-of-band notifier the REST
/// surface uses, so an MCP-proposed change pushes a heads-up too.
pub struct ChangeProposalTools {
    store: SharedChangeRequestStore,
    evidence: SharedEvidence,
    public_url: String,
    notifier: Option<SharedChangeNotifier>,
    /// The same operator-configured per-tenant quota service used by ordinary
    /// tool calls. Preview replays can read bounded audit history and evaluate
    /// Cedar repeatedly, so they consume the ordinary `call` bucket too.
    quota: Option<Arc<dyn waygate_quota::QuotaService>>,
    /// Deferred handle to `AdminState`, set once at boot. The propose
    /// path captures the target's freshness token (`capture_target_etag`) for
    /// the execute-time guard, which needs the target stores `AdminState`
    /// holds. This struct is built in the composition root BEFORE `AdminState`
    /// exists (the server factory closure is defined first), so the root passes
    /// an empty cell and fills it after building `AdminState`. By the time any
    /// connection can invoke a tool the cell is set; a call in the pre-fill
    /// window fails closed for actions that require a target witness.
    admin_state: Arc<OnceLock<Arc<AdminState>>>,
}

impl ChangeProposalTools {
    pub fn new(
        store: SharedChangeRequestStore,
        evidence: SharedEvidence,
        public_url: String,
        notifier: Option<SharedChangeNotifier>,
        quota: Option<Arc<dyn waygate_quota::QuotaService>>,
        admin_state: Arc<OnceLock<Arc<AdminState>>>,
    ) -> Self {
        Self {
            store,
            evidence,
            public_url,
            notifier,
            quota,
            admin_state,
        }
    }
}

/// A *maker* is a non-peer principal holding `mcp:propose`.
///
/// This MUST stay in lock-step with the REST gate's `peer_assertion_permits`
/// (`crates/waygate-admin/src/scope.rs`): federated Tier-C peers are NOT
/// makers of THIS gateway — they carry their own operator on the far side of
/// the federation, and `peer_assertion_permits` blocks `mcp:propose` for an
/// `AuthMethod::PeerAssertion` principal *before* the scope check. The
/// `PeerJwtValidator` already strips admin/scim:write, but `mcp:propose` is
/// belt-and-suspenders blocked here so the MCP maker surface can't be more
/// permissive than its REST twin — a registered peer claiming `mcp:propose`
/// must not be able to call `gateway-admin.propose_change`.
fn is_maker(p: &Principal) -> bool {
    p.auth_method != AuthMethod::PeerAssertion && p.has_scope(Scope::McpPropose.as_str())
}

#[async_trait]
impl BuiltinTools for ChangeProposalTools {
    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn catalog(&self) -> BuiltinCatalog {
        surface_catalog()
    }

    async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        // Hide the maker tools from non-makers — UX only; `call` re-checks.
        if principal.is_some_and(is_maker) {
            self.catalog().definitions()
        } else {
            Vec::new()
        }
    }

    async fn call(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        // Authorization boundary. `list_tools` hiding the tool from a
        // non-maker is a nicety; THIS is what stops a caller that invokes the
        // name without ever seeing it listed — including a peer-asserted
        // principal that claims `mcp:propose` (which the REST gate also
        // refuses; see `is_maker`).
        let principal = match principal {
            Some(p) if is_maker(p) => p,
            _ => return Err(insufficient_scope()),
        };
        let args = arguments.unwrap_or_default();

        match tool {
            "propose_change" => {
                let mut req: ProposeRequest =
                    serde_json::from_value(Value::Object(args)).map_err(|e| {
                        McpError::invalid_params(format!("propose_change args: {e}"), None)
                    })?;
                // Capture for the transcript line before the request is moved.
                let action_type = req.action_type.clone();
                // Resolve any uploaded document into inline text BEFORE the
                // freshness capture, so the witness, the stored row, and the
                // approver's render all describe the same resolved params. An
                // action with no document field resolves nothing, but the same
                // call still refuses a file reference smuggled into a field the
                // executor would write verbatim. Needs the admin state for the
                // file plane; a submission that names no file never reaches it.
                let files = match self.admin_state.get() {
                    Some(state) => {
                        resolve_submission_files(
                            state,
                            &req.action_type,
                            &mut req.params,
                            principal,
                        )
                        .await
                    }
                    None if engages_the_file_plane(&req.action_type, &req.params) => {
                        Err(ApiError::Internal(
                            "admin state is not ready to read an uploaded document".into(),
                        ))
                    }
                    None => Ok(Vec::new()),
                }
                .map_err(api_to_mcp)?;
                // Capture the target's freshness token NOW (same as the
                // REST propose path) so execute-on-approval can refuse a stale
                // write that would clobber an out-of-band edit. Needs the target
                // stores in `AdminState`, resolved from the deferred cell (set
                // at boot before any tool call). An unset cell is a boot-order
                // violation and fails closed for actions that require a
                // witness; legacy best-effort actions retain their prior
                // no-baseline behavior.
                let target_etag = match self.admin_state.get() {
                    Some(state) => {
                        capture_target_etag(state, &req.action_type, principal, &req.params).await
                    }
                    None if registry()
                        .get(&req.action_type)
                        .is_some_and(|executor| executor.requires_target_etag()) =>
                    {
                        Err(ApiError::Internal(
                            "admin state is not ready to capture the proposal target".into(),
                        ))
                    }
                    None => Ok(None),
                }
                .map_err(api_to_mcp)?;
                let resp = propose_core(
                    &self.store,
                    &self.evidence,
                    &self.public_url,
                    self.notifier.as_ref(),
                    principal,
                    req,
                    SubmissionContext { target_etag, files },
                )
                .await
                .map_err(api_to_mcp)?;
                // Surface the binding code + approval URL in the text block so
                // the agent repeats them in the transcript (the agent-side
                // surface the design specifies), alongside structured content
                // for clients that parse it.
                let text = format!(
                    "Queued change {id} to {action_type} for human approval — binding code \
                     {code}. A human must approve it at {url} (it executes server-side on \
                     approval). Poll get_change_status with id={id} for the decision; it \
                     expires in {ttl}s.",
                    id = resp.change_request_id,
                    code = resp.binding_code,
                    url = resp.approval_url,
                    ttl = resp.expires_in,
                );
                Ok(structured_with_text(&resp, text))
            }
            "get_change_status" => {
                let id = parse_id_arg(&args)?;
                let resp = status_core(&self.store, &self.public_url, principal, id)
                    .await
                    .map_err(api_to_mcp)?;
                Ok(structured(&resp))
            }
            "get_change_secret" => {
                let id = parse_id_arg(&args)?;
                // The burn-on-read reveal needs the full `AdminState` — the
                // secret-crypto keyring AND the change-request store — which
                // the pollers don't (they ride `self.store` directly). Resolve
                // it from the deferred cell the composition root fills at boot.
                // In the (unreachable) pre-fill window we fail closed rather
                // than pretend the channel is down — a maker only ever reaches
                // here long after boot. `retrieve_secret_core` itself maps an
                // unset GATEWAY_CHANGE_SECRET_KEY to ServiceUnavailable; this
                // guards only the cell.
                let state = self.admin_state.get().ok_or_else(|| {
                    McpError::internal_error(
                        "change-request secret channel not ready (gateway still starting)",
                        None,
                    )
                })?;
                let resp = retrieve_secret_core(state, principal, id)
                    .await
                    .map_err(api_to_mcp)?;
                // The plaintext must reach the agent, so it rides the structured
                // result's `secret` field — exactly as the REST reveal returns
                // it in the response body. This is the response payload to an
                // authorized maker, NOT a log line, so the repo "never log
                // secrets" rule (enforced for `tracing`/audit, which core keeps
                // fingerprint-only) isn't in tension here. The text block is a
                // burn notice + pointer; it deliberately does NOT echo the
                // secret, so the model isn't nudged to reprint it in prose.
                let text = format!(
                    "Retrieved the one-time secret for change {id}. The plaintext is only at \
                     `CallToolResult.structuredContent.secret`; `CallToolResult.content` is this \
                     non-secret burn notice, not serialized output. The value is now burned — \
                     capture and store `structuredContent` immediately; a second call returns \
                     `secret already retrieved`."
                );
                Ok(structured_with_text(&resp, text))
            }
            "list_my_changes" => {
                let (limit, offset, lifecycle) = parse_list_args(&args)?;
                let resp = list_core(
                    &self.store,
                    &self.public_url,
                    principal,
                    limit,
                    offset,
                    lifecycle.as_deref(),
                )
                .await
                .map_err(api_to_mcp)?;
                Ok(structured(&resp))
            }
            "describe_action" => {
                // Serve the schemars-derived params catalog so a maker
                // builds a valid `propose_change.params` from the wire surface
                // alone instead of reading this crate's source. No args ⇒ the
                // full catalog; `action_type` ⇒ that one action's schema; an
                // unknown key teaches the valid set (errors-teach, per the SOP).
                let catalog = waygate_admin::change_executor::registry().action_catalog();
                let actions: Vec<ActionEntry> = match args
                    .get("action_type")
                    .and_then(|v| v.as_str())
                {
                    None => catalog.into_iter().map(ActionEntry::from_catalog).collect(),
                    Some(at) => match catalog.into_iter().find(|e| e.action_type == at) {
                        Some(e) => vec![ActionEntry::from_catalog(e)],
                        None => {
                            let valid = waygate_admin::change_executor::registry()
                                .action_types()
                                .join(", ");
                            return Err(McpError::invalid_params(
                                format!("unknown action_type {at:?}; proposable actions: {valid}"),
                                None,
                            ));
                        }
                    },
                };
                Ok(structured(&DescribeActionResponse { actions }))
            }
            "get_action_context" => action_context::call(&self.admin_state, principal, &args).await,
            "preview_change" => {
                // Dry-run: validate params against the action's schema and
                // current target using the SAME validators + freshness capture
                // the propose path uses. Policy/manifest actions also reuse the
                // dashboard's compile/test/decision-replay effect preview. No
                // change is queued and no separate simulation engine lives here.
                let action_type = args
                    .get("action_type")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpError::invalid_params(
                            "missing required string field `action_type`",
                            None,
                        )
                    })?;
                let mut params = match args.get("params") {
                    None | Some(Value::Null) => Value::Object(Default::default()),
                    Some(v @ Value::Object(_)) => v.clone(),
                    Some(_) => {
                        let schema = registry()
                            .params_schema(action_type)
                            .ok_or_else(|| unknown_action(action_type))?;
                        let example =
                            waygate_admin::change_context::context_descriptor(action_type)
                                .map(|descriptor| descriptor.params_example)
                                .unwrap_or_else(|| json!({"params": {}}));
                        return Err(McpError::invalid_params(
                            format!(
                                "`params` must be an object; expected params schema: {schema}; \
                                 worked example: {example}"
                            ),
                            None,
                        ));
                    }
                };
                // A preview must judge the SAME params a propose would store,
                // so an uploaded document is resolved here too. Otherwise a
                // maker previewing a file-backed candidate would be told its
                // `content` is missing and would have no way to check the
                // document it actually intends to submit.
                //
                // Whenever the state exists — which is always, after boot — this
                // runs unconditionally, exactly as propose does. Deciding
                // whether to resolve by inspecting the params is what made the
                // two surfaces disagree: a foreign URL or a non-string at an
                // upload field names no gateway file, and the params schemas
                // admit unknown keys, so such a candidate previewed clean and
                // was then rejected at propose. `engages_the_file_plane` now
                // only chooses how to fail in the pre-boot window, where the
                // propose path fails closed the same way.
                let resolution = match self.admin_state.get() {
                    Some(state) => {
                        resolve_submission_files(state, action_type, &mut params, principal).await
                    }
                    None if engages_the_file_plane(action_type, &params) => {
                        Err(ApiError::Internal(
                            "admin state is not ready to read an uploaded document".into(),
                        ))
                    }
                    None => Ok(Vec::new()),
                };
                let Some(mut preview) =
                    waygate_admin::change_executor::preview_action(action_type, &params)
                else {
                    return Err(unknown_action(action_type));
                };
                // A refused submission is reported as an invalid preview rather
                // than thrown, matching how the current-state rejection below
                // is reported: propose and preview refuse the same candidates
                // for the same reasons, and preview's job is to hand back
                // something the maker can fix.
                if let Err(error) = resolution {
                    preview.valid = false;
                    preview.errors.push(api_to_mcp(error).message.to_string());
                }
                if let Some(error) = validate_propose_params_size(action_type, &params) {
                    preview.valid = false;
                    preview.errors.push(error);
                }

                let mut effect = None;
                if preview.valid {
                    // Deterministic input validation runs before quota debit;
                    // the quota then admits the bounded DB/Cedar effect work.
                    self.check_preview_quota(principal).await?;
                    let state = self.admin_state.get().ok_or_else(|| {
                        McpError::internal_error(
                            "admin state is not ready to preview the proposal target",
                            None,
                        )
                    })?;
                    let target_etag =
                        match capture_target_etag(state, action_type, principal, &params).await {
                            Ok(target_etag) => target_etag,
                            Err(error) => {
                                let detail = api_to_mcp(error).message.to_string();
                                preview.valid = false;
                                preview.errors.push(format!(
                                    "current state rejected the candidate: {detail}"
                                ));
                                None
                            }
                        };
                    effect = waygate_admin::change_effect_preview::preview_change_effect(
                        state,
                        principal.tenant.as_str(),
                        action_type,
                        &params,
                        target_etag.as_deref(),
                        Some(principal),
                    )
                    .await;
                }

                Ok(structured(&PreviewResponse::from_action_preview(
                    preview, effect,
                )))
            }
            other => Err(McpError::invalid_params(
                format!("unknown {NAMESPACE} tool: {other}"),
                None,
            )),
        }
    }
}

impl ChangeProposalTools {
    async fn check_preview_quota(&self, principal: &Principal) -> Result<(), McpError> {
        let Some(quota) = self.quota.as_ref() else {
            return Ok(());
        };
        let fq_tool = format!("{NAMESPACE}.preview_change");
        let context = waygate_quota::QuotaContext {
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: Some(principal.sub.clone()),
            client_id: None,
            server: NAMESPACE.to_owned(),
            fq_tool,
        };
        match quota
            .check_and_consume(&context, &[waygate_quota::QuotaAction::Call])
            .await
        {
            Ok(()) => Ok(()),
            Err(waygate_quota::QuotaError::RateLimited {
                policy_id,
                name,
                retry_after_seconds,
            }) => Err(McpError::new(
                ErrorCode::INVALID_REQUEST,
                format!("rate-limited by policy `{name}`; retry after {retry_after_seconds}s"),
                Some(json!({
                    "error": "rate_limited",
                    "policy_id": policy_id.to_string(),
                    "policy_name": name,
                    "retry_after_seconds": retry_after_seconds,
                })),
            )),
            Err(waygate_quota::QuotaError::Sqlx(error)) => {
                tracing::warn!(
                    tenant = %principal.tenant.as_str(),
                    error = %error,
                    "preview quota store error; allowing the call"
                );
                Ok(())
            }
        }
    }
}

/// Static descriptor for the operator visibility surface and the dispatch-time
/// Cedar classification. Derived from [`tool_defs`] so it can't drift.
/// `propose_change` queues a privileged change (a side effect, `Medium` — a
/// human still approves before anything executes); `get_change_secret` burns +
/// discloses a one-time secret (also a side effect, `Medium` — see below); the
/// two pollers are reads.
pub fn surface_descriptor() -> BuiltinSurfaceDescriptor {
    surface_catalog().descriptor()
}

pub(crate) fn surface_catalog() -> BuiltinCatalog {
    let prefix = format!("{NAMESPACE}.");
    let tools = tool_defs()
        .into_iter()
        .map(|t| {
            let full = t.name.as_ref();
            let name = full.strip_prefix(&prefix).unwrap_or(full).to_owned();
            // `get_change_secret` is `Medium`, NOT `High`, deliberately. The
            // `risk` tier flows into `resource.risk` AND `required_scope_for`
            // (the step-up scope the tier maps to). A propose-only agent
            // structurally cannot satisfy a step-up *factor* (passkey/MFA), so
            // classifying the reveal `High` would let any hardened policy that
            // gates High on step-up make the secret unretrievable over MCP —
            // re-creating the exact gap this tool closes. The reveal also can't
            // escalate authority: it returns a secret for a change a human
            // already approved, scoped to the maker's own change, single-use.
            // So it sits at the same tier as `propose_change` (one maker
            // workflow), above the Low pollers — its sensitivity is carried by
            // `side_effects` (the burn) + `pii` (a live credential), which
            // policy can still gate on without an unsatisfiable factor.
            let (risk, side_effects) = match name.as_str() {
                "propose_change" | "get_change_secret" => (RiskTier::Medium, true),
                _ => (RiskTier::Low, false),
            };
            // `get_change_status` / `list_my_changes` return `StatusResponse`,
            // which carries `approver` (the human who decided) plus the
            // executor's result detail — identity-bearing, so PII.
            // `get_change_secret` returns a live plaintext credential — the most
            // sensitive output on the surface, so PII too. The `propose_change`
            // response is only a binding code + URLs.
            let pii = matches!(
                name.as_str(),
                "get_change_status"
                    | "list_my_changes"
                    | "get_change_secret"
                    | "get_action_context"
                    | "preview_change"
            );
            CatalogTool::builtin(NAMESPACE, t, risk, side_effects, pii)
        })
        .collect();
    BuiltinCatalog::new(
        NAMESPACE,
        Scope::McpPropose.as_str(),
        "HITL control plane: queue a privileged change for human approval and poll its decision \
         (propose-only — never executes without an operator's approval).",
        tools,
    )
}

pub(crate) fn tool_defs() -> Vec<Tool> {
    vec![
        Tool::new(
            format!("{NAMESPACE}.propose_change"),
            "Queue a privileged change for human approval; it never executes on your authority. \
             Workflow: `describe_action` → advertised `get_action_context` → `preview_change` → \
             this tool. Copy gateway-returned hashes; never calculate them. Surface the binding \
             code and approval URL, then poll `get_change_status`. After an executed \
             secret-producing change, retrieve its value once with `get_change_secret`. For an \
             action whose `describe_action` row lists `file_params`, a large document may be \
             uploaded with `gateway-files.prepare_upload` and submitted as the file's URI at the \
             listed `upload_field` instead of inline.",
            propose_schema(),
        )
        .with_title("Propose a control-plane change")
        .with_output_schema::<ProposeResponse>()
        // Creates a pending change request (a side effect) but additively —
        // nothing executes until a human approves, so not `destructive`.
        .annotate(ToolAnnotations::new().read_only(false).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.describe_action"),
            "Start here. Get an action's exact `params` schema and optional preparation \
             `context`; omit `action_type` for the full catalog. When `context` is present, call \
             its tool with the supplied selector before previewing. Copy returned witnesses; \
             never derive them. A non-empty `file_params` names the fields whose document may be \
             uploaded instead of inlined, and the field to send its URI at.",
            describe_schema(),
        )
        .with_title("Describe proposable actions")
        .with_output_schema::<DescribeActionResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
        action_context::tool_def(),
        Tool::new(
            format!("{NAMESPACE}.preview_change"),
            "Dry-run prepared params without queuing. `valid: false` teaches fixes; policy and \
             manifest `effect` is the human review preview. For `mcp_annotations`, bootstrap each \
             hash with 64 zeroes. Every candidate annotation server must have exactly one observed \
             row with `connected: true`, nonempty `tools`, and empty `draft_only`; copy each \
             non-null `effect.observed[].tools[].observed_behavior_hash` into \
             `approved_behavior_hash`, then re-preview until every `draft_status` is `match` and \
             every `would_quarantine` is empty. Otherwise stop. Proposal and execution recheck \
             freshness.",
            preview_schema(),
        )
        .with_title("Preview a control-plane change (dry run)")
        .with_output_schema::<PreviewResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
        Tool::new(
            format!("{NAMESPACE}.get_change_status"),
            "Poll one change request you proposed (by its id) for the human's decision: \
             authorization_pending | approved | executing | executed | failed | denied | \
             expired. On `executed` the execution result is included; on `denied` the reason \
             is. For a secret-producing action, `execution_result.secret_available: true` is a \
             historical statement that execution produced a secret, not proof that it remains \
             retrievable. You only see your own requests.",
            status_schema(),
        )
        .with_title("Poll change status")
        .with_output_schema::<StatusResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
        Tool::new(
            format!("{NAMESPACE}.get_change_secret"),
            "Retrieve the one-time secret produced by a change you proposed — e.g. the plaintext \
             `mcpgw_…` API key from an approved `api_key.mint`. Only works after \
             `get_change_status` reports `executed` and its result carries `secret_available: \
             true` (a historical production marker, not live retrievability; most actions \
             produce no secret). SINGLE-USE: a successful call immediately burns the value. \
             Read the plaintext only from `CallToolResult.structuredContent.secret`; \
             `CallToolResult.content` contains only a non-secret burn notice, not serialized \
             output. Capture and store `structuredContent` before interpreting any other result \
             channel; a second call fails with `secret already retrieved`. You only see your \
             own requests.",
            status_schema(),
        )
        .with_title("Retrieve one-time change secret")
        .with_output_schema::<SecretResponse>()
        // Single-use burn-on-read: a successful retrieve consumes the secret.
        .annotate(ToolAnnotations::new().read_only(false).destructive(true)),
        Tool::new(
            format!("{NAMESPACE}.list_my_changes"),
            "List the change requests you proposed, newest first. Optional `lifecycle` filter: \
             pending | expired | decided. You only see your own requests.",
            list_schema(),
        )
        .with_title("List my change requests")
        .with_output_schema::<ListResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
    ]
}

/// One proposable action and the JSON Schema its `params` object must satisfy —
/// the wire row `describe_action` returns. `params_schema` is the
/// schemars-derived schema for that action's params; pass it straight to a JSON
/// Schema validator (it is an arbitrary JSON Schema object, hence the open
/// `params_schema` type).
#[derive(Serialize, schemars::JsonSchema)]
struct ActionEntry {
    /// Registry key to pass as `propose_change.action_type` (e.g.
    /// `rate_limit.update`).
    action_type: String,
    /// JSON Schema for this action's `params` object. Validate your `params`
    /// against this before calling `propose_change`.
    params_schema: Value,
    /// Valid worked params for policy/manifest actions that require current
    /// context. Replace witness placeholders with values returned by
    /// `get_action_context`.
    params_example: Option<Value>,
    /// Current-state preparation contract. `null` when the action can be
    /// constructed without an action-aware read.
    context: Option<ActionContextEntry>,
    /// Params fields this action will also accept as an uploaded file, for
    /// documents too large or too awkward to inline. Empty for most actions.
    file_params: Vec<FileParamEntry>,
}

impl ActionEntry {
    fn from_catalog(entry: waygate_admin::change_executor::ActionCatalogEntry) -> Self {
        let params_example = entry
            .context
            .as_ref()
            .map(|context| context.params_example.clone());
        Self {
            action_type: entry.action_type.to_owned(),
            params_schema: entry.params_schema,
            params_example,
            file_params: entry
                .file_params
                .iter()
                .map(|spec| FileParamEntry {
                    field: field_path(spec.pointer),
                    upload_field: field_path(&spec.file_pointer()),
                    content: spec.description.to_owned(),
                    uri_prefix: waygate_core::GATEWAY_FILE_URI_PREFIX.to_owned(),
                })
                .collect(),
            context: entry.context.map(|context| ActionContextEntry {
                tool: format!("{NAMESPACE}.get_action_context"),
                description: context.description.to_owned(),
                selector_schema: context.selector_schema,
                selector_example: context.selector_example,
            }),
        }
    }
}

/// One params field that accepts an uploaded document instead of inline text.
///
/// `upload_field` is deliberately absent from `params_schema`: the gateway
/// reads the file and substitutes its text at `field` before the params are
/// validated, stored, reviewed, or executed, so the schema describes the
/// resolved shape a proposal actually carries. Send one or the other, never
/// both.
#[derive(Serialize, schemars::JsonSchema)]
struct FileParamEntry {
    /// Dotted path of the text field, e.g. `content` or `config.instructions`.
    field: String,
    /// Dotted path to put the gateway file URI at instead, e.g. `content_file`.
    upload_field: String,
    /// What the uploaded file must contain.
    content: String,
    /// URI prefix of an acceptable value: the file must be one this gateway
    /// stored for you (upload it with `gateway-files.prepare_upload`). The
    /// gateway never fetches a URL you supply.
    uri_prefix: String,
}

/// Render a JSON pointer as the dotted path a caller writes in `params`.
fn field_path(pointer: &str) -> String {
    pointer.trim_start_matches('/').replace('/', ".")
}

#[derive(Serialize, schemars::JsonSchema)]
struct ActionContextEntry {
    /// Fully-qualified read tool to call before proposing.
    tool: String,
    /// What state the context returns and why this action needs it.
    description: String,
    /// Exact JSON Schema for `get_action_context.selector`.
    selector_schema: Value,
    /// Worked selector object that validates against `selector_schema`.
    selector_example: Value,
}

/// Response shape for `describe_action`: **always** a list of [`ActionEntry`] —
/// the full catalog with no args, or a single-element list when `action_type`
/// is supplied. Uniform on purpose so a client parses one shape regardless of
/// the filter (the earlier bare-object single-action shape was polymorphic and
/// couldn't carry one clean `output_schema`).
#[derive(Serialize, schemars::JsonSchema)]
struct DescribeActionResponse {
    actions: Vec<ActionEntry>,
}

/// Response shape for `preview_change`: proposal-equivalent validation, the
/// approval bar, and any existing policy/manifest effect preview, without
/// anything being queued.
#[derive(Serialize, schemars::JsonSchema)]
struct PreviewResponse {
    /// The action that was previewed.
    action_type: String,
    /// `true` means the params satisfy the action schema and its current-state
    /// proposal check at the instant of this preview. Proposal capture and
    /// execution recheck freshness.
    valid: bool,
    /// Schema or current-state violations to fix — empty when `valid` is true.
    /// Schema messages are payload-safe (paths and rules, never the value).
    errors: Vec<String>,
    /// Distinct human approvals the change will require.
    required_approvals: i32,
    /// The role whose members may approve.
    eligible_role: String,
    /// Extra factors each approver must present (empty ⇒ dashboard session only).
    factors: Vec<String>,
    /// Optional notified cooldown (seconds) before execute, when set.
    cooldown_seconds: Option<i32>,
    /// The action's params JSON Schema — the same one `describe_action` serves.
    params_schema: Value,
    /// Valid worked params for state-dependent policy/manifest actions.
    params_example: Option<Value>,
    /// Current policy/manifest effect computed by the same helpers as the human
    /// review queue. `null` for other action families or when schema validation
    /// failed before current state could be read.
    effect: Option<waygate_admin::change_effect_preview::ChangeEffectPreview>,
}

impl PreviewResponse {
    fn from_action_preview(
        p: waygate_admin::change_executor::ActionPreview,
        effect: Option<waygate_admin::change_effect_preview::ChangeEffectPreview>,
    ) -> Self {
        let params_example = waygate_admin::change_context::context_descriptor(&p.action_type)
            .map(|descriptor| descriptor.params_example);
        Self {
            action_type: p.action_type,
            valid: p.valid,
            errors: p.errors,
            required_approvals: p.required_approvals,
            eligible_role: p.eligible_role,
            factors: p.factors,
            cooldown_seconds: p.cooldown_seconds,
            params_schema: p.params_schema,
            params_example,
            effect,
        }
    }
}

fn propose_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "required": ["action_type", "params", "justification"],
        "properties": {
            "action_type": {
                "type": "string",
                "description": "Registry key for the action, e.g. `rate_limit.update`. Only \
                    registered, executable actions are proposable; an unknown key is rejected \
                    with the list of proposable actions.",
            },
            "params": {
                "type": "object",
                "description": "The captured intent the executor replays on approval. The shape \
                    is specific to each `action_type` and is validated against the action's JSON \
                    Schema at propose time — call `describe_action` for that schema.",
            },
            "justification": {
                "type": "string",
                "description": "Why the change is needed — shown to the human approver and \
                    recorded in the audit log.",
            },
            "ttl_seconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": 86400,
                "description": "How long the request waits for a decision before expiring. \
                    Default 900 (15m), max 86400 (24h).",
            },
        },
    }))
}

fn describe_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "properties": {
            "action_type": {
                "type": "string",
                "description": "Registry key of the action whose params schema you want, e.g. \
                    `rate_limit.update` or `api_key.mint`. Omit to get the full catalog — every \
                    proposable action paired with its params schema.",
            },
        },
    }))
}

fn preview_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "required": ["action_type"],
        "properties": {
            "action_type": {
                "type": "string",
                "description": "Registry key of the action to dry-run, e.g. `rate_limit.update`. \
                    Call `describe_action` for the full set of proposable actions.",
            },
            "params": {
                "type": "object",
                "description": "The params object you intend to pass to `propose_change`. \
                    Validated against the action's schema and current target. For state-dependent \
                    actions, obtain required selectors and freshness witnesses from the \
                    `get_action_context` contract advertised by `describe_action`. Omit only when \
                    inspecting an action whose params schema allows an empty object.",
            },
        },
    }))
}

fn status_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "required": ["id"],
        "properties": {
            "id": {
                "type": "string",
                "description": "The change_request_id returned by propose_change (the CIBA \
                    auth_req_id).",
            },
        },
    }))
}

fn list_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "properties": {
            "lifecycle": {
                "type": "string",
                "enum": ["pending", "expired", "decided"],
                "description": "Optional bucket filter.",
            },
            "limit": {"type": "integer", "minimum": 1, "description": "Max rows (default 50)."},
            "offset": {"type": "integer", "minimum": 0, "description": "Pagination offset."},
        },
    }))
}

pub(crate) fn schema_obj(v: Value) -> Arc<JsonObject> {
    Arc::new(v.as_object().cloned().expect("schema literal is an object"))
}

fn parse_id_arg(args: &JsonObject) -> Result<Uuid, McpError> {
    let raw = args
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::invalid_params("missing required string field `id`", None))?;
    Uuid::parse_str(raw.trim())
        .map_err(|_| McpError::invalid_params(format!("`id` is not a valid uuid: {raw}"), None))
}

fn unknown_action(action_type: &str) -> McpError {
    let valid = registry().action_types().join(", ");
    McpError::invalid_params(
        format!("unknown action_type {action_type:?}; proposable actions: {valid}"),
        None,
    )
}

/// Parse the optional `list_my_changes` args. An ABSENT key takes the default
/// (mirroring the REST `ListQuery` serde defaults: limit 50, offset 0, no
/// lifecycle filter), but a key that is PRESENT with the wrong JSON type is
/// rejected with `invalid_params` rather than silently defaulted — so the MCP
/// path validates as strictly as the REST `Query<ListQuery>` deserializer
/// (e.g. `{"lifecycle":123}` must error, not list everything unfiltered).
/// The lifecycle *value* is still validated by
/// `list_core`'s `parse_lifecycle` (pending|expired|decided).
fn parse_list_args(args: &JsonObject) -> Result<(u32, u32, Option<String>), McpError> {
    let limit = parse_opt_u32(args, "limit")?.unwrap_or(50);
    let offset = parse_opt_u32(args, "offset")?.unwrap_or(0);
    let lifecycle = match args.get("lifecycle") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            return Err(McpError::invalid_params(
                "`lifecycle` must be a string (pending|expired|decided)",
                None,
            ))
        }
    };
    Ok((limit, offset, lifecycle))
}

pub(crate) fn parse_opt_u32(args: &JsonObject, key: &str) -> Result<Option<u32>, McpError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| {
                McpError::invalid_params(format!("`{key}` must be a non-negative integer"), None)
            }),
    }
}

/// Structured insufficient-scope error mirroring the dispatch path's step-up
/// shape, so an MCP client can detect it programmatically (the `data`
/// envelope) and re-authorize for `mcp:propose`.
fn insufficient_scope() -> McpError {
    let data = json!({
        "error": "insufficient_scope",
        "required_scope": Scope::McpPropose.as_str(),
        "reason": "the gateway-admin namespace requires the mcp:propose maker scope",
    });
    McpError::new(
        ErrorCode::INVALID_REQUEST,
        format!(
            "step-up required (scope `{}`): the gateway-admin namespace requires mcp:propose",
            Scope::McpPropose.as_str()
        ),
        Some(data),
    )
}

/// Map the admin [`ApiError`] to the MCP wire shape: 4xx-class errors surface
/// their (client-fixable) detail as `invalid_params`; 5xx-class collapse to
/// `internal_error`.
pub(crate) fn api_to_mcp(e: ApiError) -> McpError {
    use ApiError::*;
    match e {
        BadRequest(d)
        | UnprocessableEntity(d)
        | Conflict(d)
        | NotFoundDyn(d)
        | ForbiddenDyn(d)
        | PayloadTooLarge(d) => McpError::invalid_params(d, None),
        NotFound(d) | Unauthorized(d) | Forbidden(d) => {
            McpError::invalid_params(d.to_string(), None)
        }
        ServiceUnavailable(d) => McpError::internal_error(d.to_string(), None),
        BadGateway(d) | InternalOperatorVisible(d) | Internal(d) => {
            McpError::internal_error(d, None)
        }
    }
}

pub(crate) fn structured<T: Serialize>(v: &T) -> CallToolResult {
    CallToolResult::structured(serde_json::to_value(v).unwrap_or_else(|_| json!({})))
}

fn structured_with_text<T: Serialize>(v: &T, text: String) -> CallToolResult {
    let mut r = CallToolResult::success(vec![Content::text(text)]);
    r.structured_content = Some(serde_json::to_value(v).unwrap_or_else(|_| json!({})));
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use time::{Duration, OffsetDateTime};
    use waygate_as::UpstreamCrypto;
    use waygate_changeset::{ApprovalRequirement, InMemoryChangeRequestStore, NewChangeRequest};
    use waygate_mcp::audit::InMemorySink;
    use waygate_oidc::AuthMethod;
    use waygate_upstream::pool::UpstreamPool;

    struct DenyPreviewQuota;

    #[async_trait]
    impl waygate_quota::QuotaService for DenyPreviewQuota {
        async fn check_and_consume(
            &self,
            context: &waygate_quota::QuotaContext,
            actions: &[waygate_quota::QuotaAction],
        ) -> Result<(), waygate_quota::QuotaError> {
            assert_eq!(context.tenant_id, waygate_core::TenantId::DEFAULT);
            assert_eq!(context.server, NAMESPACE);
            assert_eq!(context.fq_tool, "gateway-admin.preview_change");
            assert_eq!(actions, &[waygate_quota::QuotaAction::Call]);
            Err(waygate_quota::QuotaError::RateLimited {
                policy_id: Uuid::nil(),
                name: "preview budget".to_owned(),
                retry_after_seconds: 7,
            })
        }
    }

    #[test]
    fn surface_descriptor_matches_served_tools() {
        let prefix = format!("{NAMESPACE}.");
        let served: Vec<String> = tool_defs()
            .into_iter()
            .map(|t| t.name.as_ref().strip_prefix(&prefix).unwrap().to_owned())
            .collect();
        let d = surface_descriptor();
        let described: Vec<String> = d.tools.iter().map(|t| t.name.clone()).collect();
        assert_eq!(described, served);
        assert_eq!(d.namespace, NAMESPACE);
        assert_eq!(d.required_scope, Scope::McpPropose.as_str());
        // propose_change has a side effect (queues a change); the pollers don't.
        let propose = d.tools.iter().find(|t| t.name == "propose_change").unwrap();
        assert!(propose.side_effects && propose.risk == RiskTier::Medium);
        // PII classification feeds the dispatch-time Cedar `resource.pii`
        // attribute, so it must be exact: the two pollers return the approver
        // identity (StatusResponse.approver); propose_change returns none.
        let pii_of = |n: &str| d.tools.iter().find(|t| t.name == n).unwrap().pii;
        assert!(
            pii_of("get_change_status"),
            "status poll returns approver identity"
        );
        assert!(pii_of("list_my_changes"), "list returns approver identity");
        assert!(
            !pii_of("propose_change"),
            "propose returns only a binding code + URLs"
        );
        // get_change_secret burns + discloses a one-time secret: a side effect
        // (Medium, NOT High — see surface_descriptor's comment for why a
        // step-up-mapped High tier would break MCP retrieval) and a live
        // credential, so PII.
        let secret = d
            .tools
            .iter()
            .find(|t| t.name == "get_change_secret")
            .unwrap();
        assert!(secret.side_effects && secret.risk == RiskTier::Medium);
        assert!(
            pii_of("get_change_secret"),
            "reveal returns a live credential"
        );
        // describe_action is a pure read of the static params catalog — it must
        // stay Low / no-side-effect / no-PII, or it'd be gated like a mutation
        // (or mapped to a step-up factor a propose-only agent can't satisfy),
        // defeating the discovery path it exists to provide.
        let describe = d
            .tools
            .iter()
            .find(|t| t.name == "describe_action")
            .unwrap();
        assert!(!describe.side_effects && describe.risk == RiskTier::Low);
        assert!(
            !pii_of("describe_action"),
            "catalog schemas carry no identity"
        );
        // preview_change is a read-only dry-run — Low and no side effect, so it
        // isn't gated like a mutation or mapped to a step-up factor a
        // propose-only agent can't satisfy. Its bounded policy/manifest impact
        // samples can name principals from audit history, so it is PII.
        let preview = d.tools.iter().find(|t| t.name == "preview_change").unwrap();
        assert!(!preview.side_effects && preview.risk == RiskTier::Low);
        assert!(
            pii_of("preview_change"),
            "effect replay samples can carry principal identities"
        );
        // get_action_context is the read side of policy/manifest proposal
        // preparation. It never queues a change, but exact Cedar statements
        // may name principals, so it is PII-classified. Manifest credential
        // references remain unresolved, and recognized inline credential
        // literals are refused.
        let context = d
            .tools
            .iter()
            .find(|t| t.name == "get_action_context")
            .unwrap();
        assert!(!context.side_effects && context.risk == RiskTier::Low);
        assert!(pii_of("get_action_context"), "Cedar can name principals");
    }

    #[test]
    fn admin_tools_advertise_title_output_schema_and_annotations() {
        let defs = tool_defs();
        let by_suffix = |s: &str| {
            defs.iter()
                .find(|t| t.name.ends_with(s))
                .unwrap_or_else(|| panic!("no tool ending in {s}"))
        };
        // Every tool carries a human-readable title (SOP point 5).
        for t in &defs {
            assert!(t.title.is_some(), "{} missing title", t.name);
        }
        // Every tool advertises an output schema (SOP point 4) — including
        // describe_action, whose catalog response is now the typed
        // `DescribeActionResponse` rather than ad-hoc JSON.
        for s in [
            ".propose_change",
            ".describe_action",
            ".preview_change",
            ".get_change_status",
            ".get_change_secret",
            ".list_my_changes",
            ".get_action_context",
        ] {
            assert!(
                by_suffix(s).output_schema.is_some(),
                "{s} should advertise an output_schema"
            );
        }
        // Behavioral hints: pollers/catalog are read-only; get_change_secret
        // burns the secret (destructive); propose_change is a non-read write.
        let read_only = |s: &str| {
            by_suffix(s)
                .annotations
                .as_ref()
                .and_then(|a| a.read_only_hint)
        };
        assert_eq!(read_only(".get_change_status"), Some(true));
        assert_eq!(read_only(".describe_action"), Some(true));
        assert_eq!(read_only(".preview_change"), Some(true));
        assert_eq!(read_only(".get_action_context"), Some(true));
        assert_eq!(read_only(".propose_change"), Some(false));
        let context_input = &by_suffix(".get_action_context").input_schema;
        assert_eq!(
            context_input["required"],
            json!(["action_type"]),
            "typed input schema requires the action discriminator",
        );
        assert!(
            context_input["properties"]["action_type"]["description"].is_string()
                && context_input["properties"]["selector"]["description"].is_string(),
            "typed input schema documents both wire fields",
        );
        let status_description = by_suffix(".get_change_status")
            .description
            .as_deref()
            .expect("get_change_status description");
        assert!(status_description.contains("execution_result.secret_available: true"));
        assert!(status_description.contains("historical statement"));
        assert!(status_description.contains("not proof that it remains retrievable"));

        let secret_description = by_suffix(".get_change_secret")
            .description
            .as_deref()
            .expect("get_change_secret description");
        assert!(secret_description.contains("CallToolResult.structuredContent.secret"));
        assert!(secret_description.contains(
            "CallToolResult.content` contains only a non-secret burn notice, not serialized output"
        ));
        assert_eq!(
            by_suffix(".get_change_secret")
                .annotations
                .as_ref()
                .and_then(|a| a.destructive_hint),
            Some(true),
            "retrieving the one-time secret burns it"
        );
    }

    #[test]
    fn proposal_tool_descriptions_teach_copy_not_compute_flow() {
        let defs = tool_defs();
        let description = |suffix: &str| {
            defs.iter()
                .find(|tool| tool.name.ends_with(suffix))
                .and_then(|tool| tool.description.as_deref())
                .unwrap_or_else(|| panic!("{suffix} should advertise a description"))
        };

        let propose = description(".propose_change");
        for step in [
            "`describe_action`",
            "`get_action_context`",
            "`preview_change`",
            "`get_change_status`",
        ] {
            assert!(
                propose.contains(step),
                "propose_change should name workflow step {step}"
            );
        }
        assert!(
            propose.contains("Copy gateway-returned hashes; never calculate them"),
            "propose_change should reject client-side witness calculation"
        );

        let context = description(".get_action_context");
        assert!(context.contains("Copy returned hashes or versions verbatim"));
        assert!(context.contains("preserve its complete returned manifest"));

        let preview = description(".preview_change");
        for instruction in [
            "64 zeroes",
            "Every candidate annotation server",
            "exactly one observed row with `connected: true`",
            "nonempty `tools`",
            "empty `draft_only`",
            "each non-null",
            "effect.observed[].tools[].observed_behavior_hash",
            "`approved_behavior_hash`",
            "`draft_status` is `match`",
            "every `would_quarantine` is empty",
            "Otherwise stop",
        ] {
            assert!(
                preview.contains(instruction),
                "preview_change should teach annotation-hash step {instruction}"
            );
        }
    }

    #[test]
    fn admin_output_schemas_validate_sample_content() {
        // The cross-namespace mirror of observe/control's
        // `*_output_schemas_validate_sample_content`: a sample of each typed admin
        // response serializes and validates against its derived `output_schema`,
        // pinning serde↔schemars agreement for the propose / poll / secret / list
        // DTOs that `admin_tools_advertise_…` only checks for *presence*.
        // describe_action's response is already content-validated in
        // `describe_action_serves_catalog_and_single_action`; this covers the
        // other four so every admin tool's result shape is pinned, not just named.
        fn assert_validates<T: Serialize + schemars::JsonSchema>(sample: &T) {
            let schema = serde_json::to_value(schemars::schema_for!(T)).expect("schema serializes");
            let validator = jsonschema::validator_for(&schema).expect("output_schema compiles");
            let instance = serde_json::to_value(sample).expect("sample serializes");
            let errors: Vec<String> = validator
                .iter_errors(&instance)
                .map(|e| e.to_string())
                .collect();
            assert!(
                errors.is_empty(),
                "sample does not validate against its own output_schema: {errors:?}"
            );
        }

        let id = Uuid::nil();
        assert_validates(&ProposeResponse {
            change_request_id: id,
            status: "pending".to_owned(),
            binding_code: "AMBER-OTTER".to_owned(),
            expires_in: 900,
            interval: 5,
            approval_url: "https://gw.example/approve/x".to_owned(),
            poll_url: "https://gw.example/poll/x".to_owned(),
        });
        // Populate the optional arms (approver / execution_result) so the schema's
        // nullable fields are exercised, not skipped.
        let status = StatusResponse {
            change_request_id: id,
            status: "executed".to_owned(),
            binding_code: "AMBER-OTTER".to_owned(),
            action_type: "rate_limit.update".to_owned(),
            expires_at: "2026-06-27T00:00:00Z".to_owned(),
            interval: 5,
            approver: Some("alice".to_owned()),
            denied_reason: None,
            execution_result: Some(json!({"ok": true})),
            error_message: None,
            approval_url: "https://gw.example/approve/x".to_owned(),
        };
        assert_validates(&status);
        assert_validates(&SecretResponse {
            secret: "mcpgw_redacted".to_owned(),
        });
        // ListResponse nests StatusResponse, so this also exercises the item schema.
        assert_validates(&ListResponse {
            requests: vec![status],
            limit: 50,
            offset: 0,
        });
        // preview_change's dry-run result: populate errors + factors so the
        // nested array schemas (and the Option) are exercised, not skipped.
        assert_validates(&PreviewResponse {
            action_type: "rate_limit.update".to_owned(),
            valid: false,
            errors: vec!["\"policy_id\" is a required property".to_owned()],
            required_approvals: 1,
            eligible_role: "dashboard-admins".to_owned(),
            factors: vec!["passkey".to_owned()],
            cooldown_seconds: Some(60),
            params_schema: json!({"type": "object"}),
            params_example: None,
            effect: Some(
                waygate_admin::change_effect_preview::ChangeEffectPreview::Policy {
                    action: "Publish policy draft".to_owned(),
                    compile_status:
                        waygate_admin::change_effect_preview::PolicyCompileStatus::Error,
                    compile_error: Some("candidate does not parse".to_owned()),
                    tests: None,
                    impact: None,
                    note: None,
                    blocked: Some("candidate cannot execute".to_owned()),
                },
            ),
        });
        // A manifest effect carrying a POPULATED observed-contracts section:
        // the empty case is omitted by `skip_serializing_if`, so only this
        // shape exercises the nested per-tool schema against the advertised
        // output contract.
        assert_validates(&PreviewResponse {
            action_type: "manifest.stage_and_publish".to_owned(),
            valid: true,
            errors: Vec::new(),
            required_approvals: 1,
            eligible_role: "dashboard-admins".to_owned(),
            factors: Vec::new(),
            cooldown_seconds: None,
            params_schema: json!({"type": "object"}),
            params_example: None,
            effect: Some(
                waygate_admin::change_effect_preview::ChangeEffectPreview::Manifest {
                    action: "Publish manifest set".to_owned(),
                    effective: Some(
                        waygate_admin::manifest_effect::ManifestEffectiveImpact {
                            capability_change:
                                waygate_admin::manifest_effect::CapabilityChange::Expands,
                            activation_readiness:
                                waygate_admin::manifest_effect::ActivationReadiness::BlockedAfterChange,
                            tools: waygate_admin::manifest_effect::ToolCapabilitySummary {
                                added: 1,
                                removed: 0,
                                reclassified: 0,
                                added_side_effecting: 1,
                                added_pii: 0,
                                added_high_risk: 0,
                                approval_relaxed_servers: 0,
                                approval_tightened_servers: 0,
                                approval_relaxed_manifest_tools: 0,
                                approval_tightened_manifest_tools: 0,
                            },
                            resources:
                                waygate_admin::manifest_effect::ResourceCapabilitySummary {
                                    added: 0,
                                    removed: 0,
                                    reclassified: 0,
                                    added_high_risk: 0,
                                },
                            servers: vec![
                                waygate_admin::manifest_effect::ServerEffectiveImpact {
                                    server: "komodo".to_owned(),
                                    manifest_change:
                                        waygate_admin::manifest_effect::ManifestServerChange::Added,
                                    runtime_effect:
                                        waygate_admin::manifest_effect::RuntimeEffect::RegisterAndConnect,
                                    connected_before: None,
                                    catalog_before:
                                        waygate_admin::manifest_effect::CatalogLifecycle::Quarantined,
                                    catalog_after:
                                        waygate_admin::manifest_effect::CatalogLifecycle::Quarantined,
                                    drift_quarantined_before: 0,
                                    drift_quarantined_after_at_least: 0,
                                    readiness:
                                        waygate_admin::manifest_effect::ActivationReadiness::BlockedAfterChange,
                                    barriers: vec![
                                        waygate_admin::manifest_effect::AvailabilityBarrier::CatalogLifecycle {
                                            status: waygate_admin::manifest_effect::CatalogLifecycle::Quarantined,
                                        },
                                    ],
                                },
                            ],
                            follow_up_actions: vec![
                                waygate_admin::manifest_effect::FollowUpAction {
                                    server: "komodo".to_owned(),
                                    kind: waygate_admin::manifest_effect::FollowUpKind::PromoteCatalogServer,
                                },
                            ],
                            fleet_activation_asynchronous: true,
                        },
                    ),
                    impact: None,
                    observed: vec![
                        waygate_admin::manifest_change_preview::ObservedServerContracts {
                            server: "komodo".to_owned(),
                            connected: true,
                            note: None,
                            tools: vec![
                                waygate_admin::manifest_change_preview::ObservedToolStatus {
                                    name: "deployments_deploy".to_owned(),
                                    observed_behavior_hash: Some("a".repeat(64)),
                                    draft_status:
                                        waygate_admin::manifest_change_preview::DraftHashStatus::Mismatch,
                                    metadata_error: None,
                                },
                            ],
                            draft_only: vec!["retired_tool".to_owned()],
                            would_quarantine: vec!["deployments_deploy".to_owned()],
                        },
                    ],
                    note: None,
                    blocked: None,
                },
            ),
        });
    }

    fn tools() -> ChangeProposalTools {
        let store: SharedChangeRequestStore = Arc::new(InMemoryChangeRequestStore::new());
        let evidence: SharedEvidence = Arc::new(InMemorySink::new());
        // Empty AdminState cell: these tests exercise the propose/list/status
        // mechanics, not the freshness capture (which no-ops when unset).
        ChangeProposalTools::new(
            store,
            evidence,
            "https://gw.example".into(),
            None,
            None,
            Arc::new(OnceLock::new()),
        )
    }

    /// Build an `AdminState` whose change-request store already holds an
    /// `executed`, secret-bearing change for `maker` — the exact state a
    /// successful `api_key.mint` execute-on-approval leaves behind — wired with
    /// a real secret-crypto keyring so the burn-on-read reveal can be exercised
    /// without Postgres. Drives the change to `executed` via the public store
    /// methods (propose → eligible approval → claim → store ciphertext → mark
    /// executed), mirroring `waygate-admin`'s `executed_with_secret` helper.
    async fn state_with_secret_change(maker: &str, secret: &[u8]) -> (Arc<AdminState>, Uuid) {
        let store: SharedChangeRequestStore = Arc::new(InMemoryChangeRequestStore::new());
        let crypto = UpstreamCrypto::from_key_bytes([7u8; 32]);
        let tenant = waygate_core::TenantId::default();
        let t = tenant.as_str();
        let cr = store
            .propose(NewChangeRequest {
                tenant_id: t.to_owned(),
                requested_by: maker.to_owned(),
                client_id: None,
                action_type: "api_key.mint".into(),
                params: json!({}),
                preview: None,
                target_etag: None,
                justification: "provision a least-privilege triage key".into(),
                requirement: ApprovalRequirement::single("dashboard-admins"),
                expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            })
            .await
            .unwrap();
        // An eligible operator approves → claim → store encrypted
        // secret → mark executed.
        store
            .try_approve(t, cr.id, "operator")
            .await
            .unwrap()
            .unwrap();
        store.try_begin_execution(t, cr.id).await.unwrap().unwrap();
        let ct = crypto.encrypt(secret).unwrap();
        store
            .store_secret(t, cr.id, &ct, crypto.active_id())
            .await
            .unwrap();
        store
            .mark_executed(
                t,
                cr.id,
                json!({ "key_prefix": "mcpgw_AB", "secret_available": true }),
            )
            .await
            .unwrap()
            .unwrap();

        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let evidence: SharedEvidence = Arc::new(InMemorySink::new());
        let state = Arc::new(
            AdminState::new(
                pool,
                None,
                None,
                evidence,
                None,
                None,
                None,
                None,
                "https://gw.example".into(),
            )
            .with_change_request_store(Some(store))
            .with_change_secret_crypto(Some(crypto)),
        );
        (state, cr.id)
    }

    /// A `ChangeProposalTools` with the deferred `AdminState` cell filled — the
    /// reveal path (`get_change_secret`) reads the secret-crypto keyring + store
    /// from there, not from `self.store`, so the `self.store` here is a throwaway.
    fn tools_with_state(state: Arc<AdminState>) -> ChangeProposalTools {
        let store: SharedChangeRequestStore = Arc::new(InMemoryChangeRequestStore::new());
        let evidence: SharedEvidence = Arc::new(InMemorySink::new());
        let cell = Arc::new(OnceLock::new());
        // `OnceLock::set` returns Err(value) if already set; the Err carries
        // `Arc<AdminState>` (not Debug), so assert on `is_ok()` rather than
        // `.expect()`. The cell is freshly created, so this always succeeds.
        assert!(cell.set(state).is_ok(), "admin_state cell starts empty");
        ChangeProposalTools::new(
            store,
            evidence,
            "https://gw.example".into(),
            None,
            None,
            cell,
        )
    }

    fn principal(scopes: &[&str]) -> Principal {
        Principal {
            sub: "agent-1".into(),
            email: None,
            groups: vec![],
            issuer: "local-test".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn propose_args() -> JsonObject {
        json!({
            "action_type": "rate_limit.update",
            // Valid rate_limit.update params (params are validated at
            // propose; the field is `policy_id`, not `id`).
            "params": {"policy_id": "00000000-0000-0000-0000-000000000000", "bucket_capacity": 100},
            "justification": "raise the billing cap for the launch",
        })
        .as_object()
        .cloned()
        .unwrap()
    }

    #[tokio::test]
    async fn describe_action_serves_catalog_and_single_action() {
        let t = tools();
        let maker = principal(&["mcp:propose"]);

        // No args ⇒ full catalog: every proposable action with a params schema.
        let all = t
            .call("describe_action", Some(JsonObject::new()), Some(&maker))
            .await
            .expect("describe_action (all)");
        let all_body = all.structured_content.unwrap();
        // The real response validates against the advertised output_schema (SOP):
        // pins the typed `DescribeActionResponse` the tool serializes against the
        // schema clients read from tools/list — not just that a schema exists.
        let schema = serde_json::to_value(schemars::schema_for!(DescribeActionResponse)).unwrap();
        let validator = jsonschema::validator_for(&schema).expect("output_schema compiles");
        assert!(
            validator.iter_errors(&all_body).next().is_none(),
            "catalog response must validate against the DescribeActionResponse schema",
        );
        let actions = all_body["actions"].as_array().unwrap().clone();
        assert!(
            actions.iter().any(|a| a["action_type"] == "api_key.mint"),
            "catalog should list api_key.mint",
        );
        assert!(
            actions
                .iter()
                .all(|a| a["params_schema"]["type"] == "object"),
            "every catalog entry carries an object params schema",
        );
        let manifest = actions
            .iter()
            .find(|a| a["action_type"] == "manifest.upsert_servers")
            .expect("manifest upsert action");
        assert_eq!(
            manifest["context"]["tool"],
            "gateway-admin.get_action_context"
        );
        assert_eq!(
            manifest["context"]["selector_schema"]["type"], "object",
            "context selector must be usable from the wire surface",
        );
        assert_eq!(
            manifest["context"]["selector_example"]["server_name"], "example-messages",
            "context discovery must teach a complete selector call",
        );
        assert_eq!(
            manifest["params_example"]["base_hash"], "copy context.base_hash here",
            "stateful action discovery must teach how context feeds proposal params",
        );
        // Discovery must be enough to build the upload call: which text field
        // the document replaces, which key carries the URI, and what a valid
        // URI looks like. The key is deliberately absent from `params_schema`
        // (the gateway substitutes the text before the params are stored), so
        // this row is the only place a client can learn it exists.
        let upload = manifest["file_params"]
            .as_array()
            .and_then(|specs| specs.first())
            .expect("manifest upsert must advertise its uploadable document");
        assert_eq!(upload["field"], "content");
        assert_eq!(upload["upload_field"], "content_file");
        assert_eq!(upload["uri_prefix"], waygate_core::GATEWAY_FILE_URI_PREFIX);
        assert!(
            manifest["params_schema"]["properties"]
                .get("content_file")
                .is_none(),
            "the submission-only key must not appear in the stored-params schema",
        );
        let scalar = actions
            .iter()
            .find(|a| a["action_type"] == "manifest.rollback")
            .expect("manifest rollback action");
        assert_eq!(
            scalar["file_params"],
            json!([]),
            "an action with no document field advertises no upload path",
        );
        let params_validator = jsonschema::validator_for(&manifest["params_schema"])
            .expect("manifest params schema compiles");
        assert!(
            params_validator.is_valid(&manifest["params_example"]),
            "registry-owned worked params must validate against the advertised schema",
        );
        assert!(
            manifest["params_schema"]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|name| name == "base_hash")),
            "state-replacement params must require the context witness",
        );
        let removal = actions
            .iter()
            .find(|a| a["action_type"] == "manifest.remove_servers")
            .expect("manifest removal action");
        assert_eq!(
            removal["params_example"]["server_names"],
            json!(["example-messages"]),
            "wire discovery must teach selected-name removal without full-set reconstruction",
        );
        let removal_validator = jsonschema::validator_for(&removal["params_schema"])
            .expect("manifest removal params schema compiles");
        assert!(
            removal_validator.is_valid(&removal["params_example"]),
            "manifest removal worked params must validate against its advertised schema",
        );
        let base_hash_description = manifest["params_schema"]["properties"]["base_hash"]
            ["description"]
            .as_str()
            .expect("base_hash description");
        let normalized_base_hash_description = base_hash_description
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            normalized_base_hash_description.contains("get_action_context")
                && normalized_base_hash_description.contains("Copy it verbatim")
                && normalized_base_hash_description.contains("never calculate it"),
            "the wire schema must teach where the witness comes from and forbid computing it; \
             got: {base_hash_description}",
        );
        let content_description = manifest["params_schema"]["properties"]["content"]["description"]
            .as_str()
            .expect("content description");
        let normalized_content_description = content_description
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            normalized_content_description.contains("complete upstream manifests")
                && normalized_content_description.contains("not a tool fragment"),
            "the wire schema must require complete server entries for manifest upserts; got: \
             {content_description}",
        );

        // action_type ⇒ a single-element `actions` list (the uniform shape),
        // carrying that one action's schema reflecting its real fields.
        let one = t
            .call(
                "describe_action",
                Some(
                    json!({"action_type": "api_key.mint"})
                        .as_object()
                        .cloned()
                        .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect("describe_action (one)");
        let body = one.structured_content.unwrap();
        let filtered = body["actions"].as_array().expect("actions array");
        assert_eq!(
            filtered.len(),
            1,
            "action_type filters to exactly one entry"
        );
        assert_eq!(filtered[0]["action_type"], "api_key.mint");
        assert!(
            filtered[0]["params_schema"]["properties"]["scopes"].is_object(),
            "schema reflects the ApiKeyMintParams.scopes field",
        );
        assert!(
            filtered[0]["context"].is_null(),
            "actions without preparation state say so explicitly",
        );

        // Unknown action_type teaches the valid set instead of failing blankly.
        let err = t
            .call(
                "describe_action",
                Some(
                    json!({"action_type": "nope.nonexistent"})
                        .as_object()
                        .cloned()
                        .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect_err("unknown action_type is an error");
        assert!(
            err.message.contains("proposable actions"),
            "error should list the valid actions: {}",
            err.message,
        );
    }

    #[tokio::test]
    async fn list_tools_gated_on_propose_scope() {
        let t = tools();
        assert!(t.list_tools(None).await.is_empty());
        assert!(t
            .list_tools(Some(&principal(&["mcp:read"])))
            .await
            .is_empty());
        let maker = principal(&["mcp:propose"]);
        let names: Vec<String> = t
            .list_tools(Some(&maker))
            .await
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "gateway-admin.propose_change",
                "gateway-admin.describe_action",
                "gateway-admin.get_action_context",
                "gateway-admin.preview_change",
                "gateway-admin.get_change_status",
                "gateway-admin.get_change_secret",
                "gateway-admin.list_my_changes",
            ]
        );
    }

    #[tokio::test]
    async fn preview_change_consumes_the_existing_call_quota() {
        let store: SharedChangeRequestStore = Arc::new(InMemoryChangeRequestStore::new());
        let evidence: SharedEvidence = Arc::new(InMemorySink::new());
        let tools = ChangeProposalTools::new(
            store,
            evidence,
            "https://gw.example".into(),
            None,
            Some(Arc::new(DenyPreviewQuota)),
            Arc::new(OnceLock::new()),
        );
        let maker = principal(&["mcp:propose"]);
        let error = tools
            .call(
                "preview_change",
                Some(
                    json!({
                        "action_type": "rate_limit.update",
                        "params": {
                            "policy_id": Uuid::nil(),
                            "bucket_capacity": 10
                        }
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect_err("configured call quota denies preview before stateful work");
        assert_eq!(
            error
                .data
                .as_ref()
                .and_then(|data| data.get("error"))
                .and_then(Value::as_str),
            Some("rate_limited")
        );
        assert_eq!(
            error
                .data
                .as_ref()
                .and_then(|data| data.get("retry_after_seconds")),
            Some(&json!(7))
        );
    }

    #[tokio::test]
    async fn action_context_returns_complete_live_manifest_selected_from_wire() {
        let dir = std::env::temp_dir().join(format!("mcp-action-context-{}", Uuid::new_v4()));
        let manifests = waygate_upstream::parse_manifest_set(
            "- name: alpha\n  transport: http\n  url: http://alpha.example/mcp\n",
        )
        .expect("fixture manifest parses");
        waygate_upstream::write_manifest_set_to_dir(&dir, &manifests)
            .expect("fixture manifest directory writes");

        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let evidence: SharedEvidence = Arc::new(InMemorySink::new());
        let state = Arc::new(
            AdminState::new(
                pool,
                None,
                None,
                evidence,
                None,
                None,
                None,
                None,
                "https://gw.example".into(),
            )
            .with_servers_dir(dir.clone()),
        );
        let t = tools_with_state(state);
        let maker = principal(&["mcp:propose"]);

        let result = t
            .call(
                "get_action_context",
                Some(
                    json!({
                        "action_type": "manifest.upsert_servers",
                        "selector": {"server_name": "alpha"}
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect("manifest context read succeeds");
        let body = result.structured_content.expect("structured context");
        let schema = serde_json::to_value(schemars::schema_for!(
            waygate_admin::change_context::ActionContextResponse
        ))
        .expect("context output schema serializes");
        let validator = jsonschema::validator_for(&schema).expect("context output schema compiles");
        assert!(
            validator.iter_errors(&body).next().is_none(),
            "manifest context validates against the advertised output schema",
        );
        assert_eq!(body["action_type"], "manifest.upsert_servers");
        assert_eq!(body["context"]["kind"], "live_manifests");
        assert_eq!(body["context"]["source"], "live_disk");
        assert_eq!(body["context"]["selected"]["name"], "alpha");
        assert_eq!(
            body["context"]["selected"]["url"],
            "http://alpha.example/mcp"
        );
        let prepared_base = body["context"]["base_hash"]
            .as_str()
            .expect("context includes base_hash")
            .to_owned();
        assert!(
            !prepared_base.is_empty(),
            "response binds the selected manifest to the complete live set",
        );

        let candidate = "- name: alpha\n  transport: http\n  url: http://proposed.example/mcp\n";
        let preview = t
            .call(
                "preview_change",
                Some(
                    json!({
                        "action_type": "manifest.upsert_servers",
                        "params": {
                            "base_hash": prepared_base.clone(),
                            "content": candidate
                        }
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect("fresh manifest candidate previews");
        let preview_body = preview.structured_content.expect("structured preview");
        assert_eq!(preview_body["valid"], true);
        assert_eq!(preview_body["effect"]["domain"], "manifest");
        assert_eq!(preview_body["effect"]["action"], "Upsert manifest servers");
        assert!(
            preview_body["effect"]["impact"].is_object()
                || preview_body["effect"]["note"].is_string(),
            "the MCP preview must return the existing manifest effect or explain why replay is unavailable: {preview_body}",
        );
        let preview_schema = serde_json::to_value(schemars::schema_for!(PreviewResponse)).unwrap();
        let preview_validator =
            jsonschema::validator_for(&preview_schema).expect("preview output schema compiles");
        assert!(
            preview_validator
                .iter_errors(&preview_body)
                .next()
                .is_none(),
            "stateful response validates against the advertised output schema",
        );

        let changed = waygate_upstream::parse_manifest_set(
            "- name: alpha\n  transport: http\n  url: http://changed.example/mcp\n",
        )
        .expect("changed fixture manifest parses");
        waygate_upstream::write_manifest_set_to_dir(&dir, &changed)
            .expect("changed live manifest writes");
        let stale_preview = t
            .call(
                "preview_change",
                Some(
                    json!({
                        "action_type": "manifest.upsert_servers",
                        "params": {
                            "base_hash": prepared_base.clone(),
                            "content": candidate
                        }
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect("stale preview returns a fixable structured result");
        let stale_body = stale_preview
            .structured_content
            .expect("structured stale preview");
        assert_eq!(stale_body["valid"], false);
        assert!(
            stale_body["errors"]
                .as_array()
                .is_some_and(|errors| errors.iter().any(|error| error
                    .as_str()
                    .is_some_and(|message| message.contains("get_action_context")))),
            "stale preview should teach the maker how to refresh current state: {stale_body}",
        );
        assert_eq!(
            stale_body["effect"]["domain"], "manifest",
            "the candidate effect remains inspectable even when its freshness witness is stale",
        );

        // Size the fixture from the action's own ceiling rather than a literal,
        // so raising the envelope for a document-carrying action cannot leave
        // this assertion silently exercising a different rejection.
        let over_the_cap = "z".repeat(
            waygate_admin::change_requests::max_propose_params_bytes("manifest.upsert_servers") + 1,
        );
        let oversized_preview = t
            .call(
                "preview_change",
                Some(
                    json!({
                        "action_type": "manifest.upsert_servers",
                        "params": {
                            "base_hash": "current",
                            "content": over_the_cap
                        }
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect("oversized preview returns a fixable structured result");
        let oversized_body = oversized_preview
            .structured_content
            .expect("structured oversized preview");
        assert_eq!(oversized_body["valid"], false);
        assert!(
            oversized_body["errors"]
                .as_array()
                .is_some_and(|errors| errors.iter().any(|error| error
                    .as_str()
                    .is_some_and(|message| message.contains("params too large")))),
            "preview must enforce the exact proposal-row size cap: {oversized_body}",
        );
        assert!(
            oversized_body["effect"].is_null(),
            "a candidate that cannot be proposed must not run the expensive effect preview",
        );

        let err = t
            .call(
                "propose_change",
                Some(
                    json!({
                        "action_type": "manifest.upsert_servers",
                        "params": {
                            "base_hash": prepared_base,
                            "content": candidate
                        },
                        "justification": "replace alpha using the inspected manifest snapshot"
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect_err("a proposal based on an old context snapshot must be refused");
        assert!(
            format!("{err:?}").contains("get_action_context"),
            "stale refusal should teach the maker how to refresh its preparation context: {err:?}",
        );

        std::fs::remove_dir_all(dir).expect("fixture directory removes");
    }

    #[tokio::test]
    async fn action_context_returns_exact_live_policy_statement_from_wire() {
        let dir = std::env::temp_dir().join(format!("mcp-policy-context-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("fixture policy directory creates");
        std::fs::write(
            dir.join("10-agent-context.cedar"),
            r#"@id("agent-context-read")
permit (
    principal,
    action,
    resource
);
"#,
        )
        .expect("fixture policy writes");

        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let evidence: SharedEvidence = Arc::new(InMemorySink::new());
        let state = Arc::new(
            AdminState::new(
                pool,
                None,
                None,
                evidence,
                None,
                None,
                None,
                None,
                "https://gw.example".into(),
            )
            .with_policies_dir(dir.clone()),
        );
        let t = tools_with_state(state);
        let maker = principal(&["mcp:propose"]);

        let result = t
            .call(
                "get_action_context",
                Some(
                    json!({
                        "action_type": "policy.upsert_fragment",
                        "selector": {"policy_id": "agent-context-read"}
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect("policy context read succeeds");
        let body = result.structured_content.expect("structured context");
        assert_eq!(body["context"]["kind"], "live_policies");
        assert_eq!(body["context"]["policy_ids"], json!(["agent-context-read"]));
        assert!(
            body["context"]["selected"]["statement"]
                .as_str()
                .is_some_and(|statement| {
                    statement.contains("@id(\"agent-context-read\")")
                        && statement.contains("permit")
                }),
            "response includes the exact live policy statement",
        );
        assert!(
            body["context"]["base_hash"]
                .as_str()
                .is_some_and(|hash| !hash.is_empty()),
            "response binds the statement to the complete live policy set",
        );

        std::fs::remove_dir_all(dir).expect("fixture directory removes");
    }

    #[tokio::test]
    async fn call_without_propose_scope_is_refused() {
        let t = tools();
        // No principal.
        let err = t
            .call("propose_change", Some(propose_args()), None)
            .await
            .expect_err("no principal");
        assert!(format!("{err}").contains("mcp:propose"), "got: {err}");
        // Wrong scope.
        let err = t
            .call(
                "propose_change",
                Some(propose_args()),
                Some(&principal(&["mcp:read"])),
            )
            .await
            .expect_err("wrong scope");
        assert!(format!("{err}").contains("mcp:propose"));
        // The reveal tool sits behind the same boundary — refused with no
        // principal, before the id is even parsed or the AdminState consulted.
        let err = t
            .call(
                "get_change_secret",
                Some(
                    json!({"id": "00000000-0000-0000-0000-000000000000"})
                        .as_object()
                        .cloned()
                        .unwrap(),
                ),
                None,
            )
            .await
            .expect_err("no principal");
        assert!(format!("{err}").contains("mcp:propose"), "got: {err}");
    }

    #[tokio::test]
    async fn peer_assertion_is_not_a_maker_even_with_propose_scope() {
        // A federated Tier-C peer that claims `mcp:propose` must NOT reach
        // the maker surface — the REST gate (`peer_assertion_permits`)
        // blocks `mcp:propose` for `PeerAssertion`, and the MCP surface
        // must not be more permissive.
        let t = tools();
        let mut peer = principal(&["mcp:propose"]);
        peer.auth_method = AuthMethod::PeerAssertion;

        // Hidden from tools/list...
        assert!(
            t.list_tools(Some(&peer)).await.is_empty(),
            "a peer must not see the maker tools even with mcp:propose"
        );
        // ...AND refused at the call boundary.
        let err = t
            .call("propose_change", Some(propose_args()), Some(&peer))
            .await
            .expect_err("peer must be refused at call");
        assert!(format!("{err}").contains("mcp:propose"), "got: {err}");
    }

    #[tokio::test]
    async fn propose_surfaces_binding_code_and_approval_url() {
        let t = tools();
        let maker = principal(&["mcp:propose"]);
        let result = t
            .call("propose_change", Some(propose_args()), Some(&maker))
            .await
            .expect("propose");

        // Structured content carries the machine-readable fields.
        let sc = result.structured_content.expect("structured_content");
        let id = sc["change_request_id"].as_str().expect("id");
        let code = sc["binding_code"].as_str().expect("binding_code");
        assert_eq!(sc["status"].as_str(), Some("pending"));
        let approval_url = sc["approval_url"].as_str().unwrap();
        assert!(approval_url.contains(&format!("/admin/changes?pending_id={id}#change-{id}")));

        // The text block (the agent-side surface) repeats the binding code +
        // approval URL so the agent can echo them into the transcript.
        let text = result
            .content
            .iter()
            .find_map(|c| c.as_text().map(|t| t.text.clone()))
            .expect("text content");
        assert!(text.contains(code), "text must surface the binding code");
        assert!(
            text.contains(&format!("/admin/changes?pending_id={id}#change-{id}")),
            "text must surface the approval URL"
        );
        assert!(text.contains(id), "text must reference the change id");
    }

    #[tokio::test]
    async fn witness_required_proposal_without_admin_state_fails_closed() {
        let t = tools();
        let maker = principal(&["mcp:propose"]);
        let args = json!({
            "action_type": "rbac.assignment.grant",
            "params": {
                "role_id": "00000000-0000-0000-0000-000000000001",
                "subject_sub": "alice"
            },
            "justification": "grant the reviewed ordinary role"
        })
        .as_object()
        .cloned()
        .unwrap();

        let err = t
            .call("propose_change", Some(args), Some(&maker))
            .await
            .expect_err("a required target witness cannot be skipped");
        assert!(format!("{err}").contains("not ready"), "got: {err}");
    }

    #[tokio::test]
    async fn proposed_change_is_pollable_and_listable_by_the_maker() {
        let t = tools();
        let maker = principal(&["mcp:propose"]);
        let proposed = t
            .call("propose_change", Some(propose_args()), Some(&maker))
            .await
            .expect("propose");
        let id = proposed.structured_content.unwrap()["change_request_id"]
            .as_str()
            .unwrap()
            .to_string();

        // get_change_status reports the CIBA pending status.
        let got = t
            .call(
                "get_change_status",
                Some(json!({"id": id}).as_object().cloned().unwrap()),
                Some(&maker),
            )
            .await
            .expect("status");
        assert_eq!(
            got.structured_content.unwrap()["status"].as_str(),
            Some("authorization_pending")
        );

        // list_my_changes returns it.
        let listed = t
            .call("list_my_changes", Some(JsonObject::new()), Some(&maker))
            .await
            .expect("list");
        let reqs = listed.structured_content.unwrap()["requests"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0]["change_request_id"].as_str(), Some(id.as_str()));
    }

    #[tokio::test]
    async fn another_maker_cannot_poll_someone_elses_change() {
        let t = tools();
        let alice = principal(&["mcp:propose"]);
        let proposed = t
            .call("propose_change", Some(propose_args()), Some(&alice))
            .await
            .expect("propose");
        let id = proposed.structured_content.unwrap()["change_request_id"]
            .as_str()
            .unwrap()
            .to_string();

        let mut bob = principal(&["mcp:propose"]);
        bob.sub = "agent-2".into();
        let err = t
            .call(
                "get_change_status",
                Some(json!({"id": id}).as_object().cloned().unwrap()),
                Some(&bob),
            )
            .await
            .expect_err("bob must not see alice's change");
        assert!(format!("{err}").contains("not found"), "got: {err}");
    }

    #[tokio::test]
    async fn unknown_tool_and_bad_action_are_invalid_params() {
        let t = tools();
        let maker = principal(&["mcp:propose"]);
        let err = t
            .call("bogus", Some(JsonObject::new()), Some(&maker))
            .await
            .expect_err("unknown tool");
        assert!(format!("{err}").contains("unknown gateway-admin tool"));

        // An action_type not in the executor registry is rejected (the
        // registry IS the propose allowlist).
        let bad = json!({
            "action_type": "definitely.not.registered",
            "params": {},
            "justification": "x",
        })
        .as_object()
        .cloned()
        .unwrap();
        let err = t
            .call("propose_change", Some(bad), Some(&maker))
            .await
            .expect_err("unregistered action");
        assert!(format!("{err}").contains("unknown or non-executable action_type"));
    }

    #[tokio::test]
    async fn preview_non_object_params_teach_the_stateful_schema_and_example() {
        let t = tools();
        let maker = principal(&["mcp:propose"]);
        let err = t
            .call(
                "preview_change",
                Some(
                    json!({
                        "action_type": "manifest.upsert_servers",
                        "params": "not-an-object"
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect_err("wrong-typed params must teach the expected call");
        let message = err.message.as_ref();
        assert!(message.contains("expected params schema"));
        assert!(message.contains("worked example"));
        assert!(message.contains("base_hash"));
        assert!(message.contains("copy context.base_hash here"));
    }

    #[tokio::test]
    async fn preview_refuses_every_upload_that_propose_refuses() {
        // The proposal-equivalent contract, pinned at the case that broke it:
        // the params schemas admit unknown keys, so a bad value at an upload
        // field is invisible to schema validation, and a preview that decided
        // whether to resolve by inspecting the params would pass a candidate
        // propose then rejects. Both surfaces must refuse the same submission.
        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let evidence: SharedEvidence = Arc::new(InMemorySink::new());
        let state = Arc::new(AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "https://gw.example".into(),
        ));
        let t = tools_with_state(state);
        let maker = principal(&["mcp:propose"]);
        // Not a gateway file reference, so nothing about the VALUES announces
        // that the resolver is needed — only the declared upload key does.
        let params = json!({
            "base_hash": "current",
            "content": "- name: example-messages\n",
            "content_file": "https://example.com/manifests.yaml",
        });

        let preview = t
            .call(
                "preview_change",
                Some(
                    json!({ "action_type": "manifest.upsert_servers", "params": params })
                        .as_object()
                        .cloned()
                        .unwrap(),
                ),
                Some(&maker),
            )
            .await
            .expect("preview returns a fixable structured result");
        let body = preview.structured_content.expect("structured preview");
        assert_eq!(
            body["valid"], false,
            "preview must refuse what propose refuses: {body}"
        );
        assert!(
            body["errors"].as_array().is_some_and(|errors| errors
                .iter()
                .any(|e| e.as_str().is_some_and(|m| m.contains("content_file")))),
            "the refusal must name the offending field: {body}"
        );

        let proposed = t
            .call(
                "propose_change",
                Some(
                    json!({
                        "action_type": "manifest.upsert_servers",
                        "params": params,
                        "justification": "same params, other surface",
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
                Some(&maker),
            )
            .await;
        let error = proposed.expect_err("propose must refuse what preview called invalid");
        assert!(
            error.message.contains("content_file"),
            "both surfaces must refuse for the same, named reason: {error}",
        );
    }

    #[tokio::test]
    async fn list_my_changes_rejects_wrong_typed_args() {
        // A present-but-wrong-typed optional arg must be rejected like the
        // REST `Query<ListQuery>` path, NOT silently defaulted into an
        // unfiltered list. (Absent keys still default — see the
        // empty-object call in the round-trip test above.)
        let t = tools();
        let maker = principal(&["mcp:propose"]);
        for bad in [
            json!({"lifecycle": 123}),
            json!({"limit": "abc"}),
            json!({"offset": -1}),
        ] {
            let err = t
                .call(
                    "list_my_changes",
                    Some(bad.as_object().cloned().unwrap()),
                    Some(&maker),
                )
                .await
                .expect_err("wrong-typed arg must error");
            assert!(format!("{err}").contains("must be"), "got: {err}");
        }
    }

    #[tokio::test]
    async fn get_change_secret_reveals_once_and_is_maker_scoped() {
        // The MCP reveal arm delegates to the same `retrieve_secret_core` the
        // REST endpoint uses, so this pins the maker-facing contract end-to-end
        // over the MCP surface: a non-owner can't retrieve (404, before the
        // burn), the rightful maker gets the plaintext exactly once, and a
        // replay is refused (single-use burn).
        let (state, id) = state_with_secret_change("agent-1", b"mcpgw_REVEALME").await;
        let t = tools_with_state(state);
        let id_args = json!({ "id": id.to_string() })
            .as_object()
            .cloned()
            .unwrap();

        // A different maker cannot retrieve it — 404 (not 403). Checked before
        // the burn, so it leaves the secret intact for the rightful maker.
        let mut bob = principal(&["mcp:propose"]);
        bob.sub = "agent-2".into();
        let err = t
            .call("get_change_secret", Some(id_args.clone()), Some(&bob))
            .await
            .expect_err("a non-owner must not retrieve the secret");
        assert!(format!("{err}").contains("not found"), "got: {err}");

        // The rightful maker (sub == "agent-1") retrieves the plaintext once,
        // delivered in the structured result's `secret` field.
        let maker = principal(&["mcp:propose"]);
        let ok = t
            .call("get_change_secret", Some(id_args.clone()), Some(&maker))
            .await
            .expect("the maker retrieves the secret");
        let text = ok
            .content
            .iter()
            .find_map(|content| content.as_text().map(|text| text.text.as_str()))
            .expect("non-secret burn notice");
        assert!(text.contains("CallToolResult.structuredContent.secret"));
        assert!(text.contains("not serialized output"));
        assert!(
            !text.contains("mcpgw_REVEALME"),
            "text content must never contain the plaintext secret"
        );
        assert_eq!(
            ok.structured_content.unwrap()["secret"].as_str(),
            Some("mcpgw_REVEALME")
        );

        // Single-use: a second retrieve is refused (the burn already fired).
        let err = t
            .call("get_change_secret", Some(id_args), Some(&maker))
            .await
            .expect_err("a second retrieve must be refused");
        assert!(format!("{err}").contains("already retrieved"), "got: {err}");
    }

    #[tokio::test]
    async fn get_change_secret_without_admin_state_fails_closed() {
        // The empty-cell `tools()` helper wires no AdminState, so the reveal
        // can't reach the secret-crypto keyring. It must fail closed with a
        // clean error (never panic) — the unreachable pre-boot window.
        let t = tools();
        let maker = principal(&["mcp:propose"]);
        let args = json!({ "id": "00000000-0000-0000-0000-000000000001" })
            .as_object()
            .cloned()
            .unwrap();
        let err = t
            .call("get_change_secret", Some(args), Some(&maker))
            .await
            .expect_err("no AdminState wired");
        assert!(format!("{err}").contains("not ready"), "got: {err}");
    }
}
