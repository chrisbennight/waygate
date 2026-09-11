//! Per-request client context for dual-version serving.
//!
//! Under MCP 2026-07-28 there is no `initialize` handshake: protocol
//! version, client identity, and client capabilities arrive on every
//! request in `_meta`. Under 2025-11-25 they were captured once at
//! `initialize` and live on the session peer. rmcp's `RequestContext`
//! accessors already consult `_meta` first and fall back to the session's
//! peer info, so this module is the single seam that turns those accessors
//! into the gateway's per-request decisions — eager-catalog matching,
//! elicitation capability, disclosure-record selection, log level — instead
//! of each call site reading session state that a stateless request does
//! not have.

use rmcp::model::ProtocolVersion;
use rmcp::service::RequestContext;
use rmcp::RoleServer;

/// `_meta` key carrying the per-request log level (SEP-2575). Read as a raw
/// string: rmcp's typed `LoggingLevel` is deprecated with the Logging
/// feature itself, and the gateway only needs presence + value to honor the
/// "no `notifications/message` for requests that omitted it" rule.
const META_KEY_LOG_LEVEL: &str = "io.modelcontextprotocol/logLevel";

/// Which protocol generation the current request negotiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolGeneration {
    /// A 2025-11-25-or-earlier session: state may live on the session
    /// (per-session disclosure record, ping loop, GET-stream notifications).
    Legacy,
    /// A 2026-07-28 stateless request: nothing survives between requests
    /// except what the gateway keys by authenticated principal.
    Stateless2026,
}

/// Everything the gateway decides per request about the calling client,
/// resolved identically for both protocol generations.
#[derive(Clone, Debug)]
pub struct ClientContext {
    pub generation: ProtocolGeneration,
    /// `clientInfo.name` — from per-request `_meta` (stateless) or the
    /// session handshake (legacy). Drives the eager-catalog client match.
    pub client_name: Option<String>,
    /// Whether the client declared the elicitation capability. On the legacy
    /// path this gates server-initiated elicitation over the session's push
    /// channel; on the stateless path it gates MRTR `input_required`
    /// projection instead.
    pub elicitation_capable: bool,
    /// The client's full declared capability set — from per-request `_meta`
    /// (stateless) or the session handshake (legacy). `None` when the
    /// request carried none. MRTR passthrough reads this to decide whether
    /// an upstream pause is answerable, and the upstream pool mirrors it
    /// into per-call dials on 2026-negotiated upstreams.
    pub capabilities: Option<rmcp::model::ClientCapabilities>,
    /// `io.modelcontextprotocol/logLevel` from `_meta`, when present. The
    /// gateway emits no `notifications/message` today; parsed so a future
    /// emitter cannot forget the requests-that-omitted-it-get-nothing rule.
    pub log_level: Option<String>,
}

impl ClientContext {
    /// Resolve the client context for the current request.
    pub fn from_ctx(ctx: &RequestContext<RoleServer>) -> Self {
        let generation = match ctx.protocol_version() {
            Some(version) if version.as_str() >= ProtocolVersion::V_2026_07_28.as_str() => {
                ProtocolGeneration::Stateless2026
            }
            // Absent version means a legacy peer that already completed the
            // handshake (rmcp rejects new-protocol requests without the
            // inline version before dispatch reaches a handler).
            _ => ProtocolGeneration::Legacy,
        };
        let capabilities = ctx.client_capabilities();
        Self {
            generation,
            client_name: ctx.client_info().map(|info| info.name.to_string()),
            elicitation_capable: capabilities
                .as_ref()
                .is_some_and(|caps| caps.elicitation.is_some()),
            capabilities,
            log_level: ctx
                .meta
                .0
                .get(META_KEY_LOG_LEVEL)
                .and_then(|value| value.as_str())
                .map(str::to_owned),
        }
    }
}
