//! MCP protocol surface for the gateway.
//!
//! Every client receives a stable, authorization-filtered direct-tool
//! catalog; MCP 2026 clients receive it paginated. Clients that cannot accept
//! the full catalog can be given the compact Code Mode-only projection, whose
//! `codemode.search` and `codemode.describe` tools provide governed discovery.

// `audit` / `budget` / `cache` / `usage` live in `waygate-evidence`
// so the crates below the MCP layer that implement the traits do not
// depend up on this crate. The old `waygate_mcp::…` paths keep
// resolving via these re-exports — the same keep-resolving pattern
// as `protocol::RiskTier`.
pub use waygate_evidence::{audit, budget, cache, usage};

pub mod authz;
pub mod builtin;
pub mod call_tasks;
pub mod catalog;
pub mod catalog_changes;
pub mod client_schema;
mod count_bounds;
pub mod discovery;
pub mod error;
pub mod files;
pub mod inspection;
pub mod invocation;
pub mod origin;
pub mod ping;
pub mod protocol;
pub mod request_meta;
pub mod retained_delivery;
pub mod server;
pub mod skills;
pub(crate) mod subscriptions;
pub(crate) mod tool_list_pagination;
pub mod tool_schema;

pub use audit::{
    AuditEvent, AuditMode, AuditOutcome, AuditPrincipal, EvidenceCategory, EvidenceError,
    EvidenceRecorder, NullSink, SharedEvidence,
};
pub use authz::{AllowAllGate, AuthzGate, AuthzVerdict, BuiltinAuthz, SharedAuthz, ToolFacts};
pub use budget::{BudgetRejection, LlmBudgetGate, SharedLlmBudgetGate};
pub use builtin::{
    AssistReadTool, AssistReadTools, BuiltinCatalog, BuiltinProfileScope, BuiltinSurfaceDescriptor,
    BuiltinToolDescriptor, BuiltinTools, SharedAssistReadTools, SharedBuiltinTools,
};
pub use catalog::{SharedCatalog, UpstreamCatalog};
pub use catalog_changes::ToolCatalogEpoch;
pub use discovery::{
    compact_tool_description, rank_visible_tools, AuthorizedCatalog, BuiltinRegistry,
    CatalogAuthorization, CatalogChannel, CatalogTool, CatalogToolIdentity, CatalogToolSource,
};
pub use error::{Error, Result};
pub use invocation::{
    build_default_invocation_service, DefaultInvocationService, InvocationStage,
    InvocationStageObserver, InvocationStageStatus, SchemaValidatorCache,
    SharedInvocationStageObserver,
};
pub use ping::PingStats;
pub use server::{GatewayServer, DEFAULT_RESOURCE_RESPONSE_MAX_BYTES};
pub use tool_list_pagination::{SharedToolListCursorSealer, ToolListCursorSealer};
pub use usage::{LlmUsageRecorder, LlmUsageRow, SharedLlmUsage};
// Re-export the trait + types from `waygate-invocation` so the gateway-wide
// `waygate_mcp::*` surface stays the canonical import path even though the
// trait lives in a sibling crate. Avoids consumers needing both
// `waygate_mcp::...` and `waygate_invocation::...` imports.
pub use waygate_invocation::{
    InvocationChannel, InvocationChunk, InvocationError, InvocationRequest, InvocationResponse,
    InvocationService, InvocationStream, ResponseDelivery, SharedInvocation,
};

/// MCP spec versions this gateway serves, newest first. The first entry is
/// the primary version named by the dashboard's system info; the full list is
/// what `GatewayServer::supported_protocol_versions()` advertises (it is
/// derived from this constant, so the two cannot drift) and what the MCP
/// guide's support policy names. The conformance suite
/// under `crates/waygate-test-client/` asserts the same versions independently
/// (not derived from this constant, so pin-vs-wire drift fails conformance
/// rather than being tautologically green).
///
/// 2026-07-28 is served statelessly with a stable, paginated,
/// authorization-filtered direct-tool projection; 2025-11-25 is served on
/// sessions with the legacy discovery adapter. The transport answers an
/// `initialize` that asks for an earlier version with 2025-11-25, the newest
/// listed version that still has a session handshake. When a spec revision
/// is added or retired, update this list, the
/// conformance suite, and the MCP guide in the same change, then verify
/// against the current spec page on modelcontextprotocol.io before merging.
pub const SUPPORTED_MCP_SPEC_VERSIONS: &[&str] = &["2026-07-28", "2025-11-25"];

/// Primary (newest) supported MCP spec version — the single-version name
/// retained for the dashboard system info, the stateless request checks, and
/// compliance-mapping references.
pub const MCP_SPEC_VERSION: &str = SUPPORTED_MCP_SPEC_VERSIONS[0];

pub mod tasks;

#[cfg(test)]
mod spec_version_pin {
    use super::{MCP_SPEC_VERSION, SUPPORTED_MCP_SPEC_VERSIONS};
    use rmcp::model::ProtocolVersion;

    #[test]
    fn every_supported_version_is_one_rmcp_serves() {
        for version in SUPPORTED_MCP_SPEC_VERSIONS {
            assert!(
                ProtocolVersion::KNOWN_VERSIONS
                    .iter()
                    .any(|known| known.as_str() == *version),
                "`{version}` is not a protocol version this rmcp release knows; \
                 update SUPPORTED_MCP_SPEC_VERSIONS (and the conformance suite + \
                 MCP guide) in lockstep with the rmcp dependency",
            );
        }
    }

    #[test]
    fn primary_version_is_the_newest_supported() {
        assert_eq!(MCP_SPEC_VERSION, SUPPORTED_MCP_SPEC_VERSIONS[0]);
        let mut sorted = SUPPORTED_MCP_SPEC_VERSIONS.to_vec();
        // Spec versions are dated strings, so lexicographic order is
        // chronological order.
        sorted.sort();
        sorted.reverse();
        assert_eq!(
            SUPPORTED_MCP_SPEC_VERSIONS,
            &sorted[..],
            "SUPPORTED_MCP_SPEC_VERSIONS must be newest-first",
        );
    }
}
