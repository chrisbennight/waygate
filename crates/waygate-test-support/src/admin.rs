//! The common [`AdminState`] core behind the `dashboard_render/` suite's
//! `state_with_*` builders, plus the `example-messages` fixture manifest they
//! all seed the pool with. A test composes: `Arc::new(base_admin_state()
//! .with_x(...))` — the `with_*` combinators are `AdminState`'s own.

use std::collections::BTreeMap;
use std::sync::Arc;

use waygate_admin::AdminState;
use waygate_manifest_types::{ToolClassification, Transport, UpstreamManifest};
use waygate_upstream::UpstreamPool;

/// The fixture upstream every dashboard test seeds: one high-risk
/// side-effecting tool and one low-risk read-only tool.
pub fn example_messages_manifest() -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: "example-messages".into(),
        transport: Transport::Http,
        protocol: Default::default(),
        url: Some("http://example-messages:8000/mcp".into()),
        command: None,
        tools: vec![
            ToolClassification::new("send_msg", waygate_core::RiskTier::High, true, false),
            ToolClassification::new("list_contacts", waygate_core::RiskTier::Low, false, false),
        ],
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        session: None,
    }
}

/// A disconnected pool over the given manifests (no dialing).
pub fn disconnected_pool(manifests: BTreeMap<String, UpstreamManifest>) -> Arc<UpstreamPool> {
    Arc::new(UpstreamPool::from_manifests_disconnected(manifests))
}

/// A disconnected pool seeded with just [`example_messages_manifest`].
pub fn example_messages_pool() -> Arc<UpstreamPool> {
    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    disconnected_pool(manifests)
}

/// The minimal-everything `AdminState` core the `state_with_*` builders
/// shared: example-messages pool, null evidence, every optional store absent, and a
/// loopback public URL. Chain `AdminState`'s `with_*` methods for the
/// page under test, then `Arc::new(...)`.
pub fn base_admin_state() -> AdminState {
    base_admin_state_with_pool(example_messages_pool())
}

/// [`base_admin_state`] with a caller-supplied pool.
pub fn base_admin_state_with_pool(pool: Arc<UpstreamPool>) -> AdminState {
    AdminState::new(
        pool,
        None,
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    )
}
