//! Single integration-test binary for waygate-upstream's suites.
//!
//! Each module below was previously its own `tests/*.rs` binary; one
//! binary per module meant one link job per module, and linking the
//! many-binary layout dominated CI's compile phase. Cargo compiles this
//! whole directory as ONE test target, so keep new surfaces as new
//! modules here rather than new top-level `tests/*.rs` files (a stray
//! top-level file still compiles and runs, but as its own binary,
//! re-paying the link cost this layout removes).
//!
//! Module conventions are unchanged from the per-file era: one module
//! owns one transport/pool surface, and a regression test folds into
//! the module that owns the violated contract. Modules must stay
//! parallel-safe without process isolation: under `cargo test` they now
//! share one process (thread-per-test), while cargo-nextest still runs
//! each test in its own process — so no `std::env::set_var`, no shared
//! fixture rows without a per-test suffix, and cross-test serialization
//! needs a nextest test-group in `.config/nextest.toml`, not just a
//! process-local lock (see `discovery-pg` there for the pattern).

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use waygate_oidc::IdentityIssuer;

fn test_identity_issuer() -> Arc<IdentityIssuer> {
    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let pem = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    Arc::new(
        IdentityIssuer::from_ed25519_pkcs8_pem(
            &pem,
            "gw-e2e",
            "https://mcp.test",
            "gateway-e2e",
            Duration::from_secs(60),
        )
        .unwrap(),
    )
}

mod async_rw_parse_error;
mod discovery_batch;
mod discovery_scale;
mod identity_over_http;
mod listen_fanin_http;
mod manifests_parse;
mod mrtr_passthrough_http;
mod pool_observed_contracts;
mod pool_reconnect;
mod pool_redial_http;
mod pool_reload;
mod pool_stdio;
mod pool_tool_facts;
mod session_isolation_http;
mod sse_dropped_connection;
mod sse_transport;
mod token_exchange_over_http;
