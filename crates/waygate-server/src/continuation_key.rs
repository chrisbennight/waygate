//! The deployment's continuation seal key.
//!
//! The gateway seals its own continuation state so a retry proves which
//! pause it answers (see `waygate_mcp::invocation::continuation`). Every
//! replica must therefore hold the *same* key: any replica may serve any
//! retry, and a per-process key would make a retry answerable only by the
//! replica that relayed the pause — reintroducing exactly the affinity MRTR
//! removes.
//!
//! The same deployment key protects domain-tagged stateless `tools/list`
//! cursors so a later page can reach any replica without making the cursor
//! user-parseable or mutable. Absent key ⇒ pauses relay verbatim (unchanged
//! behaviour), files elicited mid-call are refused rather than delivered
//! without provenance, and list cursors use one process-local fallback key.

use std::sync::Arc;

use waygate_mcp::invocation::continuation::ContinuationSealer;
use waygate_mcp::ToolListCursorSealer;
use waygate_oidc::SessionKey;

use crate::mcp_discovery::DiscoveryCursorSealer;

/// Environment variable carrying the 32-byte key, base64url or 64-char hex.
const KEY_ENV: &str = "GATEWAY_MRTR_STATE_KEY";

/// Read the configured key, if any. Blank is treated as unset so an empty
/// value in a compose file or secret store does not become a key.
pub fn key_from_env() -> Option<String> {
    std::env::var(KEY_ENV)
        .ok()
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
}

/// Build the sealer for this deployment. A malformed key fails boot rather
/// than silently disabling elicited-file transfer.
pub fn sealer(encoded: Option<&str>) -> anyhow::Result<Option<Arc<ContinuationSealer>>> {
    let Some(encoded) = encoded else {
        tracing::info!(
            "{KEY_ENV} is unset; MRTR pauses relay verbatim and files elicited mid-call \
             are refused"
        );
        return Ok(None);
    };
    let key =
        SessionKey::from_encoded(encoded).map_err(|error| anyhow::anyhow!("{KEY_ENV}: {error}"))?;
    Ok(Some(Arc::new(ContinuationSealer::new(key))))
}

/// Build the process-wide `tools/list` cursor sealer. The existing
/// continuation key is deployment-stable and already shared by every replica,
/// so domain-tagged list cursors use it when configured. An unset key keeps
/// local development working with one process-local key; cursors then fail
/// closed across a restart or replica boundary and clients restart traversal.
pub fn cursor_sealer(encoded: Option<&str>) -> anyhow::Result<Arc<ToolListCursorSealer>> {
    match encoded {
        Some(encoded) => {
            let key = SessionKey::from_encoded(encoded)
                .map_err(|error| anyhow::anyhow!("{KEY_ENV}: {error}"))?;
            Ok(Arc::new(ToolListCursorSealer::new(key)))
        }
        None => {
            tracing::warn!(
                "{KEY_ENV} is unset; tools/list cursors are protected by a process-local key and must restart after a replica or process change"
            );
            Ok(Arc::new(ToolListCursorSealer::process_local()))
        }
    }
}

/// Build the process-wide gateway-discovery cursor sealer. It uses the same
/// deployment continuation key as standard tool-list cursors, with a distinct
/// required claim kind. An unset key keeps local development operational but
/// intentionally invalidates traversal after a process or replica change.
pub fn discovery(encoded: Option<&str>) -> anyhow::Result<Arc<DiscoveryCursorSealer>> {
    match encoded {
        Some(encoded) => {
            let key = SessionKey::from_encoded(encoded)
                .map_err(|error| anyhow::anyhow!("{KEY_ENV}: {error}"))?;
            Ok(Arc::new(DiscoveryCursorSealer::new(key)))
        }
        None => Ok(Arc::new(DiscoveryCursorSealer::process_local())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_key_fails_boot_rather_than_disabling_the_feature() {
        assert!(sealer(Some("not-a-32-byte-key")).is_err());
    }

    #[test]
    fn an_absent_key_disables_sealing_without_failing_boot() {
        assert!(sealer(None).expect("absent key boots").is_none());
    }

    #[test]
    fn a_well_formed_key_builds_a_sealer() {
        let hex = "11".repeat(32);
        assert!(sealer(Some(&hex)).expect("hex key").is_some());
        assert!(cursor_sealer(Some(&hex)).is_ok());
        assert!(discovery(Some(&hex)).is_ok());
    }

    #[test]
    fn an_absent_key_still_builds_process_local_cursor_protection() {
        assert!(cursor_sealer(None).is_ok());
        assert!(discovery(None).is_ok());
    }
}
