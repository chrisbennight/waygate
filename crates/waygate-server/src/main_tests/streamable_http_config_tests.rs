use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::streamable_http_server_config;

#[test]
fn sse_keepalive_interval_threads_into_rmcp_config() {
    let cfg = streamable_http_server_config(
        Some(Duration::from_secs(42)),
        CancellationToken::new(),
        vec!["gw.example".into()],
    );
    assert_eq!(cfg.sse_keep_alive, Some(Duration::from_secs(42)));
    assert_eq!(cfg.allowed_hosts, vec!["gw.example".to_string()]);
}

#[test]
fn sse_keepalive_none_overrides_rmcp_default() {
    // `None` is the parsed form of `GATEWAY_SSE_KEEPALIVE_SECONDS=0`.
    // rmcp's `Default` ships its own heartbeat interval, so the wiring
    // must actively clear the field — merely "not setting it" would leave
    // idle streams heartbeating at a rate no env var controls.
    let cfg = streamable_http_server_config(None, CancellationToken::new(), vec![]);
    assert_eq!(cfg.sse_keep_alive, None);
}

#[test]
fn legacy_session_mode_is_explicitly_enabled() {
    // Legacy (pre-2026-07-28) clients depend on sessions; the SDK default
    // must never decide this. If rmcp flips its default, this assertion —
    // not production behavior — is what breaks.
    let cfg = streamable_http_server_config(None, CancellationToken::new(), vec![]);
    assert!(cfg.legacy_session_mode);
}
