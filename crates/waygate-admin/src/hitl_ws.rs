//! `/api/v1/admin/approval_grants/subscribe`
//!
//! A WebSocket push channel for HITL (human-in-the-loop) approval
//! requests. The invocation pipeline emits a
//! [`waygate_invocation::HitlApprovalNeeded`] event whenever
//! `DefaultInvocationService::check_approval` denies a call with
//! `ApprovalRequired` for "no matching grant" (the user-actionable
//! denial — infrastructure failures like a down catalog deliberately
//! don't notify). [`ApprovalHub`] fans the event out to every
//! subscribed operator in the same tenant; the admin browser UI
//! consumes it to show "approval needed" toasts without polling the
//! REST surface.
//!
//! ## Tenant scoping
//!
//! Each subscriber is bound to the tenant of the principal that
//! opened the socket. The hub uses a single `tokio::sync::broadcast`
//! channel so the publish path stays cheap; the per-tenant filter
//! lives on the *receive* side so a misbehaving publisher can never
//! leak across tenants — a publisher that hands the wrong
//! `tenant_id` is still filtered out by every receiver whose tenant
//! doesn't match.
//!
//! ## Auth + lifecycle
//!
//! The route is gated by `require_admin` (mcp:admin scope), the
//! same as the rest of `/api/v1/admin/*`. Auth runs as part of the
//! HTTP upgrade — axum's `WebSocketUpgrade` extractor materialises
//! after middleware, so `Principal` is freshly validated on every
//! WebSocket handshake.
//!
//! Long-lived sockets are unavoidably "validated once at upgrade".
//! That's a known property of WS upgrades; mitigations live at the
//! token-lifetime layer (short-lived bearer tokens, the
//! upstream-session revocation path). This module deliberately does
//! NOT cache identity beyond the upgrade — the per-event filter
//! reads `tenant_id` captured from the upgrade-time `Principal`
//! into the receive task, which can't be mutated mid-socket.
//!
//! ## Backpressure
//!
//! `tokio::sync::broadcast` is bounded. A slow subscriber that
//! falls behind receives `RecvError::Lagged(n)` — the receive task
//! emits a `tracing::warn!` and continues. It MUST NOT exit;
//! exiting would mask the lag from the operator. A genuinely dead
//! socket exits via the close-frame path on `socket.recv()` or via
//! the send-error path on `socket.send()`.
//!
//! ### Known trade-off: shared buffer is process-wide, not per-tenant
//!
//! Because all tenants share the single broadcast channel, a burst
//! of approval-needed events in tenant A consumes buffer slots that
//! tenant B's subscriber would otherwise consume. If tenant B is
//! slow at that moment (browser paused, network hiccup), it can
//! hit `RecvError::Lagged` and miss same-tenant events *because of
//! tenant A's traffic*. This is reliability, NOT security — the
//! receive-side filter is authoritative; cross-tenant data never
//! reaches the wire even when an event slot is consumed by another
//! tenant. The Lagged warning makes the gap visible to operators.
//!
//! When deployments are single-tenant (the common shape today),
//! the issue doesn't arise. When operators report missed
//! notifications under multi-tenant bursts, the architectural fix
//! is per-tenant channels (see tracking issue #181 for the option
//! matrix). The immediate operator knob is
//! `GATEWAY_HITL_WS_BUFFER` (default 256, ceiling 65_536).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::middleware;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tokio::time::interval;
use waygate_invocation::{HitlApprovalNeeded, HitlNotifier};
use waygate_oidc::Principal;

use crate::scope::require_admin;
use crate::state::AdminState;

/// Default broadcast-channel capacity. Each in-flight event takes
/// one slot per subscriber until consumed; 256 is comfortable for
/// a small operator team and recovers fast from a brief read
/// stall. Override at boot via `GATEWAY_HITL_WS_BUFFER`.
pub const DEFAULT_BUFFER_CAPACITY: usize = 256;

/// Ping interval — drives the keepalive heartbeat the server
/// sends so a NAT timeout (typically 60-120s) doesn't silently
/// drop the socket. Picked under the default NAT idle window.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Wire shape of an approval-needed event the operator browser
/// (or any other subscriber) sees. The `event` tag lets future
/// variants (`"approval_revoked"`, `"approval_expired"`) extend
/// the schema without a breaking parse.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event")]
pub enum AdminApprovalMessage {
    /// A call to a `requires_approval=true` tool was refused
    /// because no matching grant exists. Operators mint a grant
    /// via the REST surface (`POST /api/v1/admin/approval_grants`)
    /// using the same `argument_hash` so the next retry is
    /// authorized.
    #[serde(rename = "approval_needed")]
    ApprovalNeeded {
        /// Value-free consequences and schema field names for operator review.
        summary: waygate_invocation::ApprovalSummary,
        tenant_id: String,
        principal_sub: String,
        /// Issuer that minted the requester's `sub`. The operator echoes
        /// it when minting the grant so ownership binds the full identity.
        principal_issuer: String,
        server: String,
        tool: String,
        argument_hash: String,
        /// Reviewed behavior hash of the denied tool version. The operator
        /// echoes it when minting the grant so the authorization binds to the
        /// contract they reviewed; a later behavior change refuses the mint.
        behavior_hash: String,
        /// Server-stamped emission time. Subscribers compute
        /// freshness against the server clock so an operator
        /// browser doesn't have to trust its own.
        #[serde(with = "time::serde::rfc3339")]
        emitted_at: OffsetDateTime,
    },
}

impl AdminApprovalMessage {
    fn from_event(event: HitlApprovalNeeded) -> Self {
        Self::ApprovalNeeded {
            summary: event.summary,
            tenant_id: event.tenant_id,
            principal_sub: event.principal_sub,
            principal_issuer: event.principal_issuer,
            server: event.server,
            tool: event.tool,
            argument_hash: event.argument_hash,
            behavior_hash: event.behavior_hash,
            emitted_at: OffsetDateTime::now_utc(),
        }
    }

    fn tenant_id(&self) -> &str {
        match self {
            Self::ApprovalNeeded { tenant_id, .. } => tenant_id,
        }
    }
}

/// Per-process fan-out of HITL approval events. Always
/// constructed; an event published with zero subscribers is a
/// cheap no-op (drop on the bounded channel).
pub struct ApprovalHub {
    tx: broadcast::Sender<AdminApprovalMessage>,
}

impl ApprovalHub {
    pub fn new(buffer_capacity: usize) -> Self {
        let cap = buffer_capacity.max(1);
        let (tx, _rx) = broadcast::channel(cap);
        Self { tx }
    }

    /// Test / instrumentation hook so callers can assert against
    /// a live subscriber count.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Subscribe to the broadcast. Returns the receiving half;
    /// drop it to unsubscribe.
    pub fn subscribe_raw(&self) -> broadcast::Receiver<AdminApprovalMessage> {
        self.tx.subscribe()
    }
}

impl Default for ApprovalHub {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_CAPACITY)
    }
}

impl HitlNotifier for ApprovalHub {
    fn notify_approval_needed(&self, event: HitlApprovalNeeded) {
        // Bounded broadcast — `send` returns Err only when zero
        // receivers; that's the steady-state empty-channel case
        // and not worth logging at info level. Tracing at
        // `debug` keeps the noise floor low.
        let msg = AdminApprovalMessage::from_event(event);
        match self.tx.send(msg) {
            Ok(n) => {
                tracing::debug!(delivered_to = n, "HITL approval event published",);
            }
            Err(_) => {
                tracing::debug!("HITL approval event dropped: no subscribers");
            }
        }
    }
}

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/approval_grants/subscribe",
            get(subscribe_approvals),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

/// WebSocket upgrade handler. `require_admin` already ran (layer
/// above), so this handler only sees principals with `mcp:admin`.
async fn subscribe_approvals(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
) -> Response {
    let tenant_id = principal.tenant.as_str().to_owned();
    let principal_sub = principal.sub.clone();
    let rx = state.hitl.hitl_hub.subscribe_raw();
    ws.on_upgrade(move |socket| run_subscriber(socket, tenant_id, principal_sub, rx))
}

/// Per-connection receive loop. Three concurrent sources:
///   1. broadcast events from the hub
///   2. inbound frames from the client (Ping/Pong/Close)
///   3. a periodic Ping the server emits as a heartbeat
///
/// Selecting on all three keeps the loop responsive to a dead
/// peer (the next send fails) and to a slow consumer (the
/// `Lagged` arm).
async fn run_subscriber(
    mut socket: WebSocket,
    tenant_id: String,
    principal_sub: String,
    mut rx: broadcast::Receiver<AdminApprovalMessage>,
) {
    let mut ping = interval(PING_INTERVAL);
    // The first tick fires immediately; the keepalive Ping
    // doubles as an upgrade-survived liveness check.

    tracing::info!(
        tenant = %tenant_id,
        operator_sub = %principal_sub,
        "HITL ws subscriber connected",
    );

    let mut lagged_total: u64 = 0;
    loop {
        tokio::select! {
            // Inbound from the client. The contract is server-
            // push only; we still consume the inbound half so a
            // Close frame terminates the loop cleanly and Ping
            // frames don't pile up.
            inbound = socket.recv() => {
                match inbound {
                    None => {
                        tracing::info!(
                            tenant = %tenant_id,
                            "HITL ws subscriber stream closed",
                        );
                        break;
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::info!(
                            tenant = %tenant_id,
                            "HITL ws subscriber sent Close",
                        );
                        break;
                    }
                    Some(Ok(_)) => {
                        // Ignore Ping / Pong / Text / Binary
                        // from the client — read-only contract.
                    }
                    Some(Err(e)) => {
                        tracing::warn!(
                            tenant = %tenant_id,
                            error = %e,
                            "HITL ws subscriber read error; closing",
                        );
                        break;
                    }
                }
            }
            // Outbound: broadcast event.
            recv = rx.recv() => match recv {
                Ok(msg) => {
                    // Tenant filter — single global channel,
                    // authoritative scope lives on the receive
                    // side so a buggy publisher with the wrong
                    // tenant_id still can't leak across tenants.
                    if msg.tenant_id() != tenant_id {
                        continue;
                    }
                    match serde_json::to_string(&msg) {
                        Ok(json) => {
                            if let Err(e) = socket.send(Message::Text(json.into())).await {
                                tracing::warn!(
                                    tenant = %tenant_id,
                                    error = %e,
                                    "HITL ws send failed; closing",
                                );
                                break;
                            }
                        }
                        Err(e) => {
                            // Fixed-shape enum should never
                            // fail to serialise; log at warn so
                            // a regression is visible.
                            tracing::warn!(
                                tenant = %tenant_id,
                                error = %e,
                                "HITL ws serialize failed; dropping event",
                            );
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    lagged_total = lagged_total.saturating_add(n);
                    tracing::warn!(
                        tenant = %tenant_id,
                        skipped = n,
                        lagged_total,
                        "HITL ws subscriber lagged; continuing",
                    );
                    // MUST continue — exiting would mask the lag
                    // and surface to operators as a mysterious
                    // disconnect.
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!(
                        tenant = %tenant_id,
                        "HITL ws broadcast channel closed",
                    );
                    break;
                }
            },
            // Heartbeat: keepalive Ping every PING_INTERVAL.
            // Send failure means the peer is gone.
            _ = ping.tick() => {
                if let Err(e) = socket.send(Message::Ping(Vec::new().into())).await {
                    tracing::info!(
                        tenant = %tenant_id,
                        error = %e,
                        "HITL ws keepalive ping failed; closing",
                    );
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_tenant_id_returns_inner() {
        let msg = AdminApprovalMessage::ApprovalNeeded {
            summary: Default::default(),
            tenant_id: "acme".into(),
            principal_sub: "alice".into(),
            principal_issuer: "https://issuer.test".to_owned(),
            server: "example-messages".into(),
            tool: "send_msg".into(),
            argument_hash: "deadbeef".into(),
            behavior_hash: "beef".into(),
            emitted_at: OffsetDateTime::now_utc(),
        };
        assert_eq!(msg.tenant_id(), "acme");
    }

    #[test]
    fn hub_default_constructs_with_default_capacity() {
        let hub = ApprovalHub::default();
        // No subscribers yet; send returns Err which the
        // notifier coerces to a debug-level log + drop.
        hub.notify_approval_needed(HitlApprovalNeeded {
            summary: Default::default(),
            tenant_id: "acme".into(),
            principal_sub: "alice".into(),
            principal_issuer: "https://issuer.test".to_owned(),
            server: "example-messages".into(),
            tool: "send_msg".into(),
            argument_hash: "deadbeef".into(),
            behavior_hash: "beef".into(),
        });
        assert_eq!(hub.subscriber_count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hub_publish_reaches_subscriber() {
        let hub = ApprovalHub::default();
        let mut rx = hub.subscribe_raw();
        assert_eq!(hub.subscriber_count(), 1);

        hub.notify_approval_needed(HitlApprovalNeeded {
            summary: Default::default(),
            tenant_id: "acme".into(),
            principal_sub: "alice".into(),
            principal_issuer: "https://issuer.test".to_owned(),
            server: "example-messages".into(),
            tool: "send_msg".into(),
            argument_hash: "deadbeef".into(),
            behavior_hash: "beef".into(),
        });

        let got = rx.recv().await.expect("subscriber receives the event");
        match got {
            AdminApprovalMessage::ApprovalNeeded {
                tenant_id,
                principal_sub,
                server,
                tool,
                argument_hash,
                ..
            } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(principal_sub, "alice");
                assert_eq!(server, "example-messages");
                assert_eq!(tool, "send_msg");
                assert_eq!(argument_hash, "deadbeef");
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hub_serialized_event_has_stable_shape() {
        let hub = ApprovalHub::default();
        let mut rx = hub.subscribe_raw();
        hub.notify_approval_needed(HitlApprovalNeeded {
            summary: waygate_invocation::ApprovalSummary {
                description: Some("Replace configuration; upstream retention applies.".to_owned()),
                affected_fields: vec!["contents".to_owned()],
            },
            tenant_id: "acme".into(),
            principal_sub: "alice".into(),
            principal_issuer: "https://issuer.test".to_owned(),
            server: "example-messages".into(),
            tool: "send_msg".into(),
            argument_hash: "deadbeef".into(),
            behavior_hash: "beef".into(),
        });
        let msg = rx.recv().await.expect("event");
        let json = serde_json::to_value(&msg).expect("serialise");
        // The `event` tag and the field names are the wire
        // contract — pin them so a future rename breaks tests.
        assert_eq!(json["event"], "approval_needed");
        assert_eq!(
            json["summary"]["affected_fields"],
            serde_json::json!(["contents"])
        );
        assert_eq!(
            json["summary"]["description"],
            "Replace configuration; upstream retention applies."
        );
        assert_eq!(json["tenant_id"], "acme");
        assert_eq!(json["principal_sub"], "alice");
        assert_eq!(json["server"], "example-messages");
        assert_eq!(json["tool"], "send_msg");
        assert_eq!(json["argument_hash"], "deadbeef");
        assert!(
            json["emitted_at"].is_string(),
            "emitted_at must be present and RFC3339",
        );
    }
}
