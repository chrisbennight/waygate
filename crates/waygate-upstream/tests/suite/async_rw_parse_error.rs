//! Pins the `AsyncRwTransport::receive` robustness contract that the
//! gateway's stdio dial path depends on: a malformed line on the read side
//! MUST NOT tear the connection down — subsequent valid messages still
//! surface.
//!
//! The `TokioChildProcess` transport the gateway uses for `Transport::Stdio`
//! upstreams is built on top of `AsyncRwTransport`, so without this
//! guarantee a single garbled byte on a child server's stdout (e.g. a stray
//! log line crossing into the framed channel) would silently disconnect the
//! upstream — no error surfaced, no recovery.
//!
//! What the peer sees for the bad line has changed across rmcp versions
//! while the no-silent-disconnect invariant held or was restored:
//!
//! - rmcp 1.6 silently closed the stream on the first decoder error (the
//!   regression this test originally existed to catch),
//! - rmcp 1.7 replied with JSON-RPC `-32700` *Parse error* and kept
//!   reading,
//! - rmcp 3.0 ignores syntax-invalid input entirely — no reply, because
//!   replying to garbage can trigger an error storm if the peer echoes the
//!   response back as more garbage, and the other official MCP SDKs also
//!   ignore it. Well-formed JSON of the wrong shape still gets an
//!   `Invalid request` reply.
//!
//! The gateway's stake is the recovery invariant, not the reply shape; this
//! test asserts recovery AND pins the current no-reply behaviour so an
//! upstream change back to reply-per-garbage-line (an error-storm hazard on
//! a chatty broken upstream) fails loudly rather than shipping silently.
//!
//! The test wraps an in-process `tokio::io::duplex` rather than spawning
//! a real child process: the rmcp behaviour under test is on
//! `AsyncRwTransport` itself, which is what `TokioChildProcess::new`
//! constructs over the child's stdio. Driving it over a duplex keeps
//! the test side-effect-free (no subprocess, no FS, no network) and
//! isolates the assertion to the exact transport layer.

use rmcp::transport::async_rw::AsyncRwTransport;
use rmcp::transport::Transport;
use rmcp::RoleClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn malformed_json_is_skipped_and_does_not_drop_connection() {
    // Two paired streams: `transport_io` is wrapped by the AsyncRwTransport
    // (the same shape `TokioChildProcess` uses internally over the child's
    // stdin/stdout). `peer_io` plays the role of the upstream MCP server.
    let (transport_io, peer_io) = tokio::io::duplex(4096);
    let (transport_r, transport_w) = tokio::io::split(transport_io);
    let (mut peer_r, mut peer_w) = tokio::io::split(peer_io);

    // RoleClient: the gateway is the MCP client when dialling a stdio
    // upstream, so its receive side decodes `RxJsonRpcMessage<RoleClient>`
    // (i.e. ServerRequest / ServerResult / ServerNotification).
    let mut transport = AsyncRwTransport::<RoleClient, _, _>::new(transport_r, transport_w);

    // Write two lines back-to-back from the "upstream":
    //   1. garbage that will not parse as JSON
    //   2. a valid `notifications/progress` server notification
    //
    // If the rmcp-1.6 silent-close behaviour returned, the second line
    // would never surface and the `receive()` below would resolve to
    // `None`. Under the recovery contract, `receive()` skips past the
    // garbage and yields the progress notification.
    peer_w
        .write_all(
            b"{not json\n\
              {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\
              \"params\":{\"progressToken\":\"tok-1\",\"progress\":42.0}}\n",
        )
        .await
        .expect("duplex write should succeed");

    let received = transport
        .receive()
        .await
        .expect("transport must recover from a parse error and yield the next valid message");

    // The valid message that surfaced after the parse error MUST be the
    // progress notification we sent — not an error, not None, not the
    // malformed bytes.
    let received_json = serde_json::to_value(&received).expect("serialize received message");
    assert_eq!(
        received_json["method"], "notifications/progress",
        "expected the post-recovery message to be the progress notification, got: {received_json}"
    );

    // Unparsable input gets NO reply: there is no id to correlate, and a
    // reply risks an error storm when the peer echoes responses back as
    // more garbage. Dropping the transport closes its write half, so the
    // peer reads to EOF and must observe zero bytes.
    drop(transport);
    let mut reply_buf = Vec::new();
    peer_r
        .read_to_end(&mut reply_buf)
        .await
        .expect("peer read to EOF");
    assert!(
        reply_buf.is_empty(),
        "no reply may be written for unparsable input; got: {}",
        String::from_utf8_lossy(&reply_buf)
    );
}
