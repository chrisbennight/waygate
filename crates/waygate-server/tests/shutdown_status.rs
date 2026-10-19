//! The packaged process distinguishes a clean drain from abandoned HTTP work.

#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start_gateway() -> (tokio::process::Child, u16, tempfile::TempDir) {
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve gateway port");
    let port = reserved.local_addr().expect("reserved port").port();
    drop(reserved);
    let servers = tempfile::tempdir().expect("empty manifests");
    let policies = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../waygate-authz/tests/fixtures/policies");
    let mut gateway = tokio::process::Command::new(env!("CARGO_BIN_EXE_gateway-server"));
    gateway
        .env_clear()
        .env("GATEWAY_AUTH_MODE", "disabled")
        .env("GATEWAY_LISTEN_ADDR", format!("127.0.0.1:{port}"))
        .env("GATEWAY_PUBLIC_URL", format!("http://127.0.0.1:{port}"))
        .env("GATEWAY_MCP_ALLOWED_HOSTS", "")
        .env("GATEWAY_SERVERS_DIR", servers.path())
        .env("GATEWAY_POLICIES_DIR", policies)
        .env("GATEWAY_DRAIN_TIMEOUT_SECONDS", "6")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut gateway = gateway.spawn().expect("start isolated gateway");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            assert!(
                gateway.try_wait().expect("observe gateway").is_none(),
                "gateway failed before readiness"
            );
            if reqwest::get(format!("http://127.0.0.1:{port}/readyz"))
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("isolated gateway becomes ready");
    (gateway, port, servers)
}

async fn terminate(gateway: &mut tokio::process::Child) -> std::process::ExitStatus {
    let pid = gateway.id().expect("running gateway PID").to_string();
    assert!(tokio::process::Command::new("/bin/kill")
        .args(["-TERM", &pid])
        .status()
        .await
        .expect("send SIGTERM")
        .success());
    tokio::time::timeout(Duration::from_secs(15), gateway.wait())
        .await
        .expect("shutdown remains bounded")
        .expect("reap gateway")
}

#[tokio::test]
async fn idle_gateway_exits_successfully_after_sigterm() {
    let (mut gateway, _, _servers) = start_gateway().await;
    assert!(terminate(&mut gateway).await.success());
}

#[tokio::test]
async fn unfinished_request_makes_sigterm_exit_unsuccessful() {
    let (mut gateway, port, _servers) = start_gateway().await;
    let mut request = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect MCP request");
    request.write_all(format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nExpect: 100-continue\r\nContent-Length: 10000\r\n\r\n"
    ).as_bytes()).await.expect("send pending request headers");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !response.ends_with(b"\r\n\r\n") {
            response.push(request.read_u8().await.expect("read interim response"));
            assert!(response.len() < 4096, "bounded interim response");
        }
    })
    .await
    .expect("gateway begins reading the pending body");
    assert!(
        response.starts_with(b"HTTP/1.1 100 Continue"),
        "request was admitted and its body remains unfinished"
    );
    let status = terminate(&mut gateway).await;
    assert_eq!(
        status.code(),
        Some(1),
        "incomplete cleanup must be an ordinary nonzero exit"
    );
}
