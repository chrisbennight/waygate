//! Distroless-safe `--healthcheck` probe.
//!
//! The final container image is `gcr.io/distroless/cc-debian12:nonroot`, which
//! ships no shell, wget, or curl. Docker `HEALTHCHECK` still needs to execute a
//! command that exits 0 when the service is ready. We reuse the gateway binary
//! itself: invoked with `--healthcheck`, it opens a TCP socket to the local
//! listener and sends a bare HTTP/1.0 `GET /readyz`, returning 0 on HTTP 200
//! and non-zero on anything else.
//!
//! Deliberately dependency-free (std::net only) so this is safe to call very
//! early in `main()` — before tracing, config parsing, or any async runtime
//! setup — and so the subcommand can't regress the image build surface.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const PROBE_PATH: &str = "/readyz";

pub fn run() -> i32 {
    let listen = std::env::var("GATEWAY_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    // `0.0.0.0` isn't a valid connect target; rewrite to loopback for the probe.
    let target = listen.replace("0.0.0.0", "127.0.0.1");
    let addr: SocketAddr = match target.to_socket_addrs().ok().and_then(|mut i| i.next()) {
        Some(a) => a,
        None => return 1,
    };

    let mut stream = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(_) => return 1,
    };
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let req = format!("GET {PROBE_PATH} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return 1;
    }
    let mut buf = Vec::with_capacity(256);
    if stream.read_to_end(&mut buf).is_err() {
        return 1;
    }
    // A 1.0 response starts with `HTTP/1.0 200 OK` (or `HTTP/1.1 200`). We
    // match the 3-digit status after the version token so any 2xx is healthy.
    let head = buf.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let status = head
        .split(|&b| b == b' ')
        .nth(1)
        .and_then(|s| std::str::from_utf8(s).ok())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if (200..300).contains(&status) {
        0
    } else {
        1
    }
}
