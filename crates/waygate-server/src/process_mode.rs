//! Minimal process modes handled before telemetry and configuration.
//!
//! The healthcheck keeps the distroless image self-probing without a shell or
//! HTTP client. The Code Mode runner re-enters this binary as a fresh process
//! without booting the gateway server.

#[path = "codemode_protocol.rs"]
pub(crate) mod codemode_protocol;
#[path = "codemode_runner.rs"]
mod codemode_runner;

pub fn run_requested() -> anyhow::Result<bool> {
    if std::env::args().any(|arg| arg == codemode_protocol::RUNNER_FLAG) {
        codemode_runner::run()?;
        return Ok(true);
    }
    if std::env::args().any(|arg| arg == "--healthcheck") {
        std::process::exit(crate::healthcheck::run());
    }
    Ok(false)
}
