/// Deployment posture — what to refuse at boot.
///
/// Set via `GATEWAY_DEPLOYMENT_PROFILE=dev|prod`. Defaults to `Dev` so the
/// existing local-dev `cargo run` workflow keeps working without an env
/// change.
///
/// `Prod` is the belt-and-suspenders guard against deploying with unsafe
/// defaults that happen to work locally. It refuses to boot when any of the
/// known-unsafe-in-prod combinations is present:
///
/// - `GATEWAY_AUTH_MODE=disabled` (allow-all gate with synthetic admin
///   principal — release builds already reject this independently).
/// - `GATEWAY_ACCEPT_UPSTREAM_TOKENS=true` (OAuth token-passthrough
///   anti-pattern; deprecated and slated for removal).
/// - `GATEWAY_DATABASE_URL` unset (audit events silently dropped via
///   `NullSink`; no compliance evidence).
/// - Dashboard auth unset (`/admin` would be wide open with a synthetic
///   admin principal).
/// - Any upstream manifest using `transport: stdio` (local subprocess MCP
///   without sandboxing; this gateway is a proxy, not a runtime manager).
///
/// Each refusal names the offending field and the dev-profile escape
/// (`GATEWAY_DEPLOYMENT_PROFILE=dev`) so an operator can keep iterating
/// locally without having to remember which knob to flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentProfile {
    Dev,
    Prod,
}

impl DeploymentProfile {
    pub(super) fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "dev" => Ok(Self::Dev),
            "prod" => Ok(Self::Prod),
            other => {
                anyhow::bail!("GATEWAY_DEPLOYMENT_PROFILE must be `dev` or `prod` (got `{other}`)")
            }
        }
    }

    /// Stable lowercase string form (`"dev"` / `"prod"`), as accepted by the
    /// `GATEWAY_DEPLOYMENT_PROFILE` env var and stored on
    /// `AdminState::deployment_profile` for handlers that gate on the profile.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Prod => "prod",
        }
    }
}
