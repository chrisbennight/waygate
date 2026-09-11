//! Governed catalog value mapping for upstream dispatch.

use super::*;

pub(super) fn risk_to_tier(risk: &str) -> RiskTier {
    match risk {
        "low" => RiskTier::Low,
        "medium" => RiskTier::Medium,
        "high" | "critical" => RiskTier::High,
        other => {
            tracing::warn!(
                risk = %other,
                "catalog returned an unknown risk tier; treating as High (fail-safe)",
            );
            RiskTier::High
        }
    }
}
