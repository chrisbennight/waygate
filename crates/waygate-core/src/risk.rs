//! Risk tier — the coarse risk classification of a tool call.
//!
//! Lives in `waygate-core` (rather than `waygate-mcp`) because it's a
//! cross-cutting domain type: the catalog classifies tools by it, the
//! authz layer step-up-gates on it, the typed [`crate::Facts`] carry
//! it, and the admin API surfaces it. `waygate-mcp::protocol`
//! re-exports it so existing `waygate_mcp::protocol::RiskTier` paths
//! keep resolving.

use serde::{Deserialize, Serialize};

/// Coarse risk classification of a tool. `lowercase` on the wire
/// (`"low"` / `"medium"` / `"high"`) so it reads naturally in Cedar
/// policies, manifests, and the admin API.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    utoipa::ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

impl RiskTier {
    /// Lowercase wire form, matching the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Parse the lowercase wire form (case-insensitively). Returns
    /// `None` for an unknown value rather than panicking, so callers
    /// reading config / catalog rows can decide how to handle it.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    /// Severity order, ascending.
    ///
    /// Written out rather than derived from the variant order, so reordering
    /// the enum cannot silently invert a comparison that decides whether one
    /// classification covers another.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
        }
    }

    /// Whether this tier covers `other` — at least as severe.
    ///
    /// Used where one classification stands in for another: a classification
    /// that applies when nothing more specific matches has to be at least as
    /// severe as everything it stands in for, or the unmatched case would be
    /// treated more leniently than a case someone already assessed.
    #[must_use]
    pub const fn covers(self, other: Self) -> bool {
        self.severity() >= other.severity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_matches_serde() {
        for r in [RiskTier::Low, RiskTier::Medium, RiskTier::High] {
            assert_eq!(
                serde_json::to_string(&r).unwrap(),
                format!("\"{}\"", r.as_str())
            );
        }
    }

    #[test]
    fn parse_round_trips_and_is_case_insensitive() {
        assert_eq!(RiskTier::parse("high"), Some(RiskTier::High));
        assert_eq!(RiskTier::parse("HIGH"), Some(RiskTier::High));
        assert_eq!(RiskTier::parse("nonsense"), None);
    }
}
