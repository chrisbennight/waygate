//! `TenantId` — newtype around `String` for multi-tenant routing.
//!
//! ## Why a newtype
//!
//! Bare `String` for tenant ids would let any string-typed value
//! accidentally substitute for a tenant id, and would make a
//! "missing tenant" branch one `Option<String>` deep instead of
//! a typed parse failure. The newtype:
//!
//! - Forces every call site to acknowledge whether it has a
//!   real tenant id or the [`TenantId::DEFAULT`] sentinel.
//! - Lets `serde` reject invalid ids at deserialization time
//!   (env vars, JWT claims, admin API payloads) without each
//!   call site re-implementing validation.
//! - Surfaces a single source of truth for the id format so
//!   SCIM ingestion, Cedar entity stamping, and audit-row
//!   insert all agree.
//!
//! ## Format
//!
//! Lowercase alphanumeric + dashes + underscores, 1-64 chars,
//! must start and end with an alphanumeric. Matches the shape
//! that survives URL paths, DB column primary keys, and shell
//! environment variables without escape gymnastics.
//!
//! ## Default tenant
//!
//! Single-tenant deployments and dev mode use [`TenantId::DEFAULT`]
//! (the literal `"default"`). Every storage migration that adds a
//! `tenant_id` column uses the same
//! literal as its `NOT NULL DEFAULT 'default'`, so existing rows
//! backfill atomically when the migration applies.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

/// Canonical id of a tenant, validated at construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct TenantId(String);

impl TenantId {
    /// Sentinel for single-tenant deployments. Identical to the
    /// `DEFAULT 'default'` literal every schema migration that adds
    /// a `tenant_id` column uses; existing rows backfill to this id
    /// when the column is added.
    pub const DEFAULT: &'static str = "default";

    /// Construct the default tenant id without parsing.
    pub fn default_id() -> Self {
        // SAFETY: the literal is valid by construction (matches
        // the validation rules below), so the parse can't fail.
        Self(Self::DEFAULT.to_owned())
    }

    /// Validate and construct from a raw string. Use this at
    /// every boundary that takes external input (env var, JWT
    /// claim, admin API payload, SCIM resource).
    pub fn parse(s: impl Into<String>) -> Result<Self, TenantIdError> {
        let s = s.into();
        validate(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying id as a string slice. Use this when
    /// passing the id to a SQL bind, an HTTP header, a log field,
    /// etc. — never `to_string` (that re-allocates).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True iff this is the [`Self::DEFAULT`] sentinel. Useful
    /// for branches that have a fast path when no real tenancy
    /// is configured.
    pub fn is_default(&self) -> bool {
        self.0 == Self::DEFAULT
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::default_id()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for TenantId {
    type Err = TenantIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl<'de> Deserialize<'de> for TenantId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        TenantId::parse(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TenantIdError {
    #[error("tenant id must be 1-64 characters (got {0})")]
    BadLength(usize),
    #[error(
        "tenant id must contain only lowercase ASCII letters, digits, `-`, or `_` \
         and start/end with an alphanumeric (got {0:?})"
    )]
    BadChars(String),
}

fn validate(s: &str) -> Result<(), TenantIdError> {
    let len = s.len();
    if !(1..=64).contains(&len) {
        return Err(TenantIdError::BadLength(len));
    }
    let bytes = s.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[len - 1]) {
        return Err(TenantIdError::BadChars(s.to_owned()));
    }
    if !bytes.iter().all(|&b| is_alnum(b) || b == b'-' || b == b'_') {
        return Err(TenantIdError::BadChars(s.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_parses_and_round_trips() {
        let t = TenantId::default();
        assert_eq!(t.as_str(), "default");
        assert!(t.is_default());
        assert_eq!(t, TenantId::parse("default").unwrap());
    }

    #[test]
    fn accepts_lowercase_alnum_dash_underscore() {
        for ok in [
            "default",
            "acme",
            "acme-prod",
            "acme_prod",
            "a1",
            "1a",
            "a",
            "z9",
            "co-1_2",
        ] {
            TenantId::parse(ok).unwrap_or_else(|e| panic!("`{ok}` should parse: {e}"));
        }
    }

    #[test]
    fn rejects_uppercase() {
        assert!(matches!(
            TenantId::parse("Acme"),
            Err(TenantIdError::BadChars(_))
        ));
    }

    #[test]
    fn rejects_leading_or_trailing_separator() {
        for bad in ["-acme", "acme-", "_acme", "acme_"] {
            assert!(
                matches!(TenantId::parse(bad), Err(TenantIdError::BadChars(_))),
                "`{bad}` should fail",
            );
        }
    }

    #[test]
    fn rejects_empty_and_too_long() {
        assert!(matches!(
            TenantId::parse(""),
            Err(TenantIdError::BadLength(0))
        ));
        let long = "a".repeat(65);
        assert!(matches!(
            TenantId::parse(long),
            Err(TenantIdError::BadLength(65))
        ));
    }

    #[test]
    fn rejects_disallowed_chars() {
        for bad in ["acme.prod", "acme prod", "acme/prod", "acme:prod"] {
            assert!(
                matches!(TenantId::parse(bad), Err(TenantIdError::BadChars(_))),
                "`{bad}` should fail",
            );
        }
    }

    #[test]
    fn serde_round_trips_a_valid_id() {
        let json = serde_json::to_string(&TenantId::parse("acme-prod").unwrap()).unwrap();
        assert_eq!(json, "\"acme-prod\"");
        let back: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_str(), "acme-prod");
    }

    #[test]
    fn serde_rejects_an_invalid_id() {
        let err =
            serde_json::from_str::<TenantId>("\"Acme\"").expect_err("uppercase must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("lowercase"), "serde err must explain: {msg}");
    }

    #[test]
    fn boundary_64_chars_accepted_65_rejected() {
        let ok = "a".repeat(64);
        TenantId::parse(ok).unwrap();
        let bad = "a".repeat(65);
        assert!(matches!(
            TenantId::parse(bad),
            Err(TenantIdError::BadLength(65))
        ));
    }
}
