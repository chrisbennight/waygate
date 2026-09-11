//! `mcpgw_<43-char-base64url>` token format.
//!
//! The 43 chars after the literal are 32 bytes of CSPRNG output, base64url-
//! encoded without padding (43 chars * 6 bits ≈ 258 bits, capped at the
//! 256 bits of source entropy). For storage we split into:
//!
//! * `prefix` — first [`KEY_PREFIX_LEN`] chars, indexed in the DB so the
//!   validator does a single O(log n) lookup.
//! * `secret_remainder` — the rest, fed to argon2id `verify` against the
//!   stored hash.
//!
//! Distinct `mcpgw_` literal is what makes leaked keys greppable in logs
//! and addable to secret-scanning patterns later.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::Rng;
use thiserror::Error;

/// `rand::rng()` returns a `ThreadRng` (OS-seeded, thread-local CSPRNG) —
/// the same primitive `waygate-oidc::pkce` uses for PKCE verifiers and
/// random tokens. `fill_bytes` is infallible at the API surface: the OS
/// CSPRNG doesn't return errors in practice.
fn fill_random(buf: &mut [u8]) {
    rand::rng().fill_bytes(buf);
}

/// Literal prefix every API key starts with. Distinct + greppable.
pub const TOKEN_LITERAL: &str = "mcpgw_";

/// Length of the prefix used for indexed DB lookup.
pub const KEY_PREFIX_LEN: usize = 8;

/// Length of the random-secret portion after the literal (base64url chars).
/// 32 bytes of entropy → 43 chars unpadded.
pub const SECRET_LEN: usize = 43;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("token does not start with `mcpgw_`")]
    BadLiteral,
    #[error("token secret has wrong length (expected {SECRET_LEN}, got {0})")]
    BadLength(usize),
    #[error("token secret contains invalid base64url characters")]
    BadChars,
    #[error("password-hash error: {0}")]
    Hash(String),
}

/// Parsed view over a token string. Borrows from the input — keep alive while
/// you use the fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedToken<'a> {
    pub prefix: &'a str,
    pub secret_remainder: &'a str,
}

impl<'a> ParsedToken<'a> {
    /// Parse `mcpgw_<43>` into prefix + remainder. Validates the literal,
    /// the length, and the base64url alphabet — we never want to call
    /// argon2 on garbage input that should have been rejected here.
    pub fn parse(token: &'a str) -> Result<Self, TokenError> {
        let rest = token
            .strip_prefix(TOKEN_LITERAL)
            .ok_or(TokenError::BadLiteral)?;
        if rest.len() != SECRET_LEN {
            return Err(TokenError::BadLength(rest.len()));
        }
        if !is_base64url(rest) {
            return Err(TokenError::BadChars);
        }
        let (prefix, remainder) = rest.split_at(KEY_PREFIX_LEN);
        Ok(Self {
            prefix,
            secret_remainder: remainder,
        })
    }
}

/// A freshly minted key — caller stores `key_hash` in the DB and shows
/// `display` to the user exactly once.
#[derive(Debug, Clone)]
pub struct MintedKey {
    /// The full `mcpgw_…` token to hand to the user. NEVER log or persist.
    pub display: String,
    /// Indexed lookup prefix matching [`ParsedToken::prefix`].
    pub key_prefix: String,
    /// argon2id PHC string (`$argon2id$…`) to insert into `api_keys.key_hash`.
    pub key_hash: String,
}

/// Mint a brand-new key: CSPRNG → encode → split → argon2id hash.
///
/// Caller writes `MintedKey.key_prefix` + `MintedKey.key_hash` to the
/// `api_keys` table and surfaces `MintedKey.display` to the user. The
/// display string and the source 32-byte CSPRNG output are both kept only
/// in memory and dropped when `MintedKey` is dropped.
pub fn mint() -> Result<MintedKey, TokenError> {
    let mut entropy = [0u8; 32];
    fill_random(&mut entropy);
    let secret = URL_SAFE_NO_PAD.encode(entropy);
    debug_assert_eq!(secret.len(), SECRET_LEN);

    let display = format!("{TOKEN_LITERAL}{secret}");
    let (prefix, remainder) = secret.split_at(KEY_PREFIX_LEN);

    let hash =
        hash_secret(remainder).map_err(|e| TokenError::Hash(format!("argon2 hash failed: {e}")))?;

    Ok(MintedKey {
        display,
        key_prefix: prefix.to_owned(),
        key_hash: hash,
    })
}

/// Argon2id hash of `secret_remainder` in PHC string format. The salt is
/// drawn from OS entropy per call.
pub fn hash_secret(secret_remainder: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::Argon2;
    use password_hash::{PasswordHasher, SaltString};

    let mut salt_bytes = [0u8; 16];
    fill_random(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)?;
    let argon = Argon2::default();
    let hash = argon.hash_password(secret_remainder.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Constant-time-ish verify against the stored PHC string. Returns `Ok(true)`
/// on match, `Ok(false)` on mismatch, and propagates parse errors from the
/// stored hash (which indicate DB corruption, not a bad input).
pub fn verify_secret(
    secret_remainder: &str,
    stored_hash: &str,
) -> Result<bool, argon2::password_hash::Error> {
    use argon2::Argon2;
    use password_hash::{PasswordHash, PasswordVerifier};

    let parsed = PasswordHash::new(stored_hash)?;
    match Argon2::default().verify_password(secret_remainder.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

fn is_base64url(s: &str) -> bool {
    s.bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_minted_token() {
        let m = mint().unwrap();
        let parsed = ParsedToken::parse(&m.display).unwrap();
        assert_eq!(parsed.prefix.len(), KEY_PREFIX_LEN);
        assert_eq!(parsed.prefix, m.key_prefix);
        assert_eq!(parsed.secret_remainder.len(), SECRET_LEN - KEY_PREFIX_LEN);
    }

    #[test]
    fn parse_rejects_missing_literal() {
        let err = ParsedToken::parse("not-an-api-key").unwrap_err();
        assert_eq!(err, TokenError::BadLiteral);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let err = ParsedToken::parse("mcpgw_short").unwrap_err();
        assert!(matches!(err, TokenError::BadLength(_)));
    }

    #[test]
    fn parse_rejects_bad_chars() {
        // `!` is outside the base64url alphabet, and the length is right
        // so it doesn't trip the length check first.
        let bad = format!("mcpgw_{}", "!".repeat(SECRET_LEN));
        let err = ParsedToken::parse(&bad).unwrap_err();
        assert_eq!(err, TokenError::BadChars);
    }

    #[test]
    fn verify_round_trips() {
        let m = mint().unwrap();
        let parsed = ParsedToken::parse(&m.display).unwrap();
        assert!(verify_secret(parsed.secret_remainder, &m.key_hash).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let m = mint().unwrap();
        // Use a *different* mint's remainder against the first hash.
        let m2 = mint().unwrap();
        let p2 = ParsedToken::parse(&m2.display).unwrap();
        assert!(!verify_secret(p2.secret_remainder, &m.key_hash).unwrap());
    }

    #[test]
    fn two_mints_have_distinct_prefixes_overwhelmingly() {
        // 48 bits of entropy in the prefix — a chance collision in 10 mints
        // would be astronomically unlikely. Catches "constant seeded RNG"
        // regressions if anyone ever swaps `OsRng`.
        let mut prefixes = std::collections::HashSet::new();
        for _ in 0..10 {
            prefixes.insert(mint().unwrap().key_prefix);
        }
        assert_eq!(prefixes.len(), 10);
    }

    #[test]
    fn minted_display_is_recognisable() {
        let m = mint().unwrap();
        assert!(m.display.starts_with(TOKEN_LITERAL));
        assert_eq!(m.display.len(), TOKEN_LITERAL.len() + SECRET_LEN);
    }
}
