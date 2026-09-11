//! The one AES-256-GCM envelope: `nonce (12) || ciphertext || tag (16)`.
//!
//! Before this module, two independent copies of this exact framing
//! existed — the session-cookie codec here in `waygate-oidc` and the
//! upstream-token keyring in `waygate-as` — with divergent nonce RNG
//! sources. Identical security-relevant framing must have exactly one
//! implementation; CI fails on any direct `aes_gcm` use or `aes-gcm`
//! Cargo dependency (plain or renamed) outside this module
//! (`scripts/check-single-aead.sh`). Callers may still *name* the
//! cipher type — via this module's [`Aes256Gcm`] re-export, never the
//! crate itself.
//!
//! What this module owns: nonce generation (`OsRng`, fresh per seal),
//! the blob layout, and the minimum-length check. What callers own:
//! key management (single key vs keyring), any outer encoding
//! (base64url for cookies, raw bytes for DB rows), and mapping
//! [`AeadError`] into their domain error types — so wire formats and
//! error surfaces stay exactly as they were before consolidation.
//!
//! No associated data is used: both existing envelopes bind context via
//! separate authenticated columns/claims (`key_id` column, `exp` claim),
//! not AAD. If a future caller needs AAD, add `seal_with_aad`/
//! `open_with_aad` beside these rather than widening every call site.

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Key, KeyInit, Nonce};
use thiserror::Error;

// Re-exported so callers (the waygate-as keyring) can name the cipher type
// without depending on `aes-gcm` themselves — the tripwire forbids any
// direct `aes_gcm` use outside this module.
pub use aes_gcm::Aes256Gcm;

/// Build a cipher from raw 32-byte key material. The only way callers
/// construct one — key *management* (single key, keyring, rotation)
/// stays in the caller.
pub fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

/// Nonce length AES-GCM uses here (96-bit, the recommended size).
pub const NONCE_LEN: usize = 12;

/// GCM authentication tag length.
pub const TAG_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("encrypt: {0}")]
    Encrypt(String),
    #[error("decrypt: {0}")]
    Decrypt(String),
    #[error("blob too short to contain nonce and tag")]
    Malformed,
}

/// Encrypt `plaintext`, returning `nonce || ciphertext || tag`.
/// The nonce is fresh-random (`OsRng`) per call.
pub fn seal(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AeadError::Encrypt(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `nonce || ciphertext || tag` blob produced by [`seal`]
/// (or by either pre-consolidation implementation — the framing is
/// unchanged, so existing cookies and DB rows stay decryptable).
pub fn open(cipher: &Aes256Gcm, blob: &[u8]) -> Result<Vec<u8>, AeadError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(AeadError::Malformed);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|e| AeadError::Decrypt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher(key: [u8; 32]) -> Aes256Gcm {
        super::cipher(&key)
    }

    #[test]
    fn roundtrip() {
        let c = cipher([1u8; 32]);
        let blob = seal(&c, b"hello").unwrap();
        assert_eq!(open(&c, &blob).unwrap(), b"hello");
    }

    #[test]
    fn nonce_is_random_across_seals() {
        let c = cipher([1u8; 32]);
        assert_ne!(
            seal(&c, b"same").unwrap(),
            seal(&c, b"same").unwrap(),
            "deterministic nonce would leak plaintext equality"
        );
    }

    #[test]
    fn tamper_rejected() {
        let c = cipher([1u8; 32]);
        let mut blob = seal(&c, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(open(&c, &blob), Err(AeadError::Decrypt(_))));
    }

    #[test]
    fn wrong_key_rejected() {
        let blob = seal(&cipher([1u8; 32]), b"secret").unwrap();
        assert!(matches!(
            open(&cipher([2u8; 32]), &blob),
            Err(AeadError::Decrypt(_))
        ));
    }

    #[test]
    fn truncated_blob_is_malformed_not_panic() {
        let c = cipher([1u8; 32]);
        for len in 0..(NONCE_LEN + TAG_LEN) {
            assert!(matches!(
                open(&c, &vec![0u8; len]),
                Err(AeadError::Malformed)
            ));
        }
    }
}
