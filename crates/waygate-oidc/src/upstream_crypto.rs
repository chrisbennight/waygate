//! AES-256-GCM envelope for upstream tokens stored at rest, with a
//! key-id-versioned keyring.
//!
//! The gateway caches the upstream IdP access + refresh tokens on
//! `user_upstream_sessions` (and one-shot on `oauth_codes`) so it can
//! drive Tier-A identity chaining on subsequent MCP calls. Those
//! tokens grant full access to the user's upstream session —
//! encrypting at rest makes a stolen DB dump useless without the
//! operator's `GATEWAY_UPSTREAM_TOKEN_KEY_*` material.
//!
//! ## Keyring
//!
//! [`UpstreamCrypto`] now holds a map of `key_id` → AES-256-GCM
//! cipher plus an `active_id`. New writes encrypt with the active
//! key and stamp the row's `key_id` column; reads decrypt with the
//! key matching the stored `key_id`. Rotation is operator-driven:
//! add the new key alongside the old, flip the active id, run the
//! background re-encrypt job to migrate old-key rows.
//!
//! Format on the wire: `nonce (12 bytes) || ciphertext || tag`. The
//! `key_id` lives in a column, NOT in the blob — keeping the format
//! identical to the pre-keyring single-key era means a deployment
//! encrypted under one key that just upgrades the binary stays
//! decryptable without a re-encrypt pass (every existing row gets
//! `key_id='v1'` from the migration default, and the operator pins
//! `GATEWAY_UPSTREAM_TOKEN_KEY_V1` to the bytes their current
//! single-key env var holds).

use std::collections::HashMap;

use crate::aead::{self, Aes256Gcm};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use thiserror::Error;

/// Default key id used when an operator hasn't migrated to the
/// multi-key env-var shape and is still setting the legacy
/// `GATEWAY_UPSTREAM_TOKEN_KEY` env var. The migration's column
/// default uses the same literal so existing rows stay decryptable.
pub const LEGACY_KEY_ID: &str = "v1";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decode base64 key: {0}")]
    DecodeKey(#[from] base64::DecodeError),
    #[error("key must decode to exactly 32 bytes (got {0})")]
    WrongKeyLength(usize),
    #[error("encrypt: {0}")]
    Encrypt(String),
    #[error("decrypt: {0}")]
    Decrypt(String),
    #[error("ciphertext too short to contain nonce")]
    Malformed,
    /// Stored row stamped with a `key_id` the keyring doesn't know
    /// about. Operator decommissioned the key before re-encrypting
    /// every row, OR a row arrived from a backup that used a key
    /// not present in this deployment's config. Surface so the
    /// per-call read path fails closed instead of silently treating
    /// the row as unavailable.
    #[error("unknown key id `{0}` in stored row; keyring has no matching key")]
    UnknownKeyId(String),
    /// Builder rejected a keyring missing its active key or with no
    /// keys at all. Surfaced at boot, not per-call.
    #[error("invalid keyring: {0}")]
    InvalidKeyring(String),
}

/// Encrypt/decrypt upstream tokens under a versioned keyring.
#[derive(Clone)]
pub struct UpstreamCrypto {
    keys: HashMap<String, Aes256Gcm>,
    active_id: String,
}

impl std::fmt::Debug for UpstreamCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never show key material; surface the keyring shape so an
        // operator inspecting boot logs can confirm the right number
        // of keys loaded under the right ids.
        f.debug_struct("UpstreamCrypto")
            .field("active_id", &self.active_id)
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl UpstreamCrypto {
    /// Build a single-key keyring with `active_id = LEGACY_KEY_ID`.
    /// Shorthand for the legacy single-key deployment shape; production
    /// composition wires the keyring from
    /// `waygate_as::config::AsConfig::upstream_token_keys`.
    pub fn from_key_bytes(key: [u8; 32]) -> Self {
        Self::single_key(LEGACY_KEY_ID, key)
    }

    /// Build a single-key keyring under an arbitrary id. Convenience
    /// for tests and the legacy-env-var compat path.
    pub fn single_key(id: impl Into<String>, key: [u8; 32]) -> Self {
        let id = id.into();
        let mut keys = HashMap::with_capacity(1);
        keys.insert(id.clone(), aead::cipher(&key));
        Self {
            keys,
            active_id: id,
        }
    }

    /// Build a single-key keyring from a base64-encoded key. Accepts
    /// both padded and unpadded standard base64 (tolerant of what
    /// operators paste into Infisical). Use [`Self::from_keyring`] when
    /// multiple keys are configured.
    pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
        let bytes = decode_key_base64(encoded)?;
        Ok(Self::from_key_bytes(bytes))
    }

    /// Build from an operator-supplied set of (id → base64 key)
    /// pairs and the active id. Verifies the active id is present
    /// in the map. Used by `waygate-server::main` at boot.
    pub fn from_keyring<I>(entries: I, active_id: impl Into<String>) -> Result<Self, CryptoError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let active_id = active_id.into();
        let mut keys: HashMap<String, Aes256Gcm> = HashMap::new();
        for (id, b64) in entries {
            let bytes = decode_key_base64(&b64)?;
            keys.insert(id, aead::cipher(&bytes));
        }
        if keys.is_empty() {
            return Err(CryptoError::InvalidKeyring(
                "keyring must contain at least one key".into(),
            ));
        }
        if !keys.contains_key(&active_id) {
            return Err(CryptoError::InvalidKeyring(format!(
                "active key id `{active_id}` is not present in the keyring; \
                 supplied ids: {:?}",
                keys.keys().collect::<Vec<_>>()
            )));
        }
        Ok(Self { keys, active_id })
    }

    /// The id of the key currently used for new encrypts. Stamped onto
    /// every row written by `waygate-as::sessions` and surfaced via the
    /// admin list endpoint so an operator can confirm a rotation has
    /// taken effect.
    pub fn active_id(&self) -> &str {
        &self.active_id
    }

    /// All keyring ids the gateway can currently decrypt under.
    /// Used by the re-encrypt sweeper to filter its batch query so
    /// rows stamped with a decommissioned key don't starve the
    /// loop.
    pub fn key_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    /// Encrypt under the active key. Returns the ciphertext bytes. The
    /// caller is expected to persist [`Self::active_id`] alongside.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = self
            .keys
            .get(&self.active_id)
            .expect("active key always present by construction");
        aead::seal(cipher, plaintext).map_err(map_aead_err)
    }

    /// Decrypt under the key matching `key_id`. Returns
    /// [`CryptoError::UnknownKeyId`] when the stored id isn't in the
    /// current keyring (operator removed a key without first re-
    /// encrypting every row). The Tier-A read path treats this as
    /// "stored token unavailable" and falls back per the manifest's
    /// `tier_a_required` posture.
    pub fn decrypt(&self, key_id: &str, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = self
            .keys
            .get(key_id)
            .ok_or_else(|| CryptoError::UnknownKeyId(key_id.to_owned()))?;
        aead::open(cipher, blob).map_err(map_aead_err)
    }
}

/// Map the shared envelope's errors onto this module's pre-consolidation
/// error surface (the read path matches on these variants).
fn map_aead_err(e: aead::AeadError) -> CryptoError {
    match e {
        aead::AeadError::Encrypt(m) => CryptoError::Encrypt(m),
        aead::AeadError::Decrypt(m) => CryptoError::Decrypt(m),
        aead::AeadError::Malformed => CryptoError::Malformed,
    }
}

fn decode_key_base64(encoded: &str) -> Result<[u8; 32], CryptoError> {
    let trimmed = encoded.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))?;
    if decoded.len() != 32 {
        return Err(CryptoError::WrongKeyLength(decoded.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> UpstreamCrypto {
        UpstreamCrypto::from_key_bytes([42u8; 32])
    }

    #[test]
    fn roundtrip() {
        let c = key();
        let ct = c.encrypt(b"hello world").unwrap();
        assert_eq!(c.decrypt(c.active_id(), &ct).unwrap(), b"hello world");
    }

    #[test]
    fn nonce_is_random_across_encrypts() {
        let c = key();
        let a = c.encrypt(b"same").unwrap();
        let b = c.encrypt(b"same").unwrap();
        assert_ne!(a, b, "deterministic nonce would leak equality");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let c = key();
        let mut ct = c.encrypt(b"top secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(c.decrypt(c.active_id(), &ct).is_err());
    }

    #[test]
    fn from_base64_accepts_padded_and_unpadded() {
        let raw = [7u8; 32];
        let padded = base64::engine::general_purpose::STANDARD.encode(raw);
        let unpadded = STANDARD_NO_PAD.encode(raw);
        let a = UpstreamCrypto::from_base64(&padded).unwrap();
        let b = UpstreamCrypto::from_base64(&unpadded).unwrap();
        let ct = a.encrypt(b"x").unwrap();
        assert_eq!(b.decrypt(b.active_id(), &ct).unwrap(), b"x");
    }

    #[test]
    fn from_base64_rejects_wrong_length() {
        let too_short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(matches!(
            UpstreamCrypto::from_base64(&too_short),
            Err(CryptoError::WrongKeyLength(16))
        ));
    }

    /// Two-key keyring: encrypt under active `v2`, decrypt the same
    /// blob via key id `v2`. A row stamped `v1` decrypts via the old
    /// key. This is the rotation-in-progress shape: production writes
    /// under v2 while the background re-encrypt job migrates legacy
    /// v1 rows.
    #[test]
    fn keyring_routes_encrypt_to_active_decrypt_by_stored_id() {
        let v1_key = [1u8; 32];
        let v2_key = [2u8; 32];
        let crypto = UpstreamCrypto::from_keyring(
            [
                (
                    "v1".into(),
                    base64::engine::general_purpose::STANDARD.encode(v1_key),
                ),
                (
                    "v2".into(),
                    base64::engine::general_purpose::STANDARD.encode(v2_key),
                ),
            ],
            "v2",
        )
        .unwrap();
        assert_eq!(crypto.active_id(), "v2");

        // New write under v2.
        let new_ct = crypto.encrypt(b"new world").unwrap();
        assert_eq!(crypto.decrypt("v2", &new_ct).unwrap(), b"new world");

        // Legacy row stamped v1 still decryptable (simulate by
        // encrypting with v1's cipher directly).
        let v1_cipher = aead::cipher(&v1_key);
        let legacy_ct = aead::seal(&v1_cipher, b"old world").unwrap();
        assert_eq!(crypto.decrypt("v1", &legacy_ct).unwrap(), b"old world");
    }

    #[test]
    fn keyring_refuses_when_active_missing_from_map() {
        let err = UpstreamCrypto::from_keyring(
            [(
                "v1".into(),
                base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            )],
            "v2",
        )
        .expect_err("active id must be present in keyring");
        assert!(matches!(err, CryptoError::InvalidKeyring(_)));
    }

    #[test]
    fn keyring_refuses_empty() {
        let err = UpstreamCrypto::from_keyring(std::iter::empty(), "v1")
            .expect_err("keyring must have at least one key");
        assert!(matches!(err, CryptoError::InvalidKeyring(_)));
    }

    #[test]
    fn decrypt_unknown_key_id_fails_closed() {
        let crypto = key();
        let ct = crypto.encrypt(b"x").unwrap();
        let err = crypto
            .decrypt("v99", &ct)
            .expect_err("unknown key id must not silently fall through");
        assert!(matches!(err, CryptoError::UnknownKeyId(id) if id == "v99"));
    }

    #[test]
    fn legacy_single_key_constructor_stamps_v1() {
        let c = UpstreamCrypto::from_key_bytes([1u8; 32]);
        assert_eq!(c.active_id(), LEGACY_KEY_ID);
    }

    /// Ciphertext produced by the pre-consolidation `encrypt_with` (its
    /// nonce came from `rand::rng()`) under key `[42u8; 32]`. The shared
    /// envelope must keep decrypting it — live `user_upstream_sessions`
    /// rows encrypted before the deploy must survive it.
    #[test]
    fn pre_consolidation_blob_still_decrypts() {
        let c = key();
        let blob = base64::engine::general_purpose::STANDARD
            .decode("YIlQ1MlLANQxb0xF/us9lsmRwsLekTZRdMJNgW7/HKLJgY/iuXIGUx53SPwsZL2T2MYD")
            .unwrap();
        assert_eq!(
            c.decrypt(c.active_id(), &blob).unwrap(),
            b"ws2-aead-compat-fixture"
        );
    }
}
