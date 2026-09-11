//! Refresh-on-demand for `user_upstream_sessions`.
//!
//! When the upstream access token in a stored session
//! has expired (or is within the skew window), the upstream call
//! path can hand the ciphertext to a [`SessionRefresher`], which:
//!
//! 1. Decrypts the envelope and extracts the stored `refresh_token`.
//! 2. POSTs the upstream IdP's token endpoint with the `refresh_token`
//!    grant (RFC 6749 §6).
//! 3. Re-encrypts the fresh envelope (Authentik rotates the
//!    `refresh_token` on every refresh; we keep the new one too).
//! 4. UPSERTs the result back to `user_upstream_sessions` so the next
//!    call hits the fresh ciphertext directly.
//! 5. Returns the plaintext envelope to the caller for immediate use.
//!
//! On `invalid_grant` / `expired_token` (the refresh token has been
//! revoked at the IdP, or has aged out of its own TTL), the refresher
//! calls [`UpstreamSessionStore::revoke_if_ciphertext_matches`] so the
//! row doesn't keep attempting failed refreshes — and returns
//! [`RefreshError::RefreshTokenRevoked`] so the caller can fall back
//! to the existing `principal.raw_token` path. The *conditional*
//! revoke (instead of the unconditional `revoke`) is load-bearing:
//! two concurrent expired-session calls to different Tier-A
//! upstreams could each POST the IdP with the same refresh token,
//! the winner's UPSERT writes a fresh envelope, and an unconditional
//! revoke from the loser would clobber the winner's fresh row.
//!
//! Bundles the IdP creds (token endpoint, client_id, client_secret)
//! at construction so the call path doesn't have to plumb them
//! per-call. The bundle stays on `UpstreamPool`'s session bundle
//! alongside the store and crypto keyring.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use waygate_oidc::{refresh_access_token, RefreshParams, TokenError};

use crate::callback::UpstreamTokens;
use crate::sessions::{NewSessionRow, SharedUpstreamSessionStore};
use crate::UpstreamCrypto;

/// Cooperative co-located bundle: store + crypto + IdP creds. One
/// instance per gateway boot; `Arc`-shared with [`UpstreamPool`] via
/// the session bundle so per-call refresh is a method call, not a
/// new construction.
pub struct SessionRefresher {
    sessions: SharedUpstreamSessionStore,
    crypto: Arc<UpstreamCrypto>,
    http: reqwest::Client,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
}

impl SessionRefresher {
    pub fn new(
        sessions: SharedUpstreamSessionStore,
        crypto: Arc<UpstreamCrypto>,
        http: reqwest::Client,
        token_endpoint: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Self {
            sessions,
            crypto,
            http,
            token_endpoint,
            client_id,
            client_secret,
        }
    }

    /// Refresh the access token for `(sub, upstream_issuer)`.
    ///
    /// `current_ciphertext` is the most recently fetched envelope from
    /// the store; the caller already has it in hand so we don't
    /// re-fetch (avoids a redundant DB round-trip). `current_key_id`
    /// is the keyring id under which `current_ciphertext` was
    /// encrypted — also from the same `StoredSessionRow`. The
    /// refresh re-encrypts under the *active* key (which may differ
    /// from `current_key_id` during a rotation window), so the new
    /// row's `key_id` advances as a side effect.
    pub async fn refresh(
        &self,
        sub: &str,
        upstream_issuer: &str,
        current_ciphertext: &[u8],
        current_key_id: &str,
    ) -> Result<UpstreamTokens, RefreshError> {
        // Decrypt the *current* envelope using the key that was
        // active when the row was last written. With the keyring,
        // `current_key_id` may be a retired-but-retained key — the
        // refresh path still needs to decrypt to recover the
        // refresh_token before re-encrypting under the active key.
        let plaintext = self
            .crypto
            .decrypt(current_key_id, current_ciphertext)
            .map_err(RefreshError::Decrypt)?;
        let envelope: UpstreamTokens = serde_json::from_slice(&plaintext)
            .map_err(|e| RefreshError::EnvelopeParse(e.to_string()))?;
        let Some(refresh_token) = envelope.refresh_token.as_deref() else {
            // No refresh token on file (some OIDC clients are
            // configured single-use-only, or the IdP omitted it).
            // The row can't be refreshed; the caller falls back.
            return Err(RefreshError::NoRefreshToken);
        };

        // POST the upstream IdP. Map the wire-level token errors into
        // our typed `RefreshError`: anything that comes back with
        // `invalid_grant` / `expired_token` means the refresh token
        // itself is dead, and we should revoke the row.
        let resp = match refresh_access_token(
            &self.http,
            RefreshParams {
                token_endpoint: &self.token_endpoint,
                client_id: &self.client_id,
                client_secret: &self.client_secret,
                refresh_token,
            },
        )
        .await
        {
            Ok(r) => r,
            Err(TokenError::Status { status, body }) => {
                if status.as_u16() == 400 && body_indicates_revoked_grant(&body) {
                    // CONDITIONAL revoke instead of unconditional.
                    // Two concurrent expired-session calls to
                    // different Tier-A upstreams both read the same
                    // row, both POST the IdP with the same
                    // refresh_token; the IdP
                    // rotates, the winner UPSERTs a fresh envelope,
                    // the loser gets `invalid_grant` here. An
                    // unconditional `revoke()` from the loser would
                    // delete the winner's fresh row and the user
                    // would lose their session. `revoke_if_ciphertext_matches`
                    // uses our pre-refresh ciphertext as a CAS
                    // discriminator: when the row's current ciphertext
                    // is the winner's fresh envelope, the WHERE
                    // doesn't match and the DELETE is a safe no-op.
                    // Best-effort: a store failure here is logged
                    // inside the sqlx mapping but doesn't prevent
                    // the caller's fallback.
                    let _ = self
                        .sessions
                        .revoke_if_ciphertext_matches(sub, upstream_issuer, current_ciphertext)
                        .await;
                    return Err(RefreshError::RefreshTokenRevoked { body });
                }
                return Err(RefreshError::Idp { status, body });
            }
            Err(e) => return Err(RefreshError::IdpTransport(e.to_string())),
        };

        // Construct the fresh envelope. The IdP MAY rotate the
        // refresh_token (Authentik does); fall back to the existing
        // one if the response didn't include a fresh value.
        let fresh = UpstreamTokens {
            access_token: resp.access_token,
            refresh_token: resp.refresh_token.or(envelope.refresh_token),
            id_token: resp.id_token.or(envelope.id_token),
            expires_in: resp.expires_in.or(envelope.expires_in),
            scope: resp.scope.or(envelope.scope),
        };

        // Compute the new access expiry. Match the conservative
        // default from `/oauth/callback` (1h when the IdP omits
        // expires_in).
        let access_expires_at = match fresh.expires_in {
            Some(secs) if secs > 0 => OffsetDateTime::now_utc() + time::Duration::seconds(secs),
            _ => OffsetDateTime::now_utc() + time::Duration::hours(1),
        };

        // Re-encrypt and CAS-update. Two race classes to guard
        // against:
        // - Admin DELETE between read and write would let `upsert`
        //   INSERT-resurrect the session. Guarded by
        //   `update_if_exists`.
        // - Admin DELETE → user re-auth via `/oauth/callback`
        //   (upsert-INSERT fresh row R2) → this stale refresh
        //   writes; `update_if_exists` alone would still match on
        //   `(sub, upstream_issuer)` and clobber R2 with the
        //   pre-revoke envelope. Guarded by CAS-on-ciphertext: the
        //   pre-refresh `current_ciphertext` becomes the
        //   discriminator (the row's "version"). When the row was
        //   replaced, the WHERE doesn't match.
        //
        // `Ok(false)` covers both row-gone and row-replaced; in
        // both cases the operator's intent (or the user's fresh
        // login) wins, and the refresher falls through to the
        // no-stored-token path. Same `RevokedDuringRefresh`
        // variant — the caller's behaviour is identical.
        let fresh_bytes =
            serde_json::to_vec(&fresh).map_err(|e| RefreshError::EnvelopeParse(e.to_string()))?;
        let fresh_ciphertext = self
            .crypto
            .encrypt(&fresh_bytes)
            .map_err(RefreshError::Encrypt)?;
        // Stamp the active key id alongside the new
        // ciphertext. During a rotation the refresh path is one of
        // the natural advance points — a row that was previously
        // `key_id='v1'` flips to the new active id on its next
        // refresh, no separate migration sweep needed for sessions
        // that happen to refresh during the rotation window.
        let active_key_id = self.crypto.active_id().to_owned();

        // CAS-update with sweep-race retry.
        //
        // The re-encrypt sweeper writes a
        // re-encrypted copy of the SAME plaintext under the active
        // key. If a refresh raced the sweep and lost the CAS (sweep
        // committed first), the refresh held a freshly-rotated
        // refresh_token rt-B from the IdP, but the row in the DB
        // still contained the *pre-refresh* refresh_token rt-A
        // (re-encrypted by the sweep). Returning RevokedDuringRefresh
        // would lose rt-B, and the next refresh attempt would fail
        // with IdP invalid_grant (rt-A is dead at the IdP), tripping
        // the conditional-revoke path and dropping the row entirely.
        // User loses their durable Tier-A session for no good reason.
        //
        // Fix: on CAS miss, distinguish "sweep race" (row still
        // contains the SAME plaintext we started with, just
        // re-encrypted) from "legitimate replacement" (admin DELETE,
        // user re-auth produced new plaintext). On a sweep race,
        // retry the CAS using the sweep's new ciphertext as the
        // fresh witness so rt-B lands in the row.
        let mut witness: Vec<u8> = current_ciphertext.to_vec();
        // Bounded retry: in the worst case the sweep AND another
        // refresh both race against us, but each attempt advances
        // witness state. 4 attempts is enough cushion for any
        // plausible sweep/refresh interleaving while still bounding
        // the loop.
        const MAX_CAS_ATTEMPTS: usize = 4;
        for attempt in 0..MAX_CAS_ATTEMPTS {
            let updated = self
                .sessions
                .update_if_ciphertext_matches(
                    NewSessionRow {
                        sub,
                        upstream_issuer,
                        tokens_ciphertext: &fresh_ciphertext,
                        key_id: &active_key_id,
                        access_expires_at,
                    },
                    &witness,
                )
                .await
                .map_err(RefreshError::Store)?;
            if updated {
                return Ok(fresh);
            }
            // CAS missed. Inspect the row to decide whether to
            // retry (sweep race) or surrender (legitimate
            // replacement).
            let current = self
                .sessions
                .get(sub, upstream_issuer)
                .await
                .map_err(RefreshError::Store)?;
            let Some(current_row) = current else {
                // Row is gone — admin DELETE between read and
                // write. Respect operator intent; rt-B is lost,
                // but the operator wanted the session burnt.
                tracing::warn!(
                    %sub,
                    %upstream_issuer,
                    "tier-a refresh CAS miss with row absent; admin DELETE \
                     burnt the session — not resurrecting",
                );
                return Err(RefreshError::RevokedDuringRefresh);
            };
            // Decrypt under whatever key the current row's
            // `key_id` points at. May be `active_key_id` (sweep
            // race wrote under v2) or a still-different key (rare,
            // a third writer flipped through key versions).
            let current_plaintext = match self
                .crypto
                .decrypt(&current_row.key_id, &current_row.tokens_ciphertext)
            {
                Ok(p) => p,
                Err(e) => {
                    // The current row's key isn't in our keyring —
                    // unusual but possible if the operator
                    // decommissioned a key. Treat as legitimate
                    // replacement (we can't reason about what's
                    // there) and surrender rt-B.
                    tracing::warn!(
                        %sub,
                        %upstream_issuer,
                        current_key_id = %current_row.key_id,
                        error = %e,
                        "tier-a refresh CAS miss: current row's key is unknown; \
                         not resurrecting",
                    );
                    return Err(RefreshError::RevokedDuringRefresh);
                }
            };
            if current_plaintext == plaintext {
                // Sweep race: the row's plaintext is identical to
                // what we decrypted pre-refresh, so the writer
                // between us and now only re-encrypted, didn't
                // change tokens. We hold rt-B; retry the CAS with
                // the sweep's ciphertext as the new witness.
                tracing::debug!(
                    %sub,
                    %upstream_issuer,
                    attempt,
                    "tier-a refresh CAS miss: sweep-race detected, retrying with \
                     sweep's ciphertext as new witness",
                );
                witness = current_row.tokens_ciphertext;
                continue;
            } else {
                // Plaintext changed: a user re-auth or another
                // refresh produced a new envelope. Their write
                // wins; rt-B is stale relative to the new state.
                tracing::warn!(
                    %sub,
                    %upstream_issuer,
                    attempt,
                    "tier-a refresh CAS miss: row's plaintext was replaced by a \
                     concurrent re-auth or refresh — surrendering rt-B",
                );
                return Err(RefreshError::RevokedDuringRefresh);
            }
        }
        // Ran out of retries. Log loud so an operator notices a
        // pathological sweep/refresh thrash.
        tracing::warn!(
            %sub,
            %upstream_issuer,
            "tier-a refresh CAS retry budget exhausted after {MAX_CAS_ATTEMPTS} attempts",
        );
        Err(RefreshError::RevokedDuringRefresh)
    }

    /// Skew window for "fresh enough." A token expiring within this
    /// many seconds is treated as expired so a long upstream call
    /// doesn't race the expiry. Matches the read-path skew in
    /// `UpstreamPool::resolve_tier_a_subject_token`.
    pub fn skew() -> Duration {
        Duration::from_secs(30)
    }
}

/// IdP error bodies that mean "this refresh token is dead, stop using
/// it." Both phrases come from RFC 6749 §5.2 (`invalid_grant`) and
/// the OAuth WG's `expired_token` extension. Substring match because
/// IdPs phrase the body slightly differently (Authentik sends
/// `{"error":"invalid_grant"}`; some IdPs include a `error_description`
/// field; some return both).
fn body_indicates_revoked_grant(body: &str) -> bool {
    body.contains("invalid_grant") || body.contains("expired_token")
}

pub use waygate_oidc::upstream_session::{RefreshError, SessionRefresh, SharedSessionRefresher};

/// Seam-trait impl: `UpstreamPool` consumes the
/// `waygate_oidc::upstream_session::SessionRefresh` trait object; this
/// concrete refresher is what the composition root injects. Explicit
/// UFCS delegation to the inherent method (no recursion).
#[async_trait::async_trait]
impl SessionRefresh for SessionRefresher {
    async fn refresh(
        &self,
        sub: &str,
        upstream_issuer: &str,
        current_ciphertext: &[u8],
        current_key_id: &str,
    ) -> Result<UpstreamTokens, RefreshError> {
        SessionRefresher::refresh(
            self,
            sub,
            upstream_issuer,
            current_ciphertext,
            current_key_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_grant_body_detection_matches_known_idps() {
        // Authentik sends just the error code.
        assert!(body_indicates_revoked_grant(r#"{"error":"invalid_grant"}"#));
        // Some IdPs send error_description.
        assert!(body_indicates_revoked_grant(
            r#"{"error":"invalid_grant","error_description":"token expired"}"#
        ));
        // OAuth WG extension.
        assert!(body_indicates_revoked_grant(r#"{"error":"expired_token"}"#));
        // Non-matching errors: a 400 with `invalid_request` is a
        // different class of error (the gateway sent a malformed
        // request, NOT the refresh token being dead).
        assert!(!body_indicates_revoked_grant(
            r#"{"error":"invalid_request"}"#
        ));
        // A 500-class body shouldn't be misclassified as "revoked".
        assert!(!body_indicates_revoked_grant("upstream error"));
    }
}
