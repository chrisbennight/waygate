//! Upstream session identity resolution and lifetime guards — split out of
//! `pool/mod.rs`. Child module of [`super`], so no visibility changes.

use super::*;
use crate::catalog_probe::catalog_probe_identity;

/// Install the synthetic catalog identity for the boot discovery session.
/// Privileged catalog groups require a signer and a session that no caller can
/// reuse because an upstream may retain initialize-time authorization in MCP
/// session state.
pub(super) fn install_catalog_probe_identity(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    identity_cell: Option<&IdentityCell>,
) -> Result<Option<CellClearGuard>, DialError> {
    let groups = manifest
        .auth
        .as_ref()
        .map(|auth| auth.catalog_probe_groups.as_slice())
        .unwrap_or_default();
    if !groups.is_empty() && matches!(resolve_isolation(manifest), SessionIsolation::Reuse) {
        return Err(DialError::CatalogProbeGroupsRequirePerCall {
            server: manifest.name.clone(),
        });
    }
    if !groups.is_empty() && issuer.is_none() {
        return Err(DialError::CatalogProbeGroupsRequireIdentity {
            server: manifest.name.clone(),
        });
    }
    Ok(identity_cell.map(|cell| {
        cell.set(catalog_probe_identity(&manifest.name, groups));
        CellClearGuard { cell: cell.clone() }
    }))
}

/// Clears an identity cell if a request panics, is cancelled, or returns.
pub(super) struct CellClearGuard {
    pub(super) cell: IdentityCell,
}

impl Drop for CellClearGuard {
    fn drop(&mut self) {
        self.cell.clear();
    }
}

pub(super) struct SerializerDepthGuard {
    pub(super) server: String,
}

impl Drop for SerializerDepthGuard {
    fn drop(&mut self) {
        waygate_telemetry::metrics::identity_cell_queue_dec(&self.server);
    }
}

/// Co-located store + crypto handles for Tier-A subject-token lookup.
/// Bundled because every call site that needs the store also needs
/// the crypto (decrypting the envelope) — avoids parallel `Option<X>`
/// fields that could disagree at construction time.
#[derive(Clone)]
pub(super) struct UpstreamSessionBundle {
    sessions: SharedUpstreamSessionStore,
    crypto: Arc<UpstreamCrypto>,
    /// The single upstream IdP issuer URL the gateway's AS authenticates
    /// against. Stored on the bundle so the pool doesn't reach into
    /// `AsConfig` from here (waygate-upstream stays oblivious to the
    /// AS's broader config shape).
    upstream_issuer: String,
    /// Refresh-on-demand handle. When the stored access
    /// token's `access_expires_at` is past now-plus-skew, the read
    /// path calls `refresher.refresh(...)` to mint a fresh envelope
    /// (and UPSERT it) before serving the per-call subject token.
    /// `None` is permitted so the disconnected-test pool and the
    /// pre-refresher integration tests can still construct a bundle;
    /// production always wires a `Some(...)`.
    refresher: Option<SharedSessionRefresher>,
}

impl UpstreamPool {
    /// Attach the Tier-A subject-token resolver. When set, every
    /// identity-forwarding `call_tool` consults
    /// `sessions.get(principal.sub, upstream_issuer)`, decrypts the
    /// envelope with `crypto`, and threads the upstream access token
    /// into the per-call [`IdentityContext`]. See the
    /// `upstream_sessions` field doc for the full semantics.
    ///
    /// `upstream_issuer` is the URL of the single upstream IdP the
    /// gateway's AS authenticates against (e.g. the Authentik tenant's
    /// issuer URL — `AsConfig::upstream_issuer`). Stored on the pool
    /// because `IdentityContext` already carries the *per-upstream*
    /// audience, not the IdP issuer; we don't want every manifest to
    /// repeat the IdP URL.
    pub fn with_upstream_sessions(
        mut self,
        sessions: SharedUpstreamSessionStore,
        crypto: Arc<UpstreamCrypto>,
        upstream_issuer: String,
        refresher: Option<SharedSessionRefresher>,
    ) -> Self {
        self.upstream_sessions = Some(UpstreamSessionBundle {
            sessions,
            crypto,
            upstream_issuer,
            refresher,
        });
        self
    }

    /// Best-effort Tier-A subject-token resolution. Returns the
    /// decrypted upstream access token from `user_upstream_sessions`
    /// when one exists and is still valid; returns `None` (and logs
    /// the cause) on any failure so the augmenter falls back to
    /// `principal.raw_token` as the existing path did.
    ///
    /// When the stored access token is past `now() + skew`, this
    /// helper calls the bundled [`SharedSessionRefresher`] to
    /// (atomically) refresh against the upstream IdP and UPSERT the
    /// fresh envelope. If the refresher returns success, the fresh
    /// access token is used for this call. If it returns
    /// `RefreshError::RefreshTokenRevoked` (the refresh token aged
    /// out at the IdP), the refresher has already removed the row;
    /// we fall back to `raw_token`. Other refresh errors (transport,
    /// IdP 5xx, encrypt) also fall back — the per-call response
    /// shape stays "either Tier-A succeeds or we forward whatever
    /// raw_token the caller arrived with."
    ///
    /// `server` is only used for tracing context — the lookup itself
    /// is keyed on the bundled `upstream_issuer` (one IdP for the
    /// whole gateway, today).
    /// Turn a manifest's `tier_c_peer: <id>`
    /// into the `aud` claim for the per-call identity JWT.
    /// Returns the cached peer's `issuer` URL — the value the
    /// remote MCP gateway uses as its own audience claim, and
    /// what their `PeerJwtValidator` will match
    /// against `iss` on the outbound JWT we mint.
    ///
    /// Fail-closed in three places:
    /// 1. No `peer_jwks_cache` wired (operator forgot
    ///    `with_peer_jwks_cache` at the composition root) —
    ///    refuse so a misconfigured deployment can't
    ///    accidentally fall through to the Tier-B server-name
    ///    audience.
    /// 2. Peer present in the registry but not yet in the cache
    ///    (refresh hasn't completed, or the peer's JWKS fetch
    ///    is failing) — refuse rather than mint a token the
    ///    remote can't verify.
    /// 3. Peer id unknown (admin deleted the registration
    ///    after the manifest was loaded) — same refusal,
    ///    same reasoning.
    ///
    /// All three return [`McpError::internal_error`] so the
    /// JSON-RPC client gets a structured "this gateway can't
    /// fulfill the request" rather than a silent 401 dance at
    /// the remote peer.
    pub(super) async fn resolve_tier_c_audience(
        &self,
        server: &str,
        peer_id: ::uuid::Uuid,
        sub: &str,
    ) -> Result<String, McpError> {
        let Some(cache) = self.peer_jwks_cache.as_ref() else {
            tracing::warn!(
                %server,
                %peer_id,
                %sub,
                "tier_c_peer requested but no peer_jwks_cache wired in this pool; refusing",
            );
            return Err(McpError::internal_error(
                format!(
                    "upstream `{server}` configured with `tier_c_peer:` but this \
                     gateway was built without a peer JWKS cache. Wire \
                     `with_peer_jwks_cache` at the composition root or remove the \
                     `tier_c_peer:` field from the manifest."
                ),
                None,
            ));
        };
        match cache.get_by_peer_id(peer_id).await {
            Some(cached) => {
                tracing::debug!(
                    %server,
                    %peer_id,
                    peer_tenant = %cached.tenant_id,
                    peer_issuer = %cached.issuer,
                    trust_tier = cached.trust_tier.as_str(),
                    %sub,
                    "tier_c peer resolved; identity JWT will carry peer-tenant audience",
                );
                Ok(cached.issuer.clone())
            }
            None => {
                tracing::warn!(
                    %server,
                    %peer_id,
                    %sub,
                    "tier_c_peer not in cache (deleted, JWKS fetch failing, or refresh pending); \
                     refusing call",
                );
                Err(McpError::internal_error(
                    format!(
                        "upstream `{server}` requires Tier-C peer `{peer_id}` but no \
                         cached JWKS entry was found. The peer may have been deleted \
                         from `federated_peers`, its JWKS endpoint may be failing, or \
                         the periodic refresh hasn't completed yet. Check \
                         `gateway_peer_jwks_refresh_*` metrics."
                    ),
                    None,
                ))
            }
        }
    }

    pub(super) async fn resolve_tier_a_subject_token(
        &self,
        server: &str,
        sub: &str,
    ) -> Option<String> {
        let bundle = self.upstream_sessions.as_ref()?;
        let row = match bundle.sessions.get(sub, &bundle.upstream_issuer).await {
            Ok(Some(row)) => row,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(
                    %server,
                    %sub,
                    error = %e,
                    "tier-a session lookup failed; falling back to raw_token",
                );
                return None;
            }
        };
        // Skew window: don't use a token that's within 30 seconds of
        // expiry — even a fast upstream round-trip can land after the
        // token's expiry timestamp. When the bundle has a refresher
        // attached this branch refreshes and uses the fresh token
        // instead of skipping and falling back.
        let skew = time::Duration::seconds(30);
        if row.access_expires_at <= time::OffsetDateTime::now_utc() + skew {
            return self
                .refresh_and_use(bundle, server, sub, &row.tokens_ciphertext, &row.key_id)
                .await;
        }
        // Route decrypt to the keyring entry matching the row's
        // stamped `key_id`. After an operator rotates the active
        // key, rows still encrypted under the previous key remain
        // decryptable as long as the old key stays in the ring; the
        // background re-encrypt sweeper migrates them forward over
        // time.
        let plaintext = match bundle.crypto.decrypt(&row.key_id, &row.tokens_ciphertext) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    %server,
                    %sub,
                    error = %e,
                    "tier-a session ciphertext failed to decrypt; falling back to raw_token",
                );
                return None;
            }
        };
        match serde_json::from_slice::<UpstreamTokens>(&plaintext) {
            Ok(envelope) => Some(envelope.access_token),
            Err(e) => {
                tracing::warn!(
                    %server,
                    %sub,
                    error = %e,
                    "tier-a session plaintext failed JSON parse; falling back to raw_token",
                );
                None
            }
        }
    }

    /// Drive a refresh-on-demand round-trip when the
    /// stored access token is past expiry, and return the fresh access
    /// token on success. Returns `None` (caller falls back to
    /// `raw_token`) on bundle missing a refresher (test / disconnected
    /// pool), on `RefreshError::RefreshTokenRevoked` (refresh token
    /// aged out at the IdP; the refresher has already removed the
    /// row), or on any other refresh failure (transport / IdP 5xx /
    /// encrypt / store failure) — the last category logs at WARN so
    /// an operator can debug.
    async fn refresh_and_use(
        &self,
        bundle: &UpstreamSessionBundle,
        server: &str,
        sub: &str,
        current_ciphertext: &[u8],
        current_key_id: &str,
    ) -> Option<String> {
        let Some(refresher) = bundle.refresher.as_ref() else {
            tracing::debug!(
                %server,
                %sub,
                "tier-a session near-expiry but no refresher wired; falling back to raw_token",
            );
            return None;
        };
        match refresher
            .refresh(
                sub,
                &bundle.upstream_issuer,
                current_ciphertext,
                current_key_id,
            )
            .await
        {
            Ok(fresh) => {
                tracing::debug!(
                    %server,
                    %sub,
                    "tier-a session refreshed on demand; using fresh access token",
                );
                Some(fresh.access_token)
            }
            Err(RefreshError::RefreshTokenRevoked { .. }) => {
                tracing::info!(
                    %server,
                    %sub,
                    "tier-a refresh-token revoked at IdP; row dropped; falling back to raw_token",
                );
                None
            }
            // A stored envelope with no
            // refresh_token field is a configuration artifact (some
            // OIDC clients are single-use-only), not an error worth
            // alerting on every call. DEBUG instead of WARN so it
            // doesn't fill operator logs on every Tier-A call by
            // such a client.
            Err(e @ RefreshError::NoRefreshToken) => {
                tracing::debug!(
                    %server,
                    %sub,
                    error = %e,
                    "tier-a session has no refresh_token; falling back to raw_token",
                );
                None
            }
            Err(e) => {
                tracing::warn!(
                    %server,
                    %sub,
                    error = %e,
                    "tier-a refresh-on-demand failed; falling back to raw_token",
                );
                None
            }
        }
    }

    /// Pre-flight the RFC 8693 exchange in the pool
    /// (instead of inside `IdentityAugmenter::headers()`) so a
    /// failure becomes observable at the dispatch-refusing layer
    /// rather than a silent "forward without Authorization" inside
    /// the augmenter. Returns the downscoped bearer plaintext on
    /// success, `None` on any failure. The
    /// `tier_a_required` fail-closed gate runs against this value;
    /// keeping the exchange call here is what makes the gate
    /// enforceable.
    ///
    /// Returns `None` (caller's `enforce_tier_a_required` may refuse,
    /// or the augmenter falls back to Tier-B / on-the-fly exchange
    /// for non-required upstreams) when the pool wasn't built with an
    /// `ExchangeBundle`, the upstream's manifest has no `exchange:`
    /// settings, the subject token chain (stored or `principal.raw_token`)
    /// produced no value, or the exchange call itself fails.
    pub(super) async fn preflight_exchange(
        &self,
        server: &str,
        principal: &Principal,
        exchange_settings: Option<&ExchangeSettings>,
        stored_upstream_subject_token: Option<&str>,
    ) -> Option<String> {
        let bundle = self.exchange.as_ref()?;
        let cfg = exchange_settings?;
        let subject = stored_upstream_subject_token.or(principal.raw_token.as_deref())?;
        let scope = cfg.scope.as_deref();
        let exchange = &bundle.client;
        match bundle
            .cache
            .get_or_exchange(subject, &cfg.audience, scope, || {
                exchange.exchange(waygate_oidc::ExchangeRequest {
                    subject_token: subject,
                    audience: &cfg.audience,
                    scope,
                })
            })
            .await
        {
            Ok(exchanged) => Some(exchanged.access_token),
            Err(e) => {
                tracing::warn!(
                    %server,
                    user = %principal.sub,
                    audience = %cfg.audience,
                    error = %e,
                    "tier-a pre-flight exchange failed",
                );
                None
            }
        }
    }
}

/// Fail-closed refusal gates for manifests that demand identity minting
/// this pool cannot perform (`tier_a_required`, `tier_c_peer:`), moved
/// verbatim from the dispatch path. Runs before any breaker, identity, or
/// dial cost so the operator gets one clear signal instead of a silent
/// downgraded dispatch or a misleading remote 401.
pub(super) fn refuse_identityless_tiers(
    server: &str,
    snapshot: &crate::UpstreamManifest,
    forwards_identity: bool,
    principal: Option<&waygate_oidc::Principal>,
) -> Result<(), rmcp::ErrorData> {
    if snapshot.tier_a_required {
        let principal_sub = principal.map(|p| p.sub.as_str()).unwrap_or("<anonymous>");
        if !forwards_identity {
            tracing::warn!(
                %server,
                user = %principal_sub,
                "tier_a_required=true but pool was built without identity forwarding; refusing dispatch",
            );
            return Err(McpError::internal_error(
                format!(
                    "upstream `{server}` requires Tier-A but this gateway was built \
                     without identity forwarding (no GATEWAY_IDENTITY_*). Configure \
                     the AS + identity issuer or relax `tier_a_required` on the manifest."
                ),
                None,
            ));
        }
        if principal.is_none() {
            return Err(McpError::internal_error(
                format!(
                    "upstream `{server}` requires Tier-A but the call arrived without \
                     a principal (auth disabled). Tier-A enforcement needs an OAuth-\
                     authenticated caller."
                ),
                None,
            ));
        }
    }

    // `tier_c_peer:` MUST refuse dispatch loud when the
    // pool can't actually mint the peer JWT. If the resolver
    // lived inside the `(forwards_identity,
    // Some(principal))` match arm only, calls reaching
    // the `_ => None` branch (no identity issuer, no
    // principal, stdio transport) would silently go out as
    // raw upstream POSTs without the Tier-C
    // Authorization header. A manifest that declares
    // Tier-C MUST get a gateway-side refusal, not a
    // misleading 401 at the remote.
    if snapshot.tier_c_peer.is_some() {
        let principal_sub = principal.map(|p| p.sub.as_str()).unwrap_or("<anonymous>");
        if !forwards_identity {
            tracing::warn!(
                %server,
                user = %principal_sub,
                "tier_c_peer set but pool was built without identity forwarding; refusing dispatch",
            );
            return Err(McpError::internal_error(
                format!(
                    "upstream `{server}` configured with `tier_c_peer:` but this gateway \
                     was built without an identity issuer (no GATEWAY_IDENTITY_*). \
                     Configure the AS + identity issuer or remove `tier_c_peer:` from \
                     the manifest."
                ),
                None,
            ));
        }
        if principal.is_none() {
            return Err(McpError::internal_error(
                format!(
                    "upstream `{server}` configured with `tier_c_peer:` but the call \
                     arrived without a principal (auth disabled). Tier-C enforcement \
                     needs an authenticated caller."
                ),
                None,
            ));
        }
    }
    Ok(())
}
