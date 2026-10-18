//! `StreamableHttpClient` wrapper that injects `X-MCP-Identity: <jwt>` into
//! every upstream HTTP call.
//!
//! rmcp's transport config bakes `auth_header` and `custom_headers` in once
//! at connect time, so to carry a *per-caller* identity we wrap the inner
//! client and read the current caller from a shared [`IdentityCell`] on every
//! method call. `UpstreamPool` pins the cell with a mutex per upstream so
//! concurrent calls to the same server can't step on each other's identity.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::stream::BoxStream;
use http::{HeaderName, HeaderValue};
use rmcp::model::ClientJsonRpcMessage;
use rmcp::transport::streamable_http_client::{
    SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
};
use sse_stream::Sse;

use waygate_manifest_types::IdentityTokenPolicy;
use waygate_oidc::{ExchangeRequest, IdentityIssuer, Principal, TokenCache, TokenExchangeClient};

/// Header we stamp on every upstream request that carries a caller's
/// identity JWT. Lowercase per HTTP convention — `http::HeaderName` stores
/// normalized names internally either way.
pub const IDENTITY_HEADER: HeaderName = HeaderName::from_static("x-mcp-identity");

/// Per-upstream RFC 8693 token-exchange settings — mirrors `ExchangeConfig`
/// in the manifest layer but lives here to keep the client crate oblivious
/// to YAML parsing.
#[derive(Clone, Debug)]
pub struct ExchangeSettings {
    pub audience: String,
    pub scope: Option<String>,
}

/// Who is calling, and which upstream they're calling. Consumed by
/// [`IdentityForwardingClient`] to mint a per-call JWT with the right `aud`
/// and — if `exchange` is populated and a subject token is available —
/// to swap for a downscoped IdP-issued access token.
///
/// Subject-token resolution order (set by `UpstreamPool` before each
/// call):
///
/// 1. `stored_upstream_subject_token`: decrypted access token from
///    `user_upstream_sessions` (the user's actual IdP token,
///    preserved across the gateway's own bearer rotation). Preferred
///    when present.
/// 2. `principal.raw_token`: the gateway-issued bearer the caller
///    arrived with. Fallback when no durable upstream session row
///    exists (or it's expired and refresh-on-demand isn't wired yet).
///
/// Tier-B (`X-MCP-Identity` JWT) is governed by `token_policy` and
/// unaffected by the order above.
#[derive(Clone, Debug)]
pub struct IdentityContext {
    pub principal: Principal,
    pub audience: String,
    /// Opt-in Tier A parameters. Absence means Tier B only (identity JWT).
    pub exchange: Option<ExchangeSettings>,
    /// Decrypted upstream access token from `user_upstream_sessions`,
    /// populated by `UpstreamPool` when a durable session is available
    /// for `(principal.sub, configured upstream_issuer)`. The
    /// `headers()` path prefers this over `principal.raw_token` as the
    /// subject token for RFC 8693 exchange. `None` means no stored
    /// session (caller never logged in via the gateway AS, or the row
    /// expired before this slice's refresh-on-demand follow-up
    /// lands).
    pub stored_upstream_subject_token: Option<String>,
    /// Pre-flighted RFC 8693 exchange result. When
    /// the pool was able to swap the subject token for a downscoped
    /// upstream-IdP-minted bearer before dispatch, the bearer lives
    /// here. The augmenter uses this directly as the Authorization
    /// header. Doing the exchange at
    /// `headers()` time would let exchange failures silently forward
    /// the request without an Authorization header, bypassing the
    /// `tier_a_required` fail-closed posture. Pre-flighting in the
    /// pool surfaces the failure where the dispatch-refusing gate
    /// can act on it.
    pub exchanged_bearer: Option<String>,
    /// When the
    /// manifest set `tier_c_peer: <peer_id>`, this is the
    /// resolved peer's canonical issuer URL (== the remote
    /// gateway's expected audience claim). The augmenter
    /// stamps the minted JWT as `Authorization: Bearer`
    /// (NOT just `X-MCP-Identity`) because the remote
    /// gateway's `PeerJwtValidator` only reads
    /// `Authorization`. `None` ⇒ Tier-B-only header mode
    /// (existing behavior). Mutually exclusive with
    /// `exchange` — Tier-C overrides Tier-A's claim on
    /// `Authorization`; manifest load refuses
    /// `tier_c_peer + exchange` together.
    pub tier_c_audience: Option<String>,
    /// Whether this upstream receives the gateway-signed token in
    /// `X-MCP-Identity`, and which optional claims the token carries,
    /// resolved from the upstream's manifest.
    pub token_policy: IdentityTokenPolicy,
}

/// Shared mailbox that `UpstreamPool::call_tool` fills in before invoking the
/// rmcp worker and clears out after. Cloning is cheap (Arc).
#[derive(Clone, Default)]
pub struct IdentityCell(Arc<Mutex<Option<IdentityContext>>>);

impl IdentityCell {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&self, ctx: IdentityContext) {
        *self.0.lock().expect("identity cell poisoned") = Some(ctx);
    }
    pub fn clear(&self) {
        self.0.lock().expect("identity cell poisoned").take();
    }
    pub fn get(&self) -> Option<IdentityContext> {
        self.0.lock().expect("identity cell poisoned").clone()
    }
}

/// Standalone helper that mints the identity headers for a given caller, so
/// the streamable-HTTP client and the legacy SSE transport stamp identical
/// headers. Holds the issuer + cell + (optional) RFC 8693 client and cache.
///
/// Two modes depending on manifest config:
///   * **Tier B (per server)**: mint a gateway-signed identity JWT and add it
///     as `X-MCP-Identity` when the context's `token_policy` sends it. Cheap,
///     no network round-trip.
///   * **Tier A (opt-in, requires an IdP that speaks RFC 8693)**: if the
///     caller's raw subject token is available and the upstream declares an
///     exchange audience, swap the token at the IdP and add the result as
///     `Authorization: Bearer <downscoped>`. The Tier B header still goes
///     along so upstreams can choose which channel they trust.
#[derive(Clone)]
pub struct IdentityAugmenter {
    issuer: Arc<IdentityIssuer>,
    cell: IdentityCell,
    exchange: Option<Arc<TokenExchangeClient>>,
    cache: Arc<TokenCache>,
}

impl IdentityAugmenter {
    pub fn new(issuer: Arc<IdentityIssuer>, cell: IdentityCell) -> Self {
        Self {
            issuer,
            cell,
            exchange: None,
            cache: Arc::new(TokenCache::default()),
        }
    }

    /// Attach a token-exchange client + shared cache. The same client can be
    /// reused across every upstream; per-upstream audience/scope come in on
    /// the [`IdentityContext`].
    pub fn with_exchange(
        mut self,
        exchange: Arc<TokenExchangeClient>,
        cache: Arc<TokenCache>,
    ) -> Self {
        self.exchange = Some(exchange);
        self.cache = cache;
        self
    }

    /// Cell handle so the pool can populate identity context per-call.
    pub fn cell(&self) -> &IdentityCell {
        &self.cell
    }

    /// Build the identity headers to merge into an outbound upstream request,
    /// based on whatever the cell currently holds. Returns an empty map when
    /// the cell is unset. The pool explicitly installs either its bounded
    /// catalog-probe identity during discovery or the real principal during a
    /// caller dispatch; the transport must not invent an identity outside
    /// those contexts.
    pub async fn headers(&self) -> HashMap<HeaderName, HeaderValue> {
        let mut out: HashMap<HeaderName, HeaderValue> = HashMap::new();
        let Some(ctx) = self.cell.get() else {
            return out;
        };
        // Tier B: the gateway-signed JWT, minted when this upstream receives
        // it in `X-MCP-Identity` or when a Tier C peer assertion needs it.
        // With `tier_c_peer:` the JWT carries the PEER's audience and is ALSO
        // stamped as `Authorization: Bearer`, because the remote gateway's
        // PeerJwtValidator reads only Authorization. The manifest's claim
        // selection applies to both placements.
        let policy = ctx.token_policy;
        if policy.send_header || ctx.tier_c_audience.is_some() {
            let mint_audience = ctx
                .tier_c_audience
                .as_deref()
                .unwrap_or(ctx.audience.as_str());
            let principal = principal_for_token(&ctx.principal, policy);
            match self.issuer.mint(&principal, mint_audience) {
                Ok(jwt) => {
                    if policy.send_header {
                        match HeaderValue::from_str(&jwt) {
                            Ok(val) => {
                                out.insert(IDENTITY_HEADER, val);
                            }
                            Err(e) => tracing::warn!(
                                error = %e,
                                "identity jwt not a valid http header value — dropped",
                            ),
                        }
                    }
                    if ctx.tier_c_audience.is_some() {
                        // Tier-A's exchange path below is mutually exclusive
                        // with Tier-C (enforced at manifest load), so there's
                        // no conflict over Authorization.
                        let bearer = format!("Bearer {jwt}");
                        match HeaderValue::from_str(&bearer) {
                            Ok(mut val) => {
                                val.set_sensitive(true);
                                out.insert(http::header::AUTHORIZATION, val);
                                return out;
                            }
                            Err(e) => tracing::warn!(
                                error = %e,
                                "tier-c minted JWT not a valid bearer http header value — dropped",
                            ),
                        }
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    audience = %mint_audience,
                    principal = %ctx.principal.sub,
                    "mint identity jwt failed — calling upstream without X-MCP-Identity",
                ),
            }
        }

        // Tier A: stamp the Authorization header.
        //
        // When the pool
        // pre-flighted the exchange, `ctx.exchanged_bearer` carries
        // the downscoped bearer ready to go — use it directly. This
        // is the only path that satisfies `tier_a_required: true`:
        // pre-flight failures become pool-side dispatch refusals
        // (see `pool::enforce_tier_a_required`), so by the time
        // `headers()` runs the value here is either the genuine
        // pre-flight result or the legacy on-the-fly path below.
        if let Some(bearer_value) = ctx.exchanged_bearer.as_deref() {
            let bearer = format!("Bearer {bearer_value}");
            match HeaderValue::from_str(&bearer) {
                Ok(mut val) => {
                    val.set_sensitive(true);
                    out.insert(http::header::AUTHORIZATION, val);
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "pre-flighted exchanged bearer not a valid http header value — dropped",
                ),
            }
            return out;
        }

        // Legacy on-the-fly exchange path: kept for manifests that
        // don't have a pre-flight wired (no `exchange:` triple in
        // `UpstreamPool`'s `ExchangeBundle`, or the pool was built
        // via `connect()` without an identity issuer). The on-the-
        // fly path silently drops the header on failure — fine for
        // graceful Tier-B fallback, refused upstream of here for
        // `tier_a_required` upstreams.
        //
        // Subject-token preference order:
        //   1. `stored_upstream_subject_token` — the user's IdP access token
        //      from `user_upstream_sessions`, preserved across the gateway's
        //      own bearer rotation. Preferred because it carries the
        //      *upstream IdP's* notion of the user, not the gateway's
        //      transient bearer — the right actor for downscoping.
        //   2. `principal.raw_token` — fallback for callers without a
        //      durable session row (legacy clients, or upstream
        //      sessions that pre-date the `user_upstream_sessions` table).
        // dev-principal paths leave both empty; the if-let short-circuits.
        let subject_token = ctx
            .stored_upstream_subject_token
            .as_deref()
            .or(ctx.principal.raw_token.as_deref());
        if let (Some(exchange), Some(cfg), Some(subject)) =
            (&self.exchange, &ctx.exchange, subject_token)
        {
            let scope = cfg.scope.as_deref();
            let fetch_result = self
                .cache
                .get_or_exchange(subject, &cfg.audience, scope, || {
                    exchange.exchange(ExchangeRequest {
                        subject_token: subject,
                        audience: &cfg.audience,
                        scope,
                    })
                })
                .await;
            match fetch_result {
                Ok(exchanged) => {
                    let bearer = format!("Bearer {}", exchanged.access_token);
                    match HeaderValue::from_str(&bearer) {
                        Ok(mut val) => {
                            val.set_sensitive(true);
                            out.insert(http::header::AUTHORIZATION, val);
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "exchanged access token not a valid http header value — dropped",
                        ),
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        audience = %cfg.audience,
                        principal = %ctx.principal.sub,
                        "token exchange failed — forwarding without downscoped bearer",
                    );
                }
            }
        }
        out
    }
}

/// The principal as the token for one upstream may describe it: optional
/// claims the upstream's manifest leaves out are removed before minting.
fn principal_for_token(
    principal: &Principal,
    policy: IdentityTokenPolicy,
) -> std::borrow::Cow<'_, Principal> {
    if policy.include_email && policy.include_groups {
        return std::borrow::Cow::Borrowed(principal);
    }
    let mut limited = principal.clone();
    if !policy.include_email {
        limited.email = None;
    }
    if !policy.include_groups {
        limited.groups.clear();
    }
    std::borrow::Cow::Owned(limited)
}

/// Wraps an inner [`StreamableHttpClient`] and, whenever an [`IdentityCell`]
/// is populated, injects caller identity into the upstream request via the
/// shared [`IdentityAugmenter`].
#[derive(Clone)]
pub struct IdentityForwardingClient<C>
where
    C: StreamableHttpClient,
{
    inner: C,
    augmenter: IdentityAugmenter,
}

impl<C> IdentityForwardingClient<C>
where
    C: StreamableHttpClient,
{
    pub fn new(inner: C, issuer: Arc<IdentityIssuer>, cell: IdentityCell) -> Self {
        Self {
            inner,
            augmenter: IdentityAugmenter::new(issuer, cell),
        }
    }

    pub fn with_exchange(
        mut self,
        exchange: Arc<TokenExchangeClient>,
        cache: Arc<TokenCache>,
    ) -> Self {
        self.augmenter = self.augmenter.with_exchange(exchange, cache);
        self
    }

    pub fn cell(&self) -> IdentityCell {
        self.augmenter.cell.clone()
    }

    async fn augment(
        &self,
        mut headers: HashMap<HeaderName, HeaderValue>,
    ) -> HashMap<HeaderName, HeaderValue> {
        for (k, v) in self.augmenter.headers().await {
            headers.insert(k, v);
        }
        headers
    }
}

impl<C> StreamableHttpClient for IdentityForwardingClient<C>
where
    C: StreamableHttpClient + Sync,
{
    type Error = C::Error;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let headers = self.augment(custom_headers).await;
        self.inner
            .post_message(uri, message, session_id, auth_header, headers)
            .await
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let headers = self.augment(custom_headers).await;
        self.inner
            .delete_session(uri, session_id, auth_header, headers)
            .await
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let headers = self.augment(custom_headers).await;
        self.inner
            .get_stream(uri, session_id, last_event_id, auth_header, headers)
            .await
    }

    // The `_with_max_sse_event_size` methods have default implementations
    // that delegate to the base methods on *this wrapper* — which would
    // silently bypass the inner client's raw-byte event-size enforcement.
    // Implement them explicitly so both the identity headers and the size
    // limit reach the wrapped client.
    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let headers = self.augment(custom_headers).await;
        self.inner
            .post_message_with_max_sse_event_size(
                uri,
                message,
                session_id,
                auth_header,
                headers,
                max_sse_event_size,
            )
            .await
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let headers = self.augment(custom_headers).await;
        self.inner
            .get_stream_with_max_sse_event_size(
                uri,
                session_id,
                last_event_id,
                auth_header,
                headers,
                max_sse_event_size,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use rmcp::model::{ClientJsonRpcMessage, JsonRpcRequest};
    use rmcp::transport::streamable_http_client::StreamableHttpPostResponse;

    use waygate_oidc::IdentityClaims;

    /// Inner client that records what headers it was asked to send, so we can
    /// assert the wrapper injected what we expected without going near HTTP.
    #[derive(Clone, Default)]
    struct RecordingClient {
        last_headers: Arc<StdMutex<HashMap<HeaderName, HeaderValue>>>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("fake client error: {0}")]
    struct FakeError(String);

    impl StreamableHttpClient for RecordingClient {
        type Error = FakeError;

        async fn post_message(
            &self,
            _uri: Arc<str>,
            _message: ClientJsonRpcMessage,
            _session_id: Option<Arc<str>>,
            _auth_header: Option<String>,
            custom_headers: HashMap<HeaderName, HeaderValue>,
        ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
            *self.last_headers.lock().unwrap() = custom_headers;
            Ok(StreamableHttpPostResponse::Accepted)
        }

        async fn delete_session(
            &self,
            _uri: Arc<str>,
            _session_id: Arc<str>,
            _auth_header: Option<String>,
            _custom_headers: HashMap<HeaderName, HeaderValue>,
        ) -> Result<(), StreamableHttpError<Self::Error>> {
            Ok(())
        }

        async fn get_stream(
            &self,
            _uri: Arc<str>,
            _session_id: Option<Arc<str>>,
            _last_event_id: Option<String>,
            _auth_header: Option<String>,
            _custom_headers: HashMap<HeaderName, HeaderValue>,
        ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>>
        {
            Err(StreamableHttpError::ServerDoesNotSupportSse)
        }
    }

    fn test_issuer() -> Arc<IdentityIssuer> {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap();
        Arc::new(
            IdentityIssuer::from_ed25519_pkcs8_pem(
                &pem,
                "gw-test",
                "https://mcp.test",
                "gateway-main",
                Duration::from_secs(60),
            )
            .unwrap(),
        )
    }

    fn dummy_message() -> ClientJsonRpcMessage {
        ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: rmcp::model::JsonRpcVersion2_0,
            id: rmcp::model::NumberOrString::Number(1),
            request: rmcp::model::ClientRequest::PingRequest(rmcp::model::PingRequest::default()),
        })
    }

    #[tokio::test]
    async fn injects_header_when_cell_populated() {
        let recorder = RecordingClient::default();
        let captured = recorder.last_headers.clone();
        let issuer = test_issuer();
        let cell = IdentityCell::new();
        let client = IdentityForwardingClient::new(recorder, issuer.clone(), cell.clone());

        cell.set(IdentityContext {
            principal: Principal {
                sub: "user-a".into(),
                email: Some("a@ex.test".into()),
                groups: vec!["mcp-users".into()],
                issuer: "https://auth.test/".into(),
                scopes: vec!["mcp:invoke".into()],
                tenant: waygate_core::TenantId::default(),
                auth_method: waygate_oidc::AuthMethod::Oauth,
                raw_token: None,
                roles: vec![],
                scim: None,
                enrichment_blocked: None,
                api_key_profile_restrictions: None,
            },
            audience: "example-messages".into(),
            exchange: None,
            stored_upstream_subject_token: None,
            exchanged_bearer: None,
            tier_c_audience: None,
            token_policy: waygate_manifest_types::IdentityTokenPolicy::FULL,
        });

        client
            .post_message(
                "http://upstream/mcp".into(),
                dummy_message(),
                None,
                None,
                HashMap::new(),
            )
            .await
            .expect("post");

        let headers = captured.lock().unwrap().clone();
        let jwt = headers
            .get(&IDENTITY_HEADER)
            .expect("X-MCP-Identity injected");
        let jwt_str = jwt.to_str().unwrap();

        let jwks = issuer.jwks();
        let key = DecodingKey::from_jwk(&jwks.keys[0]).unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://mcp.test"]);
        v.set_audience(&["example-messages"]);
        let decoded = decode::<IdentityClaims>(jwt_str, &key, &v).unwrap();
        assert_eq!(decoded.claims.sub, "user-a");
        assert_eq!(decoded.claims.act.sub, "gateway-main");
        assert_eq!(decoded.claims.aud, "example-messages");
    }

    #[tokio::test]
    async fn leaves_headers_untouched_when_cell_empty() {
        let recorder = RecordingClient::default();
        let captured = recorder.last_headers.clone();
        let client = IdentityForwardingClient::new(recorder, test_issuer(), IdentityCell::new());

        client
            .post_message(
                "http://upstream/mcp".into(),
                dummy_message(),
                None,
                None,
                HashMap::new(),
            )
            .await
            .expect("post");
        assert!(captured.lock().unwrap().is_empty());
    }

    /// Seed a `TokenCache` with a known exchanged token keyed on
    /// `(subject, audience, scope)`. Lets the augmenter's
    /// `cache.get_or_exchange(...)` call hit the cache instead of
    /// running the (absent) HTTP exchange. The token's `access_token`
    /// is `downscoped-for:{subject}` so the assertion can verify
    /// *which* subject token was fed in.
    async fn prime_cache_with(
        subject: &str,
        audience: &str,
        scope: Option<&str>,
    ) -> Arc<TokenCache> {
        let cache = Arc::new(TokenCache::default());
        let subject_owned = subject.to_owned();
        let _ = cache
            .get_or_exchange(subject, audience, scope, || {
                let s = subject_owned.clone();
                async move {
                    Ok::<_, waygate_oidc::ExchangeError>(waygate_oidc::ExchangedToken {
                        access_token: format!("downscoped-for:{s}"),
                        issued_token_type: None,
                        expires_in: Some(60),
                        scope: None,
                        token_type: None,
                    })
                }
            })
            .await
            .expect("seed cache");
        cache
    }

    #[tokio::test]
    async fn augmenter_prefers_stored_upstream_subject_token_over_raw_token() {
        // Read-path contract: when both
        // `stored_upstream_subject_token` and `principal.raw_token` are
        // present and the upstream opted into exchange, the augmenter
        // must feed the *stored* token (the user's IdP access token)
        // as the RFC 8693 subject, not the gateway's bearer.
        //
        // We seed the `TokenCache` once with the *expected* subject so
        // the cache hit succeeds. Then we set `principal.raw_token` to
        // a different value: a cache miss on that key would surface as
        // a different cache entry and an attempt to invoke the (absent)
        // exchange client. The test never sees that path — the
        // assertion confirms the augmenter pulled from the stored
        // subject's cache slot.
        let stored = "user-upstream-access-token";
        let raw = "gateway-bearer-token-DIFFERENT";
        let audience = "https://example-messages.test/mcp";
        let cache = prime_cache_with(stored, audience, None).await;

        let issuer = test_issuer();
        let cell = IdentityCell::new();
        // Augmenter with a fake exchange client we never expect to call.
        let exchange = Arc::new(TokenExchangeClient::new(
            waygate_core::http_client::client(waygate_core::http_client::Profile::Interactive)
                .unwrap(),
            "https://idp.test/token",
            "client-id",
            "client-secret",
        ));
        let aug = IdentityAugmenter::new(issuer, cell.clone()).with_exchange(exchange, cache);

        cell.set(IdentityContext {
            principal: Principal {
                sub: "alice".into(),
                email: None,
                groups: vec![],
                issuer: "https://auth.test/".into(),
                scopes: vec![],
                tenant: waygate_core::TenantId::default(),
                auth_method: waygate_oidc::AuthMethod::Oauth,
                raw_token: Some(raw.into()),
                roles: vec![],
                scim: None,
                enrichment_blocked: None,
                api_key_profile_restrictions: None,
            },
            audience: "example-messages".into(),
            exchange: Some(ExchangeSettings {
                audience: audience.into(),
                scope: None,
            }),
            stored_upstream_subject_token: Some(stored.into()),
            exchanged_bearer: None,
            tier_c_audience: None,
            token_policy: waygate_manifest_types::IdentityTokenPolicy::FULL,
        });

        let headers = aug.headers().await;
        let authz = headers
            .get(&http::header::AUTHORIZATION)
            .expect("Authorization injected when exchange settings + subject token available");
        assert_eq!(
            authz.to_str().unwrap(),
            format!("Bearer downscoped-for:{stored}"),
            "augmenter must feed the stored upstream token (not raw_token) as RFC 8693 subject",
        );
    }

    #[tokio::test]
    async fn augmenter_falls_back_to_raw_token_when_stored_absent() {
        // When the durable session row is absent
        // (or expired and refresh-on-demand produced no token), the
        // augmenter falls back to using
        // `principal.raw_token` as the subject. Confirms the
        // `or(principal.raw_token)` fallback in the augmenter.
        let raw = "gateway-bearer-token";
        let audience = "https://example-messages.test/mcp";
        let cache = prime_cache_with(raw, audience, None).await;

        let issuer = test_issuer();
        let cell = IdentityCell::new();
        let exchange = Arc::new(TokenExchangeClient::new(
            waygate_core::http_client::client(waygate_core::http_client::Profile::Interactive)
                .unwrap(),
            "https://idp.test/token",
            "client-id",
            "client-secret",
        ));
        let aug = IdentityAugmenter::new(issuer, cell.clone()).with_exchange(exchange, cache);

        cell.set(IdentityContext {
            principal: Principal {
                sub: "alice".into(),
                email: None,
                groups: vec![],
                issuer: "https://auth.test/".into(),
                scopes: vec![],
                tenant: waygate_core::TenantId::default(),
                auth_method: waygate_oidc::AuthMethod::Oauth,
                raw_token: Some(raw.into()),
                roles: vec![],
                scim: None,
                enrichment_blocked: None,
                api_key_profile_restrictions: None,
            },
            audience: "example-messages".into(),
            exchange: Some(ExchangeSettings {
                audience: audience.into(),
                scope: None,
            }),
            stored_upstream_subject_token: None,
            exchanged_bearer: None,
            tier_c_audience: None,
            token_policy: waygate_manifest_types::IdentityTokenPolicy::FULL,
        });

        let headers = aug.headers().await;
        let authz = headers
            .get(&http::header::AUTHORIZATION)
            .expect("Authorization injected on raw_token fallback path");
        assert_eq!(
            authz.to_str().unwrap(),
            format!("Bearer downscoped-for:{raw}"),
            "augmenter must fall back to raw_token when stored subject token is absent",
        );
    }

    #[tokio::test]
    async fn clearing_cell_stops_injection() {
        let recorder = RecordingClient::default();
        let captured = recorder.last_headers.clone();
        let issuer = test_issuer();
        let cell = IdentityCell::new();
        let client = IdentityForwardingClient::new(recorder, issuer, cell.clone());

        cell.set(IdentityContext {
            principal: Principal {
                sub: "user-a".into(),
                email: None,
                groups: vec![],
                issuer: "https://auth.test/".into(),
                scopes: vec![],
                tenant: waygate_core::TenantId::default(),
                auth_method: waygate_oidc::AuthMethod::Oauth,
                raw_token: None,
                roles: vec![],
                scim: None,
                enrichment_blocked: None,
                api_key_profile_restrictions: None,
            },
            audience: "example-messages".into(),
            exchange: None,
            stored_upstream_subject_token: None,
            exchanged_bearer: None,
            tier_c_audience: None,
            token_policy: waygate_manifest_types::IdentityTokenPolicy::FULL,
        });
        cell.clear();

        client
            .post_message(
                "http://upstream/mcp".into(),
                dummy_message(),
                None,
                None,
                HashMap::new(),
            )
            .await
            .expect("post");
        assert!(captured.lock().unwrap().is_empty());
    }

    fn caller() -> Principal {
        Principal {
            sub: "user-a".into(),
            email: Some("a@ex.test".into()),
            groups: vec!["mcp-users".into()],
            issuer: "https://auth.test/".into(),
            scopes: vec!["mcp:invoke".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn context(
        token_policy: IdentityTokenPolicy,
        tier_c_audience: Option<&str>,
    ) -> IdentityContext {
        IdentityContext {
            principal: caller(),
            audience: "example-messages".into(),
            exchange: None,
            stored_upstream_subject_token: None,
            exchanged_bearer: None,
            tier_c_audience: tier_c_audience.map(str::to_owned),
            token_policy,
        }
    }

    fn decode_token(issuer: &IdentityIssuer, jwt: &str, audience: &str) -> IdentityClaims {
        let key = DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://mcp.test"]);
        v.set_audience(&[audience]);
        decode::<IdentityClaims>(jwt, &key, &v).unwrap().claims
    }

    /// An upstream whose manifest withholds the token receives no identity
    /// header at all, even with a caller in the cell.
    #[tokio::test]
    async fn a_withheld_token_sends_no_identity_header() {
        let cell = IdentityCell::new();
        let augmenter = IdentityAugmenter::new(test_issuer(), cell.clone());
        cell.set(context(
            IdentityTokenPolicy {
                send_header: false,
                ..IdentityTokenPolicy::FULL
            },
            None,
        ));

        assert!(augmenter.headers().await.is_empty());
    }

    /// The token carries only the optional claims the manifest selects; the
    /// subject is always present.
    #[tokio::test]
    async fn the_token_carries_only_the_selected_optional_claims() {
        let issuer = test_issuer();
        let cell = IdentityCell::new();
        let augmenter = IdentityAugmenter::new(issuer.clone(), cell.clone());
        cell.set(context(
            IdentityTokenPolicy {
                send_header: true,
                include_email: false,
                include_groups: false,
            },
            None,
        ));

        let headers = augmenter.headers().await;
        let jwt = headers.get(&IDENTITY_HEADER).expect("token sent");
        let claims = decode_token(&issuer, jwt.to_str().unwrap(), "example-messages");
        assert_eq!(claims.sub, "user-a");
        assert_eq!(claims.email, None);
        assert!(claims.groups.is_empty());
    }

    /// A Tier C peer assertion still reaches `Authorization` when the manifest
    /// withholds the `X-MCP-Identity` copy.
    #[tokio::test]
    async fn a_tier_c_assertion_survives_a_withheld_identity_header() {
        let issuer = test_issuer();
        let cell = IdentityCell::new();
        let augmenter = IdentityAugmenter::new(issuer.clone(), cell.clone());
        cell.set(context(
            IdentityTokenPolicy {
                send_header: false,
                ..IdentityTokenPolicy::FULL
            },
            Some("https://peer.test"),
        ));

        let headers = augmenter.headers().await;
        assert!(!headers.contains_key(&IDENTITY_HEADER));
        let bearer = headers
            .get(&http::header::AUTHORIZATION)
            .expect("peer assertion on Authorization")
            .to_str()
            .unwrap();
        let jwt = bearer.strip_prefix("Bearer ").expect("bearer scheme");
        let claims = decode_token(&issuer, jwt, "https://peer.test");
        assert_eq!(claims.sub, "user-a");
    }
}
