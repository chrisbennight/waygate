//! Boot-time builders for `main()` — audit sink, identity keyring,
//! Tier-A bundle, AS router, bearer layer, dashboard auth, and the
//! small env parsers. Split from `main.rs`; bodies moved verbatim.
//! Opens with `use super::*;` so the crate root's imports keep
//! resolving.

use super::*;

/// Process-wide OIDC clients built by the composition root. Discovery keeps
/// reqwest's existing redirect behavior; token requests refuse redirects so a
/// code or refresh token cannot be replayed to another origin.
pub(crate) struct OidcHttpClients {
    discovery: reqwest::Client,
    token: reqwest::Client,
}

pub(crate) fn build_oidc_http_clients(cfg: &Config) -> anyhow::Result<Option<OidcHttpClients>> {
    if cfg.dashboard.is_none() && cfg.as_server.is_none() {
        return Ok(None);
    }
    let discovery = waygate_core::http_client::client(waygate_core::http_client::Profile::Standard)
        .context("building the OIDC discovery HTTP client")?;
    let token = waygate_core::http_client::builder(waygate_core::http_client::Profile::Standard)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building the OIDC token HTTP client")?;
    Ok(Some(OidcHttpClients { discovery, token }))
}

/// Adapter from `waygate-oidc`'s [`AuthAttemptRecorder`] trait to the
/// gateway-wide [`SharedEvidence`] sink. Lets the bearer middleware
/// record `AuthAttempt`-category audit rows without `waygate-oidc`
/// taking a direct dependency on `waygate-mcp::audit` (which would form
/// a cycle, since `waygate-mcp` already depends on `waygate-oidc`).
///
/// Maps the three failure outcomes to discriminated `action` values so
/// the admin Activity feed can filter "missing header" floods from
/// "invalid token" floods from "infra unavailable" without parsing the
/// reason string.
///
/// **Hot-path posture:** unlike lower-volume admin and lifecycle recorders,
/// this recorder fires inside the per-request bearer middleware. The
/// production `SharedEvidence` is a bounded non-blocking decorator, so this
/// method submits directly without creating one detached task per rejection.
/// A full queue drops with metrics and a rate-limited warning instead of
/// coupling 401/503 latency or process memory to PostgreSQL latency.
pub(crate) struct EvidenceAuthAttempts(pub(crate) SharedEvidence);

#[async_trait::async_trait]
impl AuthAttemptRecorder for EvidenceAuthAttempts {
    async fn record(&self, outcome: AuthAttemptOutcome, reason: String) {
        let action = match outcome {
            AuthAttemptOutcome::MissingHeader => "AuthAttemptMissingHeader",
            AuthAttemptOutcome::Rejected => "AuthAttemptRejected",
            AuthAttemptOutcome::InfraUnavailable => "AuthAttemptInfraUnavailable",
        };
        let event = waygate_mcp::AuditEvent::new(action, waygate_mcp::AuditOutcome::ExecutionError)
            .with_category(waygate_mcp::EvidenceCategory::AuthAttempt)
            .with_reason(reason);
        self.0.record_chained_best_effort(event).await;
    }
}

pub(crate) async fn build_audit_sink(
    cfg: &Config,
) -> anyhow::Result<(
    SharedEvidence,
    Option<Arc<dyn AuditReader>>,
    Option<DatabasePools>,
    Option<waygate_mcp::audit::EvidenceQueueHandle>,
)> {
    match &cfg.database_url {
        Some(url) => {
            // Outbox targets are parsed once into Config so the
            // recorder and the drain spawn path read from the
            // same list. Empty/unset preserves the base fast
            // path (single-INSERT, no tx) so deployments without
            // exporters see no behavior change.
            if !cfg.evidence_outbox_targets.is_empty() {
                tracing::info!(
                    targets = ?cfg.evidence_outbox_targets,
                    "evidence outbox enabled — record_required will enqueue one row \
                     per target inside the audit-write transaction",
                );
            }
            // Three pools over the same database reserve independent permits
            // for audit persistence, control-plane stores, and dashboard
            // reads. Their default 8/8/8 split preserves the previous total
            // process budget of 24 while preventing either competing workload
            // from starving audit writes.
            let pools = build_database_pools(url, cfg.database_pools).await?;
            let audit_pool = pools.audit_pool();
            PgAuditSink::migrate(&audit_pool)
                .await
                .context("run audit migrations")?;
            let sink = Arc::new(
                PgAuditSink::with_pool(audit_pool)
                    .with_outbox_targets(cfg.evidence_outbox_targets.clone()),
            );
            let reader: Arc<dyn AuditReader> =
                Arc::new(PgAuditSink::with_pool(pools.audit_reader_pool()));
            tracing::info!(
                audit_max_conns = cfg.database_pools.audit_max_connections,
                control_max_conns = cfg.database_pools.control_max_connections,
                reader_max_conns = cfg.database_pools.reader_max_connections,
                reader_isolated = pools.reader_isolated(),
                chained_queue_shards = waygate_mcp::audit::CHAINED_EVIDENCE_QUEUE_SHARDS,
                queue_capacity = waygate_mcp::audit::EVIDENCE_QUEUE_CAPACITY,
                queue_batch_size = waygate_mcp::audit::EVIDENCE_QUEUE_BATCH_SIZE,
                reason_max_bytes = waygate_mcp::audit::MAX_EVIDENCE_REASON_BYTES,
                "audit sink: Postgres with bounded best-effort submission (migrations applied)"
            );
            let sink: SharedEvidence = sink;
            let (sink, queue_handle) = waygate_mcp::audit::BoundedEvidenceRecorder::spawn(sink);
            Ok((sink, Some(reader), Some(pools), Some(queue_handle)))
        }
        None => {
            tracing::warn!(
                "GATEWAY_DATABASE_URL unset — audit events will be dropped. \
                 Do not run this in production."
            );
            Ok((Arc::new(NullSink), None, None, None))
        }
    }
}

pub(crate) fn build_exchange_bundle(cfg: &Config) -> anyhow::Result<Option<ExchangeBundle>> {
    let Some(TokenExchangeConfig {
        token_endpoint,
        client_id,
        client_secret,
    }) = cfg.token_exchange.as_ref()
    else {
        tracing::info!(
            "token exchange disabled — upstreams will receive only the gateway-minted \
             identity JWT (Tier B). Set GATEWAY_TOKEN_EXCHANGE_* to enable RFC 8693."
        );
        return Ok(None);
    };
    let http = waygate_core::http_client::builder(waygate_core::http_client::Profile::Interactive)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building the token-exchange HTTP client")?;
    let client = Arc::new(TokenExchangeClient::new(
        http,
        token_endpoint.clone(),
        client_id.clone(),
        client_secret.clone(),
    ));
    tracing::info!(
        endpoint = %token_endpoint,
        client_id = %client_id,
        "token exchange ready — upstreams with `exchange:` in their manifest will receive downscoped bearer tokens",
    );
    Ok(Some(ExchangeBundle {
        client,
        cache: Arc::new(TokenCache::default()),
    }))
}

/// Bundle returned by [`build_tier_a_session_bundle`]. Carries the four
/// handles `UpstreamPool::with_upstream_sessions` needs. `refresher`
/// stays `Option<...>` so the pool's builder method signature accepts
/// future test paths (the disconnected fixture) that don't wire one;
/// the production composition root here always populates it because
/// the gateway boots `build_as_router` further down which also
/// requires upstream IdP discovery, so "AS enabled ⇒ refresher
/// present" is a gateway-wide invariant.
pub(crate) struct TierABundle {
    pub(crate) sessions: waygate_as::sessions::SharedUpstreamSessionStore,
    pub(crate) crypto: Arc<UpstreamCrypto>,
    pub(crate) upstream_issuer: String,
    pub(crate) refresher: Option<waygate_as::session_refresh::SharedSessionRefresher>,
}

/// Build the Tier-A session-lookup bundle. Carries the durable
/// [`UpstreamSessionStore`], the AES-256-GCM `UpstreamCrypto` the
/// store ciphertext was encrypted with, the upstream IdP issuer URL,
/// and the refresh-on-demand handle. Returns `None`
/// (Tier-A read disabled, pool falls back to `principal.raw_token`)
/// when the gateway isn't running its own AS, no DB pool is wired,
/// or the upstream IdP issuer isn't configured.
///
/// The store + crypto + issuer triple is required together by design.
/// OIDC discovery against the upstream IdP for the refresher's
/// `token_endpoint` is **fatal** at boot — `build_as_router` further
/// down treats the same discovery as fatal (the AS can't serve
/// `/oauth/authorize` without it), so making the refresher's
/// discovery best-effort here would just defer the gateway-wide
/// failure by ~50 lines.
pub(crate) async fn build_tier_a_session_bundle(
    cfg: &Config,
    db_pool: Option<&PgPool>,
    oidc_http: Option<&OidcHttpClients>,
) -> anyhow::Result<Option<TierABundle>> {
    let Some(as_cfg) = cfg.as_server.as_ref() else {
        return Ok(None);
    };
    let Some(pool) = db_pool else {
        return Ok(None);
    };
    let Some(upstream_issuer) = cfg.authentik_issuer.clone() else {
        return Ok(None);
    };
    let oidc_http = oidc_http
        .context("AS mode requires the shared OIDC HTTP clients (checked during composition)")?;
    let crypto = Arc::new(
        UpstreamCrypto::from_keyring(
            as_cfg.upstream_token_keys.iter().cloned(),
            &as_cfg.upstream_token_active_id,
        )
        .map_err(|e| anyhow::anyhow!("GATEWAY_UPSTREAM_TOKEN_KEY_*: {e}"))?,
    );
    let sessions: waygate_as::sessions::SharedUpstreamSessionStore = Arc::new(
        waygate_as::sessions::PgUpstreamSessionStore::new(pool.clone()),
    );

    // OIDC discovery against the upstream IdP for the refresher's
    // token_endpoint. Fatal on failure to match `build_as_router`'s
    // semantics (the AS itself can't serve `/oauth/authorize`
    // without the IdP, so a degraded refresher would just defer the
    // gateway-wide failure by ~50 lines): making refresher discovery
    // best-effort here would be a contradictory promise — the
    // gateway would still abort boot via the AS path. Both paths
    // must agree on the same gateway-wide invariant: "AS enabled
    // ⇒ upstream IdP must be reachable at boot."
    let endpoints = OidcEndpoints::discover(&oidc_http.discovery, &upstream_issuer)
        .await
        .with_context(|| format!("OIDC discovery from upstream IdP {upstream_issuer}"))?;
    let refresher: waygate_as::session_refresh::SharedSessionRefresher =
        Arc::new(waygate_as::session_refresh::SessionRefresher::new(
            sessions.clone(),
            crypto.clone(),
            oidc_http.token.clone(),
            endpoints.token_endpoint,
            as_cfg.upstream_client_id.clone(),
            as_cfg.upstream_client_secret.clone(),
        ));
    tracing::info!(
        %upstream_issuer,
        "Tier-A refresh-on-demand wired",
    );
    let refresher = Some(refresher);

    Ok(Some(TierABundle {
        sessions,
        crypto,
        upstream_issuer,
        refresher,
    }))
}

/// Returns the active signing issuer + the full keyring. The active
/// issuer threads through every downstream sign path unchanged from
/// the pre-rotation shape; the keyring feeds the JWKS route so
/// verifiers can validate tokens signed under any kid in the
/// rotation set. `None` ⇒ no identity signing configured (gateway
/// boots without minting identity tokens).
///
/// Takes `&mut Config` and `.take()`s `cfg.identity` so the private
/// PEM bytes don't survive into `AppState`'s clone of Config. After
/// this call `cfg.identity` is `None`; the active key's private
/// material lives only inside the returned `IdentityIssuer`'s opaque
/// `EncodingKey`, and inactive kids never enter long-lived state at
/// all — their PEMs are parsed into `Jwk`s and dropped before this
/// function returns.
pub(crate) fn build_identity_keyring(
    cfg: &mut Config,
) -> anyhow::Result<Option<(SharedIdentityIssuer, SharedIdentityKeyring)>> {
    let public_url = cfg.public_url.clone();
    let Some(IdentityConfig {
        keys,
        active_kid,
        gateway_id,
        ttl,
    }) = cfg.identity.take()
    else {
        tracing::warn!(
            "GATEWAY_IDENTITY_SIGNING_KEY_* (or GATEWAY_IDENTITY_JWT_KEYS) unset — \
             gateway will not mint identity tokens. Upstreams cannot verify caller identity."
        );
        return Ok(None);
    };

    // Capture the configured kid list for error messages
    // and the boot log BEFORE we destructure `keys` into
    // active/verify-only buckets (the original Vec is then
    // dropped along with its PEM strings).
    let configured_kids: Vec<String> = keys.iter().map(|k| k.kid.clone()).collect();
    let mut active_source: Option<IdentityKeySource> = None;
    let mut verify_only_sources: Vec<IdentityKeySource> = Vec::with_capacity(keys.len());
    for k in keys {
        if k.kid == active_kid {
            active_source = Some(k);
        } else {
            verify_only_sources.push(k);
        }
    }
    let active_source = active_source.ok_or_else(|| {
        anyhow::anyhow!(
            "GATEWAY_IDENTITY_JWT_ACTIVE={active_kid:?} not present in configured \
             keys (kids: {configured_kids:?})"
        )
    })?;

    // Build a FULL IdentityIssuer (with EncodingKey) for the
    // active kid only; for every other kid in the rotation, derive
    // just the public JWK and drop the private bytes. The
    // verify-only source vector is consumed inside the loop
    // so each PEM falls out of scope as soon as its JWK is
    // extracted.
    let active_issuer = IdentityIssuer::from_ed25519_pkcs8_pem(
        &active_source.pem,
        active_source.kid.clone(),
        public_url,
        gateway_id,
        ttl,
    )
    .with_context(|| {
        format!(
            "build active identity issuer for kid {:?}",
            active_source.kid
        )
    })?;
    // `active_source.pem` is no longer needed; `EncodingKey`
    // inside `active_issuer` holds the parsed signing key.
    drop(active_source);
    let active: SharedIdentityIssuer = Arc::new(active_issuer);

    let mut verify_only_jwks = Vec::with_capacity(verify_only_sources.len());
    for k in verify_only_sources {
        let jwk = waygate_oidc::pub_jwk_from_ed25519_pkcs8_pem(&k.pem, &k.kid)
            .with_context(|| format!("derive verify-only JWK for kid {:?}", k.kid))?;
        verify_only_jwks.push(jwk);
        // `k` (and its PEM) falls out of scope here, so the
        // inactive kid's private bytes are released as soon
        // as the JWK is derived.
    }

    let keyring = waygate_oidc::IdentityKeyring::new(active.clone(), verify_only_jwks)
        .with_context(|| {
            format!(
                "construct identity keyring (active_kid={active_kid:?}, configured \
                 kids={configured_kids:?})"
            )
        })?;
    tracing::info!(
        active_kid = %active.kid,
        all_kids = ?keyring.kids(),
        ttl_secs = ttl.as_secs(),
        gateway_id = %active.gateway_id,
        "identity keyring ready",
    );
    Ok(Some((active, Arc::new(keyring))))
}

/// Assemble the frozen-at-boot system info snapshot the
/// dashboard Settings page renders. Mirrors the env-var
/// surface back to the operator: deployment profile, auth
/// mode, MCP spec version, gateway version, plus optional
/// JWKS / introspection summaries. Never carries secret
/// material — the introspection `client_secret` is omitted
/// here at the boundary, not just in `Debug`.
pub(crate) fn build_system_info(
    cfg: &Config,
    identity_keyring: Option<&SharedIdentityKeyring>,
) -> waygate_admin::state::SystemInfo {
    use waygate_admin::state::{IntrospectionSummary, JwksSummary, SystemInfo};

    let deployment_profile = cfg.deployment_profile.as_str();
    let auth_mode = match cfg.auth_mode {
        AuthMode::Enforce => "enforce",
        AuthMode::Disabled => "disabled",
    };

    // JWKS lifecycle is a snapshot — operators rotate by
    // restarting with a new `GATEWAY_IDENTITY_JWT_ACTIVE`, so
    // a frozen copy at boot is accurate for the process'
    // lifetime.
    let jwks = identity_keyring.map(|ring| JwksSummary {
        active_kid: ring.active().kid.clone(),
        all_kids: ring.kids(),
        jwks_url: format!(
            "{}{}",
            cfg.public_url.trim_end_matches('/'),
            waygate_oidc::JWKS_PATH
        ),
    });
    let identity_token_ttl_secs = identity_keyring.map(|ring| ring.active().ttl.as_secs());

    // Introspection summary deliberately omits
    // `client_secret`. Operators see endpoint + client_id +
    // cache shape; the secret stays in process memory only.
    //
    // Stamp `active` using the SAME `want_upstream` predicate the
    // bearer chain uses to decide whether to wire the
    // `OpaqueTokenValidator`. When
    // `GATEWAY_AS_ENABLED=true` AND
    // `GATEWAY_ACCEPT_UPSTREAM_TOKENS!=true`, the validator is
    // gated off (OAuth token-passthrough anti-pattern), but
    // the env vars are still SET — the Settings page now
    // reports `configured but inactive` instead of falsely
    // claiming the validator is on the chain. The shared
    // helper in `waygate_admin::dashboard_settings` is the
    // single source of truth so the two surfaces can't drift
    // — the matching call site is in `build_oidc_chain`
    // (search this file for `want_upstream`).
    let introspection_active = waygate_admin::dashboard_settings::introspection_active(
        cfg.as_server.is_some(),
        cfg.accept_upstream_tokens,
    );
    let introspection = cfg.introspection.as_ref().map(|i| IntrospectionSummary {
        introspection_url: i.introspection_url.clone(),
        client_id: i.client_id.clone(),
        max_positive_ttl_secs: i.max_positive_ttl.as_secs(),
        negative_ttl_secs: i.negative_ttl.as_secs(),
        active: introspection_active,
    });

    SystemInfo {
        deployment_profile,
        auth_mode,
        mcp_spec_version: waygate_mcp::MCP_SPEC_VERSION,
        mcp_spec_versions: waygate_mcp::SUPPORTED_MCP_SPEC_VERSIONS,
        gateway_version: env!("CARGO_PKG_VERSION"),
        as_enabled: cfg.as_server.is_some(),
        accept_upstream_tokens: cfg.accept_upstream_tokens,
        jwks,
        introspection,
        identity_token_ttl_secs,
    }
}

pub(crate) async fn build_dashboard_auth(
    cfg: &Config,
    oidc_http: Option<&OidcHttpClients>,
) -> anyhow::Result<DashboardAuth> {
    let Some(dash) = cfg.dashboard.as_ref() else {
        tracing::warn!(
            "dashboard auth disabled (GATEWAY_DASHBOARD_CLIENT_ID / _SECRET / _SESSION_KEY unset). \
             /admin is wide-open to anyone on the network and every request gets a synthetic \
             admin principal. Do not run this in production."
        );
        return Ok(DashboardAuth::Disabled);
    };
    let Some(issuer) = cfg.authentik_issuer.as_deref() else {
        anyhow::bail!(
            "dashboard auth configured but AUTHENTIK_ISSUER is unset — cannot discover OIDC endpoints"
        );
    };
    let oidc_http = oidc_http.context(
        "dashboard auth requires the shared OIDC HTTP clients (checked during composition)",
    )?;

    let endpoints = OidcEndpoints::discover(&oidc_http.discovery, issuer)
        .await
        .with_context(|| format!("OIDC discovery from issuer {issuer}"))?;
    tracing::info!(
        issuer = %issuer,
        authorize = %endpoints.authorization_endpoint,
        token = %endpoints.token_endpoint,
        jwks = %endpoints.jwks_uri,
        "discovered dashboard OIDC endpoints"
    );

    // Separate JwksProvider: the dashboard's ID-token validator pulls from the
    // same JWKS URI but the cache is independent of the access-token path.
    let jwks = Arc::new(JwksProvider::new(issuer));
    jwks.prime().await;

    let id_validator = Arc::new(IdTokenValidator::new(jwks, issuer, dash.client_id.clone()));
    let session_key = SessionKey::from_encoded(&dash.session_key_encoded)
        .map_err(|e| anyhow::anyhow!("GATEWAY_DASHBOARD_SESSION_KEY: {e}"))?;

    let oidc_cfg = DashboardOidcConfig {
        client_id: dash.client_id.clone(),
        client_secret: dash.client_secret.clone(),
        redirect_uri: dash.redirect_uri.clone(),
        endpoints,
        token_http: oidc_http.token.clone(),
        id_token_validator: id_validator,
        session_key,
        secure_cookies: dash.secure_cookies,
        session_ttl: dash.session_ttl_secs,
        login_state_ttl: dash.login_state_ttl_secs,
        scopes: dash.scopes.clone(),
        allowed_step_up_scopes: dash.allowed_step_up_scopes.clone(),
    };
    tracing::info!(
        client_id = %dash.client_id,
        redirect_uri = %dash.redirect_uri,
        scopes = ?dash.scopes,
        secure_cookies = dash.secure_cookies,
        session_ttl_secs = dash.session_ttl_secs,
        "dashboard PKCE auth ready"
    );
    Ok(DashboardAuth::Enforce {
        cfg: Arc::new(oidc_cfg),
        // Filled by the caller via `with_principal_enricher` once
        // the SCIM/RBAC chain is built — keeps the construction
        // graph free of a forward reference to the enricher
        // crate from inside the OIDC builder.
        enricher: None,
    })
}

/// Parse a comma/whitespace-separated env var into a deduped list of trimmed,
/// non-empty entries. Used for the EMA target allowlists
/// (`GATEWAY_AS_IDJAG_AUDIENCES`, `GATEWAY_AS_IDJAG_RESOURCES`). Absent var ⇒
/// empty list.
pub(crate) fn parse_idjag_list(var: &str) -> Vec<String> {
    std::env::var(var)
        .ok()
        .map(|s| {
            let mut out: Vec<String> = Vec::new();
            for item in s.split([',', ' ', '\t', '\n', '\r']) {
                let item = item.trim();
                if !item.is_empty() && !out.iter().any(|e| e == item) {
                    out.push(item.to_owned());
                }
            }
            out
        })
        .unwrap_or_default()
}

/// When `GATEWAY_AS_ENABLED=true`, build the gateway-as-Authorization-Server
/// router. Discovers Authentik's authorize/token endpoints, loads the
/// upstream-token encryption key, and wires everything up on the shared
/// Postgres pool. Returns `None` when AS mode is off — caller then skips
/// merging AS routes.
// Composition-root builder: it threads the AS's many collaborators (pool,
// issuer, evidence, authz, enricher, keyring, resource ids) in one place. A
// params struct would just move the list without aiding readability.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_as_router(
    cfg: &Config,
    db_pool: Option<&PgPool>,
    oidc_http: Option<&OidcHttpClients>,
    identity_issuer: Option<&SharedIdentityIssuer>,
    evidence: waygate_mcp::audit::SharedEvidence,
    // Deps for the EMA token-exchange (ID-JAG mint) endpoint —
    // the Cedar gate (cross-app policy), the chained principal enricher
    // (SCIM-authoritative facts), and the identity keyring (to validate
    // gateway-minted subject tokens). All reuse the same instances the
    // /mcp + bearer paths use.
    authz: SharedAuthz,
    principal_enricher: Option<&Arc<dyn waygate_oidc::PrincipalEnricher>>,
    identity_keyring: Option<&SharedIdentityKeyring>,
    // Per-upstream resource ids derived from the manifests — unioned into
    // the ID-JAG mint resource allowlist so mint accepts the same canonical
    // resource ids the /mcp bearer validator binds on redeem.
    manifest_resource_ids: Vec<String>,
    // The shared federation peer JWKS cache (Tier-C), so the redeem path
    // can verify a peer-minted ID-JAG against the peer's keys. `None` ⇒ only
    // self-issued ID-JAGs are redeemable.
    peer_jwks: Option<waygate_federation::jwks::SharedPeerJwksCache>,
) -> anyhow::Result<Option<(Router<()>, OauthStore)>> {
    let Some(as_cfg) = cfg.as_server.as_ref() else {
        return Ok(None);
    };
    let pool = db_pool
        .cloned()
        .context("GATEWAY_AS_ENABLED=true requires GATEWAY_DATABASE_URL (checked in Config)")?;
    let issuer = cfg
        .authentik_issuer
        .as_ref()
        .context("GATEWAY_AS_ENABLED=true requires AUTHENTIK_ISSUER (checked in Config)")?;
    let identity = identity_issuer
        .cloned()
        .context("GATEWAY_AS_ENABLED=true requires identity issuer (checked in Config)")?;
    let oidc_http = oidc_http
        .context("AS mode requires the shared OIDC HTTP clients (checked during composition)")?;

    let AsServerConfig {
        upstream_client_id,
        upstream_client_secret,
        upstream_redirect_uri,
        upstream_scopes,
        upstream_token_keys,
        upstream_token_active_id,
        cimd_allowed_hosts,
        cimd_dev_doc_dir,
        access_token_ttl,
        refresh_token_ttl,
        transaction_ttl,
        code_ttl,
        allowed_scopes,
    } = as_cfg.clone();

    let endpoints = OidcEndpoints::discover(&oidc_http.discovery, issuer)
        .await
        .with_context(|| format!("OIDC discovery from issuer {issuer} (for AS mode)"))?;
    tracing::info!(
        issuer = %issuer,
        authorize = %endpoints.authorization_endpoint,
        token = %endpoints.token_endpoint,
        "discovered upstream endpoints for AS mode"
    );

    // id_token validator for `/oauth/callback`. Audience is the gateway's
    // upstream client_id (that's what Authentik sets as `aud` on id_tokens
    // it issues to us), issuer is `AUTHENTIK_ISSUER`. Its own JwksProvider
    // — independent cache from the access-token path.
    let upstream_id_jwks = Arc::new(JwksProvider::new(issuer));
    upstream_id_jwks.prime().await;
    let upstream_id_validator = Arc::new(IdTokenValidator::new(
        upstream_id_jwks,
        issuer,
        upstream_client_id.clone(),
    ));

    let upstream_crypto =
        UpstreamCrypto::from_keyring(upstream_token_keys, &upstream_token_active_id)
            .map_err(|e| anyhow::anyhow!("GATEWAY_UPSTREAM_TOKEN_KEY_*: {e}"))?;
    tracing::info!(
        active_id = %upstream_crypto.active_id(),
        "loaded upstream-token keyring for AS mode"
    );

    // Gateway-wide kill switch for the interactive consent
    // screen. Default false (the audit-only path stays
    // unchanged); set to `true` for high-assurance deployments
    // that want OAuth 2.1 §10.4 confused-deputy mitigation made
    // VISIBLE to end users. A future per-tenant
    // `tenants.require_explicit_consent` column could replace
    // this gateway-wide flag.
    let require_explicit_consent =
        waygate_core::env::bool_default_off("GATEWAY_REQUIRE_EXPLICIT_CONSENT");
    if require_explicit_consent {
        tracing::warn!(
            "GATEWAY_REQUIRE_EXPLICIT_CONSENT=true — every /oauth/callback for a \
             new (tenant, sub, client) tuple will route through the consent screen \
             before the gateway code is minted",
        );
    }
    // EMA (ID-JAG) token-exchange config. Disabled by default;
    // enabled per-deployment via GATEWAY_AS_IDJAG_ENABLED.
    let idjag_enabled = waygate_core::env::bool_default_off("GATEWAY_AS_IDJAG_ENABLED");
    let idjag_ttl = waygate_core::env::duration_secs(
        "GATEWAY_AS_IDJAG_TTL_SECONDS",
        300,
        1..=u64::MAX,
        "lifetime of a minted ID-JAG in seconds",
    )?;
    let idjag_require_scim = waygate_core::env::bool_default_on("GATEWAY_AS_IDJAG_REQUIRE_SCIM");
    // Advertise EMA support in RFC 8414 metadata (ID-JAG grant URNs +
    // grant profile). Off by default; the metadata handler additionally requires
    // EMA to be wired (`ema.is_some()`) before broadcasting.
    let idjag_advertise = waygate_core::env::bool_default_off("GATEWAY_AS_IDJAG_ADVERTISE");
    // EMA target allowlists. Audiences default to the gateway's own issuer
    // (Tier-A/B self-redemption — the client redeems the ID-JAG back at this
    // same gateway); operators add peer Resource-AS issuers via
    // GATEWAY_AS_IDJAG_AUDIENCES. Resources are operator-enumerated MCP-server
    // identifiers (GATEWAY_AS_IDJAG_RESOURCES) — fail-closed (empty ⇒ no
    // resource may be granted). Resources are derived from the
    // per-upstream manifest resource ids (`manifest_resource_ids`), unioned with
    // any operator-listed GATEWAY_AS_IDJAG_RESOURCES so mint + the /mcp redeem
    // binding agree on the canonical resource id format.
    let mut idjag_allowed_audiences: Vec<String> =
        vec![cfg.public_url.trim_end_matches('/').to_owned()];
    idjag_allowed_audiences.extend(parse_idjag_list("GATEWAY_AS_IDJAG_AUDIENCES"));
    let mut idjag_known_resources: Vec<String> = manifest_resource_ids;
    for r in parse_idjag_list("GATEWAY_AS_IDJAG_RESOURCES") {
        if !idjag_known_resources.contains(&r) {
            idjag_known_resources.push(r);
        }
    }
    // EMA redeem: issuers whose ID-JAGs the jwt-bearer grant accepts.
    // Defaults to the gateway's own issuer (homelab self-redemption — the
    // gateway is the Resource AS for the ID-JAGs it mints); operators add
    // trusted peer/IdP issuers via GATEWAY_AS_TRUSTED_IDP_ISSUERS.
    let mut idjag_trusted_issuers: Vec<String> =
        vec![cfg.public_url.trim_end_matches('/').to_owned()];
    idjag_trusted_issuers.extend(parse_idjag_list("GATEWAY_AS_TRUSTED_IDP_ISSUERS"));
    let as_config = AsConfig {
        public_url: cfg.public_url.clone(),
        audience: cfg.audience.clone(),
        upstream_issuer: issuer.clone(),
        upstream_authorize_endpoint: endpoints.authorization_endpoint,
        upstream_token_endpoint: endpoints.token_endpoint,
        upstream_client_id,
        upstream_client_secret,
        upstream_redirect_uri,
        upstream_scopes,
        upstream_crypto,
        cimd_allowed_hosts,
        cimd_dev_doc_dir,
        access_token_ttl,
        refresh_token_ttl,
        transaction_ttl,
        code_ttl,
        allowed_scopes,
        require_explicit_consent,
        idjag_ttl,
        idjag_require_scim,
        idjag_allowed_audiences,
        idjag_known_resources,
        idjag_trusted_issuers,
        idjag_advertise,
    };
    as_config
        .validate()
        .map_err(|e| anyhow::anyhow!("AS config invalid: {e}"))?;

    tracing::info!(
        public_url = %as_config.public_url,
        audience = %as_config.audience,
        access_ttl_secs = as_config.access_token_ttl.as_secs(),
        cimd_hosts = ?as_config.cimd_allowed_hosts,
        "gateway-as-AS mode enabled"
    );
    let store = OauthStore::new(pool.clone());

    // Wire the EMA token-exchange (ID-JAG mint) endpoint when
    // enabled. The subject resolver validates a gateway-minted access token
    // (preloaded keyring JWKS — the primary path, where the client SSO'd to
    // the gateway via CIMD) or an Authentik id_token; the cross-app policy
    // reuses the same Cedar gate as /mcp; the enricher is the same chained
    // (tenant+SCIM+RBAC) enricher the bearer middleware uses, so the mint is
    // gated on SCIM-authoritative facts.
    let ema = if idjag_enabled {
        let keyring = identity_keyring.context(
            "GATEWAY_AS_IDJAG_ENABLED=true requires an identity keyring (AS mode provides one)",
        )?;
        let jwks_json = serde_json::to_string(&keyring.jwks())
            .context("serialize gateway JWKS for ID-JAG subject resolver")?;
        let gw_jwks = Arc::new(
            JwksProvider::from_preloaded(cfg.public_url.clone(), &jwks_json)
                .context("preload gateway JWKS for ID-JAG subject resolver")?,
        );
        let access_validator = Arc::new(BearerValidator::new(
            gw_jwks.clone(),
            cfg.public_url.clone(),
            cfg.audience.clone(),
        ));
        let subject_resolver: Arc<dyn waygate_as::SubjectTokenResolver> = Arc::new(
            crate::ema::ServerSubjectResolver::new(access_validator, upstream_id_validator.clone()),
        );
        let cross_app_policy: Arc<dyn waygate_as::CrossAppPolicy> =
            Arc::new(crate::ema::CedarCrossAppPolicy::new(authz.clone()));
        tracing::info!(
            ttl_secs = idjag_ttl.as_secs(),
            require_scim = idjag_require_scim,
            trusted_issuers = ?as_config.idjag_trusted_issuers,
            "EMA enabled at /oauth/token (token-exchange mint + jwt-bearer redeem)"
        );
        Some(waygate_as::EmaDeps {
            subject_resolver,
            cross_app_policy,
            enricher: principal_enricher.cloned(),
            // The redeem path verifies ID-JAG signatures against the same
            // gateway keyring JWKS (self-redemption). gw_jwks is shared with the
            // mint subject-resolver's access validator above.
            verifier: Some(gw_jwks),
            // The redeem path authenticates the redeeming confidential
            // client against this registry (admin-managed via
            // /api/v1/admin/oauth-clients).
            client_store: Some(Arc::new(waygate_as::PgConfidentialClientStore::new(
                pool.clone(),
            ))),
            // The redeem path verifies a peer-minted ID-JAG's (Tier-C)
            // signature against the shared federation peer JWKS cache (the same
            // cache the inbound PeerJwtValidator + the outbound pool use), and
            // takes the redeemed token's tenant from the peer's federated_peers
            // record. `None` ⇒ only self-issued ID-JAGs are redeemable.
            peer_jwks: peer_jwks.clone(),
        })
    } else {
        None
    };

    let router = waygate_as::build_router(
        as_config,
        pool,
        oidc_http.token.clone(),
        identity,
        upstream_id_validator,
        evidence,
        ema,
    );
    Ok(Some((router, store)))
}

/// The bearer layer builder also surfaces the concrete
/// `ApiKeyValidator` (when configured) so `AdminState` can hold the
/// same `Arc` the chain consumes. The tenant DELETE cleanup
/// invalidates this validator's cache after revoking rows; without
/// a shared handle the cache flush wouldn't bite the bearer hot
/// path.
// The BearerValidator that trusts gateway-minted access tokens
// MUST be preloaded with every kid in the rotation keyring, not
// just the active key. Otherwise an operator flipping
// GATEWAY_IDENTITY_JWT_ACTIVE from v1→v2 would 401 every
// still-unexpired v1 access token on the very next request
// because the validator's preloaded JwksProvider only knows
// about v2. The public JWKS route already carries both kids;
// the gateway's own internal validator must be fed
// `keyring.jwks()` (all kids), not `issuer.jwks()`
// (single-key), by threading the keyring through this builder.
pub(crate) async fn build_bearer_layer(
    cfg: &Config,
    identity_keyring: Option<&SharedIdentityKeyring>,
    db_pool: Option<&PgPool>,
    // Optional peer JWKS cache. When `Some`, a `PeerJwtValidator`
    // is added to the chain so JWTs whose `iss` matches a
    // registered `federated_peers` row are accepted under that
    // peer's tenant attribution. The cache is shared with the
    // refresh task — both sides hold the same `Arc` so refreshed
    // JWKS land immediately on the validator's hot path.
    peer_jwks_cache: Option<waygate_federation::jwks::SharedPeerJwksCache>,
    // Per-upstream RFC 9728 resource ids → server name. The
    // gateway-JWT validator accepts these as audiences (additive to the estate
    // audience) and records a single-server binding for resource-scoped tokens.
    idjag_resource_audiences: std::collections::HashMap<String, String>,
) -> anyhow::Result<(BearerLayer, Option<Arc<ApiKeyValidator>>)> {
    match cfg.auth_mode {
        AuthMode::Disabled => {
            tracing::warn!(
                "GATEWAY_AUTH_MODE=disabled — /mcp and /api/v1 are wide open. \
                 Do not run this in production."
            );
            Ok((BearerLayer::disabled(), None))
        }
        AuthMode::Enforce => {
            let mut validators: Vec<Arc<dyn HeaderValidator>> = Vec::new();
            let mut api_key_validator_arc: Option<Arc<ApiKeyValidator>> = None;

            // Gateway-minted tokens (CIMD mode). Preloaded JWKS
            // from the IdentityKeyring — no HTTP hop, no
            // discovery; the gateway is its own AS and trusts
            // every kid in its own rotation set. Preloading just
            // the active key would 401 unexpired access tokens
            // minted under a prior kid the moment
            // GATEWAY_IDENTITY_JWT_ACTIVE is flipped — defeating
            // the rotation goal.
            if cfg.as_server.is_some() {
                let keyring = identity_keyring.ok_or_else(|| {
                    anyhow::anyhow!("AS mode requires an identity keyring (checked in Config)")
                })?;
                let jwks_json = serde_json::to_string(&keyring.jwks())
                    .context("serialize gateway JWKS for preloaded validator")?;
                let jwks = Arc::new(
                    JwksProvider::from_preloaded(cfg.public_url.clone(), &jwks_json)
                        .context("preload gateway JWKS")?,
                );
                // Accept per-upstream resource ids as audiences too
                // (additive to the estate audience) so EMA-redeemed,
                // resource-scoped tokens validate AND are confined to their
                // upstream via the recorded server binding.
                let resource_audience_count = idjag_resource_audiences.len();
                let v: Arc<dyn HeaderValidator> = Arc::new(
                    BearerValidator::new(jwks, cfg.public_url.clone(), cfg.audience.clone())
                        .with_resource_audiences(idjag_resource_audiences),
                );
                validators.push(v);
                tracing::info!(
                    issuer = %cfg.public_url,
                    audience = %cfg.audience,
                    resource_audiences = resource_audience_count,
                    "bearer validator configured: gateway-minted (preloaded JWKS)"
                );
            }

            // Upstream (Authentik) tokens. Required when AS is disabled; also
            // kept on as a fallback validator when `accept_upstream_tokens` —
            // see `Config::accept_upstream_tokens` for the M2M / service-
            // account use case that flag supports.
            let want_upstream = cfg.as_server.is_none() || cfg.accept_upstream_tokens;
            if want_upstream {
                if let Some(issuer) = cfg.authentik_issuer.as_ref() {
                    let jwks = Arc::new(JwksProvider::new(issuer.clone()));
                    jwks.prime().await;
                    let validator = BearerValidator::new(jwks, issuer, cfg.audience.clone())
                        .with_additional_issuers(cfg.authentik_additional_issuers.clone());
                    let v: Arc<dyn HeaderValidator> = Arc::new(validator);
                    validators.push(v);
                    tracing::info!(
                        issuer = %issuer,
                        additional_issuers = ?cfg.authentik_additional_issuers,
                        audience = %cfg.audience,
                        "bearer validator configured: Authentik"
                    );
                } else if cfg.as_server.is_none() {
                    anyhow::bail!("enforce mode requires AUTHENTIK_ISSUER (checked in Config)");
                }
            }

            // RFC 7662 opaque-token introspection. Slotted
            // between the JWT validators above and the API-key
            // validator below — JWT-shaped tokens (3 base64url
            // segments) skip this path via the shape filter
            // in `OpaqueTokenValidator::validate_header`,
            // and API-key-shaped tokens (`mcpgw_…`) skip
            // it too. Only set up when both env triples
            // (URL + client id + secret) are present.
            //
            // The introspection validator accepts UPSTREAM
            // (Authentik) opaque tokens, which is the same OAuth
            // "token passthrough" anti-pattern the
            // `accept_upstream_tokens` flag gates the JWT
            // validator against. Reuse the same `want_upstream`
            // criterion (`as_server is None || flag is set`)
            // so the introspection path can't sneak past it.
            // In the typical `GATEWAY_AS_ENABLED=true` +
            // `GATEWAY_ACCEPT_UPSTREAM_TOKENS=false` (the
            // recommended, prod-safe combo), the operator
            // wants Authentik tokens REJECTED — both the JWT
            // shape and the opaque shape.
            if let Some(intro) = cfg.introspection.as_ref() {
                if !want_upstream {
                    tracing::warn!(
                        introspection_url = %intro.introspection_url,
                        "GATEWAY_INTROSPECTION_URL is set but GATEWAY_AS_ENABLED=true \
                         AND GATEWAY_ACCEPT_UPSTREAM_TOKENS!=true — introspection validator \
                         not wired (would be the OAuth token-passthrough anti-pattern). \
                         Unset GATEWAY_INTROSPECTION_URL, OR set \
                         GATEWAY_ACCEPT_UPSTREAM_TOKENS=true (development only; prod refuses) to \
                         opt in explicitly."
                    );
                } else {
                    // JWT and opaque-token validators must both read the literal
                    // `tenant` claim so authorization and audit agree on tenancy.
                    let intro_cfg = waygate_oidc::IntrospectionConfig {
                        introspection_url: intro.introspection_url.clone(),
                        client_id: intro.client_id.clone(),
                        client_secret: intro.client_secret.clone(),
                        issuer: cfg
                            .authentik_issuer
                            .clone()
                            .unwrap_or_else(|| cfg.public_url.clone()),
                        expected_audience: cfg.audience.clone(),
                        tenant_claim: "tenant".into(),
                        max_positive_ttl: intro.max_positive_ttl,
                        negative_ttl: intro.negative_ttl,
                        cache_capacity: 8192,
                    };
                    let validator = waygate_oidc::OpaqueTokenValidator::new(intro_cfg)
                        .map_err(|e| anyhow::anyhow!("introspection validator construct: {e}"))?;
                    let v: Arc<dyn HeaderValidator> = validator;
                    validators.push(v);
                    tracing::info!(
                        introspection_url = %intro.introspection_url,
                        max_positive_ttl_secs = intro.max_positive_ttl.as_secs(),
                        negative_ttl_secs = intro.negative_ttl.as_secs(),
                        "bearer validator configured: RFC 7662 introspection (opaque tokens)"
                    );
                }
            }

            // Static API keys. Disabled by default; when enabled, runs
            // last in the chain so any legitimate JWT is preferred (an
            // OAuth token will hit one of the JWT validators above first,
            // and the API-key validator only ever spends argon2 cycles on
            // headers that actually start with `mcpgw_`). Requires the
            // Postgres pool — gated by config-level check.
            if let Some(api_keys) = &cfg.api_keys {
                let pool = db_pool.ok_or_else(|| {
                    anyhow::anyhow!(
                        "GATEWAY_API_KEYS_ENABLED=true requires a DB pool \
                         (checked in Config)",
                    )
                })?;
                let store = ApiKeyStore::new(pool.clone());
                let validator = ApiKeyValidator::new(
                    store,
                    ApiKeyValidatorConfig {
                        cache_ttl: api_keys.cache_ttl,
                        ..ApiKeyValidatorConfig::default()
                    },
                );
                // Hand the profile store to the validator so it can
                // resolve `Principal.api_key_profile_restrictions`
                // at validation time. The invocation gate then
                // enforces with no per-call store lookup.
                let validator = validator.with_profile_store(Some(Arc::new(
                    waygate_apikeys::PgProfileStore::new(pool.clone()),
                )
                    as Arc<dyn waygate_apikeys::ProfileStore>));
                // Retain the concrete Arc so AdminState can call
                // `invalidate_all()` on it from the tenant DELETE
                // cleanup. The chain still consumes a type-erased Arc.
                api_key_validator_arc = Some(validator.clone());
                let v: Arc<dyn HeaderValidator> = validator;
                validators.push(v);
                tracing::info!(
                    cache_ttl_secs = api_keys.cache_ttl.as_secs(),
                    "bearer validator configured: api_keys (static `mcpgw_…` tokens)",
                );
            }

            // Peer-asserted JWT validator, wired only when a
            // federated_peers store + JWKS cache pair were
            // threaded through. Pushed LAST in
            // the chain so a peer-issued token only hits this
            // leg if AS, Authentik, introspection, and the
            // api-key validator all rejected it — minimising
            // redundant work in the common single-tenant case
            // where peer federation is unused. The validator
            // itself is a fall-through path on a cache miss:
            // when no cached peer matches the `iss` claim it
            // returns a client error and the bearer middleware
            // 401s without poisoning subsequent validators
            // (there are none after this one). When the cache
            // is empty (no peers refreshed yet), every token
            // surfaces as a no-peer rejection; the configured
            // refresh task warms the cache once at boot and
            // every `peer_jwks_refresh_interval` after.
            if let Some(cache) = peer_jwks_cache {
                let v: Arc<dyn HeaderValidator> =
                    Arc::new(waygate_federation::peer_jwt::PeerJwtValidator::new(
                        cache,
                        cfg.audience.clone(),
                    ));
                validators.push(v);
                tracing::info!(
                    audience = %cfg.audience,
                    "bearer validator configured: peer assertion (Tier-C federated peers)",
                );
            }

            if validators.is_empty() {
                anyhow::bail!(
                    "no bearer validators configured — set AUTHENTIK_ISSUER or \
                     GATEWAY_AS_ENABLED=true"
                );
            }

            let resource_metadata_url = format!(
                "{}{}",
                cfg.public_url.trim_end_matches('/'),
                ResourceMetadata::PATH
            );
            // Per MCP 2025-11-25, 401 challenges SHOULD include a `scope`
            // parameter advertising the minimum scopes a fresh client
            // should request. Baseline = `mcp:invoke mcp:read`; the
            // `mcp:invoke:high` step-up scope comes back via 403
            // `insufficient_scope` challenges from the authz layer
            // per-request, not here.
            Ok((
                BearerLayer::enforce_multi(validators, resource_metadata_url)
                    .with_scope_hint("mcp:invoke mcp:read"),
                api_key_validator_arc,
            ))
        }
    }
}

/// Resolve rmcp's host allowlist.
///
/// rmcp 1.8 rejects any request whose `Host` header isn't in this list
/// (DNS-rebinding guard). Defaults ship with only `localhost`/`127.0.0.1`/
/// `::1`, which 403s every request through Traefik. When the operator
/// passes `GATEWAY_MCP_ALLOWED_HOSTS` we use that list verbatim (empty
/// list disables the guard, e.g. when Traefik already enforces the host
/// match). Otherwise we derive a sensible default from the gateway's
/// public URL plus the loopback entries the healthcheck relies on.
pub(crate) fn resolve_mcp_allowed_hosts(
    public_url: &str,
    override_list: Option<&[String]>,
) -> anyhow::Result<Vec<String>> {
    if let Some(list) = override_list {
        return Ok(list.to_vec());
    }
    let parsed = url::Url::parse(public_url)
        .with_context(|| format!("GATEWAY_PUBLIC_URL is not a valid URL: {public_url}"))?;
    let host = parsed
        .host_str()
        .with_context(|| format!("GATEWAY_PUBLIC_URL has no host: {public_url}"))?
        .to_ascii_lowercase();
    let mut allowed = vec![
        host.clone(),
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
    ];
    if let Some(port) = parsed.port() {
        allowed.push(format!("{host}:{port}"));
    }
    allowed.sort();
    allowed.dedup();
    Ok(allowed)
}

/// Build the rmcp streamable-HTTP server config from operator settings.
///
/// The SSE keepalive interval must be set explicitly in BOTH directions:
/// rmcp's `Default` carries its own 15s heartbeat, so leaving the field
/// untouched would heartbeat at an interval no env var controls, and
/// `GATEWAY_SSE_KEEPALIVE_SECONDS=0` (`None` here) must actively override
/// that default to truly silence idle streams.
pub(crate) fn streamable_http_server_config(
    sse_keepalive: Option<std::time::Duration>,
    cancellation_token: CancellationToken,
    allowed_hosts: Vec<String>,
) -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        // Legacy (pre-2026-07-28) clients get sessions; the SDK default must
        // never decide this. 2026-07-28 requests are always served
        // statelessly regardless of this flag, so enabling it cannot leak
        // sessions into the new protocol.
        .with_legacy_session_mode(true)
        .with_max_request_body_bytes(crate::codemode_limits::limits().parent_frame_bytes)
        .with_sse_keep_alive(sse_keepalive)
        .with_cancellation_token(cancellation_token)
        .with_allowed_hosts(allowed_hosts)
}

pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install ctrl-c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install sigterm handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}

/// Default per-tenant cache row cap when `GATEWAY_LLM_CACHE_MAX_ROWS_PER_TENANT`
/// is unset.
pub(crate) const DEFAULT_LLM_CACHE_MAX_ROWS_PER_TENANT: i64 = 10_000;

/// Map the parsed `GATEWAY_LLM_CACHE_MAX_ROWS_PER_TENANT` value to the
/// per-tenant evict-oldest cap: `0` means **unbounded by count**
/// (TTL + sweep only) → `None`; `n > 0` caps a tenant at `n` rows. The default
/// is finite on purpose — the whole point of the cap is to bound growth within
/// a TTL window, so "unset" must not mean "unlimited". Parsing and
/// reject-at-boot on garbage live in the `waygate_core::env::u64_in` call at
/// the use site; this keeps only the 0-sentinel semantics.
pub(crate) fn llm_cache_row_cap(rows: u64) -> Option<i64> {
    match rows {
        0 => None,
        n => Some(n as i64),
    }
}

/// Break-glass store constructor for the `AdminState` wiring. The same
/// handle is wrapped around the Cedar gate (`BreakGlassGate::new`), so
/// admin reads / mints and runtime claims see the same rows.
pub(crate) fn build_break_glass_store(pg: sqlx::PgPool) -> waygate_authz::SharedBreakGlassStore {
    std::sync::Arc::new(waygate_authz::PgBreakGlassStore::new(pg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use waygate_mcp::audit::{EvidencePosture, InMemorySink};

    #[tokio::test]
    async fn rejected_bearer_attempts_use_chained_best_effort() {
        let sink = Arc::new(InMemorySink::new());
        let evidence: SharedEvidence = sink.clone();
        EvidenceAuthAttempts(evidence)
            .record(AuthAttemptOutcome::Rejected, "invalid bearer".to_owned())
            .await;

        let rows = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let rows = sink.snapshot_with_posture().await;
                if !rows.is_empty() {
                    break rows;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached evidence write must complete");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].posture, EvidencePosture::ChainedBestEffort);
        assert_eq!(
            rows[0].event.category,
            waygate_mcp::EvidenceCategory::AuthAttempt
        );
    }
}
