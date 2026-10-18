//! Transport construction for upstream connections.
//!
//! [`connect`] is the gateway's transport factory: given a parsed
//! [`UpstreamManifest`] and the optional identity-forwarding wiring, it
//! builds the right rmcp client transport (streamable HTTP, legacy SSE,
//! or stdio child process), serves it, and returns the connected
//! [`RunningService`]. Factored out of `UpstreamPool::dial` so the
//! per-transport construction lives in one place — the building block a
//! future per-upstream connection pool (the IdentityBroker work) dials
//! through.
//!
//! `dial` keeps the common tail (the post-connect `tools/list` + the
//! `Connection` it builds); this module owns transport-specific construction
//! and the initialization deadline every network dial must enforce.

use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use http::{HeaderName, HeaderValue};
use rmcp::model::{ClientCapabilities, ClientConfig, Implementation, ProtocolVersion};
use rmcp::service::{ClientInitializeError, ClientLifecycleMode, ClientServiceExt, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use zeroize::Zeroizing;

use waygate_oidc::SharedIdentityIssuer;

use crate::bounded_http_client::BoundedResponseClient;
use crate::dial_trace::{bounded_text, DialTrace, ExchangeRecorder};
use crate::http_policy;
use crate::identity_client::{IdentityAugmenter, IdentityCell, IdentityForwardingClient};
use crate::pool::ExchangeBundle;
use crate::sse_client;
use crate::{MtlsConfig, Transport, UpstreamAuth, UpstreamManifest, UpstreamProtocol};

#[derive(Debug, thiserror::Error)]
pub(crate) enum DialError {
    #[error("upstream transport connection failed: {0}")]
    Connect(String),
    #[error("http upstream missing `url`")]
    MissingUrl,
    #[error("upstream `{server}` has an invalid network URL")]
    InvalidNetworkUrl { server: String },
    #[error("could not resolve upstream `{server}`: {source}")]
    ResolveNetwork {
        server: String,
        #[source]
        source: std::io::Error,
    },
    #[error("upstream `{server}` resolved to no network addresses")]
    NoNetworkAddresses { server: String },
    #[error("stdio upstream missing `command`")]
    MissingCommand,
    #[error("spawn subprocess: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("initialize failed: {0}")]
    Init(String),
    #[error("tools/list failed: {0}")]
    ListTools(String),
    #[error("auth env var `{env}` and its `{env}_FILE` companion are unset or empty")]
    MissingAuthEnv { env: String },
    /// A resolved secret cannot be sent as a header value, for example because
    /// it contains a line break. Only the variable name is reported.
    #[error("auth secret from `{env}` is not a valid HTTP header value")]
    AuthSecretNotHeaderSafe { env: String },
    /// A fixed `headers:` entry the manifest validator should have refused.
    #[error("`headers:` entry `{name}` is not a valid HTTP header")]
    InvalidFixedHeader { name: String },
    #[error("auth bearer file named by `{file_env}` could not be read: {source}")]
    AuthFileRead {
        file_env: String,
        #[source]
        source: std::io::Error,
    },
    #[error("auth bearer file named by `{file_env}` exceeds the {max_bytes}-byte limit")]
    AuthFileTooLarge { file_env: String, max_bytes: usize },
    #[error("auth bearer file named by `{file_env}` is not a regular file")]
    AuthFileNotRegular { file_env: String },
    #[error("auth bearer file named by `{file_env}` is not valid UTF-8")]
    AuthFileInvalidUtf8 { file_env: String },
    #[error("auth bearer file named by `{file_env}` is empty")]
    AuthFileEmpty { file_env: String },
    #[error("`auth:` block is empty — set `bearer_env: <ENV_VAR_NAME>`")]
    EmptyAuth,
    #[error("`auth:` is not supported for transport `{transport}` — only http and sse")]
    UnsupportedAuthForTransport { transport: &'static str },
    #[error(
        "upstream `{server}` configures `auth.catalog_probe_groups`, but the gateway has no \
         identity signer"
    )]
    CatalogProbeGroupsRequireIdentity { server: String },
    #[error(
        "upstream `{server}` configures `auth.catalog_probe_groups`, which requires \
         `session.isolation: per_call` so callers cannot reuse the privileged discovery session"
    )]
    CatalogProbeGroupsRequirePerCall { server: String },
    /// `mtls:` block omitted `cert_path` or `key_path`.
    /// Both are required when the block is present (no
    /// silent partial-mtls — that would be either no-TLS
    /// or anonymous-TLS, neither of which is mTLS).
    #[error("`mtls:` block requires both `cert_path` and `key_path`")]
    MtlsMissingField,
    /// `mtls.cert_path` / `key_path` / `ca_path`
    /// resolved but the file couldn't be read. Wraps the
    /// underlying IO error with the path that failed so
    /// an operator's first investigation step is `ls`.
    #[error("mtls: failed to read `{path}`: {source}")]
    MtlsReadFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("mtls: credential file `{path}` is not a regular file")]
    MtlsFileNotRegular { path: String },
    #[error("mtls: credential file `{path}` exceeds the {max_bytes}-byte limit")]
    MtlsFileTooLarge { path: String, max_bytes: usize },
    /// `mtls.cert_path` / `key_path` / `ca_path`
    /// loaded but `reqwest::Identity::from_pem` /
    /// `Certificate::from_pem` couldn't parse them. Most
    /// common cause: passing a `.der` file with a `.pem`
    /// path, or a key in a format rustls doesn't understand.
    #[error("mtls: invalid PEM in `{path}`: {detail}")]
    MtlsInvalidPem { path: String, detail: String },
    /// `mtls:` configured under SSE or stdio.
    /// Only `http` transport runs through a `reqwest::Client`
    /// the gateway controls; SSE has its own client (which
    /// doesn't carry the identity wiring today), stdio
    /// doesn't speak TLS at all. Reject loud rather than
    /// silently ignoring the field.
    #[error("`mtls:` is not supported for transport `{transport}` — only http")]
    MtlsUnsupportedForTransport { transport: &'static str },
    /// Building the `reqwest::Client` with the mTLS
    /// identity failed (e.g. underlying rustls rejected the
    /// configuration). Distinguished from `MtlsInvalidPem`
    /// because the cause is the assembled Client, not a
    /// single file.
    #[error("mtls: build reqwest client: {0}")]
    MtlsClientBuild(String),
    /// Building the shared non-mTLS streaming client failed before any
    /// upstream request was attempted.
    #[error("build upstream streaming HTTP client: {0}")]
    HttpClientBuild(String),
    /// The transport connected, but the MCP initialization handshake did not
    /// complete before the production deadline. `exchanges` summarizes what a
    /// streamable-HTTP dial was still waiting on, when the dial recorded any.
    #[error("upstream MCP handshake exceeded {timeout:?}{}", exchange_suffix(.exchanges.as_deref()))]
    HandshakeTimeout {
        timeout: Duration,
        exchanges: Option<String>,
    },
    /// The upstream answered a request with a redirect. Upstream requests
    /// never follow one, because the request carries the gateway's credentials
    /// and the caller's identity and the target is outside the pinned host.
    #[error(
        "upstream `{server}` answered with a redirect (HTTP {status}); redirect refused. \
         Set its `url` to the address that serves MCP without redirecting"
    )]
    RedirectRefused {
        server: String,
        status: http::StatusCode,
    },
    /// A legacy-SSE upstream announced a message endpoint on another origin.
    /// `announced` holds only that origin, never the endpoint's path or query.
    #[error(
        "upstream `{server}` announced an SSE message endpoint on {announced}; endpoint refused \
         because it must use the scheme, host, and port of the configured `url`"
    )]
    SseEndpointRefused { server: String, announced: String },
    /// Security guard: `mtls:` is
    /// configured but the upstream URL is plaintext
    /// `http://`. mTLS only activates during a TLS
    /// handshake; with `http://` no handshake happens,
    /// the client cert is never presented, and the
    /// operator believes the cert is in use while the
    /// gateway is dialing unauthenticated. Refuse loud
    /// rather than silently dropping the cert.
    #[error("mtls: requires an `https://` upstream URL; got `{url}` for server `{server}`")]
    MtlsRequiresHttps { server: String, url: String },
}

/// Byte cap on the SDK text a handshake or catalog failure carries. That text
/// can quote an upstream response, and it reaches operator logs and audit
/// evidence.
const MAX_DIAL_ERROR_DETAIL_BYTES: usize = 1024;

impl DialError {
    fn connect(detail: impl std::fmt::Display) -> Self {
        Self::Connect(bounded_text(
            &detail.to_string(),
            MAX_DIAL_ERROR_DETAIL_BYTES,
        ))
    }

    fn init(detail: impl std::fmt::Display) -> Self {
        Self::Init(bounded_text(
            &detail.to_string(),
            MAX_DIAL_ERROR_DETAIL_BYTES,
        ))
    }

    pub(crate) fn list_tools(detail: impl std::fmt::Display) -> Self {
        Self::ListTools(bounded_text(
            &detail.to_string(),
            MAX_DIAL_ERROR_DETAIL_BYTES,
        ))
    }

    /// Append what the upstream did on this dial to a handshake or catalog
    /// failure, whose SDK text alone can be as little as `Transport closed`.
    fn with_http_exchanges(self, exchanges: &DialTrace) -> Self {
        let Some(summary) = exchanges.summary() else {
            return self;
        };
        match self {
            Self::Connect(detail) => Self::Connect(format!("{detail}; {summary}")),
            Self::Init(detail) => Self::Init(format!("{detail}; {summary}")),
            Self::ListTools(detail) => Self::ListTools(format!("{detail}; {summary}")),
            Self::HandshakeTimeout {
                timeout,
                exchanges: None,
            } => Self::HandshakeTimeout {
                timeout,
                exchanges: Some(summary),
            },
            other => other,
        }
    }

    pub(crate) fn handshake_timeout(timeout: Duration) -> Self {
        Self::HandshakeTimeout {
            timeout,
            exchanges: None,
        }
    }

    pub(crate) fn redirect_refused(server: &str, refused: http_policy::RedirectRefused) -> Self {
        Self::RedirectRefused {
            server: server.to_owned(),
            status: refused.status,
        }
    }
}

fn exchange_suffix(exchanges: Option<&str>) -> String {
    exchanges
        .map(|summary| format!("; {summary}"))
        .unwrap_or_default()
}

fn map_client_initialize_error(
    server: &str,
    error: ClientInitializeError,
    probe: &BoundedResponseClient,
) -> DialError {
    if let Some(refused) = probe.refused_redirect() {
        DialError::redirect_refused(server, refused)
    } else if probe.connection_failed() {
        DialError::connect(error)
    } else {
        DialError::init(error)
    }
}

fn map_sse_connect_error(server: &str, error: sse_client::SseConnectError) -> DialError {
    match error {
        sse_client::SseConnectError::RedirectRefused(refused) => {
            DialError::redirect_refused(server, refused)
        }
        sse_client::SseConnectError::EndpointRefused { announced } => {
            DialError::SseEndpointRefused {
                server: server.to_owned(),
                announced,
            }
        }
        other => DialError::init(other),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PinnedNetworkDestination {
    host: String,
    port: u16,
    addresses: Vec<IpAddr>,
}

impl PinnedNetworkDestination {
    pub(crate) fn new(host: String, port: u16, addresses: Vec<IpAddr>) -> Self {
        Self {
            host,
            port,
            addresses,
        }
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    fn socket_addresses(&self) -> Vec<SocketAddr> {
        self.addresses
            .iter()
            .copied()
            .map(|address| SocketAddr::new(address, self.port))
            .collect()
    }
}

pub(crate) struct ConnectedService {
    pub(crate) service: RunningService<RoleClient, ClientConfig>,
    pub(crate) network_destination: Option<PinnedNetworkDestination>,
    pub(crate) cleartext_control_plane: bool,
    /// Cancel to end every request this connection still has open with the
    /// upstream before the service closes. Only streamable HTTP holds a
    /// request open that the service's own shutdown cannot reach.
    pub(crate) open_requests: tokio_util::sync::CancellationToken,
    /// Set when this connection refused a redirect. A dial request after the
    /// handshake fails only as a generic request error, so the dial reads this
    /// to report the refusal instead.
    pub(crate) refused_redirect: std::sync::Arc<std::sync::OnceLock<http_policy::RedirectRefused>>,
}

/// A connection whose dial is still recording its HTTP exchanges.
///
/// The connection is handed over only by [`Self::finish_dial`], which ends the
/// recording, so traffic on an established connection is never recorded. The
/// pool's dial lists the catalog through [`Self::service`] first, because a
/// failed listing is still a failed dial.
pub(crate) struct DialedService {
    connected: ConnectedService,
    exchanges: DialTrace,
}

impl DialedService {
    /// The session, for requests that are still part of the dial.
    pub(crate) fn service(&self) -> &RunningService<RoleClient, ClientConfig> {
        &self.connected.service
    }

    /// `error` followed by a summary of this dial's HTTP exchanges.
    pub(crate) fn with_http_exchanges(&self, error: DialError) -> DialError {
        error.with_http_exchanges(&self.exchanges)
    }

    /// The redirect this connection refused, if a dial request was redirected.
    pub(crate) fn refused_redirect(&self) -> Option<http_policy::RedirectRefused> {
        self.connected.refused_redirect.get().copied()
    }

    /// End the dial: stop recording and hand over the connection.
    pub(crate) fn finish_dial(self) -> ConnectedService {
        self.connected
    }

    #[cfg(test)]
    pub(crate) fn exchange_recorder(&self) -> ExchangeRecorder {
        self.exchanges.recorder()
    }
}

/// Build + serve the rmcp client transport for `manifest`, returning the
/// connected [`RunningService`]. The caller (`dial`) does the
/// post-connect `tools/list` and assembles its `Connection`. Network
/// transports must complete MCP initialization within the shared production
/// handshake deadline so every dial caller gets the same bounded behavior.
pub(crate) async fn connect(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
) -> Result<RunningService<RoleClient, ClientConfig>, DialError> {
    connect_with_handshake_timeout(
        manifest,
        issuer,
        cell,
        exchange,
        ClientCapabilities::default(),
        http_policy::HANDSHAKE_TIMEOUT,
    )
    .await
}

pub(crate) async fn connect_with_destination(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
) -> Result<DialedService, DialError> {
    connect_with_handshake_timeout_and_destination(
        manifest,
        issuer,
        cell,
        exchange,
        ClientCapabilities::default(),
        http_policy::HANDSHAKE_TIMEOUT,
    )
    .await
}

/// [`connect`] with an explicit client capability declaration for this dial.
///
/// The SDK fixes the declared capabilities per dial (the 2026-07-28 leg
/// stamps them into every request's `_meta`; the legacy leg sends them in
/// `initialize`), so per-caller capability mirroring is only possible where
/// the dial itself is per-caller: the pool's per-call ephemeral dial passes
/// the downstream caller's declared capabilities here when the upstream
/// negotiates 2026-07-28, so the upstream issues an MRTR pause exactly when
/// the caller can answer it. Every shared dial (boot/catalog lanes, reuse
/// lanes, legacy upstreams) keeps the default empty set — the gateway itself
/// fulfils no server-initiated request, so advertising nothing is the honest
/// declaration and the pre-MRTR behavior. On a legacy session the SDK's
/// default handler still replies: it answers `ping`, returns an empty root
/// list, declines elicitation and refuses sampling.
pub(crate) async fn connect_with_capabilities(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
    capabilities: ClientCapabilities,
) -> Result<DialedService, DialError> {
    connect_with_handshake_timeout_and_destination(
        manifest,
        issuer,
        cell,
        exchange,
        capabilities,
        http_policy::HANDSHAKE_TIMEOUT,
    )
    .await
}

/// Map the manifest's `protocol:` selection onto the rmcp client
/// lifecycle for one dial.
///
/// - `auto` probes with `server/discover` and drops to the legacy
///   `initialize` handshake if that probe fails at all. The downgrade is
///   the dial's, not the SDK's: see [`connect_with_handshake_timeout`]
///   for why the SDK's own `METHOD_NOT_FOUND` condition never fires
///   against a genuinely older upstream.
/// - `legacy` runs the initialize handshake unconditionally.
/// - `2026-07-28` requires discovery and never falls back.
/// - SSE transport is legacy by definition (the transport predates the
///   stateless protocol): `auto` resolves to the legacy handshake with
///   no discovery round trip, and manifest validation rejects an
///   explicit `2026-07-28` on SSE before a dial can happen.
///
/// Every dial runs this mapping fresh — deliberately no lifecycle
/// caching, so the observed generation is per-lane state as of that
/// lane's dial.
pub(crate) fn lifecycle_for(manifest: &UpstreamManifest) -> ClientLifecycleMode {
    if matches!(manifest.transport, Transport::Sse) {
        return ClientLifecycleMode::Initialize;
    }
    match manifest.protocol {
        UpstreamProtocol::Legacy => ClientLifecycleMode::Initialize,
        UpstreamProtocol::V20260728 => ClientLifecycleMode::Discover {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        },
        UpstreamProtocol::Auto => default_auto_lifecycle(),
    }
}

/// The gateway's `auto` lifecycle: prefer 2026-07-28 discovery, with the
/// SDK's own downgrade to the 2025-11-25 initialize handshake for a peer
/// that proves it is legacy. That proof is rarer than it looks, so the
/// dial wraps this mode in a broader bridge — see
/// [`connect_with_handshake_timeout`].
///
/// One definition — [`lifecycle_for`] and the `classify` CLI's scaffold
/// dial both use it, so operator tooling can never negotiate a different
/// generation than the serving path would.
pub fn default_auto_lifecycle() -> ClientLifecycleMode {
    ClientLifecycleMode::Auto {
        preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        legacy_version: Some(ProtocolVersion::V_2025_11_25),
    }
}

/// The client configuration every gateway dial and the `classify` CLI send.
///
/// The configured client version is read only by the plain `initialize`
/// lifecycle; discovery and the SDK's `auto` fallback choose their own. It
/// stays the SDK's newest version on purpose. An upstream that speaks that
/// version answers the handshake with it and keeps no protocol session, while
/// one that answers with an older version opens a session for the handshake.
/// Per-call isolation dials on every call, so proposing an older version would
/// open a session per call on an upstream that could have served them without
/// one, and a session-limited upstream refuses every call once its limit is
/// reached. A legacy upstream answers with the version it speaks either way.
pub fn client_config(
    capabilities: ClientCapabilities,
    implementation: Implementation,
) -> ClientConfig {
    ClientConfig::new(capabilities, implementation)
}

/// The lifecycle the `auto` bridge falls back to when discovery fails —
/// the second half of the negotiation [`default_auto_lifecycle`] starts.
///
/// Exported as a pair with it so a caller that builds its own transport
/// (the `classify` CLI) runs the same two-step negotiation the serving
/// dial does, instead of reinventing the second step and drifting from it.
pub fn legacy_bridge_lifecycle() -> ClientLifecycleMode {
    ClientLifecycleMode::Initialize
}

/// Dial under [`lifecycle_for`], bridging `auto` down to the legacy
/// handshake when discovery fails.
///
/// The SDK's `Auto` lifecycle downgrades only when the peer answers
/// `server/discover` with `METHOD_NOT_FOUND`, and renegotiates only on a
/// structured `UNSUPPORTED_PROTOCOL_VERSION` error. Both are behaviors of a
/// server that already speaks the stateless generation. A server that
/// predates it cannot produce either: the discovery probe carries an
/// `MCP-Protocol-Version` header for a version such a server does not know,
/// so it is refused at the transport or session layer — as an unsupported
/// version, an unexpected non-`initialize` message, or a missing session —
/// before any method dispatch could answer `METHOD_NOT_FOUND`. Left to the
/// SDK alone, `auto` therefore means "new generation only", and every
/// older upstream fails to connect at all.
///
/// So `auto` owns the bridge here: one discovery attempt, and on any
/// handshake-phase failure one fresh legacy dial. It must be a fresh dial
/// rather than a second handshake on the same transport, because these
/// refusals are fatal to the transport worker — by the time the error
/// surfaces there is no live channel left to retry on.
///
/// The retry is deliberately not conditioned on the shape of the failure.
/// A refusal by a legacy server and an unreachable upstream both arrive as
/// transport errors that can only be told apart by matching on SDK message
/// text, which would silently stop bridging the day that wording changed.
/// Retrying once costs an unreachable upstream a second connection refusal
/// and buys independence from every upstream's phrasing.
///
/// Scope is exactly `auto`: an explicit `2026-07-28` must still fail rather
/// than be silently downgraded, and `legacy` has no discovery leg to fall
/// back from. The legacy leg proposes [`client_config`]'s version; the
/// handshake negotiates the version in its response, so the server picks what
/// it supports.
///
/// Both attempts record into one [`DialTrace`], so a failure that reaches the
/// caller also shows how discovery failed before the bridge.
async fn connect_with_handshake_timeout(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
    capabilities: ClientCapabilities,
    handshake_timeout: Duration,
) -> Result<RunningService<RoleClient, ClientConfig>, DialError> {
    Ok(connect_with_handshake_timeout_and_destination(
        manifest,
        issuer,
        cell,
        exchange,
        capabilities,
        handshake_timeout,
    )
    .await?
    .finish_dial()
    .service)
}

async fn connect_with_handshake_timeout_and_destination(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
    capabilities: ClientCapabilities,
    handshake_timeout: Duration,
) -> Result<DialedService, DialError> {
    let exchanges = DialTrace::new();
    let lifecycle = lifecycle_for(manifest);
    let dialed = dial_once(
        manifest,
        issuer,
        cell,
        exchange,
        capabilities.clone(),
        handshake_timeout,
        lifecycle.clone(),
        exchanges.recorder(),
    )
    .await;

    let dialed = match dialed {
        // Only the handshake itself is bridgeable. A timeout, a failed
        // subprocess spawn, a refused redirect, or a rejected `auth:`/`mtls:`
        // block would fail the same way twice, and retrying a timeout would
        // spend the handshake budget a second time.
        Err(DialError::Init(_)) if matches!(lifecycle, ClientLifecycleMode::Auto { .. }) => {
            dial_once(
                manifest,
                issuer,
                cell,
                exchange,
                capabilities,
                handshake_timeout,
                ClientLifecycleMode::Initialize,
                exchanges.recorder(),
            )
            .await
        }
        dialed => dialed,
    };
    match dialed {
        Ok(connected) => Ok(DialedService {
            connected,
            exchanges,
        }),
        Err(error) => Err(error.with_http_exchanges(&exchanges)),
    }
}

/// One dial under exactly the lifecycle it is given, with no fallback. A
/// streamable-HTTP dial reports its exchanges to `exchanges`; SSE and stdio
/// record none.
#[allow(clippy::too_many_arguments)]
async fn dial_once(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
    capabilities: ClientCapabilities,
    handshake_timeout: Duration,
    lifecycle: ClientLifecycleMode,
    exchanges: ExchangeRecorder,
) -> Result<ConnectedService, DialError> {
    let info = client_config(
        capabilities,
        Implementation::new(
            concat!("mcp-tool-search-gateway/", env!("CARGO_PKG_VERSION")),
            env!("CARGO_PKG_VERSION"),
        ),
    );
    match manifest.transport {
        Transport::Http => {
            let url = manifest
                .url
                .as_deref()
                .ok_or(DialError::MissingUrl)?
                .to_owned();
            let destination = resolve_network_destination(&manifest.name, &url).await?;
            // Resolve `auth:` from process env *before* building the transport
            // — a missing env var must fail the dial, not silently leak an
            // unauthenticated request to the configured URL. The query secret,
            // if any, is added only by the bounded client, so `url` and every
            // error built from it stay free of it.
            let credentials = resolve_request_credentials(manifest)?;
            let mut config = StreamableHttpClientTransportConfig::with_uri(url.clone());
            if let Some(token) = credentials.bearer {
                config = config.auth_header(token);
            }
            if !credentials.headers.is_empty() {
                config = config.custom_headers(credentials.headers.into_iter().collect());
            }
            // Build exactly one shared-policy streaming client per dial. The
            // non-mTLS and mTLS paths share the same no-total-timeout, bounded
            // connect, and disabled-idle-pool policy; mTLS only layers identity
            // and trust material onto that builder.
            // Security: an
            // `mtls:` block with an `http://` URL silently
            // disables TLS — no handshake, cert never
            // presented, operator believes the cert is in
            // use while the gateway dials unauthenticated.
            // Refuse loud BEFORE constructing the client
            // so the operator gets a structured error,
            // not a "works but isn't actually mTLS"
            // silent failure.
            let http = match manifest.mtls.as_ref() {
                Some(mtls) => {
                    if !url_is_https(&url) {
                        return Err(DialError::MtlsRequiresHttps {
                            server: manifest.name.clone(),
                            url: url.clone(),
                        });
                    }
                    build_mtls_client_with_destination(mtls, Some(&destination))?
                }
                None => build_streaming_client(Some(&destination))?,
            };
            let http =
                BoundedResponseClient::new(http, exchanges).with_query_secret(credentials.query);
            let connection_probe = http.clone();
            let open_requests = http.open_requests();
            let service = match (issuer, cell) {
                (Some(issuer), Some(cell)) => {
                    let mut wrapped =
                        IdentityForwardingClient::new(http, issuer.clone(), cell.clone());
                    if let Some(bundle) = exchange {
                        wrapped =
                            wrapped.with_exchange(bundle.client.clone(), bundle.cache.clone());
                    }
                    let transport = StreamableHttpClientTransport::with_client(wrapped, config);
                    tokio::time::timeout(
                        handshake_timeout,
                        info.serve_with_lifecycle(transport, lifecycle),
                    )
                    .await
                    .map_err(|_| DialError::handshake_timeout(handshake_timeout))?
                    .map_err(|error| {
                        map_client_initialize_error(&manifest.name, error, &connection_probe)
                    })
                }
                _ => {
                    let transport = StreamableHttpClientTransport::with_client(http, config);
                    tokio::time::timeout(
                        handshake_timeout,
                        info.serve_with_lifecycle(transport, lifecycle),
                    )
                    .await
                    .map_err(|_| DialError::handshake_timeout(handshake_timeout))?
                    .map_err(|error| {
                        map_client_initialize_error(&manifest.name, error, &connection_probe)
                    })
                }
            }?;
            Ok(ConnectedService {
                service,
                network_destination: Some(destination),
                cleartext_control_plane: url::Url::parse(&url)
                    .is_ok_and(|url| url.scheme() == "http"),
                open_requests,
                refused_redirect: connection_probe.refused_redirect_slot(),
            })
        }
        Transport::Sse => {
            // Static per-upstream credentials (`auth:` and `headers:`): resolve
            // from process env before dialing. A set-but-empty env fails the
            // dial loud rather than leaking an unauthenticated SSE connection —
            // same contract as the HTTP branch. `sse_client::connect` stamps
            // them on both the SSE GET and every message POST.
            let credentials = resolve_request_credentials(manifest)?.into_sse();
            // SSE flows through a different reqwest
            // client (`sse_client::connect`) that doesn't
            // wire per-upstream identity material today. Reject
            // loud rather than silently ignoring the mtls
            // block — same shape as the auth-on-sse error
            // above.
            if manifest.mtls.is_some() {
                return Err(DialError::MtlsUnsupportedForTransport { transport: "sse" });
            }
            let url = manifest
                .url
                .as_deref()
                .ok_or(DialError::MissingUrl)?
                .to_owned();
            let destination = resolve_network_destination(&manifest.name, &url).await?;
            let augmenter = match (issuer, cell) {
                (Some(issuer), Some(cell)) => {
                    let mut a = IdentityAugmenter::new(issuer.clone(), cell.clone());
                    if let Some(bundle) = exchange {
                        a = a.with_exchange(bundle.client.clone(), bundle.cache.clone());
                    }
                    Some(a)
                }
                _ => None,
            };
            // SSE stays on `info.serve` (the legacy initialize lifecycle):
            // the transport predates the stateless protocol, `lifecycle_for`
            // maps it to Initialize regardless of `protocol: auto`, and
            // manifest validation rejects an explicit `2026-07-28`.
            let handshake = async {
                let connected = sse_client::connect_with_control_plane(
                    &url,
                    build_streaming_client(Some(&destination))?,
                    augmenter,
                    credentials,
                    handshake_timeout,
                    http_policy::WRITE_TIMEOUT,
                )
                .await
                .map_err(|error| map_sse_connect_error(&manifest.name, error))?;
                let cleartext_control_plane = connected.cleartext_control_plane;
                let refused_redirect = connected.refused_redirect;
                let service = info.serve(connected.transport).await.map_err(|error| {
                    refused_redirect.get().map_or_else(
                        || DialError::init(error),
                        |refused| DialError::redirect_refused(&manifest.name, *refused),
                    )
                })?;
                Ok::<_, DialError>((service, cleartext_control_plane, refused_redirect))
            };
            let (service, cleartext_control_plane, refused_redirect) =
                tokio::time::timeout(handshake_timeout, handshake)
                    .await
                    .map_err(|_| DialError::handshake_timeout(handshake_timeout))??;
            Ok(ConnectedService {
                service,
                network_destination: Some(destination),
                cleartext_control_plane,
                open_requests: Default::default(),
                refused_redirect,
            })
        }
        Transport::Stdio => {
            // Stdio has no per-request HTTP header, so neither a bearer nor a
            // synthetic catalog identity can be delivered to the child.
            if manifest.auth.is_some() {
                return Err(DialError::UnsupportedAuthForTransport { transport: "stdio" });
            }
            if manifest.mtls.is_some() {
                return Err(DialError::MtlsUnsupportedForTransport { transport: "stdio" });
            }
            let argv = manifest
                .command
                .as_deref()
                .filter(|v| !v.is_empty())
                .ok_or(DialError::MissingCommand)?;
            if manifest.exchange.is_some() {
                // Token exchange is HTTP-centric (RFC 8693 over the IdP's
                // token endpoint with audience = upstream URI). Stdio has no
                // per-request header to stamp, so the field is inert here.
                tracing::warn!(
                    server = %manifest.name,
                    "exchange: block ignored for stdio upstream — identity forwarding is HTTP-only",
                );
            }
            for name in manifest
                .env_passthrough
                .iter()
                .filter(|name| std::env::var_os(name).is_none())
            {
                tracing::warn!(
                    server = %manifest.name,
                    variable = %name,
                    "env_passthrough names a variable the gateway has not set; the stdio child \
                     starts without it",
                );
            }
            let cmd = stdio_command(&argv[0], &argv[1..], &manifest.env_passthrough);
            let transport = TokioChildProcess::new(cmd).map_err(DialError::Spawn)?;
            let service = info
                .serve_with_lifecycle(transport, lifecycle)
                .await
                .map_err(DialError::init)?;
            Ok(ConnectedService {
                service,
                network_destination: None,
                cleartext_control_plane: false,
                open_requests: Default::default(),
                refused_redirect: Default::default(),
            })
        }
    }
}

/// Gateway environment variables every stdio child receives when the gateway
/// has them set. None carries a credential: `PATH` resolves the command and
/// any program it starts (launchers such as `npx` and `uvx` depend on it),
/// `HOME` and `TMPDIR` are where runtimes keep caches and scratch files, and
/// `LANG`, `LC_ALL` and `TZ` keep text encoding and timestamps consistent with
/// the gateway. Anything else reaches the child only through the manifest's
/// `env_passthrough`.
const STDIO_BASELINE_ENV: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"];

/// Build the command that starts a stdio upstream. The child's environment
/// starts empty, so it inherits none of the gateway's variables, then
/// receives [`STDIO_BASELINE_ENV`] and the variables `env_passthrough` names,
/// each with the gateway's own value. A named variable the gateway has not
/// set is left out rather than failing the start.
///
/// The gateway dial and the `classify` CLI both start upstream servers here,
/// so a scaffolded server sees the environment it will be served with.
pub fn stdio_command(
    program: &str,
    args: &[String],
    env_passthrough: &[String],
) -> tokio::process::Command {
    stdio_command_with_env(program, args, env_passthrough, |name| {
        std::env::var_os(name)
    })
}

fn stdio_command_with_env(
    program: &str,
    args: &[String],
    env_passthrough: &[String],
    gateway_env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args).env_clear();
    let names = STDIO_BASELINE_ENV
        .iter()
        .copied()
        .chain(env_passthrough.iter().map(String::as_str));
    for name in names {
        if let Some(value) = gateway_env(name) {
            cmd.env(name, value);
        }
    }
    cmd
}

async fn resolve_network_destination(
    server: &str,
    raw_url: &str,
) -> Result<PinnedNetworkDestination, DialError> {
    let url = url::Url::parse(raw_url).map_err(|_| DialError::InvalidNetworkUrl {
        server: server.to_owned(),
    })?;
    let host = url
        .host_str()
        .ok_or_else(|| DialError::InvalidNetworkUrl {
            server: server.to_owned(),
        })?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| DialError::InvalidNetworkUrl {
            server: server.to_owned(),
        })?;
    let resolved = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|source| DialError::ResolveNetwork {
            server: server.to_owned(),
            source,
        })?;
    let mut addresses = Vec::new();
    for address in resolved.map(|address| address.ip()) {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(DialError::NoNetworkAddresses {
            server: server.to_owned(),
        });
    }
    Ok(PinnedNetworkDestination::new(host, port, addresses))
}

fn pin_client_builder(
    builder: reqwest::ClientBuilder,
    destination: Option<&PinnedNetworkDestination>,
) -> reqwest::ClientBuilder {
    let Some(destination) = destination else {
        return builder;
    };
    let addresses = destination.socket_addresses();
    builder.resolve_to_addrs(destination.host(), &addresses)
}

fn build_streaming_client(
    destination: Option<&PinnedNetworkDestination>,
) -> Result<reqwest::Client, DialError> {
    pin_client_builder(http_policy::streaming_builder(), destination)
        .build()
        .map_err(|error| DialError::HttpClientBuild(error.to_string()))
}

/// Build a `reqwest::Client` wired with the manifest's
/// mTLS material. Reads `cert_path` + `key_path` (required), and
/// `ca_path` (optional). The cert + key are concatenated and
/// handed to `reqwest::Identity::from_pem`, which is the simplest
/// API across both file shapes (one cert+key blob OR two
/// separate-file blobs concatenated for it). The optional CA is
/// added via `Client::builder().add_root_certificate(...)`, which
/// SUPPLEMENTS the platform's default trust store rather than
/// replacing it — operators who need a private CA only can use
/// the platform store too; full-pinning is a stricter setting we
/// could add later behind a `tls_verify: strict` flag.
///
/// The error surface is intentionally distinct per-failure (`MtlsMissingField`,
/// `MtlsReadFailed`, `MtlsFileNotRegular`, `MtlsFileTooLarge`,
/// `MtlsInvalidPem`, `MtlsClientBuild`) so an
/// operator's first investigation step is named by the error
/// rather than "look in logs."
#[cfg(test)]
fn build_mtls_client(mtls: &MtlsConfig) -> Result<reqwest::Client, DialError> {
    build_mtls_client_with_destination(mtls, None)
}

fn build_mtls_client_with_destination(
    mtls: &MtlsConfig,
    destination: Option<&PinnedNetworkDestination>,
) -> Result<reqwest::Client, DialError> {
    let cert_path = mtls.cert_path.as_ref().ok_or(DialError::MtlsMissingField)?;
    let key_path = mtls.key_path.as_ref().ok_or(DialError::MtlsMissingField)?;

    let cert_bytes = read_mtls_file(cert_path)?;
    let key_bytes = read_mtls_file(key_path)?;

    // Concatenate cert + key into a single PEM blob and hand
    // to `Identity::from_pem`. If the operator pointed both
    // fields at the same file (single-file PEM with both
    // sections), `read` returns the same bytes twice;
    // `from_pem` ignores trailing PEM blocks of the same
    // section type, so this is robust to that shape.
    let mut combined = Zeroizing::new(Vec::with_capacity(cert_bytes.len() + key_bytes.len() + 1));
    combined.extend_from_slice(&cert_bytes);
    if !cert_bytes.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(&key_bytes);

    let identity =
        reqwest::Identity::from_pem(&combined).map_err(|e| DialError::MtlsInvalidPem {
            path: format!("{} + {}", cert_path.display(), key_path.display()),
            detail: e.to_string(),
        })?;

    let mut builder =
        pin_client_builder(http_policy::streaming_builder(), destination).identity(identity);

    if let Some(ca) = mtls.ca_path.as_ref() {
        let ca_bytes = read_mtls_file(ca)?;
        // A CA bundle can carry MULTIPLE roots in one file.
        // `Certificate::from_pem` reads one cert per call;
        // `from_pem_bundle` (reqwest 0.12+) reads all of
        // them. Use the bundle parser so an operator can
        // pin a CA-with-intermediates file.
        let certs = reqwest::Certificate::from_pem_bundle(&ca_bytes).map_err(|e| {
            DialError::MtlsInvalidPem {
                path: ca.display().to_string(),
                detail: e.to_string(),
            }
        })?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }

    builder
        .build()
        .map_err(|e| DialError::MtlsClientBuild(e.to_string()))
}

/// Does `url` use
/// the `https://` scheme? Returns `true` only for an
/// exact case-insensitive `https://` prefix; everything
/// else (`http://`, missing scheme, blank, weird casing
/// that happens to canonicalize differently) is rejected.
/// Used as the mTLS pre-flight guard so a manifest can't
/// configure a client cert that the gateway then drops on
/// the floor by dialing plaintext.
fn url_is_https(url: &str) -> bool {
    // Case-insensitive prefix match — `Url::parse` would
    // be more thorough but pulls in a parse path for what's
    // a literal scheme check. The full URL validation
    // happens inside reqwest when the request actually
    // dials; this gate is exclusively about "are we doing
    // TLS at all."
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("https://")
}

/// Resolve a manifest [`UpstreamAuth`] block into the bearer string sent on
/// the wire. Pulled out of [`connect`] so the parsing/lookup contract is easy
/// to unit-test and so adding a future variant (mTLS, basic) only needs to
/// extend this one function.
const MAX_AUTH_FILE_BYTES: usize = 16 * 1024;
/// Kubernetes caps each Secret at 1 MiB. Applying the same ceiling per mTLS
/// file keeps credential loading and versioning bounded while comfortably
/// covering ordinary PEM chains and CA bundles.
const MAX_MTLS_FILE_BYTES: usize = 1024 * 1024;

enum BoundedCredentialFileError {
    Read(std::io::Error),
    NotRegular,
    TooLarge,
}

fn read_bounded_credential_file(
    path: &std::path::Path,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, BoundedCredentialFileError> {
    let metadata = std::fs::metadata(path).map_err(BoundedCredentialFileError::Read)?;
    if !metadata.is_file() {
        return Err(BoundedCredentialFileError::NotRegular);
    }
    if metadata.len() > max_bytes as u64 {
        return Err(BoundedCredentialFileError::TooLarge);
    }
    let mut file = File::open(path).map_err(BoundedCredentialFileError::Read)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize + 1));
    file.by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(BoundedCredentialFileError::Read)?;
    if bytes.len() > max_bytes {
        return Err(BoundedCredentialFileError::TooLarge);
    }
    Ok(bytes)
}

fn read_mtls_file(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, DialError> {
    let display = || path.display().to_string();
    match read_bounded_credential_file(path, MAX_MTLS_FILE_BYTES) {
        Ok(bytes) => Ok(bytes),
        Err(BoundedCredentialFileError::Read(source)) => Err(DialError::MtlsReadFailed {
            path: display(),
            source,
        }),
        Err(BoundedCredentialFileError::NotRegular) => {
            Err(DialError::MtlsFileNotRegular { path: display() })
        }
        Err(BoundedCredentialFileError::TooLarge) => Err(DialError::MtlsFileTooLarge {
            path: display(),
            max_bytes: MAX_MTLS_FILE_BYTES,
        }),
    }
}

/// Process-local version of the credential material a dial consumes. The
/// keyed digest is retained only for equality checks; its value is deliberately
/// redacted from `Debug` and is never exported through logs, metrics, or APIs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CredentialMaterialVersion([u8; 32]);

impl std::fmt::Debug for CredentialMaterialVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialMaterialVersion([redacted])")
    }
}

#[cfg(test)]
impl CredentialMaterialVersion {
    pub(crate) const fn test_value(value: u8) -> Self {
        Self([value; 32])
    }
}

/// Version every dial-time secret source without retaining its bytes. File
/// failures are stable states, so one readable→unreadable transition resets a
/// recovery episode while repeated SIGHUPs against the same failure do not.
pub(crate) fn credential_material_version(
    manifest: &UpstreamManifest,
    key: &[u8; 32],
) -> CredentialMaterialVersion {
    let mut version = blake3::Hasher::new_keyed(key);
    version.update(b"mcp-gateway/upstream-credential-material/v1");

    // Every secret the `auth:` block reads, in a fixed order, so rotating any
    // one of them changes the version.
    let secret_envs = manifest
        .auth
        .as_ref()
        .map(UpstreamAuth::secret_env_names)
        .unwrap_or_default();
    version.update(&(secret_envs.len() as u64).to_le_bytes());
    for env in secret_envs {
        version.update(b"secret-present");
        hash_public_component(&mut version, env.as_bytes());
        let value = Zeroizing::new(std::env::var(env).unwrap_or_default());
        if value.is_empty() {
            let file_env = format!("{env}_FILE");
            let path = std::env::var(&file_env).unwrap_or_default();
            version.update(b"secret-file");
            hash_file_component(&mut version, key, path.as_ref(), MAX_AUTH_FILE_BYTES);
        } else {
            version.update(b"secret-env");
            hash_secret_component(&mut version, key, value.as_bytes());
        }
    }

    if let Some(mtls) = manifest.mtls.as_ref() {
        version.update(b"mtls-present");
        hash_optional_file_component(
            &mut version,
            key,
            mtls.cert_path.as_deref(),
            MAX_MTLS_FILE_BYTES,
        );
        hash_optional_file_component(
            &mut version,
            key,
            mtls.key_path.as_deref(),
            MAX_MTLS_FILE_BYTES,
        );
        hash_optional_file_component(
            &mut version,
            key,
            mtls.ca_path.as_deref(),
            MAX_MTLS_FILE_BYTES,
        );
    } else {
        version.update(b"mtls-absent");
    }

    CredentialMaterialVersion(*version.finalize().as_bytes())
}

fn hash_public_component(version: &mut blake3::Hasher, value: &[u8]) {
    version.update(&(value.len() as u64).to_le_bytes());
    version.update(value);
}

fn hash_secret_component(version: &mut blake3::Hasher, key: &[u8; 32], value: &[u8]) {
    let digest = blake3::keyed_hash(key, value);
    version.update(digest.as_bytes());
}

fn hash_optional_file_component(
    version: &mut blake3::Hasher,
    key: &[u8; 32],
    path: Option<&std::path::Path>,
    max_bytes: usize,
) {
    match path {
        Some(path) => {
            version.update(b"file-present");
            hash_file_component(version, key, path, max_bytes);
        }
        None => {
            version.update(b"file-absent");
        }
    }
}

fn hash_file_component(
    version: &mut blake3::Hasher,
    key: &[u8; 32],
    path: &std::path::Path,
    max_bytes: usize,
) {
    let mut component = blake3::Hasher::new_keyed(key);
    component.update(b"mcp-gateway/upstream-credential-file/v1");
    hash_public_component(&mut component, path.as_os_str().as_encoded_bytes());
    match read_bounded_credential_file(path, max_bytes) {
        Ok(bytes) => {
            component.update(b"readable");
            component.update(&bytes);
        }
        Err(BoundedCredentialFileError::Read(_)) => {
            component.update(b"unavailable");
        }
        Err(BoundedCredentialFileError::NotRegular) => {
            component.update(b"non-regular");
        }
        Err(BoundedCredentialFileError::TooLarge) => {
            component.update(b"too-large");
        }
    }
    version.update(component.finalize().as_bytes());
}

fn resolve_auth_token(server: &str, auth: &UpstreamAuth) -> Result<String, DialError> {
    let env = auth.bearer_env.as_deref().ok_or(DialError::EmptyAuth)?;
    resolve_secret_env(server, env)
}

/// Read one secret from `env`, or from the bounded file its `<env>_FILE`
/// companion names when `env` is unset or empty.
fn resolve_secret_env(server: &str, env: &str) -> Result<String, DialError> {
    let raw = std::env::var(env).unwrap_or_default();
    if !raw.is_empty() {
        return Ok(raw);
    }

    let file_env = format!("{env}_FILE");
    let path = std::env::var(&file_env).unwrap_or_default();
    if path.is_empty() {
        tracing::error!(
            server = %server,
            env = %env,
            file_env = %file_env,
            "auth bearer env and file sources are unset or empty — refusing to dial unauthenticated",
        );
        return Err(DialError::MissingAuthEnv {
            env: env.to_owned(),
        });
    }

    let bytes = match read_bounded_credential_file(path.as_ref(), MAX_AUTH_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(BoundedCredentialFileError::Read(source)) => {
            return Err(DialError::AuthFileRead {
                file_env: file_env.clone(),
                source,
            });
        }
        Err(BoundedCredentialFileError::NotRegular) => {
            return Err(DialError::AuthFileNotRegular { file_env });
        }
        Err(BoundedCredentialFileError::TooLarge) => {
            return Err(DialError::AuthFileTooLarge {
                file_env,
                max_bytes: MAX_AUTH_FILE_BYTES,
            });
        }
    };
    let text =
        std::str::from_utf8(bytes.as_slice()).map_err(|_| DialError::AuthFileInvalidUtf8 {
            file_env: file_env.clone(),
        })?;
    let token = text.trim_end_matches(['\r', '\n']).to_owned();
    if token.is_empty() {
        return Err(DialError::AuthFileEmpty { file_env });
    }
    Ok(token)
}

/// Resolve the optional static bearer without treating a group-only or
/// non-bearer auth block as empty. An explicitly empty `auth: {}` remains an
/// operator error and must fail before transport I/O, while
/// `catalog_probe_groups` may stand alone because the signed identity header
/// supplies that separate auth mechanism.
fn resolve_static_bearer(
    server: &str,
    auth: Option<&UpstreamAuth>,
) -> Result<Option<String>, DialError> {
    match auth {
        None => Ok(None),
        Some(auth) if auth.bearer_env.is_some() => resolve_auth_token(server, auth).map(Some),
        Some(auth)
            if auth.catalog_probe_groups.is_empty() && auth.secret_env_names().is_empty() =>
        {
            Err(DialError::EmptyAuth)
        }
        Some(_) => Ok(None),
    }
}

/// A secret query parameter added to every request URL. It is applied only
/// where a request leaves the gateway, so configured URLs, logs and errors
/// never carry it. There is deliberately no `Debug` implementation.
pub(crate) struct QuerySecret {
    name: String,
    value: zeroize::Zeroizing<String>,
}

impl QuerySecret {
    /// `url` with this parameter appended.
    pub(crate) fn apply(&self, url: &url::Url) -> url::Url {
        let mut url = url.clone();
        url.query_pairs_mut().append_pair(&self.name, &self.value);
        url
    }

    /// `uri` with this parameter appended, for the SDK's string URIs. A URI
    /// that does not parse is returned unchanged; the request then fails at
    /// the HTTP layer exactly as it would have without the parameter.
    pub(crate) fn apply_str(&self, uri: &str) -> String {
        match url::Url::parse(uri) {
            Ok(url) => self.apply(&url).into(),
            Err(_) => uri.to_owned(),
        }
    }
}

/// The static credential and fixed headers a manifest attaches to every
/// request, resolved from the environment at dial time. Secret header values
/// are marked sensitive, and nothing here implements `Debug`.
pub(crate) struct RequestCredentials {
    /// The `auth.bearer_env` token, which the streamable-HTTP transport sends
    /// through its own `Authorization: Bearer` slot.
    pub(crate) bearer: Option<String>,
    /// The same token as a ready `Authorization` value for the SSE client.
    bearer_header: Option<HeaderValue>,
    /// The `auth.header` or `auth.basic` header and the fixed `headers:`.
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) query: Option<std::sync::Arc<QuerySecret>>,
}

/// [`RequestCredentials`] for the legacy SSE client, which stamps every
/// header itself, the bearer included.
pub(crate) struct SseCredentials {
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) query: Option<std::sync::Arc<QuerySecret>>,
}

impl RequestCredentials {
    pub(crate) fn into_sse(self) -> SseCredentials {
        let mut headers = self.headers;
        if let Some(value) = self.bearer_header {
            headers.insert(0, (http::header::AUTHORIZATION, value));
        }
        SseCredentials {
            headers,
            query: self.query,
        }
    }
}

fn sensitive_header_value(env: &str, value: &str) -> Result<HeaderValue, DialError> {
    let mut value =
        HeaderValue::from_str(value).map_err(|_| DialError::AuthSecretNotHeaderSafe {
            env: env.to_owned(),
        })?;
    value.set_sensitive(true);
    Ok(value)
}

/// Resolve `auth:` and `headers:` for one dial. Every secret is read from
/// its environment variable or `<NAME>_FILE` companion; a missing one fails
/// the dial before any request is sent.
pub(crate) fn resolve_request_credentials(
    manifest: &UpstreamManifest,
) -> Result<RequestCredentials, DialError> {
    let server = manifest.name.as_str();
    let auth = manifest.auth.as_ref();
    let bearer = resolve_static_bearer(server, auth)?;
    let bearer_header = match (
        bearer.as_deref(),
        auth.and_then(|a| a.bearer_env.as_deref()),
    ) {
        (Some(token), Some(env)) => Some(sensitive_header_value(
            env,
            &zeroize::Zeroizing::new(format!("Bearer {token}")),
        )?),
        _ => None,
    };
    let mut credentials = RequestCredentials {
        bearer,
        bearer_header,
        headers: Vec::new(),
        query: None,
    };
    if let Some(auth) = auth {
        if let Some(header) = auth.header.as_ref() {
            let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| {
                DialError::InvalidFixedHeader {
                    name: header.name.clone(),
                }
            })?;
            let secret = zeroize::Zeroizing::new(resolve_secret_env(server, &header.value_env)?);
            let value = zeroize::Zeroizing::new(format!(
                "{}{}",
                header.prefix.as_deref().unwrap_or_default(),
                secret.as_str()
            ));
            credentials
                .headers
                .push((name, sensitive_header_value(&header.value_env, &value)?));
        }
        if let Some(basic) = auth.basic.as_ref() {
            use base64::Engine as _;
            let username =
                zeroize::Zeroizing::new(resolve_secret_env(server, &basic.username_env)?);
            let password = match basic.password_env.as_deref() {
                Some(env) => zeroize::Zeroizing::new(resolve_secret_env(server, env)?),
                None => zeroize::Zeroizing::new(String::new()),
            };
            let encoded =
                zeroize::Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(format!(
                    "{}:{}",
                    username.as_str(),
                    password.as_str()
                )));
            let value = zeroize::Zeroizing::new(format!("Basic {}", encoded.as_str()));
            credentials.headers.push((
                http::header::AUTHORIZATION,
                sensitive_header_value(&basic.username_env, &value)?,
            ));
        }
        if let Some(query) = auth.query.as_ref() {
            credentials.query = Some(std::sync::Arc::new(QuerySecret {
                name: query.name.clone(),
                value: zeroize::Zeroizing::new(resolve_secret_env(server, &query.value_env)?),
            }));
        }
    }
    for (name, value) in &manifest.headers {
        let invalid = || DialError::InvalidFixedHeader { name: name.clone() };
        credentials.headers.push((
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?,
            HeaderValue::from_str(value).map_err(|_| invalid())?,
        ));
    }
    Ok(credentials)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::sse::{Event, Sse};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Router;
    use tokio::sync::{mpsc, Mutex};
    use tokio_stream::wrappers::ReceiverStream;
    use uuid::Uuid;

    use super::*;

    type TestEventSender = mpsc::Sender<Result<Event, Infallible>>;

    #[derive(Clone, Default)]
    struct StalledHandshakeState {
        event_sender: Arc<Mutex<Option<TestEventSender>>>,
    }

    async fn stalled_handshake_sse(
        State(state): State<StalledHandshakeState>,
    ) -> Sse<ReceiverStream<Result<Event, Infallible>>> {
        let (tx, rx) = mpsc::channel(4);
        tx.send(Ok(Event::default().event("endpoint").data("/mcp/messages")))
            .await
            .expect("send endpoint event");
        *state.event_sender.lock().await = Some(tx);
        Sse::new(ReceiverStream::new(rx))
    }

    #[tokio::test]
    async fn sse_dial_times_out_when_initialize_response_never_arrives() {
        let state = StalledHandshakeState::default();
        let app = Router::new()
            .route("/mcp/sse", get(stalled_handshake_sse))
            .route("/mcp/messages", post(|| async { StatusCode::ACCEPTED }))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });
        let manifest: UpstreamManifest = serde_yaml::from_str(&format!(
            "name: stalled-sse\ntransport: sse\nurl: http://{addr}/mcp/sse\n"
        ))
        .expect("parse test manifest");
        let deadline = Duration::from_millis(100);

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            connect_with_handshake_timeout(
                &manifest,
                None,
                None,
                None,
                ClientCapabilities::default(),
                deadline,
            ),
        )
        .await
        .expect("the dial function must enforce its own handshake deadline");
        server.abort();

        assert!(
            matches!(
                result,
                Err(DialError::HandshakeTimeout { timeout, exchanges: None }) if timeout == deadline
            ),
            "stalled MCP initialization returned {result:?}",
        );
    }

    #[tokio::test]
    async fn http_dial_times_out_when_initialize_response_never_arrives() {
        let app = Router::new().route(
            "/mcp",
            post(|| async { std::future::pending::<StatusCode>().await }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });
        let manifest: UpstreamManifest = serde_yaml::from_str(&format!(
            "name: stalled-http\ntransport: http\nurl: http://{addr}/mcp\n"
        ))
        .expect("parse test manifest");
        let deadline = Duration::from_millis(100);

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            connect_with_handshake_timeout(
                &manifest,
                None,
                None,
                None,
                ClientCapabilities::default(),
                deadline,
            ),
        )
        .await
        .expect("the dial function must enforce its own handshake deadline");
        server.abort();

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("a stalled MCP initialization must not connect"),
        };
        assert!(
            matches!(&error, DialError::HandshakeTimeout { timeout, .. } if *timeout == deadline),
            "stalled MCP initialization returned {error:?}",
        );
        // The deadline alone would not say which request the upstream left
        // waiting.
        let text = error.to_string();
        assert!(
            text.contains("HTTP exchanges on this dial: POST server/discover -> "),
            "{text}"
        );
    }

    type SeenHeaders = Arc<Mutex<Vec<axum::http::HeaderMap>>>;

    /// The host a redirect or an announced message endpoint points at. It
    /// answers anything and counts every request, so a test can prove the
    /// gateway sent it nothing at all.
    struct OtherHost {
        addr: std::net::SocketAddr,
        requests: Arc<AtomicUsize>,
        server: tokio::task::JoinHandle<()>,
    }

    async fn spawn_other_host() -> OtherHost {
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let app = Router::new().fallback(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { StatusCode::OK }
        });
        let (addr, server) = serve_test_app(app).await;
        OtherHost {
            addr,
            requests,
            server,
        }
    }

    async fn serve_test_app(app: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });
        (addr, server)
    }

    #[derive(Clone)]
    struct RedirectState {
        status: StatusCode,
        location: String,
        seen: SeenHeaders,
    }

    async fn redirect_handler(
        State(state): State<RedirectState>,
        headers: axum::http::HeaderMap,
    ) -> impl IntoResponse {
        state.seen.lock().await.push(headers);
        (
            state.status,
            [(axum::http::header::LOCATION, state.location.clone())],
        )
    }

    /// The identity a dial stamps during catalog discovery, signed by a
    /// synthetic test key.
    fn catalog_probe_forwarding(server: &str) -> (SharedIdentityIssuer, IdentityCell) {
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode test signing key");
        let issuer = Arc::new(
            waygate_oidc::IdentityIssuer::from_ed25519_pkcs8_pem(
                &pem,
                "gw-test",
                "https://gateway.test",
                "gateway-main",
                Duration::from_secs(60),
            )
            .expect("test identity issuer"),
        );
        let cell = IdentityCell::new();
        cell.set(crate::catalog_probe::catalog_probe_identity(server, &[]));
        (issuer, cell)
    }

    /// The configured host received the static bearer and the identity token,
    /// so both were in play, and the other host received no request at all.
    async fn assert_credentials_stayed_on_the_configured_host(
        seen: &SeenHeaders,
        bearer: &str,
        other: &OtherHost,
    ) {
        let expected_authorization = format!("Bearer {bearer}");
        assert!(
            seen.lock().await.iter().any(|headers| {
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .is_some_and(|value| value.as_bytes() == expected_authorization.as_bytes())
                    && headers.contains_key(crate::identity_client::IDENTITY_HEADER)
            }),
            "the configured host must receive the bearer and the identity token",
        );
        assert_eq!(
            other.requests.load(Ordering::SeqCst),
            0,
            "no request may reach a host other than the configured one",
        );
    }

    #[tokio::test]
    async fn http_dial_refuses_a_redirect_and_sends_its_target_nothing() {
        let env = "GW_TEST_TRANSPORT_HTTP_REDIRECT_BEARER";
        let bearer = "synthetic-http-bearer";
        unsafe { std::env::set_var(env, bearer) };
        for status in [
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            let other = spawn_other_host().await;
            let state = RedirectState {
                status,
                location: format!("http://{}/mcp?token=synthetic-location-token", other.addr),
                seen: SeenHeaders::default(),
            };
            let (addr, server) = serve_test_app(
                Router::new()
                    .route("/mcp", axum::routing::any(redirect_handler))
                    .with_state(state.clone()),
            )
            .await;
            let manifest: UpstreamManifest = serde_yaml::from_str(&format!(
                "name: redirecting-http\ntransport: http\nurl: http://{addr}/mcp\nauth:\n  bearer_env: {env}\n"
            ))
            .expect("parse test manifest");
            let (issuer, cell) = catalog_probe_forwarding(&manifest.name);

            let result = connect_with_handshake_timeout(
                &manifest,
                Some(&issuer),
                Some(&cell),
                None,
                ClientCapabilities::default(),
                Duration::from_secs(5),
            )
            .await;
            server.abort();
            other.server.abort();

            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("{status}: a redirected dial must not connect"),
            };
            assert!(
                matches!(
                    &error,
                    DialError::RedirectRefused { server, status: refused }
                        if server == "redirecting-http" && *refused == status
                ),
                "{status}: {error:?}",
            );
            let text = error.to_string();
            assert!(
                text.contains("`redirecting-http`") && text.contains("redirect refused"),
                "{text}"
            );
            assert!(
                !text.contains("synthetic-location-token")
                    && !text.contains(&other.addr.to_string()),
                "the error must not quote the redirect target: {text}"
            );
            assert_credentials_stayed_on_the_configured_host(&state.seen, bearer, &other).await;
        }
        unsafe { std::env::remove_var(env) };
    }

    /// The receive stream and the message POST are separate requests, and each
    /// one carries the credentials, so a redirect on either fails the dial.
    #[tokio::test]
    async fn sse_dial_refuses_a_redirect_on_the_stream_or_a_message_post() {
        let env = "GW_TEST_TRANSPORT_SSE_REDIRECT_BEARER";
        let bearer = "synthetic-sse-bearer";
        unsafe { std::env::set_var(env, bearer) };
        for redirected in ["/mcp/sse", "/mcp/messages"] {
            let other = spawn_other_host().await;
            let state = RedirectState {
                status: StatusCode::TEMPORARY_REDIRECT,
                location: format!("http://{}{redirected}", other.addr),
                seen: SeenHeaders::default(),
            };
            let redirect = axum::routing::any(redirect_handler).with_state(state.clone());
            let app = match redirected {
                "/mcp/sse" => Router::new().route("/mcp/sse", redirect),
                _ => Router::new()
                    .route(
                        "/mcp/sse",
                        get(stalled_handshake_sse).with_state(StalledHandshakeState::default()),
                    )
                    .route("/mcp/messages", redirect),
            };
            let (addr, server) = serve_test_app(app).await;
            let manifest: UpstreamManifest = serde_yaml::from_str(&format!(
                "name: redirecting-sse\ntransport: sse\nurl: http://{addr}/mcp/sse\nauth:\n  bearer_env: {env}\n"
            ))
            .expect("parse test manifest");
            let (issuer, cell) = catalog_probe_forwarding(&manifest.name);

            let result = connect_with_handshake_timeout(
                &manifest,
                Some(&issuer),
                Some(&cell),
                None,
                ClientCapabilities::default(),
                Duration::from_secs(5),
            )
            .await;
            server.abort();
            other.server.abort();

            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("{redirected}: a redirected dial must not connect"),
            };
            assert!(
                matches!(
                    &error,
                    DialError::RedirectRefused { server, status }
                        if server == "redirecting-sse" && *status == StatusCode::TEMPORARY_REDIRECT
                ),
                "{redirected}: {error:?}",
            );
            assert!(
                error.to_string().contains("redirect refused"),
                "{redirected}: {error}"
            );
            assert_credentials_stayed_on_the_configured_host(&state.seen, bearer, &other).await;
        }
        unsafe { std::env::remove_var(env) };
    }

    #[tokio::test]
    async fn sse_dial_refuses_a_message_endpoint_on_another_origin() {
        let env = "GW_TEST_TRANSPORT_SSE_ENDPOINT_BEARER";
        let bearer = "synthetic-endpoint-bearer";
        unsafe { std::env::set_var(env, bearer) };
        let other = spawn_other_host().await;
        let endpoint = format!(
            "http://{}/mcp/messages?session_id=synthetic-session",
            other.addr
        );
        let seen = SeenHeaders::default();
        let open_streams: Arc<Mutex<Vec<TestEventSender>>> = Arc::default();
        let app = Router::new().route(
            "/mcp/sse",
            get({
                let seen = Arc::clone(&seen);
                move |headers: axum::http::HeaderMap| {
                    let seen = Arc::clone(&seen);
                    let open_streams = Arc::clone(&open_streams);
                    let endpoint = endpoint.clone();
                    async move {
                        seen.lock().await.push(headers);
                        let (tx, rx) = mpsc::channel(4);
                        tx.send(Ok(Event::default().event("endpoint").data(endpoint)))
                            .await
                            .expect("send endpoint event");
                        open_streams.lock().await.push(tx);
                        Sse::new(ReceiverStream::new(rx))
                    }
                }
            }),
        );
        let (addr, server) = serve_test_app(app).await;
        let manifest: UpstreamManifest = serde_yaml::from_str(&format!(
            "name: relocating-sse\ntransport: sse\nurl: http://{addr}/mcp/sse\nauth:\n  bearer_env: {env}\n"
        ))
        .expect("parse test manifest");
        let (issuer, cell) = catalog_probe_forwarding(&manifest.name);

        let result = connect_with_handshake_timeout(
            &manifest,
            Some(&issuer),
            Some(&cell),
            None,
            ClientCapabilities::default(),
            Duration::from_secs(5),
        )
        .await;
        server.abort();
        other.server.abort();
        unsafe { std::env::remove_var(env) };

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("an endpoint on another origin must not connect"),
        };
        let expected_origin = format!("http://{}", other.addr);
        assert!(
            matches!(
                &error,
                DialError::SseEndpointRefused { server, announced }
                    if server == "relocating-sse" && *announced == expected_origin
            ),
            "{error:?}",
        );
        let text = error.to_string();
        assert!(
            text.contains("`relocating-sse`") && text.contains("endpoint refused"),
            "{text}"
        );
        assert!(
            !text.contains("synthetic-session"),
            "the error must not quote the endpoint's query: {text}"
        );
        assert_credentials_stayed_on_the_configured_host(&seen, bearer, &other).await;
    }

    #[tokio::test]
    async fn empty_auth_block_fails_before_http_or_sse_transport_io() {
        for transport in ["http", "sse"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test listener");
            let addr = listener.local_addr().expect("test listener address");
            let manifest: UpstreamManifest = serde_yaml::from_str(&format!(
                "name: empty-auth-{transport}\ntransport: {transport}\nurl: http://{addr}/mcp\nauth: {{}}\n"
            ))
            .expect("parse empty-auth manifest");

            let result = connect_with_handshake_timeout(
                &manifest,
                None,
                None,
                None,
                ClientCapabilities::default(),
                Duration::from_millis(100),
            )
            .await;

            assert!(
                matches!(result, Err(DialError::EmptyAuth)),
                "{transport} must reject an explicit empty auth block, got {result:?}",
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(10), listener.accept())
                    .await
                    .is_err(),
                "{transport} must reject empty auth before opening a connection",
            );
        }
    }

    #[tokio::test]
    async fn stdio_rejects_an_explicit_empty_auth_block() {
        let manifest: UpstreamManifest = serde_yaml::from_str(
            "name: empty-auth-stdio\ntransport: stdio\ncommand:\n  - /does-not-run\nauth: {}\n",
        )
        .expect("parse empty-auth stdio manifest");

        let result = connect_with_handshake_timeout(
            &manifest,
            None,
            None,
            None,
            ClientCapabilities::default(),
            Duration::from_millis(100),
        )
        .await;

        assert!(matches!(
            result,
            Err(DialError::UnsupportedAuthForTransport { transport: "stdio" })
        ));
    }

    #[test]
    fn resolve_auth_token_returns_value_when_env_set() {
        // Unique per-test env name so concurrent tests don't collide;
        // `set_var` is process-global. SAFETY mirrors the pre-extraction
        // pool tests: scoped to a name no other test uses.
        let env = "GW_TEST_TRANSPORT_AUTH_TOKEN_SET";
        unsafe { std::env::set_var(env, "secret-bearer") };
        let auth = UpstreamAuth {
            bearer_env: Some(env.to_owned()),
            ..Default::default()
        };
        let token = resolve_auth_token("test-server", &auth).expect("env set");
        assert_eq!(token, "secret-bearer");
        unsafe { std::env::remove_var(env) };
    }

    #[test]
    fn resolve_static_bearer_distinguishes_absent_empty_bearer_and_group_only_auth() {
        assert!(resolve_static_bearer("test-server", None)
            .expect("absent auth is valid")
            .is_none());

        let empty = UpstreamAuth::default();
        assert!(matches!(
            resolve_static_bearer("test-server", Some(&empty)),
            Err(DialError::EmptyAuth)
        ));

        let group_only = UpstreamAuth {
            catalog_probe_groups: vec!["service-operators".into()],
            ..Default::default()
        };
        assert!(resolve_static_bearer("test-server", Some(&group_only))
            .expect("group-only auth is carried by the signed identity header")
            .is_none());

        let env = "GW_TEST_TRANSPORT_OPTIONAL_STATIC_BEARER";
        unsafe { std::env::set_var(env, "secret-bearer") };
        let bearer = UpstreamAuth {
            bearer_env: Some(env.into()),
            ..Default::default()
        };
        assert_eq!(
            resolve_static_bearer("test-server", Some(&bearer))
                .expect("configured bearer must resolve"),
            Some("secret-bearer".into()),
        );
        unsafe { std::env::remove_var(env) };
    }

    #[test]
    fn resolve_auth_token_errors_when_env_unset() {
        let env = "GW_TEST_TRANSPORT_AUTH_TOKEN_UNSET";
        unsafe { std::env::remove_var(env) };
        let auth = UpstreamAuth {
            bearer_env: Some(env.to_owned()),
            ..Default::default()
        };
        let err =
            resolve_auth_token("test-server", &auth).expect_err("missing env must fail the dial");
        match err {
            DialError::MissingAuthEnv { env: e } => assert_eq!(e, env),
            other => panic!("expected MissingAuthEnv, got {other:?}"),
        }
    }

    #[test]
    fn resolve_auth_token_errors_when_env_empty() {
        let env = "GW_TEST_TRANSPORT_AUTH_TOKEN_EMPTY";
        unsafe { std::env::set_var(env, "") };
        let auth = UpstreamAuth {
            bearer_env: Some(env.to_owned()),
            ..Default::default()
        };
        let err =
            resolve_auth_token("test-server", &auth).expect_err("empty env must fail the dial");
        match err {
            DialError::MissingAuthEnv { env: e } => assert_eq!(e, env),
            other => panic!("expected MissingAuthEnv, got {other:?}"),
        }
        unsafe { std::env::remove_var(env) };
    }

    #[test]
    fn resolve_auth_token_reads_bounded_file_companion() {
        let env = "GW_TEST_TRANSPORT_AUTH_TOKEN_FILE";
        let file_env = format!("{env}_FILE");
        let dir = std::env::temp_dir().join(format!("gateway-auth-{}", Uuid::new_v4()));
        let path = dir.join("bearer");
        std::fs::create_dir(&dir).expect("create isolated auth test directory");
        std::fs::write(&path, b"file-secret-bearer\n").expect("write auth test file");
        unsafe {
            std::env::remove_var(env);
            std::env::set_var(&file_env, &path);
        }

        let auth = UpstreamAuth {
            bearer_env: Some(env.to_owned()),
            ..Default::default()
        };
        let token = resolve_auth_token("test-server", &auth).expect("file source is valid");
        assert_eq!(token, "file-secret-bearer");

        unsafe { std::env::remove_var(&file_env) };
        std::fs::remove_dir_all(dir).expect("remove isolated auth test directory");
    }

    #[test]
    fn resolve_auth_token_accepts_exact_file_size_limit() {
        let env = "GW_TEST_TRANSPORT_AUTH_TOKEN_FILE_LIMIT";
        let file_env = format!("{env}_FILE");
        let dir = std::env::temp_dir().join(format!("gateway-auth-{}", Uuid::new_v4()));
        let path = dir.join("bearer");
        std::fs::create_dir(&dir).expect("create isolated auth test directory");
        std::fs::write(&path, vec![b'x'; MAX_AUTH_FILE_BYTES])
            .expect("write boundary auth test file");
        unsafe {
            std::env::remove_var(env);
            std::env::set_var(&file_env, &path);
        }

        let auth = UpstreamAuth {
            bearer_env: Some(env.to_owned()),
            ..Default::default()
        };
        let token = resolve_auth_token("test-server", &auth).expect("limit is inclusive");
        assert_eq!(token.len(), MAX_AUTH_FILE_BYTES);

        unsafe { std::env::remove_var(&file_env) };
        std::fs::remove_dir_all(dir).expect("remove isolated auth test directory");
    }

    #[test]
    fn resolve_auth_token_rejects_invalid_file_sources() {
        enum Expected {
            Empty,
            InvalidUtf8,
            TooLarge,
        }

        let cases: [(&str, Vec<u8>, Expected); 3] = [
            ("EMPTY", b"\r\n".to_vec(), Expected::Empty),
            ("UTF8", vec![0xff], Expected::InvalidUtf8),
            (
                "LARGE",
                vec![b'x'; MAX_AUTH_FILE_BYTES + 1],
                Expected::TooLarge,
            ),
        ];

        for (suffix, contents, expected) in cases {
            let env = format!("GW_TEST_TRANSPORT_AUTH_TOKEN_FILE_{suffix}");
            let file_env = format!("{env}_FILE");
            let dir = std::env::temp_dir().join(format!("gateway-auth-{}", Uuid::new_v4()));
            let path = dir.join("bearer");
            std::fs::create_dir(&dir).expect("create isolated auth test directory");
            std::fs::write(&path, contents).expect("write invalid auth test file");
            unsafe {
                std::env::remove_var(&env);
                std::env::set_var(&file_env, &path);
            }
            let auth = UpstreamAuth {
                bearer_env: Some(env.clone()),
                ..Default::default()
            };

            let error = resolve_auth_token("test-server", &auth)
                .expect_err("invalid file source must fail closed");
            match expected {
                Expected::Empty => assert!(matches!(error, DialError::AuthFileEmpty { .. })),
                Expected::InvalidUtf8 => {
                    assert!(matches!(error, DialError::AuthFileInvalidUtf8 { .. }))
                }
                Expected::TooLarge => {
                    assert!(matches!(error, DialError::AuthFileTooLarge { .. }))
                }
            }

            unsafe { std::env::remove_var(&file_env) };
            std::fs::remove_dir_all(dir).expect("remove isolated auth test directory");
        }
    }

    #[test]
    fn resolve_auth_token_rejects_unreadable_file_without_logging_its_path() {
        let env = "GW_TEST_TRANSPORT_AUTH_TOKEN_FILE_UNREADABLE";
        let file_env = format!("{env}_FILE");
        let dir = std::env::temp_dir().join(format!("gateway-auth-{}", Uuid::new_v4()));
        let path = dir.join("missing-bearer");
        std::fs::create_dir(&dir).expect("create isolated auth test directory");
        unsafe {
            std::env::remove_var(env);
            std::env::set_var(&file_env, &path);
        }
        let auth = UpstreamAuth {
            bearer_env: Some(env.to_owned()),
            ..Default::default()
        };

        let error = resolve_auth_token("test-server", &auth)
            .expect_err("unreadable file source must fail closed");
        assert!(matches!(error, DialError::AuthFileRead { .. }));
        assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));

        unsafe { std::env::remove_var(&file_env) };
        std::fs::remove_dir_all(dir).expect("remove isolated auth test directory");
    }

    #[cfg(unix)]
    #[test]
    fn resolve_auth_token_rejects_non_regular_source_without_reading_to_eof() {
        let env = "GW_TEST_TRANSPORT_AUTH_TOKEN_NON_REGULAR";
        let file_env = format!("{env}_FILE");
        unsafe {
            std::env::remove_var(env);
            std::env::set_var(&file_env, "/dev/zero");
        }
        let auth = UpstreamAuth {
            bearer_env: Some(env.to_owned()),
            ..Default::default()
        };

        assert!(matches!(
            resolve_auth_token("test-server", &auth),
            Err(DialError::AuthFileNotRegular { .. })
        ));

        unsafe { std::env::remove_var(&file_env) };
    }

    #[test]
    fn resolve_auth_token_errors_on_empty_auth_block() {
        let auth = UpstreamAuth::default();
        let err = resolve_auth_token("test-server", &auth)
            .expect_err("empty auth block must fail the dial");
        assert!(matches!(err, DialError::EmptyAuth));
    }

    #[test]
    fn credential_material_version_tracks_in_place_mtls_rotation_without_disclosure() {
        let dir = std::env::temp_dir().join(format!("gateway-mtls-version-{}", Uuid::new_v4()));
        let cert_path = dir.join("client.crt");
        let key_path = dir.join("client.key");
        std::fs::create_dir(&dir).expect("create isolated mTLS directory");
        std::fs::write(&cert_path, b"first-certificate").expect("write initial certificate");
        std::fs::write(&key_path, b"stable-private-key").expect("write private key");
        let mut manifest: UpstreamManifest = serde_yaml::from_str(
            "name: mtls-version\ntransport: http\nurl: https://upstream.example/mcp\n",
        )
        .expect("parse mTLS version manifest");
        manifest.mtls = Some(MtlsConfig {
            cert_path: Some(cert_path.clone()),
            key_path: Some(key_path),
            ca_path: None,
        });
        let process_key = [7; 32];

        let initial = credential_material_version(&manifest, &process_key);
        assert_eq!(
            initial,
            credential_material_version(&manifest, &process_key),
            "unchanged material must have a stable process-local version",
        );
        std::fs::write(&cert_path, b"second-certificate").expect("rotate certificate in place");
        assert_ne!(
            initial,
            credential_material_version(&manifest, &process_key),
            "content rotation at the same manifest path must advance the version",
        );
        assert_eq!(
            format!("{initial:?}"),
            "CredentialMaterialVersion([redacted])"
        );

        std::fs::remove_dir_all(dir).expect("remove isolated mTLS directory");
    }

    #[cfg(unix)]
    #[test]
    fn credential_material_version_bounds_non_regular_sources() {
        let mut manifest: UpstreamManifest = serde_yaml::from_str(
            "name: mtls-device\ntransport: http\nurl: https://upstream.example/mcp\n",
        )
        .expect("parse mTLS device manifest");
        manifest.mtls = Some(MtlsConfig {
            cert_path: Some("/dev/zero".into()),
            key_path: Some("/dev/zero".into()),
            ca_path: None,
        });

        assert_eq!(
            credential_material_version(&manifest, &[7; 32]),
            credential_material_version(&manifest, &[7; 32]),
            "a non-regular source must produce a stable state without reading it",
        );
    }

    // ---- mTLS helper tests --------------------------------------------

    #[cfg(unix)]
    #[test]
    fn build_mtls_client_rejects_non_regular_source_without_reading_to_eof() {
        let mtls = MtlsConfig {
            cert_path: Some("/dev/zero".into()),
            key_path: Some("/dev/zero".into()),
            ca_path: None,
        };

        assert!(matches!(
            build_mtls_client(&mtls),
            Err(DialError::MtlsFileNotRegular { .. })
        ));
    }

    #[test]
    fn build_mtls_client_rejects_oversized_regular_file() {
        let dir = std::env::temp_dir().join(format!("gateway-mtls-limit-{}", Uuid::new_v4()));
        let cert_path = dir.join("client.crt");
        let key_path = dir.join("client.key");
        std::fs::create_dir(&dir).expect("create isolated mTLS directory");
        std::fs::write(&cert_path, vec![b'x'; MAX_MTLS_FILE_BYTES + 1])
            .expect("write oversized certificate");
        std::fs::write(&key_path, b"unused-key").expect("write private key");
        let mtls = MtlsConfig {
            cert_path: Some(cert_path),
            key_path: Some(key_path),
            ca_path: None,
        };

        assert!(matches!(
            build_mtls_client(&mtls),
            Err(DialError::MtlsFileTooLarge {
                max_bytes: MAX_MTLS_FILE_BYTES,
                ..
            })
        ));

        std::fs::remove_dir_all(dir).expect("remove isolated mTLS directory");
    }

    #[test]
    fn build_mtls_client_errors_when_cert_path_missing() {
        let mtls = MtlsConfig {
            cert_path: None,
            key_path: Some(std::path::PathBuf::from("/tmp/key.pem")),
            ca_path: None,
        };
        let err = build_mtls_client(&mtls).expect_err("missing cert_path must fail");
        assert!(matches!(err, DialError::MtlsMissingField));
    }

    #[test]
    fn build_mtls_client_errors_when_key_path_missing() {
        let mtls = MtlsConfig {
            cert_path: Some(std::path::PathBuf::from("/tmp/cert.pem")),
            key_path: None,
            ca_path: None,
        };
        let err = build_mtls_client(&mtls).expect_err("missing key_path must fail");
        assert!(matches!(err, DialError::MtlsMissingField));
    }

    #[test]
    fn build_mtls_client_errors_when_cert_file_missing() {
        // Use a path that very likely doesn't exist; if some
        // CI runs as root and happens to have the file we'd
        // bypass this assertion, so use a name with a UUID
        // shape.
        let cert = std::env::temp_dir().join("mtls-cert-does-not-exist-xyz.pem");
        let key = std::env::temp_dir().join("mtls-key-does-not-exist-xyz.pem");
        // Guard: ensure neither exists.
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
        let mtls = MtlsConfig {
            cert_path: Some(cert.clone()),
            key_path: Some(key),
            ca_path: None,
        };
        let err = build_mtls_client(&mtls).expect_err("missing file must fail");
        match err {
            DialError::MtlsReadFailed { path, .. } => {
                assert!(
                    path.contains("mtls-cert-does-not-exist-xyz.pem"),
                    "error must name the failing file: {path}",
                );
            }
            other => panic!("expected MtlsReadFailed, got {other:?}"),
        }
    }

    #[test]
    fn build_mtls_client_errors_on_garbage_pem() {
        // Write some non-PEM bytes and confirm the parser
        // rejects them with MtlsInvalidPem (not a generic
        // io error). The cert + key are the same garbage
        // file so we cover the cert-side parse failure.
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let cert = dir.join(format!("mtls-garbage-cert-{pid}.pem"));
        let key = dir.join(format!("mtls-garbage-key-{pid}.pem"));
        std::fs::write(&cert, b"not a real PEM file").expect("write garbage cert");
        std::fs::write(&key, b"definitely not a key").expect("write garbage key");
        let mtls = MtlsConfig {
            cert_path: Some(cert.clone()),
            key_path: Some(key.clone()),
            ca_path: None,
        };
        let err = build_mtls_client(&mtls).expect_err("garbage PEM must fail");
        match err {
            DialError::MtlsInvalidPem { path, .. } => {
                assert!(
                    path.contains("mtls-garbage"),
                    "error must name the failing path: {path}",
                );
            }
            other => panic!("expected MtlsInvalidPem, got {other:?}"),
        }
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }

    // The success path ("valid cert + key produces a
    // usable client") isn't unit-tested here — synthesizing
    // a real self-signed Ed25519/RSA cert from inside a
    // unit test would pull in rcgen as a dev-dep just for
    // this slice. The error paths above pin the
    // operator-actionable failure modes; the success path
    // gets exercised in any production deployment that
    // configures the block. A follow-up PR can add a
    // wiremock-backed end-to-end mTLS round-trip test if
    // we want that coverage in CI.

    // ---- HTTPS guard ---------------------------------------------------

    #[test]
    fn url_is_https_accepts_https_scheme() {
        assert!(url_is_https("https://upstream.example/mcp"));
        // Case-insensitive: an operator typing `HTTPS://`
        // shouldn't be locked out by capitalization the
        // URL itself doesn't care about.
        assert!(url_is_https("HTTPS://upstream.example/mcp"));
        assert!(url_is_https("HtTpS://upstream.example/mcp"));
        // Leading whitespace in the manifest YAML is
        // surprisingly easy to introduce; trim before
        // the prefix check.
        assert!(url_is_https("   https://upstream.example/mcp"));
    }

    #[test]
    fn url_is_https_rejects_plaintext_and_other_schemes() {
        // The dangerous case: `http://` with
        // `mtls:` set silently disables TLS.
        assert!(!url_is_https("http://upstream.example/mcp"));
        assert!(!url_is_https("HTTP://upstream.example/mcp"));
        // Empty string / missing scheme / unrelated
        // schemes — all rejected (mTLS without TLS makes
        // no sense regardless of why it's missing).
        assert!(!url_is_https(""));
        assert!(!url_is_https("upstream.example/mcp"));
        assert!(!url_is_https("ws://upstream.example/mcp"));
        assert!(!url_is_https("file:///etc/passwd"));
        // A scheme containing `https` as a substring but
        // not as the actual scheme must not slip through —
        // `https-faux://` doesn't match `https://`.
        assert!(!url_is_https("https-faux://upstream.example/mcp"));
    }

    // ---- manifest YAML round-trip ------------------------------------

    #[test]
    fn upstream_manifest_yaml_round_trips_mtls_block() {
        // Operator-facing YAML shape — keep it stable so
        // an in-flight manifest doesn't break on minor
        // version bumps.
        let yaml = r#"
name: secure-svc
transport: http
url: https://mcp.internal/mcp
mtls:
  cert_path: /etc/gateway/secure-svc.crt
  key_path: /etc/gateway/secure-svc.key
  ca_path: /etc/gateway/internal-ca.crt
"#;
        let parsed: crate::UpstreamManifest = serde_yaml::from_str(yaml).expect("parse yaml");
        let mtls = parsed.mtls.expect("mtls block present");
        assert_eq!(
            mtls.cert_path,
            Some(std::path::PathBuf::from("/etc/gateway/secure-svc.crt"))
        );
        assert_eq!(
            mtls.key_path,
            Some(std::path::PathBuf::from("/etc/gateway/secure-svc.key"))
        );
        assert_eq!(
            mtls.ca_path,
            Some(std::path::PathBuf::from("/etc/gateway/internal-ca.crt"))
        );
    }

    #[test]
    fn upstream_manifest_yaml_omits_mtls_when_absent() {
        let yaml = r#"
name: plain-http
transport: http
url: https://mcp.example/mcp
"#;
        let parsed: crate::UpstreamManifest = serde_yaml::from_str(yaml).expect("parse yaml");
        assert!(parsed.mtls.is_none(), "mtls must default to None");
    }
    /// Static credentials and fixed headers on the wire, observed by a server
    /// that records each request's headers and query string and refuses it.
    mod request_credentials {
        use super::*;

        type Seen = Arc<std::sync::Mutex<Vec<(http::HeaderMap, Option<String>)>>>;

        async fn spawn_capture() -> (std::net::SocketAddr, Seen) {
            let seen: Seen = Arc::default();
            let recorded = Arc::clone(&seen);
            let app = Router::new().fallback(move |request: axum::extract::Request| {
                let recorded = Arc::clone(&recorded);
                async move {
                    recorded.lock().unwrap().push((
                        request.headers().clone(),
                        request.uri().query().map(str::to_owned),
                    ));
                    StatusCode::UNAUTHORIZED
                }
            });
            let (addr, _server) = serve_test_app(app).await;
            (addr, seen)
        }

        fn manifest(yaml: &str) -> UpstreamManifest {
            serde_yaml::from_str(yaml).expect("test manifest")
        }

        /// Sets test-only variables for one test; each name is unique to it.
        struct Env(Vec<&'static str>);

        impl Env {
            fn set(pairs: &[(&'static str, &str)]) -> Self {
                for (name, value) in pairs {
                    // SAFETY: process-global, but every name is unique to one test.
                    unsafe { std::env::set_var(name, value) };
                }
                Self(pairs.iter().map(|(name, _)| *name).collect())
            }
        }

        impl Drop for Env {
            fn drop(&mut self) {
                for name in &self.0 {
                    // SAFETY: as in `set`.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }

        fn first_request(seen: &Seen) -> (http::HeaderMap, Option<String>) {
            seen.lock()
                .unwrap()
                .first()
                .cloned()
                .expect("the upstream received a request")
        }

        #[tokio::test]
        async fn a_header_secret_and_fixed_headers_reach_an_http_upstream() {
            let _env = Env::set(&[("GW_TEST_CRED_HEADER_SECRET", "header-secret-41f2")]);
            let (addr, seen) = spawn_capture().await;
            let m = manifest(&format!(
                "name: hosted\ntransport: http\nprotocol: legacy\nurl: http://{addr}/mcp\n\
                 auth:\n  header:\n    name: x-api-key\n    value_env: GW_TEST_CRED_HEADER_SECRET\n\
                 headers:\n  x-client-name: waygate-test\n"
            ));

            assert!(connect(&m, None, None, None).await.is_err());

            let (headers, _) = first_request(&seen);
            assert_eq!(headers["x-api-key"], "header-secret-41f2");
            assert_eq!(headers["x-client-name"], "waygate-test");
            assert!(!headers.contains_key(http::header::AUTHORIZATION));
        }

        #[tokio::test]
        async fn a_prefixed_authorization_header_and_basic_auth_are_sent_as_configured() {
            let _env = Env::set(&[
                ("GW_TEST_CRED_TOKEN_SECRET", "token-secret-9c1d"),
                ("GW_TEST_CRED_BASIC_USER", "api-user"),
                ("GW_TEST_CRED_BASIC_PASSWORD", "basic-secret-2b7e"),
            ]);
            let (addr, seen) = spawn_capture().await;
            let token = manifest(&format!(
                "name: hosted\ntransport: http\nprotocol: legacy\nurl: http://{addr}/mcp\n\
                 auth:\n  header:\n    name: Authorization\n    prefix: \"Token \"\n    \
                 value_env: GW_TEST_CRED_TOKEN_SECRET\n"
            ));
            assert!(connect(&token, None, None, None).await.is_err());
            assert_eq!(
                first_request(&seen).0[http::header::AUTHORIZATION],
                "Token token-secret-9c1d"
            );

            let (addr, seen) = spawn_capture().await;
            let basic = manifest(&format!(
                "name: hosted\ntransport: http\nprotocol: legacy\nurl: http://{addr}/mcp\n\
                 auth:\n  basic:\n    username_env: GW_TEST_CRED_BASIC_USER\n    \
                 password_env: GW_TEST_CRED_BASIC_PASSWORD\n"
            ));
            assert!(connect(&basic, None, None, None).await.is_err());
            assert_eq!(
                first_request(&seen).0[http::header::AUTHORIZATION],
                // base64("api-user:basic-secret-2b7e")
                "Basic YXBpLXVzZXI6YmFzaWMtc2VjcmV0LTJiN2U="
            );
        }

        #[tokio::test]
        async fn a_query_secret_is_added_beside_the_configured_query() {
            let _env = Env::set(&[("GW_TEST_CRED_QUERY_SECRET", "query-secret-77a9")]);
            let (addr, seen) = spawn_capture().await;
            let m = manifest(&format!(
                "name: hosted\ntransport: http\nprotocol: legacy\nurl: http://{addr}/mcp?tools=a\n\
                 auth:\n  query:\n    name: apiKey\n    value_env: GW_TEST_CRED_QUERY_SECRET\n"
            ));

            assert!(connect(&m, None, None, None).await.is_err());

            let (_, query) = first_request(&seen);
            assert_eq!(query.as_deref(), Some("tools=a&apiKey=query-secret-77a9"));
        }

        /// A transport failure on a URL carrying the query secret must not
        /// repeat that URL, on either network transport.
        #[tokio::test]
        async fn a_failed_dial_never_repeats_the_query_secret() {
            let _env = Env::set(&[("GW_TEST_CRED_QUERY_LEAK", "query-secret-3e58")]);
            let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = unused.local_addr().unwrap();
            drop(unused);
            for transport in ["http", "sse"] {
                let m = manifest(&format!(
                    "name: hosted\ntransport: {transport}\nprotocol: legacy\n\
                     url: http://{addr}/mcp\nauth:\n  query:\n    name: apiKey\n    \
                     value_env: GW_TEST_CRED_QUERY_LEAK\n"
                ));
                let error = match connect(&m, None, None, None).await {
                    Ok(_) => panic!("{transport}: nothing listens there"),
                    Err(error) => error.to_string(),
                };
                assert!(
                    !error.contains("query-secret-3e58"),
                    "{transport}: the dial error repeated the secret"
                );
            }
        }

        #[tokio::test]
        async fn sse_sends_credentials_and_fixed_headers_on_the_stream_request() {
            let _env = Env::set(&[("GW_TEST_CRED_SSE_SECRET", "sse-secret-5f10")]);
            let (addr, seen) = spawn_capture().await;
            let m = manifest(&format!(
                "name: hosted\ntransport: sse\nurl: http://{addr}/sse\n\
                 auth:\n  query:\n    name: key\n    value_env: GW_TEST_CRED_SSE_SECRET\n\
                 headers:\n  x-client-name: waygate-test\n"
            ));

            assert!(connect(&m, None, None, None).await.is_err());

            let (headers, query) = first_request(&seen);
            assert_eq!(query.as_deref(), Some("key=sse-secret-5f10"));
            assert_eq!(headers["x-client-name"], "waygate-test");
        }

        #[test]
        fn a_missing_or_unsafe_secret_fails_the_dial_naming_only_the_variable() {
            let m = manifest(
                "name: hosted\ntransport: http\nurl: http://hosted/mcp\n\
                 auth:\n  header:\n    name: x-api-key\n    value_env: GW_TEST_CRED_UNSET\n",
            );
            assert!(matches!(
                resolve_request_credentials(&m),
                Err(DialError::MissingAuthEnv { env }) if env == "GW_TEST_CRED_UNSET"
            ));

            let _env = Env::set(&[("GW_TEST_CRED_MULTILINE", "line-one\nsecret-line-two")]);
            let m = manifest(
                "name: hosted\ntransport: http\nurl: http://hosted/mcp\n\
                 auth:\n  header:\n    name: x-api-key\n    value_env: GW_TEST_CRED_MULTILINE\n",
            );
            let error = match resolve_request_credentials(&m) {
                Err(error @ DialError::AuthSecretNotHeaderSafe { .. }) => error.to_string(),
                Err(other) => panic!("expected an unsafe-secret error, got {other}"),
                Ok(_) => panic!("a multi-line secret cannot be a header value"),
            };
            assert!(error.contains("GW_TEST_CRED_MULTILINE"));
            assert!(!error.contains("secret-line-two"));
        }

        #[test]
        fn rotating_any_secret_changes_the_credential_version() {
            let key = [7u8; 32];
            let m = manifest(
                "name: hosted\ntransport: http\nurl: http://hosted/mcp\n\
                 auth:\n  header:\n    name: x-api-key\n    value_env: GW_TEST_CRED_ROTATE\n",
            );
            let _env = Env::set(&[("GW_TEST_CRED_ROTATE", "first-value")]);
            let before = credential_material_version(&m, &key);
            // SAFETY: the name is unique to this test.
            unsafe { std::env::set_var("GW_TEST_CRED_ROTATE", "second-value") };
            assert_ne!(before, credential_material_version(&m, &key));
        }
    }

    /// The stdio child's environment, observed from real child processes.
    /// Failure messages name variables but never print a value, because a
    /// regression would expose the test process's own environment.
    #[cfg(unix)]
    mod stdio_environment {
        use std::collections::BTreeMap;
        use std::ffi::OsString;

        use super::*;

        /// The entries `env -0` prints, keyed by name. NUL separation keeps a
        /// multi-line value from being read as further entries.
        fn parse_env_report(report: &[u8]) -> BTreeMap<String, Vec<u8>> {
            report
                .split(|byte| *byte == 0)
                .filter(|entry| !entry.is_empty())
                .map(|entry| {
                    let split = entry.iter().position(|byte| *byte == b'=');
                    let (name, value) = entry.split_at(split.unwrap_or(entry.len()));
                    let value = value.get(1..).unwrap_or_default();
                    (String::from_utf8_lossy(name).into_owned(), value.to_vec())
                })
                .collect()
        }

        /// Assert that `observed` holds exactly the `expected` names, each
        /// with its expected value.
        fn assert_child_env(observed: &BTreeMap<String, Vec<u8>>, expected: &[(&str, &str)]) {
            let mut expected_names: Vec<&str> = expected.iter().map(|(name, _)| *name).collect();
            expected_names.sort_unstable();
            let observed_names: Vec<&str> = observed.keys().map(String::as_str).collect();
            assert_eq!(observed_names, expected_names, "stdio child variable names");
            for (name, value) in expected {
                assert!(
                    observed[*name] == value.as_bytes(),
                    "`{name}` did not carry the gateway's value",
                );
            }
        }

        /// Run `env -0` as a stdio child whose gateway environment is
        /// `gateway_env`, and return the environment it reports.
        async fn child_environment(
            gateway_env: &[(&str, &str)],
            env_passthrough: &[String],
        ) -> BTreeMap<String, Vec<u8>> {
            let args = ["-0".to_owned()];
            let output = stdio_command_with_env("/usr/bin/env", &args, env_passthrough, |name| {
                gateway_env
                    .iter()
                    .find(|(candidate, _)| *candidate == name)
                    .map(|(_, value)| OsString::from(value))
            })
            .output()
            .await
            .expect("run env as a stdio child");
            assert!(output.status.success(), "env exited with {}", output.status);
            parse_env_report(&output.stdout)
        }

        #[tokio::test]
        async fn stdio_child_receives_only_the_baseline_and_named_variables() {
            // A stand-in gateway environment holding the identity signing key,
            // an `auth.bearer_env` credential and database settings next to two
            // baseline variables. The values are synthetic.
            let gateway_env = [
                ("PATH", "/usr/bin:/bin"),
                ("LANG", "C.UTF-8"),
                ("GATEWAY_IDENTITY_SIGNING_KEY_PEM", "fixture-signing-key"),
                ("EXAMPLE_UPSTREAM_BEARER", "fixture-upstream-bearer"),
                ("GATEWAY_DATABASE_URL", "fixture-gateway-database"),
                ("AUDIT_DATABASE_URL", "fixture-audit-database"),
                ("GATEWAY_AS_DATABASE_URL", "fixture-as-database"),
            ];
            let baseline = [("PATH", "/usr/bin:/bin"), ("LANG", "C.UTF-8")];

            // An exact name match also proves that nothing from the test
            // process's own environment reached the child.
            assert_child_env(&child_environment(&gateway_env, &[]).await, &baseline);

            // Naming a variable passes the gateway's value through. A named
            // variable the gateway has not set is left out without failing the
            // start, and unnamed secrets stay withheld.
            let named = [
                "EXAMPLE_UPSTREAM_BEARER".to_owned(),
                "AUDIT_DATABASE_URL".to_owned(),
                "EXAMPLE_UNSET_VARIABLE".to_owned(),
            ];
            let mut expected = baseline.to_vec();
            expected.extend([
                ("EXAMPLE_UPSTREAM_BEARER", "fixture-upstream-bearer"),
                ("AUDIT_DATABASE_URL", "fixture-audit-database"),
            ]);
            assert_child_env(&child_environment(&gateway_env, &named).await, &expected);
        }

        #[tokio::test]
        async fn stdio_dial_withholds_unnamed_gateway_variables_from_the_child() {
            let named = "GW_TEST_STDIO_ENV_NAMED_TOKEN";
            let unnamed = "GW_TEST_STDIO_ENV_UNNAMED_TOKEN";
            // SAFETY: `set_var` is process-global; both names are unique to this
            // test, so no concurrent reader can observe them.
            unsafe {
                std::env::set_var(named, "fixture-named-token");
                std::env::set_var(unnamed, "fixture-unnamed-token");
            }
            let dir = std::env::temp_dir().join(format!("gateway-stdio-env-{}", Uuid::new_v4()));
            std::fs::create_dir(&dir).expect("create isolated stdio env test directory");
            let report = dir.join("child-env");
            // The child writes its environment to `report` and exits without
            // speaking MCP. The shell holds the child's stdout open until `env`
            // has finished, so the dial fails only after the report is complete.
            let manifest: UpstreamManifest = serde_json::from_value(serde_json::json!({
                "name": "env-report",
                "transport": "stdio",
                "protocol": "legacy",
                "command": [
                    "/bin/sh",
                    "-c",
                    "/usr/bin/env -0 > \"$1\"",
                    "sh",
                    report.to_str().expect("temporary path is UTF-8"),
                ],
                "env_passthrough": [named],
            }))
            .expect("test manifest parses");

            let dialed = tokio::time::timeout(
                Duration::from_secs(10),
                connect(&manifest, None, None, None),
            )
            .await
            .expect("a stdio child that exits must not hang the dial");
            // SAFETY: as above, the names are unique to this test.
            unsafe {
                std::env::remove_var(named);
                std::env::remove_var(unnamed);
            }
            assert!(
                dialed.is_err(),
                "a child that never speaks MCP cannot connect"
            );
            let observed = parse_env_report(&std::fs::read(&report).expect("child wrote its env"));
            std::fs::remove_dir_all(&dir).expect("remove isolated stdio env test directory");

            assert!(
                observed
                    .get(named)
                    .is_some_and(|value| value == b"fixture-named-token"),
                "the named variable must carry the gateway's value",
            );
            assert!(
                !observed.contains_key(unnamed),
                "an unnamed variable must be withheld"
            );
            // Nothing else from the test process's environment arrived: only the
            // baseline, the named variable, and what the shell sets for itself.
            let shell_maintained = ["PWD", "OLDPWD", "SHLVL", "_"];
            for name in observed.keys() {
                assert!(
                    STDIO_BASELINE_ENV.contains(&name.as_str())
                        || name == named
                        || shell_maintained.contains(&name.as_str()),
                    "stdio child received unlisted variable `{name}`",
                );
            }
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn manifest(transport: &str, protocol: Option<&str>) -> UpstreamManifest {
        let protocol_line = protocol
            .map(|p| format!("protocol: \"{p}\"\n"))
            .unwrap_or_default();
        let body = match transport {
            "stdio" => format!("name: t\ntransport: stdio\ncommand: [x]\n{protocol_line}"),
            other => format!("name: t\ntransport: {other}\nurl: http://u/mcp\n{protocol_line}"),
        };
        serde_yaml::from_str(&body).expect("test manifest")
    }

    /// The manifest `protocol:` → rmcp lifecycle mapping, the item's core
    /// dial-behavior contract: `auto` discovers with a legacy fallback,
    /// `legacy` never discovers, `2026-07-28` never falls back, and SSE is
    /// always the legacy handshake no matter what `auto` says.
    #[test]
    fn lifecycle_mapping_matches_the_manifest_contract() {
        for transport in ["http", "stdio"] {
            assert!(
                matches!(
                    lifecycle_for(&manifest(transport, None)),
                    ClientLifecycleMode::Auto {
                        preferred_versions,
                        legacy_version: Some(legacy),
                    } if preferred_versions == vec![ProtocolVersion::V_2026_07_28]
                        && legacy == ProtocolVersion::V_2025_11_25
                ),
                "{transport}: default is auto with a 2025-11-25 legacy fallback"
            );
            assert!(matches!(
                lifecycle_for(&manifest(transport, Some("legacy"))),
                ClientLifecycleMode::Initialize
            ));
            assert!(
                matches!(
                    lifecycle_for(&manifest(transport, Some("2026-07-28"))),
                    ClientLifecycleMode::Discover { preferred_versions }
                        if preferred_versions == vec![ProtocolVersion::V_2026_07_28]
                ),
                "{transport}: explicit 2026-07-28 requires discovery, no fallback"
            );
        }
        // SSE is legacy by definition — auto never discovers there.
        assert!(matches!(
            lifecycle_for(&manifest("sse", None)),
            ClientLifecycleMode::Initialize
        ));
        assert!(matches!(
            lifecycle_for(&manifest("sse", Some("legacy"))),
            ClientLifecycleMode::Initialize
        ));
    }

    /// An upstream that speaks the newest version answers the handshake with
    /// it and keeps no protocol session, so a per-call dial must not ask for
    /// an older, session-holding version.
    #[test]
    fn the_initialize_handshake_proposes_the_newest_version() {
        let config = client_config(
            ClientCapabilities::default(),
            Implementation::new("lifecycle-test", "0"),
        );
        assert_eq!(config.protocol_version, ProtocolVersion::LATEST);
    }

    #[test]
    fn handshake_and_catalog_failures_carry_bounded_escaped_detail() {
        let body = format!(
            "HTTP 502 Bad Gateway:\nforged log line {}",
            "x".repeat(4096)
        );
        for error in [
            DialError::init(&body),
            DialError::connect(&body),
            DialError::list_tools(&body),
        ] {
            let text = error.to_string();
            assert!(
                text.len()
                    <= MAX_DIAL_ERROR_DETAIL_BYTES + "upstream transport connection failed: ".len(),
                "{} bytes",
                text.len()
            );
            assert!(
                text.contains("HTTP 502 Bad Gateway:\\nforged log line"),
                "{text}"
            );
            assert!(!text.contains('\n'), "{text}");
        }
    }
}
