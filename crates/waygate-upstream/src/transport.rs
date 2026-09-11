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

use rmcp::model::{ClientCapabilities, ClientInfo, Implementation, ProtocolVersion};
use rmcp::service::{ClientInitializeError, ClientLifecycleMode, ClientServiceExt, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use zeroize::Zeroizing;

use waygate_oidc::SharedIdentityIssuer;

use crate::bounded_http_client::BoundedResponseClient;
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
    #[error("auth.bearer_env env var `{env}` and its `{env}_FILE` companion are unset or empty")]
    MissingAuthEnv { env: String },
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
    /// complete before the production deadline.
    #[error("upstream MCP handshake exceeded {0:?}")]
    HandshakeTimeout(Duration),
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

fn map_client_initialize_error(error: ClientInitializeError, connection_failed: bool) -> DialError {
    if connection_failed {
        DialError::Connect(error.to_string())
    } else {
        DialError::Init(error.to_string())
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
    pub(crate) service: RunningService<RoleClient, ClientInfo>,
    pub(crate) network_destination: Option<PinnedNetworkDestination>,
    pub(crate) cleartext_control_plane: bool,
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
) -> Result<RunningService<RoleClient, ClientInfo>, DialError> {
    connect_with_capabilities(
        manifest,
        issuer,
        cell,
        exchange,
        ClientCapabilities::default(),
    )
    .await
}

pub(crate) async fn connect_with_destination(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
) -> Result<ConnectedService, DialError> {
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
/// answers no server-initiated request, so advertising nothing is the honest
/// declaration and the pre-MRTR behavior.
pub(crate) async fn connect_with_capabilities(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
    capabilities: ClientCapabilities,
) -> Result<RunningService<RoleClient, ClientInfo>, DialError> {
    connect_with_handshake_timeout(
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
/// back from. The legacy leg keeps proposing the client's own latest
/// version in `initialize` — the handshake negotiates the version in its
/// response, so the server picks what it supports.
async fn connect_with_handshake_timeout(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
    capabilities: ClientCapabilities,
    handshake_timeout: Duration,
) -> Result<RunningService<RoleClient, ClientInfo>, DialError> {
    Ok(connect_with_handshake_timeout_and_destination(
        manifest,
        issuer,
        cell,
        exchange,
        capabilities,
        handshake_timeout,
    )
    .await?
    .service)
}

async fn connect_with_handshake_timeout_and_destination(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
    capabilities: ClientCapabilities,
    handshake_timeout: Duration,
) -> Result<ConnectedService, DialError> {
    let lifecycle = lifecycle_for(manifest);
    let dialed = dial_once(
        manifest,
        issuer,
        cell,
        exchange,
        capabilities.clone(),
        handshake_timeout,
        lifecycle.clone(),
    )
    .await;

    match dialed {
        // Only the handshake itself is bridgeable. A timeout, a failed
        // subprocess spawn, or a rejected `auth:`/`mtls:` block would fail
        // the same way twice, and retrying a timeout would spend the
        // handshake budget a second time.
        Err(DialError::Init(_)) if matches!(lifecycle, ClientLifecycleMode::Auto { .. }) => {
            dial_once(
                manifest,
                issuer,
                cell,
                exchange,
                capabilities,
                handshake_timeout,
                ClientLifecycleMode::Initialize,
            )
            .await
        }
        dialed => dialed,
    }
}

/// One dial under exactly the lifecycle it is given, with no fallback.
#[allow(clippy::too_many_arguments)]
async fn dial_once(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    cell: Option<&IdentityCell>,
    exchange: Option<&ExchangeBundle>,
    capabilities: ClientCapabilities,
    handshake_timeout: Duration,
    lifecycle: ClientLifecycleMode,
) -> Result<ConnectedService, DialError> {
    let info = ClientInfo::new(
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
            // unauthenticated request to the configured URL.
            let mut config = StreamableHttpClientTransportConfig::with_uri(url.clone());
            if let Some(token) = resolve_static_bearer(&manifest.name, manifest.auth.as_ref())? {
                config = config.auth_header(token);
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
            let http = BoundedResponseClient::new(http);
            let connection_probe = http.clone();
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
                    .map_err(|_| DialError::HandshakeTimeout(handshake_timeout))?
                    .map_err(|error| {
                        map_client_initialize_error(error, connection_probe.connection_failed())
                    })
                }
                _ => {
                    let transport = StreamableHttpClientTransport::with_client(http, config);
                    tokio::time::timeout(
                        handshake_timeout,
                        info.serve_with_lifecycle(transport, lifecycle),
                    )
                    .await
                    .map_err(|_| DialError::HandshakeTimeout(handshake_timeout))?
                    .map_err(|error| {
                        map_client_initialize_error(error, connection_probe.connection_failed())
                    })
                }
            }?;
            Ok(ConnectedService {
                service,
                network_destination: Some(destination),
                cleartext_control_plane: url::Url::parse(&url)
                    .is_ok_and(|url| url.scheme() == "http"),
            })
        }
        Transport::Sse => {
            // Static per-upstream bearer (`auth.bearer_env`): resolve from
            // process env before dialing. A set-but-empty env fails the dial
            // loud rather than leaking an unauthenticated SSE connection — same
            // contract as the HTTP branch. `sse_client::connect` stamps the
            // resolved token on both the SSE GET and every message POST.
            let static_bearer = resolve_static_bearer(&manifest.name, manifest.auth.as_ref())?;
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
                    static_bearer,
                    handshake_timeout,
                    http_policy::WRITE_TIMEOUT,
                )
                .await
                .map_err(|e| DialError::Init(e.to_string()))?;
                let cleartext_control_plane = connected.cleartext_control_plane;
                let service = info
                    .serve(connected.transport)
                    .await
                    .map_err(|e| DialError::Init(e.to_string()))?;
                Ok::<_, DialError>((service, cleartext_control_plane))
            };
            let (service, cleartext_control_plane) =
                tokio::time::timeout(handshake_timeout, handshake)
                    .await
                    .map_err(|_| DialError::HandshakeTimeout(handshake_timeout))??;
            Ok(ConnectedService {
                service,
                network_destination: Some(destination),
                cleartext_control_plane,
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
            let mut cmd = tokio::process::Command::new(&argv[0]);
            if argv.len() > 1 {
                cmd.args(&argv[1..]);
            }
            let transport = TokioChildProcess::new(cmd).map_err(DialError::Spawn)?;
            let service = info
                .serve_with_lifecycle(transport, lifecycle)
                .await
                .map_err(|e| DialError::Init(e.to_string()))?;
            Ok(ConnectedService {
                service,
                network_destination: None,
                cleartext_control_plane: false,
            })
        }
    }
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

    match manifest
        .auth
        .as_ref()
        .and_then(|auth| auth.bearer_env.as_ref())
    {
        Some(env) => {
            version.update(b"bearer-present");
            hash_public_component(&mut version, env.as_bytes());
            let value = Zeroizing::new(std::env::var(env).unwrap_or_default());
            if value.is_empty() {
                let file_env = format!("{env}_FILE");
                let path = std::env::var(&file_env).unwrap_or_default();
                version.update(b"bearer-file");
                hash_file_component(&mut version, key, path.as_ref(), MAX_AUTH_FILE_BYTES);
            } else {
                version.update(b"bearer-env");
                hash_secret_component(&mut version, key, value.as_bytes());
            }
        }
        None => {
            version.update(b"bearer-absent");
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

/// Resolve the optional static bearer without treating a group-only auth block
/// as empty. An explicitly empty `auth: {}` remains an operator error and must
/// fail before transport I/O, while `catalog_probe_groups` may stand alone
/// because the signed identity header supplies that separate auth mechanism.
fn resolve_static_bearer(
    server: &str,
    auth: Option<&UpstreamAuth>,
) -> Result<Option<String>, DialError> {
    match auth {
        None => Ok(None),
        Some(auth) if auth.bearer_env.is_some() => resolve_auth_token(server, auth).map(Some),
        Some(auth) if auth.catalog_probe_groups.is_empty() => Err(DialError::EmptyAuth),
        Some(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::sse::{Event, Sse};
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
            matches!(result, Err(DialError::HandshakeTimeout(actual)) if actual == deadline),
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

        assert!(
            matches!(result, Err(DialError::HandshakeTimeout(actual)) if actual == deadline),
            "stalled MCP initialization returned {result:?}",
        );
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
}
