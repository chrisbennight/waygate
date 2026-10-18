//! MCP resource requests over the upstream pool.

use super::*;
use rmcp::model::{
    ClientRequest, GetExtensions, ReadResourceRequest, RequestMetaObject, ServerResult,
};
use rmcp::service::PeerRequestOptions;
use rmcp::service::ServiceError;
use waygate_mcp::catalog::{
    AdmittedResourceReadError, CallScopedResourceError, CallScopedResourceReader, ResourceClaim,
};

use crate::bounded_http_client::{response_materialization_limit, ResponseByteLimit};

pub(super) enum ResourceRequest {
    List(Option<PaginatedRequestParams>),
    ListTemplates(Option<PaginatedRequestParams>),
    Read(ReadResourceRequestParams),
}

pub(super) enum ResourceResponse {
    List(ListResourcesResult),
    ListTemplates(ListResourceTemplatesResult),
    Read(ReadResourceResult),
}

pub(super) enum ResourceRequestError {
    Mcp(McpError),
    ResponseTooLarge { limit_bytes: usize },
}

impl From<ResourceRequestError> for McpError {
    fn from(error: ResourceRequestError) -> Self {
        match error {
            ResourceRequestError::Mcp(error) => error,
            ResourceRequestError::ResponseTooLarge { limit_bytes } => McpError::internal_error(
                format!(
                    "upstream response exceeded the {limit_bytes}-byte caller materialization budget"
                ),
                Some(serde_json::json!({
                    "error": waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_ERROR,
                })),
            ),
        }
    }
}

impl From<McpError> for ResourceRequestError {
    fn from(error: McpError) -> Self {
        Self::Mcp(error)
    }
}

pub(super) fn manifest_supports_resource_operations(manifest: &UpstreamManifest) -> bool {
    !manifest.tier_a_required && manifest.exchange.is_none() && manifest.tier_c_peer.is_none()
}

/// Resource reads and listings reach an upstream only through prefixes its
/// manifest declares, so an upstream that offers resources without any
/// declaration is unreachable for them. Say so where the operator sees it,
/// whether the upstream connected that way or a reload removed its last
/// declaration.
pub(super) fn warn_if_resources_undeclared(
    manifest: &UpstreamManifest,
    resource_capability_advertised: bool,
) {
    if resource_capability_advertised
        && manifest.resources.is_empty()
        && manifest_supports_resource_operations(manifest)
    {
        tracing::warn!(
            server = %manifest.name,
            "upstream advertises MCP resources but its manifest declares no resource prefix; \
             the gateway does not route resource reads or listings to it",
        );
    }
}

fn resource_transport_name(transport: &crate::Transport) -> &'static str {
    match transport {
        crate::Transport::Http => "http",
        crate::Transport::Sse => "sse",
        crate::Transport::Stdio => "stdio",
    }
}

fn bounded_resource_read_unsupported(transport: &crate::Transport) -> McpError {
    let transport = resource_transport_name(transport);
    McpError::internal_error(
        format!("bounded resource reads are unsupported for {transport} transport"),
        Some(serde_json::json!({
            "error": "bounded_resource_read_unsupported",
            "transport": transport,
        })),
    )
}

impl UpstreamPool {
    pub(super) fn declared_resource_claims(&self, server: &str) -> Vec<ResourceClaim> {
        self.entries
            .load()
            .get(server)
            .map(|entry| {
                entry
                    .manifest_snapshot()
                    .resources
                    .iter()
                    .map(|claim| ResourceClaim {
                        uri_prefix: claim.uri_prefix.clone(),
                        risk: claim.risk,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(super) fn admitted_resource_routing_claims_inner(&self) -> Vec<(String, ResourceClaim)> {
        let entries = self.entries.load();
        let mut names: Vec<&String> = entries.keys().collect();
        names.sort();
        names
            .into_iter()
            .flat_map(|name| {
                entries[name]
                    .manifest_snapshot()
                    .resources
                    .into_iter()
                    .map(|claim| {
                        (
                            name.clone(),
                            ResourceClaim {
                                uri_prefix: claim.uri_prefix,
                                risk: claim.risk,
                            },
                        )
                    })
            })
            .collect()
    }

    pub(super) async fn request_resource_templates_inner(
        &self,
        server: &str,
        params: Option<PaginatedRequestParams>,
        principal: Option<&Principal>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        match self
            .request_resource_inner(server, ResourceRequest::ListTemplates(params), principal)
            .await?
        {
            ResourceResponse::ListTemplates(result) => Ok(result),
            ResourceResponse::List(_) | ResourceResponse::Read(_) => {
                unreachable!("template-list request returned another resource response")
            }
        }
    }
}

impl ResourceRequest {
    fn response_materialization_limit(&self) -> Option<usize> {
        let Self::Read(params) = self else {
            return None;
        };
        params
            .meta
            .as_ref()?
            .get(waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY)?
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
    }
}

/// Build the `resources/read` request an upstream receives from the gateway's
/// own read parameters.
///
/// As with a tool call, the request metadata holds only values the gateway
/// sets; every other `_meta` key is dropped. The private response budget is
/// moved onto a request extension, which the gateway's HTTP transport reads and
/// rmcp never serializes. The request-local client capabilities are the
/// gateway's file promise for this one read. rmcp stamps the dial's
/// initialize-time client capabilities before sending; an explicit request
/// option is applied afterwards and therefore preserves the per-request file
/// signal instead of letting the connection default erase it.
fn upstream_read_request(
    mut params: ReadResourceRequestParams,
) -> (ClientRequest, PeerRequestOptions) {
    let mut meta = params.meta.take().unwrap_or_default();
    let limit = meta
        .remove(waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY)
        .as_ref()
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok());
    let mut request = ClientRequest::ReadResourceRequest(ReadResourceRequest::new(params));
    if let Some(limit) = limit {
        request.extensions_mut().insert(ResponseByteLimit(limit));
    }
    let options = match meta.remove(waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY) {
        Some(capabilities) => {
            let mut outbound = RequestMetaObject::new();
            outbound.insert(
                waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY.to_owned(),
                capabilities,
            );
            PeerRequestOptions::no_options().with_meta(outbound)
        }
        None => PeerRequestOptions::no_options(),
    };
    (request, options)
}

async fn send_read_request(
    client: &RunningService<RoleClient, ClientConfig>,
    params: ReadResourceRequestParams,
) -> Result<ReadResourceResult, ServiceError> {
    let (request, options) = upstream_read_request(params);
    let response = client
        .send_request_with_option(request, options)
        .await?
        .await_response()
        .await?;
    match response {
        ServerResult::ReadResourceResult(result) => Ok(result),
        _ => Err(ServiceError::UnexpectedResponse),
    }
}

async fn send_resource_request(
    client: &RunningService<RoleClient, ClientConfig>,
    request: ResourceRequest,
) -> Result<ResourceResponse, ServiceError> {
    match request {
        ResourceRequest::List(params) => client
            .list_resources(params)
            .await
            .map(ResourceResponse::List),
        ResourceRequest::ListTemplates(params) => client
            .list_resource_templates(params)
            .await
            .map(ResourceResponse::ListTemplates),
        ResourceRequest::Read(params) => send_read_request(client, params)
            .await
            .map(ResourceResponse::Read),
    }
}

pub(super) struct SessionResourceReader<'a> {
    pub(super) server: &'a str,
    pub(super) client: &'a RunningService<RoleClient, ClientConfig>,
    pub(super) timeout: Option<Duration>,
    pub(super) bounded_reads_supported: bool,
}

#[async_trait]
impl CallScopedResourceReader for SessionResourceReader<'_> {
    async fn read_resource(
        &self,
        params: ReadResourceRequestParams,
    ) -> Result<ReadResourceResult, CallScopedResourceError> {
        if params.meta.as_ref().is_some_and(|meta| {
            meta.get(waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY)
                .is_some()
        }) && !self.bounded_reads_supported
        {
            return Err(CallScopedResourceError::Mcp(McpError::internal_error(
                "bounded retained-response reads require streamable HTTP transport",
                Some(serde_json::json!({"error":"bounded_resource_read_unsupported"})),
            )));
        }
        let read = send_read_request(self.client, params);
        let result = match self.timeout {
            Some(timeout) => tokio::time::timeout(timeout, read).await.map_err(|_| {
                CallScopedResourceError::Transport(format!(
                    "upstream `{}` retained-resource request timed out after {}s",
                    self.server,
                    timeout.as_secs(),
                ))
            })?,
            None => read.await,
        };
        match result {
            Ok(resource) => Ok(resource),
            Err(ServiceError::McpError(error)) => Err(CallScopedResourceError::Mcp(error)),
            Err(error) => match response_materialization_limit(&error) {
                Some(limit_bytes) => Err(CallScopedResourceError::Mcp(
                    ResourceRequestError::ResponseTooLarge { limit_bytes }.into(),
                )),
                None => Err(CallScopedResourceError::Transport(format!(
                    "upstream `{}` retained-resource request: {error}",
                    self.server,
                ))),
            },
        }
    }
}

impl UpstreamPool {
    pub(super) async fn resource_routing_snapshot_inner(&self) -> ResourceRoutingSnapshot {
        let _routing_guard = self.resource_routing.read().await;
        ResourceRoutingSnapshot {
            generation: self.resource_routing_generation.load(Ordering::Acquire),
            claims: self.admitted_resource_routing_claims_inner(),
        }
    }

    pub(super) async fn read_resource_admitted_inner(
        &self,
        server: &str,
        params: ReadResourceRequestParams,
        principal: Option<&Principal>,
        admitted: &ResourceReadAdmission,
    ) -> Result<ReadResourceResult, AdmittedResourceReadError> {
        let _routing_guard = self.resource_routing.read().await;
        let current_generation = self.resource_routing_generation.load(Ordering::Acquire);
        if admitted.generation != current_generation || admitted.server != server {
            return Err(AdmittedResourceReadError::RoutingChanged);
        }

        let entry = self
            .entry(server)
            .map_err(AdmittedResourceReadError::Upstream)?;
        let manifest = entry.manifest_snapshot();
        let claim = &admitted.claim;
        let identity_matches = manifest.resources.iter().any(|current| {
            current.uri_prefix == claim.uri_prefix
                && current.risk == claim.risk
                && params.uri.starts_with(&current.uri_prefix)
        });
        if !identity_matches {
            return Err(AdmittedResourceReadError::RoutingChanged);
        }
        if params
            .meta
            .as_ref()
            .and_then(|meta| {
                meta.get(waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY)
            })
            .is_some()
            && !matches!(&manifest.transport, crate::Transport::Http)
        {
            return Err(AdmittedResourceReadError::BoundedUnsupported {
                transport: resource_transport_name(&manifest.transport),
            });
        }

        match self
            .request_resource_inner(server, ResourceRequest::Read(params), principal)
            .await
            .map_err(|error| match error {
                ResourceRequestError::ResponseTooLarge { limit_bytes } => {
                    AdmittedResourceReadError::ResponseTooLarge { limit_bytes }
                }
                ResourceRequestError::Mcp(error) => AdmittedResourceReadError::Upstream(error),
            })? {
            ResourceResponse::Read(result) => Ok(result),
            ResourceResponse::ListTemplates(_) => {
                unreachable!("read request returned a template-list response")
            }
            ResourceResponse::List(_) => unreachable!("read request returned a list response"),
        }
    }

    pub(super) async fn call_tool_response_processed_with_resource_routing(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
        processing: CallToolResultProcessing<'_>,
    ) -> Result<CallToolResponse, waygate_mcp::catalog::InvocationError> {
        // Retained-response processing authorizes URI risk from the selected
        // server's resource claims and may read that URI on this exact session.
        // Keep those claims stable until processing releases the session.
        let _routing_guard = self.resource_routing.read().await;
        self.call_tool_traced_processed(server, tool_name, args, principal, admitted, processing)
            .await
    }

    pub(super) fn resource_operations_supported_inner(&self, server: &str) -> bool {
        self.entries.load().get(server).is_some_and(|entry| {
            let manifest = entry.manifest_snapshot();
            manifest_supports_resource_operations(&manifest)
        })
    }

    pub(super) async fn resource_capability_advertised_inner(&self, server: &str) -> bool {
        let entry = self.entries.load().get(server).cloned();
        let Some(entry) = entry else {
            return false;
        };
        let manifest = entry.manifest_snapshot();
        if !manifest_supports_resource_operations(&manifest) {
            return false;
        }
        for slot in &entry.slots {
            if slot
                .conn
                .read()
                .await
                .as_ref()
                .is_some_and(|conn| conn.resource_capability_advertised)
            {
                return true;
            }
        }
        false
    }

    pub(super) async fn request_resource_inner(
        &self,
        server: &str,
        request: ResourceRequest,
        principal: Option<&Principal>,
    ) -> Result<ResourceResponse, ResourceRequestError> {
        let entry = self.entry(server)?;
        if entry.removed.load(Ordering::Acquire) {
            return Err(McpError::invalid_params(
                format!("upstream `{server}` is being removed"),
                None,
            )
            .into());
        }

        let snapshot = entry.manifest_snapshot();
        if request.response_materialization_limit().is_some()
            && !matches!(&snapshot.transport, crate::Transport::Http)
        {
            return Err(bounded_resource_read_unsupported(&snapshot.transport).into());
        }
        if snapshot.tier_a_required || snapshot.exchange.is_some() || snapshot.tier_c_peer.is_some()
        {
            return Err(McpError::internal_error(
                format!(
                    "upstream `{server}` requires delegated identity that MCP resource forwarding \
                     does not support"
                ),
                None,
            )
            .into());
        }

        let identity_context = match (entry.forwards_identity, principal) {
            (true, Some(principal)) => Some(IdentityContext {
                principal: principal.clone(),
                audience: server.to_owned(),
                exchange: None,
                stored_upstream_subject_token: None,
                exchanged_bearer: None,
                tier_c_audience: None,
                token_policy: snapshot.identity_token_policy(),
            }),
            _ => None,
        };

        let permit = match entry.breaker.acquire() {
            Ok(permit) => permit,
            Err(BreakerError::Open) => {
                return Err(McpError::internal_error(
                    format!("upstream `{server}` circuit open"),
                    None,
                )
                .into());
            }
            Err(BreakerError::ProbeInFlight) => {
                return Err(McpError::internal_error(
                    format!("upstream `{server}` circuit probing recovery"),
                    None,
                )
                .into());
            }
        };

        waygate_telemetry::metrics::identity_cell_queue_inc(server);
        let _depth_guard = SerializerDepthGuard {
            server: server.to_owned(),
        };
        let wait_start = std::time::Instant::now();
        let lane = entry.admit(resolve_isolation(&snapshot)).await;
        waygate_telemetry::metrics::record_identity_cell_wait(
            server,
            wait_start.elapsed().as_secs_f64(),
        );

        let conn_guard = lane.slot.conn.read().await;
        let Some(conn) = conn_guard.as_ref() else {
            permit.failure();
            entry.record_runtime_failure(UpstreamErrorClass::Transport);
            return Err(McpError::internal_error(
                format!("upstream `{server}` is not connected"),
                None,
            )
            .into());
        };
        if entry.removed.load(Ordering::Acquire) {
            permit.neutral();
            return Err(McpError::invalid_params(
                format!("upstream `{server}` is being removed"),
                None,
            )
            .into());
        }
        if !redial_committed_fields_eq(&snapshot, &entry.manifest_snapshot()) {
            permit.neutral();
            return Err(McpError::internal_error(
                format!(
                    "upstream `{server}` connection shape or identity changed during resource \
                     request setup — retry the request"
                ),
                None,
            )
            .into());
        }

        let isolation = lane.isolation;
        let result = match isolation {
            SessionIsolation::PerCall => {
                let cell = entry.forwards_identity.then(IdentityCell::new);
                if let (Some(cell), Some(context)) = (cell.as_ref(), identity_context) {
                    cell.set(context);
                }
                let service = match transport::connect(
                    &snapshot,
                    self.issuer.as_ref(),
                    cell.as_ref(),
                    self.exchange.as_ref(),
                )
                .await
                {
                    Ok(service) => service,
                    Err(error) => {
                        permit.failure();
                        entry.record_runtime_failure(UpstreamErrorClass::from_dial_error(&error));
                        return Err(McpError::internal_error(
                            format!("upstream `{server}` resource-session dial failed: {error}"),
                            None,
                        )
                        .into());
                    }
                };
                let response = match self.call_timeout_for(&snapshot) {
                    Some(timeout) => {
                        match tokio::time::timeout(
                            timeout,
                            send_resource_request(&service, request),
                        )
                        .await
                        {
                            Ok(response) => response,
                            Err(_) => {
                                permit.failure();
                                entry.record_runtime_failure(UpstreamErrorClass::Timeout);
                                return Err(McpError::internal_error(
                                    format!(
                                        "upstream `{server}` resource request timed out after {}s",
                                        timeout.as_secs()
                                    ),
                                    None,
                                )
                                .into());
                            }
                        }
                    }
                    None => send_resource_request(&service, request).await,
                };
                // Session DELETE only if this service's own dial created a
                // session — a stateless 2026-negotiated dial tears down
                // without one (same contract as the tool-call path).
                let _ = service.cancel().await;
                response
            }
            SessionIsolation::Reuse => {
                let _cell_guard = match (conn.identity_cell.as_ref(), identity_context) {
                    (Some(cell), Some(context)) => {
                        cell.set(context);
                        Some(CellClearGuard { cell: cell.clone() })
                    }
                    _ => None,
                };
                match self.call_timeout_for(&snapshot) {
                    Some(timeout) => {
                        match tokio::time::timeout(
                            timeout,
                            send_resource_request(&conn.client, request),
                        )
                        .await
                        {
                            Ok(response) => response,
                            Err(_) => {
                                permit.failure();
                                drop(conn_guard);
                                self.mark_slot_down(
                                    server,
                                    &entry,
                                    lane.slot,
                                    UpstreamErrorClass::Timeout,
                                )
                                .await;
                                return Err(McpError::internal_error(
                                    format!(
                                        "upstream `{server}` resource request timed out after {}s",
                                        timeout.as_secs()
                                    ),
                                    None,
                                )
                                .into());
                            }
                        }
                    }
                    None => send_resource_request(&conn.client, request).await,
                }
            }
        };
        match result {
            Ok(response) => {
                let recovered = permit.success();
                drop(conn_guard);
                self.settle_probe_recovery(server, &entry, recovered).await;
                Ok(response)
            }
            Err(ServiceError::McpError(error)) => {
                let recovered = permit.success();
                drop(conn_guard);
                self.settle_probe_recovery(server, &entry, recovered).await;
                Err(error.into())
            }
            Err(error) => {
                if let Some(limit_bytes) = response_materialization_limit(&error) {
                    let recovered = permit.success();
                    drop(conn_guard);
                    self.settle_probe_recovery(server, &entry, recovered).await;
                    return Err(ResourceRequestError::ResponseTooLarge { limit_bytes });
                }
                permit.failure();
                drop(conn_guard);
                if matches!(isolation, SessionIsolation::Reuse) {
                    self.mark_slot_down(server, &entry, lane.slot, UpstreamErrorClass::Transport)
                        .await;
                } else {
                    entry.record_runtime_failure(UpstreamErrorClass::Transport);
                }
                Err(McpError::internal_error(
                    format!("upstream `{server}` resource request: {error}"),
                    None,
                )
                .into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{bounded_resource_read_unsupported, upstream_read_request};
    use crate::bounded_http_client::ResponseByteLimit;
    use rmcp::model::{
        ClientJsonRpcMessage, ClientRequest, GetExtensions, ReadResourceRequestParams, RequestId,
        RequestMetaObject,
    };
    use serde_json::json;

    #[test]
    fn an_upstream_read_carries_only_gateway_metadata() {
        let capabilities = json!({"files": {"download": true, "transports": ["https"]}});
        let mut meta = RequestMetaObject::new();
        meta.insert(
            waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY.to_owned(),
            json!(4096),
        );
        meta.insert(
            waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY.to_owned(),
            capabilities.clone(),
        );
        meta.insert("example.test/caller".to_owned(), json!(1));
        let params = ReadResourceRequestParams::new("docs://report").with_meta(meta);

        let (request, options) = upstream_read_request(params);

        assert_eq!(
            request
                .extensions()
                .get::<ResponseByteLimit>()
                .map(|limit| limit.0),
            Some(4096),
        );
        let option_meta = options.meta.expect("the file promise is a request option");
        assert_eq!(
            option_meta.keys().collect::<Vec<_>>(),
            vec![waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY],
        );
        assert_eq!(
            option_meta[waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY],
            capabilities,
        );
        let ClientRequest::ReadResourceRequest(read) = &request else {
            panic!("a resource read builds a read request")
        };
        assert!(read.params.meta.is_none());
        let wire =
            serde_json::to_value(ClientJsonRpcMessage::request(request, RequestId::Number(1)))
                .unwrap();
        assert!(
            wire["params"].get("_meta").is_none(),
            "only rmcp's stamping and the request options may add metadata: {wire}"
        );
    }

    #[test]
    fn an_unbounded_read_without_a_file_promise_adds_no_metadata() {
        let mut meta = RequestMetaObject::new();
        meta.insert("example.test/caller".to_owned(), json!(1));
        let (request, options) =
            upstream_read_request(ReadResourceRequestParams::new("docs://report").with_meta(meta));

        assert!(request.extensions().get::<ResponseByteLimit>().is_none());
        assert!(options.meta.is_none());
    }

    #[test]
    fn non_http_bounded_reads_name_the_stable_error_and_transport() {
        for (transport, expected) in [
            (crate::Transport::Sse, "sse"),
            (crate::Transport::Stdio, "stdio"),
        ] {
            let error = bounded_resource_read_unsupported(&transport);
            let data = error.data.expect("stable bounded-read error data");
            assert_eq!(data["error"], "bounded_resource_read_unsupported");
            assert_eq!(data["transport"], expected);
        }
    }
}
