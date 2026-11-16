//! Draft file-transfer authorization requests over the upstream pool.

use super::*;
use rmcp::model::{
    ClientCapabilities, ClientRequest, CustomRequest, MetaObject, RequestMetaObject, ServerResult,
};
use rmcp::service::{PeerRequestOptions, ServiceError};

enum FileAuthorizationRequest {
    Upload(AuthorizeUploadParams),
    Download(AuthorizeDownloadParams),
    Lifecycle { uri: String, cancel: bool },
}

enum FileAuthorizationResponse {
    Upload(AuthorizeUploadResult),
    Download(AuthorizeDownloadResult),
    Lifecycle(Value),
}

impl FileAuthorizationResponse {
    fn descriptor_url(&self) -> Option<&str> {
        match self {
            Self::Upload(result) => Some(&result.upload.url),
            Self::Download(result) => Some(&result.download.url),
            Self::Lifecycle(_) => None,
        }
    }
}

/// Carry the gateway's file-capability declaration past the SDK's per-request
/// metadata stamping.
///
/// A leg negotiated at 2026-07-28 stamps the client capability key onto every
/// outgoing request from the capabilities declared when the connection was
/// dialed, and that stamp *replaces* the same key carried in the request
/// params rather than merging into it. The SDK's typed capability struct has
/// no member for the draft's `files` declaration, so on such a leg the params
/// copy alone reaches the upstream as an empty capability object and an
/// upstream that honours the draft refuses the transfer. An explicit
/// per-request override is applied after the stamping, so it is the one place
/// the declaration survives on both protocol generations.
///
/// The declaration is composed onto whatever the dial declared, so a leg that
/// mirrors a caller capability keeps it.
pub(super) fn client_capability_meta(
    declared: &ClientCapabilities,
    operation: waygate_mcp::files::FileOperation,
    cleartext_control_plane: bool,
) -> RequestMetaObject {
    let mut capabilities = match serde_json::to_value(declared) {
        Ok(Value::Object(declared)) => declared,
        // A capability struct of optional members always serializes to an
        // object; declaring nothing else is the safe base if that changes.
        _ => Map::new(),
    };
    let mut files = waygate_mcp::files::stateless_client_file_capability(operation);
    if cleartext_control_plane {
        files["transports"]
            .as_array_mut()
            .expect("the gateway file capability declares transports")
            .push(Value::String("http".to_owned()));
    }
    capabilities.insert(
        waygate_mcp::files::FILES_CAPABILITY_MEMBER.to_owned(),
        files,
    );
    RequestMetaObject(MetaObject(Map::from_iter([(
        waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY.to_owned(),
        Value::Object(capabilities),
    )])))
}

async fn send_file_authorization(
    client: &RunningService<RoleClient, ClientConfig>,
    request: &FileAuthorizationRequest,
    cleartext_control_plane: bool,
) -> Result<FileAuthorizationResponse, ServiceError> {
    let (method, params, operation) = match request {
        FileAuthorizationRequest::Upload(params) => (
            waygate_mcp::files::AUTHORIZE_UPLOAD_METHOD,
            serde_json::to_value(params),
            waygate_mcp::files::FileOperation::Upload,
        ),
        FileAuthorizationRequest::Download(params) => (
            waygate_mcp::files::AUTHORIZE_DOWNLOAD_METHOD,
            serde_json::to_value(params),
            waygate_mcp::files::FileOperation::Download,
        ),
        FileAuthorizationRequest::Lifecycle { uri, cancel } => (
            if *cancel {
                "files/cancelUpload"
            } else {
                "files/transferStatus"
            },
            Ok(serde_json::json!({"uri":uri})),
            waygate_mcp::files::FileOperation::Upload,
        ),
    };
    let params = params.map_err(|_| ServiceError::UnexpectedResponse)?;
    let response = client
        .send_request_with_option(
            ClientRequest::CustomRequest(CustomRequest::new(method, Some(params))),
            PeerRequestOptions::no_options().with_meta(client_capability_meta(
                &client.service().capabilities,
                operation,
                cleartext_control_plane,
            )),
        )
        .await?
        .await_response()
        .await?;
    match response {
        ServerResult::CustomResult(result) => match request {
            FileAuthorizationRequest::Upload(_) => result
                .result_as::<AuthorizeUploadResult>()
                .map(FileAuthorizationResponse::Upload)
                .map_err(|_| ServiceError::UnexpectedResponse),
            FileAuthorizationRequest::Download(_) => result
                .result_as::<AuthorizeDownloadResult>()
                .map(FileAuthorizationResponse::Download)
                .map_err(|_| ServiceError::UnexpectedResponse),
            FileAuthorizationRequest::Lifecycle { .. } => result
                .result_as::<Value>()
                .map(FileAuthorizationResponse::Lifecycle)
                .map_err(|_| ServiceError::UnexpectedResponse),
        },
        _ => Err(ServiceError::UnexpectedResponse),
    }
}

impl UpstreamPool {
    async fn ensure_file_upload_contract_current(
        &self,
        entry: &UpstreamEntry,
        snapshot: &UpstreamManifest,
        conn: &Connection,
        server: &str,
        principal: Option<&Principal>,
        admitted_tool: Option<(&str, &InvocationContractIdentity, Option<&str>)>,
    ) -> Result<(), McpError> {
        let Some((tool_name, admitted, binding)) = admitted_tool else {
            return Ok(());
        };
        let current_manifest = entry.manifest_snapshot();
        if binding
            .is_some_and(|expected| tasks::binding(&current_manifest).as_deref() != Some(expected))
        {
            return Err(waygate_mcp::files::file_transfer_failure(
                waygate_mcp::files::FileTransferReason::TemporarilyUnavailable,
                "upload's originating upstream configuration changed; restore it before recovery",
            ));
        }
        let tenant = principal
            .map(|principal| principal.tenant.as_str())
            .unwrap_or(waygate_core::TenantId::DEFAULT);
        if dispatch_contract_is_current(
            entry,
            snapshot,
            &current_manifest,
            &conn.live_tools,
            tool_name,
            self.tool_reviews.is_none(),
        ) && self
            .admitted_contract_is_current(
                tenant,
                server,
                tool_name,
                &current_manifest,
                conn,
                admitted,
            )
            .await
        {
            Ok(())
        } else {
            // The shared contract-drift refusal predates the bounded file
            // vocabulary; on the file surface it carries the category a
            // client can route on (refresh and retry may succeed).
            let mut error = contract_changed_error(server, tool_name);
            error.data = Some(serde_json::json!({
                waygate_mcp::files::FILE_TRANSFER_REASON_KEY:
                    waygate_mcp::files::FileTransferReason::TemporarilyUnavailable.as_str()
            }));
            Err(error)
        }
    }

    async fn authorize_file_transfer_inner(
        &self,
        server: &str,
        request: FileAuthorizationRequest,
        principal: Option<&Principal>,
        admitted_tool: Option<(&str, &InvocationContractIdentity, Option<&str>)>,
    ) -> Result<
        (
            FileAuthorizationResponse,
            waygate_mcp::files::FileTransferNetwork,
            String,
        ),
        McpError,
    > {
        // The shared unknown-upstream refusal gains the file surface's
        // bounded category, matching the removal refusal below: a reload can
        // restore the server, so retrying later may succeed.
        let entry = self.entry(server).map_err(|mut error| {
            error.data = Some(serde_json::json!({
                waygate_mcp::files::FILE_TRANSFER_REASON_KEY:
                    waygate_mcp::files::FileTransferReason::TemporarilyUnavailable.as_str()
            }));
            error
        })?;
        if entry.removed.load(Ordering::Acquire) {
            return Err(waygate_mcp::files::file_transfer_failure(
                waygate_mcp::files::FileTransferReason::TemporarilyUnavailable,
                format!("upstream `{server}` is being removed"),
            ));
        }

        let snapshot = entry.manifest_snapshot();
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
                return Err(waygate_mcp::files::file_transfer_failure(
                    waygate_mcp::files::FileTransferReason::TemporarilyUnavailable,
                    format!("upstream `{server}` circuit open"),
                ));
            }
            Err(BreakerError::ProbeInFlight) => {
                return Err(waygate_mcp::files::file_transfer_failure(
                    waygate_mcp::files::FileTransferReason::TemporarilyUnavailable,
                    format!("upstream `{server}` circuit probing recovery"),
                ));
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
            return Err(waygate_mcp::files::file_transfer_failure(
                waygate_mcp::files::FileTransferReason::TemporarilyUnavailable,
                format!("upstream `{server}` is not connected"),
            ));
        };
        if entry.removed.load(Ordering::Acquire) {
            permit.neutral();
            return Err(waygate_mcp::files::file_transfer_failure(
                waygate_mcp::files::FileTransferReason::TemporarilyUnavailable,
                format!("upstream `{server}` is being removed"),
            ));
        }
        if !redial_committed_fields_eq(&snapshot, &entry.manifest_snapshot()) {
            permit.neutral();
            return Err(waygate_mcp::files::file_transfer_failure(
                waygate_mcp::files::FileTransferReason::TemporarilyUnavailable,
                format!(
                    "upstream `{server}` connection shape or identity changed during file \
                     request setup — retry the request"
                ),
            ));
        }

        let isolation = lane.isolation;
        let (result, network_destination, cleartext_control_plane) = match isolation {
            SessionIsolation::PerCall => {
                let cell = entry.forwards_identity.then(IdentityCell::new);
                if let (Some(cell), Some(context)) = (cell.as_ref(), identity_context) {
                    cell.set(context);
                }
                let connected = match transport::connect_with_destination(
                    &snapshot,
                    self.issuer.as_ref(),
                    cell.as_ref(),
                    self.exchange.as_ref(),
                    conn.http_client.as_ref(),
                )
                .await
                {
                    Ok(dialed) => dialed.finish_dial(),
                    Err(error) => {
                        permit.failure();
                        entry.record_runtime_failure(UpstreamErrorClass::from_dial_error(&error));
                        // Dial errors can carry the configured upstream URL,
                        // certificate paths, or handshake detail; the caller
                        // receives only the bounded failure while the detail
                        // stays in the gateway log.
                        tracing::warn!(
                            %server,
                            %error,
                            "upstream file-session dial failed"
                        );
                        return Err(waygate_mcp::files::file_transfer_failure(
                            waygate_mcp::files::FileTransferReason::TransferFailed,
                            format!("upstream `{server}` file session could not be established"),
                        ));
                    }
                };
                let transport::ConnectedService {
                    service,
                    network_destination,
                    cleartext_control_plane,
                    ..
                } = connected;
                if let Err(error) = self
                    .ensure_file_upload_contract_current(
                        &entry,
                        &snapshot,
                        conn,
                        server,
                        principal,
                        admitted_tool,
                    )
                    .await
                {
                    permit.neutral();
                    let _ = service.cancel().await;
                    return Err(error);
                }
                let response = match self.call_timeout_for(&snapshot) {
                    Some(timeout) => {
                        match tokio::time::timeout(
                            timeout,
                            send_file_authorization(&service, &request, cleartext_control_plane),
                        )
                        .await
                        {
                            Ok(response) => response,
                            Err(_) => {
                                permit.failure();
                                entry.record_runtime_failure(UpstreamErrorClass::Timeout);
                                return Err(waygate_mcp::files::file_transfer_failure(
                                    waygate_mcp::files::FileTransferReason::TransferFailed,
                                    format!(
                                        "upstream `{server}` file authorization timed out after \
                                         {}s",
                                        timeout.as_secs()
                                    ),
                                ));
                            }
                        }
                    }
                    None => {
                        send_file_authorization(&service, &request, cleartext_control_plane).await
                    }
                };
                let _ = service.cancel().await;
                (response, network_destination, cleartext_control_plane)
            }
            SessionIsolation::Reuse => {
                if let Err(error) = self
                    .ensure_file_upload_contract_current(
                        &entry,
                        &snapshot,
                        conn,
                        server,
                        principal,
                        admitted_tool,
                    )
                    .await
                {
                    permit.neutral();
                    return Err(error);
                }
                let _cell_guard = match (conn.identity_cell.as_ref(), identity_context) {
                    (Some(cell), Some(context)) => {
                        cell.set(context);
                        Some(CellClearGuard { cell: cell.clone() })
                    }
                    _ => None,
                };
                let response = match self.call_timeout_for(&snapshot) {
                    Some(timeout) => {
                        match tokio::time::timeout(
                            timeout,
                            send_file_authorization(
                                &conn.client,
                                &request,
                                conn.cleartext_control_plane,
                            ),
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
                                return Err(waygate_mcp::files::file_transfer_failure(
                                    waygate_mcp::files::FileTransferReason::TransferFailed,
                                    format!(
                                        "upstream `{server}` file authorization timed out after \
                                         {}s",
                                        timeout.as_secs()
                                    ),
                                ));
                            }
                        }
                    }
                    None => {
                        send_file_authorization(
                            &conn.client,
                            &request,
                            conn.cleartext_control_plane,
                        )
                        .await
                    }
                };
                (
                    response,
                    conn.network_destination.clone(),
                    conn.cleartext_control_plane,
                )
            }
        };
        match result {
            Ok(response) => {
                let recovered = permit.success();
                drop(conn_guard);
                self.settle_probe_recovery(server, &entry, recovered).await;
                let current = entry.manifest_snapshot();
                if !redial_committed_fields_eq(&snapshot, &current) {
                    return Err(waygate_mcp::files::file_transfer_failure(
                        waygate_mcp::files::FileTransferReason::TemporarilyUnavailable,
                        format!(
                            "upstream `{server}` connection changed during file authorization — \
                             retry the request"
                        ),
                    ));
                }
                let pinned_network_addresses = private_file_destination_addresses(
                    &current,
                    response.descriptor_url().unwrap_or(""),
                    network_destination.as_ref(),
                );
                let network = if matches!(current.transport, Transport::Stdio) {
                    waygate_mcp::files::FileTransferNetwork::Local
                } else if pinned_network_addresses.is_empty() {
                    waygate_mcp::files::FileTransferNetwork::Public
                } else {
                    waygate_mcp::files::FileTransferNetwork::Pinned {
                        addresses: pinned_network_addresses,
                        cleartext_control_plane,
                    }
                };
                let binding = tasks::binding(&snapshot).ok_or_else(|| {
                    waygate_mcp::files::file_transfer_failure(
                        waygate_mcp::files::FileTransferReason::TransferFailed,
                        "upstream configuration identity is unavailable",
                    )
                })?;
                Ok((response, network, binding))
            }
            Err(ServiceError::McpError(error)) => {
                let recovered = permit.success();
                drop(conn_guard);
                self.settle_probe_recovery(server, &entry, recovered).await;
                // The upstream's own authorization error may carry
                // provider-private identifiers, signed URLs, or transfer
                // detail, so neither the downstream response nor the gateway
                // log receives its message. An explicit allowlist preserves
                // typed recovery categories, limits and retry guidance only.
                // The code is still a capability signal: method-not-found
                // means the upstream has no native file transfer, which the
                // caller must be able to distinguish from a failed attempt.
                tracing::warn!(
                    server = %server,
                    code = ?error.code,
                    "upstream file authorization refused"
                );
                Err(classify_authorization_error(server, &error))
            }
            Err(error) => {
                permit.failure();
                drop(conn_guard);
                if matches!(isolation, SessionIsolation::Reuse) {
                    self.mark_slot_down(server, &entry, lane.slot, UpstreamErrorClass::Transport)
                        .await;
                } else {
                    entry.record_runtime_failure(UpstreamErrorClass::Transport);
                }
                Err(waygate_mcp::files::file_transfer_failure(
                    waygate_mcp::files::FileTransferReason::TransferFailed,
                    format!("upstream `{server}` file authorization: {error}"),
                ))
            }
        }
    }

    pub(super) async fn manage_upload(
        &self,
        server: &str,
        request: waygate_mcp::files::UploadRecoveryRequest,
        principal: Option<&Principal>,
    ) -> Result<Value, McpError> {
        let (response, _, _) = self
            .authorize_file_transfer_inner(
                server,
                FileAuthorizationRequest::Lifecycle {
                    uri: request.uri,
                    cancel: request.cancel,
                },
                principal,
                Some((&request.tool, &request.contract, Some(&request.binding))),
            )
            .await?;
        let FileAuthorizationResponse::Lifecycle(value) = response else {
            unreachable!("lifecycle response")
        };
        Ok(value)
    }

    pub(super) async fn authorize_download(
        &self,
        server: &str,
        params: AuthorizeDownloadParams,
        principal: Option<&Principal>,
    ) -> Result<waygate_mcp::files::AuthorizedFileDownload, McpError> {
        let (response, network, _) = self
            .authorize_file_transfer_inner(
                server,
                FileAuthorizationRequest::Download(params),
                principal,
                None,
            )
            .await?;
        let FileAuthorizationResponse::Download(response) = response else {
            unreachable!("download authorization returned an upload response")
        };
        Ok(waygate_mcp::files::AuthorizedFileDownload { response, network })
    }

    pub(super) async fn authorize_upload(
        &self,
        server: &str,
        tool_name: &str,
        params: AuthorizeUploadParams,
        principal: Option<&Principal>,
        admitted: &InvocationContractIdentity,
    ) -> Result<waygate_mcp::files::AuthorizedFileUpload, McpError> {
        let (response, network, binding) = self
            .authorize_file_transfer_inner(
                server,
                FileAuthorizationRequest::Upload(params),
                principal,
                Some((tool_name, admitted, None)),
            )
            .await?;
        let FileAuthorizationResponse::Upload(response) = response else {
            unreachable!("upload authorization returned a download response")
        };
        Ok(waygate_mcp::files::AuthorizedFileUpload {
            response,
            network,
            binding,
        })
    }
}

/// Preserve only bounded, typed recovery metadata. Upstream prose, paths,
/// identifiers and transfer credentials never cross this boundary.
fn classify_authorization_error(server: &str, error: &McpError) -> McpError {
    let Some(data) = error.data.as_ref().and_then(Value::as_object) else {
        return classify_refused_authorization(server, error.code);
    };
    let Some(category) = data.get("error").and_then(Value::as_str).filter(|v| {
        matches!(
            *v,
            "temporarily_unavailable"
                | "invalid_file_input"
                | "file_unavailable"
                | "completion_unknown"
                | "quota_exhausted"
                | "integrity_mismatch"
                | "policy_violation"
        )
    }) else {
        return classify_refused_authorization(server, error.code);
    };
    let mut safe = Map::new();
    safe.insert("error".into(), category.into());
    if let Some(reason) = data.get("reason").and_then(Value::as_str).filter(|value| {
        waygate_invocation::file_recovery::FileRecoveryReason::parse(value).is_some()
    }) {
        safe.insert("reason".into(), reason.into());
    }
    if let Some(stage) = data.get("stage").and_then(Value::as_str).filter(|value| {
        waygate_invocation::file_recovery::FileRecoveryStage::parse(value).is_some()
    }) {
        safe.insert("stage".into(), stage.into());
    }
    for field in ["retryable", "publication_attempted"] {
        if let Some(value) = data.get(field).and_then(Value::as_bool) {
            safe.insert(field.into(), value.into());
        }
    }
    for field in ["retry_after_seconds", "max_bytes", "capacity"] {
        if let Some(value) = data.get(field).and_then(Value::as_u64) {
            safe.insert(field.into(), value.into());
        }
    }
    let message = match category {
        "temporarily_unavailable" => format!("upstream `{server}` upload capacity is unavailable; retain the gateway file URI and follow retry guidance"),
        "invalid_file_input" => format!("upstream `{server}` refused the uploaded file; correct the declared file constraints"),
        "completion_unknown" => format!("upstream `{server}` upload publication outcome is unknown; inspect delivery status before retrying"),
        _ => format!("upstream `{server}` refused file authorization ({category})"),
    };
    McpError::new(error.code, message, Some(Value::Object(safe)))
}

/// The bounded downstream shape of an upstream's own authorization refusal.
/// Method-not-found is the one code that is a capability signal — the
/// upstream has no native file transfer — and it must stay distinguishable
/// from a failed attempt. Only the code informs the branch; the upstream's
/// message is never carried.
fn classify_refused_authorization(server: &str, code: rmcp::model::ErrorCode) -> McpError {
    if code == rmcp::model::ErrorCode::METHOD_NOT_FOUND {
        waygate_mcp::files::file_transfer_failure(
            waygate_mcp::files::FileTransferReason::NotEnabled,
            format!("upstream `{server}` does not support native file transfer"),
        )
    } else {
        waygate_mcp::files::file_transfer_failure(
            waygate_mcp::files::FileTransferReason::TransferFailed,
            format!("upstream `{server}` file authorization failed"),
        )
    }
}

fn private_file_destination_addresses(
    manifest: &UpstreamManifest,
    transfer_url: &str,
    network_destination: Option<&transport::PinnedNetworkDestination>,
) -> Vec<std::net::IpAddr> {
    if matches!(manifest.transport, Transport::Stdio) {
        // A stdio upstream is already executable code inside the gateway's
        // network boundary. Blocking its local file endpoint would remove a
        // useful path without containing an authority it does not already hold.
        return Vec::new();
    }
    let Some(network_destination) = network_destination else {
        return Vec::new();
    };
    let Ok(transfer) = url::Url::parse(transfer_url) else {
        return Vec::new();
    };
    // The file service may use a different HTTPS port from the MCP endpoint.
    // The upstream already controls this host and supplies the transfer
    // headers; the gateway does not add caller or gateway credentials.
    if transfer
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(network_destination.host()))
    {
        network_destination.addresses().to_vec()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_capability_advertises_http_only_for_a_cleartext_control_plane() {
        let protected = client_capability_meta(
            &ClientCapabilities::default(),
            waygate_mcp::files::FileOperation::Download,
            false,
        );
        let cleartext = client_capability_meta(
            &ClientCapabilities::default(),
            waygate_mcp::files::FileOperation::Download,
            true,
        );

        assert_eq!(
            protected.0 .0[waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY]["files"]["transports"],
            serde_json::json!(["https"])
        );
        assert_eq!(
            cleartext.0 .0[waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY]["files"]["transports"],
            serde_json::json!(["https", "http"])
        );
    }

    #[test]
    fn upload_refusal_retains_recovery_facts_without_private_detail() {
        let error = McpError::invalid_params(
            "private upstream message with signed transfer authority",
            Some(serde_json::json!({
                "error":"temporarily_unavailable","reason":"upload_capacity_exhausted","stage":"authorize_upload",
                "retryable":true,"retry_after_seconds":12,"publication_attempted":false,"capacity":20,
                "uri":"mcp-file://private/hidden","authorization":"hidden","max_bytes":"not a number"
            })),
        );
        let projected = classify_authorization_error("printable", &error);
        assert_eq!(
            projected.data,
            Some(
                serde_json::json!({"error":"temporarily_unavailable","reason":"upload_capacity_exhausted","stage":"authorize_upload","retryable":true,"retry_after_seconds":12,"publication_attempted":false,"capacity":20})
            )
        );
        assert!(!projected.to_string().contains("signed transfer"));
        let error = McpError::invalid_params(
            "private",
            Some(
                serde_json::json!({"error":"invalid_file_input","reason":"private-value","stage":"private-path"}),
            ),
        );
        assert_eq!(
            classify_authorization_error("printable", &error).data,
            Some(serde_json::json!({"error":"invalid_file_input"}))
        );
    }

    #[test]
    fn upstream_method_not_found_surfaces_as_missing_native_support() {
        let unsupported =
            classify_refused_authorization("printable", rmcp::model::ErrorCode::METHOD_NOT_FOUND);
        assert!(unsupported
            .to_string()
            .contains("does not support native file transfer"));
        assert_eq!(
            unsupported.data.expect("bounded category")["error"],
            "not_enabled"
        );

        let failed =
            classify_refused_authorization("printable", rmcp::model::ErrorCode::INVALID_REQUEST);
        assert!(failed.to_string().contains("file authorization failed"));
        assert_eq!(
            failed.data.expect("bounded category")["error"],
            "transfer_failed"
        );
    }

    #[test]
    fn private_file_destination_is_limited_to_the_upstream_host() {
        let manifest: UpstreamManifest = serde_yaml::from_str(
            "name: printable\ntransport: http\ntrust: internal\nurl: http://files.internal:3000/mcp\n",
        )
        .unwrap();
        let destination = transport::PinnedNetworkDestination::new(
            "files.internal".to_owned(),
            3000,
            vec!["10.0.0.8".parse().unwrap()],
        );
        assert_eq!(
            private_file_destination_addresses(
                &manifest,
                "https://files.internal:8443/output",
                Some(&destination),
            ),
            vec!["10.0.0.8".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(private_file_destination_addresses(
            &manifest,
            "https://metadata.internal/output",
            Some(&destination),
        )
        .is_empty());
    }

    #[test]
    fn stdio_upstream_keeps_its_existing_local_network_access() {
        let manifest: UpstreamManifest =
            serde_yaml::from_str("name: printable\ntransport: stdio\ncommand: [printable]\n")
                .unwrap();
        assert!(private_file_destination_addresses(
            &manifest,
            "https://127.0.0.1:8443/output",
            None,
        )
        .is_empty());
    }
}
