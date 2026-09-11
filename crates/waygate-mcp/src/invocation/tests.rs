//! Unit tests for the invocation pipeline, split from `mod.rs` so the
//! pipeline module stays within its god-file ceiling.

#[cfg(test)]
mod schema_cache_service_tests {
    use super::super::*;
    use crate::audit::NullSink;
    use crate::authz::AllowAllGate;
    use crate::catalog::UpstreamCatalog;

    struct NeverCalledCatalog;

    #[async_trait::async_trait]
    impl UpstreamCatalog for NeverCalledCatalog {
        async fn list_servers(&self) -> Vec<String> {
            Vec::new()
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<rmcp::model::Tool>, ErrorData> {
            unreachable!("cache-sharing test never queries the catalog")
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<serde_json::Map<String, serde_json::Value>>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, ErrorData> {
            unreachable!("cache-sharing test never dispatches")
        }
    }

    #[test]
    fn independently_built_services_reuse_an_injected_process_cache() {
        let cache = SchemaValidatorCache::shared();
        let build = || {
            DefaultInvocationService::new(
                Arc::new(NeverCalledCatalog),
                Arc::new(AllowAllGate),
                Arc::new(NullSink),
            )
            .with_schema_validator_cache(Arc::clone(&cache))
        };
        let first_service = build();
        let second_service = build();
        let tool_id = uuid::Uuid::new_v4();
        let schema = serde_json::json!({"type": "integer"});

        let CachedValidator::Ready(first) =
            first_service
                .schema_validator_cache
                .get_or_compile(tool_id, "catalog-hash", &schema)
        else {
            panic!("test schema must compile")
        };
        let CachedValidator::Ready(second) =
            second_service
                .schema_validator_cache
                .get_or_compile(tool_id, "catalog-hash", &schema)
        else {
            panic!("test schema must compile")
        };

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(cache.compilation_count(), 1);
    }
}

#[cfg(test)]
mod retained_response_pipeline_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use rmcp::model::{
        CallToolResult, ErrorData, ReadResourceRequestParams, ReadResourceResult, ResourceContents,
    };
    use serde_json::json;

    use super::super::*;
    use crate::audit::{AuditOutcome, InMemorySink, NullSink};
    use crate::authz::{AllowAllGate, AuthzGate, AuthzVerdict};
    use crate::catalog::UpstreamCatalog;

    #[derive(Default)]
    struct RetainedFiles {
        body: std::sync::Mutex<Vec<u8>>,
        published: AtomicUsize,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl crate::files::FileOutputProcessor for RetainedFiles {
        fn retained_response_max_bytes(&self) -> Option<usize> {
            Some(1024 * 1024 * 1024)
        }

        async fn prepare_retained(
            &self,
            _context: crate::files::FileOutputContext,
            body: crate::files::RetainedFileBody,
        ) -> Result<crate::files::PreparedRetainedFile, ErrorData> {
            if self.fail {
                return Err(ErrorData::internal_error("storage unavailable", None));
            }
            *self.body.lock().unwrap() = body.bytes;
            Ok(crate::files::PreparedRetainedFile {
                file: crate::files::FileValue {
                    uri: "mcp-file://gateway/00000000-0000-4000-8000-000000000001".into(),
                    name: None,
                    mime_type: Some(body.media_type),
                    size: Some(self.body.lock().unwrap().len() as u64),
                    digest: None,
                },
                batch_id: "test-batch".into(),
            })
        }

        async fn prepare(
            &self,
            _context: crate::files::FileOutputContext,
            result: CallToolResult,
        ) -> Result<crate::files::PreparedFileOutput, ErrorData> {
            Ok(crate::files::PreparedFileOutput {
                result,
                batch_id: None,
                file_count: 0,
            })
        }
        async fn publish(&self, _batch: &str, files: usize) -> Result<(), ErrorData> {
            self.published.fetch_add(files, Ordering::SeqCst);
            Ok(())
        }
        async fn discard(&self, _batch: &str) {}
    }

    #[tokio::test]
    async fn direct_retained_response_publishes_complete_bytes_without_inlining() {
        let (service, catalog) = service();
        let files = Arc::new(RetainedFiles::default());
        let service = service.with_file_output_processor(Some(files.clone()));
        let response = service
            .invoke(None, InvocationRequest::new("connector", "download"))
            .await
            .expect("direct file delivery");
        let InvocationResponse::Unary(result) = response else {
            panic!("unary result")
        };
        assert_eq!(*files.body.lock().unwrap(), BODY.as_bytes());
        assert_eq!(files.published.load(Ordering::SeqCst), 1);
        assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
        assert!(result
            .structured_content
            .as_ref()
            .unwrap()
            .get("data")
            .is_none());
        assert_eq!(
            result.meta.as_ref().unwrap()[crate::files::RETAINED_DELIVERY_META_KEY]
                ["delivery_status"],
            "file"
        );
        assert!(!serde_json::to_string(&result).unwrap().contains(BODY));
    }

    #[tokio::test]
    async fn serialized_response_over_runtime_budget_uses_file_delivery() {
        let (service, catalog) = service();
        let files = Arc::new(RetainedFiles::default());
        let service = service.with_file_output_processor(Some(files.clone()));
        let response = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(BODY.len()),
            )
            .await
            .expect("serialized envelope falls back to storage");
        let InvocationResponse::Unary(result) = response else {
            panic!("unary result")
        };
        assert_eq!(
            result.meta.as_ref().unwrap()[crate::files::RETAINED_DELIVERY_META_KEY]
                ["delivery_status"],
            "file"
        );
        assert_eq!(*files.body.lock().unwrap(), BODY.as_bytes());
        assert_eq!(files.published.load(Ordering::SeqCst), 1);
        assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mutation_attachment_failure_preserves_applied_outcome() {
        let catalog = Arc::new(RetainedCatalog {
            side_effects: true,
            ..Default::default()
        });
        let files = Arc::new(RetainedFiles {
            fail: true,
            ..Default::default()
        });
        let service = DefaultInvocationService::new(
            catalog.clone(),
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        )
        .with_file_output_processor(Some(files.clone()));
        let response = service
            .invoke(None, InvocationRequest::new("connector", "mutate"))
            .await
            .expect("applied operation remains successful");
        let InvocationResponse::Unary(result) = response else {
            panic!("unary result")
        };
        let delivery = &result.meta.as_ref().unwrap()[crate::files::RETAINED_DELIVERY_META_KEY];
        assert_eq!(delivery["operation_status"], "succeeded");
        assert_eq!(delivery["delivery_status"], "unavailable");
        assert_eq!(delivery["retry_operation"], false);
        assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
        assert_eq!(files.published.load(Ordering::SeqCst), 0);
    }

    const URI: &str = "connector-response:/downloadLog/0";
    #[tokio::test]
    async fn retained_file_delivery_validates_the_body_before_publication() {
        for side_effects in [false, true] {
            for valid in [false, true] {
                let catalog = Arc::new(RetainedCatalog {
                    side_effects,
                    output_schema: Some(json!({"type":"object", "required":["data"],
                        "properties":{"data":{"const":if valid { BODY } else { "different body" }}}})),
                    ..Default::default()
                });
                let files = Arc::new(RetainedFiles::default());
                let sink = Arc::new(InMemorySink::default());
                let service = DefaultInvocationService::new(
                    catalog.clone(),
                    Arc::new(AllowAllGate),
                    sink.clone(),
                )
                .with_file_output_processor(Some(files.clone()));
                let response = service
                    .invoke(None, InvocationRequest::new("connector", "download"))
                    .await;
                assert_eq!(files.published.load(Ordering::SeqCst), usize::from(valid));
                assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
                if valid {
                    let InvocationResponse::Unary(result) = response.unwrap() else {
                        panic!("unary result")
                    };
                    let published_schema = crate::retained_delivery::output_schema(
                        catalog.output_schema.as_ref().unwrap().as_object().unwrap(),
                    );
                    let validator = jsonschema::validator_for(&json!(published_schema)).unwrap();
                    assert!(validator.is_valid(result.structured_content.as_ref().unwrap()));
                } else {
                    assert!(
                        files.body.lock().unwrap().is_empty(),
                        "invalid body was not staged"
                    );
                    if side_effects {
                        let InvocationResponse::Unary(result) = response.unwrap() else {
                            panic!("unary")
                        };
                        let delivery = &result.meta.as_ref().unwrap()
                            [crate::files::RETAINED_DELIVERY_META_KEY];
                        assert_eq!(delivery["delivery_status"], "unavailable");
                        assert_eq!(delivery["retry_operation"], false);
                        let rows = sink.snapshot().await;
                        assert!(rows
                            .iter()
                            .any(|r| r.action == "ResponseDelivery"
                                && r.outcome == AuditOutcome::Denied));
                        assert!(rows
                            .iter()
                            .any(|r| r.action == "CallTool" && r.outcome == AuditOutcome::Success));
                        assert!(!rows
                            .iter()
                            .any(|r| r.action == "CallTool" && r.outcome == AuditOutcome::Denied));
                    } else {
                        assert!(matches!(
                            response,
                            Err(InvocationError::OutputSchemaViolation { .. })
                        ));
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn retained_mutation_delivery_errors_keep_actionable_categories() {
        for (missing_resource, missing_envelope_field, storage, expected) in [
            (false, None, false, "retained_response_storage_unavailable"),
            (true, None, true, "retained_response_resource_unavailable"),
            (
                false,
                Some("media_type"),
                true,
                "retained_response_invalid_envelope",
            ),
        ] {
            let catalog = Arc::new(RetainedCatalog {
                side_effects: true,
                missing_resource,
                missing_envelope_field,
                ..Default::default()
            });
            let mut service =
                DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), Arc::new(NullSink));
            if storage {
                service =
                    service.with_file_output_processor(Some(Arc::new(RetainedFiles::default())));
            }
            let InvocationResponse::Unary(result) = service
                .invoke(None, InvocationRequest::new("connector", "mutate"))
                .await
                .unwrap()
            else {
                panic!("unary")
            };
            let delivery = &result.meta.as_ref().unwrap()[crate::files::RETAINED_DELIVERY_META_KEY];
            assert_eq!(delivery["error"], expected);
            assert_eq!(delivery["operation_status"], "succeeded");
            assert_eq!(delivery["retry_operation"], false);
        }
    }

    const CHANGED_URI: &str = "connector-response:/downloadLog/changed";
    #[tokio::test]
    async fn retained_transport_failure_remains_identifiable_for_reads_and_mutations() {
        for side_effects in [false, true] {
            let catalog = Arc::new(RetainedCatalog {
                side_effects,
                unsupported_transport: true,
                ..Default::default()
            });
            let service =
                DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), Arc::new(NullSink))
                    .with_file_output_processor(Some(Arc::new(RetainedFiles::default())));
            let response = service
                .invoke(None, InvocationRequest::new("connector", "download"))
                .await;
            if side_effects {
                let InvocationResponse::Unary(result) = response.unwrap() else {
                    panic!("unary")
                };
                let delivery =
                    &result.meta.as_ref().unwrap()[crate::files::RETAINED_DELIVERY_META_KEY];
                assert_eq!(delivery["error"], "bounded_resource_read_unsupported");
                assert_eq!(delivery["retry_operation"], false);
            } else {
                let Err(InvocationError::Upstream(error)) = response else {
                    panic!("transport refusal")
                };
                assert_eq!(
                    error.data.unwrap()["error"],
                    "bounded_resource_read_unsupported"
                );
            }
        }
    }

    #[tokio::test]
    async fn retained_delivery_records_only_forwarded_redactions() {
        for missing_resource in [false, true] {
            let catalog = Arc::new(RetainedCatalog {
                side_effects: true,
                missing_resource,
                ..Default::default()
            });
            let sink = Arc::new(InMemorySink::default());
            let service =
                DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), sink.clone())
                    .with_file_output_processor(Some(Arc::new(RetainedFiles {
                        fail: true,
                        ..Default::default()
                    })))
                    .with_inspectors(vec![Arc::new(ReplaceBody)]);
            let InvocationResponse::Unary(result) = service
                .invoke(None, InvocationRequest::new("connector", "mutate"))
                .await
                .unwrap()
            else {
                panic!("unary")
            };
            assert_eq!(
                result.meta.as_ref().unwrap()[crate::files::RETAINED_DELIVERY_META_KEY]
                    ["delivery_status"],
                "unavailable"
            );
            let forwarded = result
                .structured_content
                .as_ref()
                .and_then(|root| root.get("data"))
                == Some(&json!("withheld"));
            assert_eq!(forwarded, missing_resource);
            let redaction_recorded = sink.snapshot().await.iter().any(|row| {
                row.reason.as_deref().is_some_and(|reason| {
                    reason.contains("response inspector `replace-body` redacted")
                })
            });
            assert_eq!(redaction_recorded, forwarded);
        }
    }

    #[tokio::test]
    async fn retained_file_disk_quota_does_not_authorize_unbounded_recovery() {
        let catalog = Arc::new(RetainedCatalog {
            declared_bytes: Some(128 * 1024 * 1024),
            ..Default::default()
        });
        let service = DefaultInvocationService::new(
            catalog.clone(),
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        )
        .with_file_output_processor(Some(Arc::new(RetainedFiles::default())));
        let error = service
            .invoke(None, InvocationRequest::new("connector", "download"))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            InvocationError::ResponseMaterializationLimit { .. }
        ));
        assert_eq!(
            catalog.reads.load(Ordering::SeqCst),
            0,
            "refuse before allocating the resource response"
        );
    }

    struct ReplaceBody;

    #[async_trait::async_trait]
    impl crate::inspection::Inspector for ReplaceBody {
        fn name(&self) -> &'static str {
            "replace-body"
        }
        async fn inspect(
            &self,
            _ctx: &crate::inspection::InspectionContext<'_>,
            result: &CallToolResult,
        ) -> crate::inspection::Decision {
            let mut redacted = result.clone();
            redacted.structured_content.as_mut().unwrap()["data"] = json!("withheld");
            crate::inspection::Decision::Redact {
                redacted,
                findings_count: 1,
            }
        }
    }

    #[tokio::test]
    async fn retained_file_metadata_describes_the_inspected_replacement() {
        let (service, _) = service();
        let files = Arc::new(RetainedFiles::default());
        let service = service
            .with_file_output_processor(Some(files.clone()))
            .with_inspectors(vec![Arc::new(ReplaceBody)]);
        let InvocationResponse::Unary(result) = service
            .invoke(None, InvocationRequest::new("connector", "download"))
            .await
            .unwrap()
        else {
            panic!("unary")
        };
        let bytes = files.body.lock().unwrap().clone();
        assert_eq!(bytes, b"withheld");
        assert_eq!(
            result.structured_content.as_ref().unwrap()["payload"]["bytes"],
            bytes.len()
        );
        assert_eq!(
            result.meta.as_ref().unwrap()[crate::files::RETAINED_DELIVERY_META_KEY]["file"]["size"],
            bytes.len()
        );
    }

    const BODY: &str = "failure here";

    struct RetainedCatalog {
        reads: AtomicUsize,
        declared_bytes: Option<u64>,
        output_schema: Option<serde_json::Value>,
        missing_envelope_field: Option<&'static str>,
        resource_body: &'static str,
        side_effects: bool,
        refuse_for_materialization_limit: bool,
        missing_resource: bool,
        unsupported_transport: bool,
        resource_uri: &'static str,
        retained_uri: &'static str,
        resource_claims: Vec<crate::catalog::ResourceClaim>,
        fleet_resource_claims: Vec<(String, crate::catalog::ResourceClaim)>,
    }

    impl Default for RetainedCatalog {
        fn default() -> Self {
            Self {
                reads: AtomicUsize::new(0),
                declared_bytes: None,
                output_schema: None,
                missing_envelope_field: None,
                resource_body: BODY,
                side_effects: false,
                refuse_for_materialization_limit: false,
                missing_resource: false,
                unsupported_transport: false,
                resource_uri: URI,
                retained_uri: URI,
                resource_claims: Vec::new(),
                fleet_resource_claims: Vec::new(),
            }
        }
    }

    struct BodyInspector;

    struct RejectAttachment;

    #[async_trait::async_trait]
    impl crate::inspection::Inspector for RejectAttachment {
        fn name(&self) -> &'static str {
            "reject-attachment"
        }
        async fn inspect(
            &self,
            _ctx: &crate::inspection::InspectionContext<'_>,
            _result: &CallToolResult,
        ) -> crate::inspection::Decision {
            crate::inspection::Decision::Block {
                reason: "attachment withheld".into(),
            }
        }
    }

    #[tokio::test]
    async fn recovery_and_inspection_failure_cannot_erase_an_applied_mutation() {
        for missing_resource in [false, true] {
            let catalog = Arc::new(RetainedCatalog {
                side_effects: true,
                missing_resource,
                ..Default::default()
            });
            let sink = Arc::new(InMemorySink::default());
            let service = DefaultInvocationService::new(
                catalog.clone(),
                Arc::new(AllowAllGate),
                sink.clone(),
            )
            .with_inspectors(vec![Arc::new(RejectAttachment)]);
            let response = service
                .invoke(
                    None,
                    InvocationRequest::new("connector", "mutate")
                        .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                        .with_response_materialization_limit(1024),
                )
                .await
                .expect("confirmed mutation remains successful");
            let InvocationResponse::Unary(result) = response else {
                panic!("unary result")
            };
            let delivery = &result.meta.as_ref().unwrap()[crate::files::RETAINED_DELIVERY_META_KEY];
            assert_eq!(delivery["operation_status"], "succeeded");
            assert_eq!(delivery["delivery_status"], "unavailable");
            assert_eq!(delivery["retry_operation"], false);
            assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
            assert_eq!(
                result.structured_content.as_ref().unwrap(),
                &json!({"_gateway_delivery": delivery}),
                "only delivery status is forwarded, without the rejected attachment"
            );
            let rows = sink.snapshot().await;
            assert!(rows
                .iter()
                .any(|r| r.action == "ResponseDelivery" && r.outcome == AuditOutcome::Denied));
            assert!(rows
                .iter()
                .any(|r| r.action == "CallTool" && r.outcome == AuditOutcome::Success));
            assert!(!rows
                .iter()
                .any(|r| r.action == "CallTool" && r.outcome == AuditOutcome::Denied));
        }
    }

    struct DenyResourceGate;

    struct DenyDiscoveryGate;

    struct RequireHighResourceGate;

    #[async_trait::async_trait]
    impl AuthzGate for DenyResourceGate {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_resource_read(
            &self,
            _principal: &Principal,
            _server: &str,
            _uri: &str,
            _risk: crate::protocol::RiskTier,
        ) -> AuthzVerdict {
            AuthzVerdict::Deny {
                reason: "resource read denied".to_owned(),
                policy_ids: vec!["deny-resource".to_owned()],
                reasons: vec!["resource policy denied access".to_owned()],
            }
        }

        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            AuthzVerdict::Allow {
                policy_ids: Vec::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl AuthzGate for DenyDiscoveryGate {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            false
        }

        async fn authorize_resource_read(
            &self,
            _principal: &Principal,
            _server: &str,
            _uri: &str,
            _risk: crate::protocol::RiskTier,
        ) -> AuthzVerdict {
            AuthzVerdict::Allow {
                policy_ids: Vec::new(),
            }
        }

        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            AuthzVerdict::Allow {
                policy_ids: Vec::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl AuthzGate for RequireHighResourceGate {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_resource_read(
            &self,
            _principal: &Principal,
            _server: &str,
            _uri: &str,
            risk: crate::protocol::RiskTier,
        ) -> AuthzVerdict {
            if risk == crate::protocol::RiskTier::High {
                AuthzVerdict::StepUpRequired {
                    required_scope: "mcp:invoke:high".to_owned(),
                    reason: "high-risk retained resource requires step-up".to_owned(),
                    policy_ids: vec!["step-up-high-resource".to_owned()],
                }
            } else {
                AuthzVerdict::Allow {
                    policy_ids: vec!["permit-low-resource".to_owned()],
                }
            }
        }

        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            AuthzVerdict::Allow {
                policy_ids: Vec::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::inspection::Inspector for BodyInspector {
        fn name(&self) -> &'static str {
            "retained-body"
        }

        async fn inspect(
            &self,
            _ctx: &crate::inspection::InspectionContext<'_>,
            result: &CallToolResult,
        ) -> crate::inspection::Decision {
            if serde_json::to_string(result).is_ok_and(|encoded| encoded.contains(BODY)) {
                crate::inspection::Decision::Block {
                    reason: "recovered body reached response inspection".to_owned(),
                }
            } else {
                crate::inspection::Decision::Pass
            }
        }
    }

    fn retained_result(uri: &str) -> CallToolResult {
        let mut result = CallToolResult::structured(json!({
            "content_type": "text/plain",
            "headers": {},
            "operation_id": "downloadLog",
            "payload": {
                "bytes": BODY.len(),
                "context_ceiling_bytes": 65_536,
                "inlined": false,
                "media_type": "text/plain",
                "reason": "above the context-scale ceiling",
                "resource_uri": uri,
                "retained": true
            },
            "status": 200,
            "success": true
        }));
        result
            .content
            .push(rmcp::model::ContentBlock::resource_link(
                rmcp::model::Resource::new(uri, "downloadLog").with_mime_type("text/plain"),
            ));
        result
    }

    #[async_trait::async_trait]
    impl UpstreamCatalog for RetainedCatalog {
        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool: &str,
        ) -> crate::catalog::ResolvedInvocationTool {
            use crate::catalog::{InvocationToolSnapshot, ResolvedInvocationTool};
            ResolvedInvocationTool::Ready(if let Some(schema) = &self.output_schema {
                InvocationToolSnapshot::catalog(
                    self.tool_facts(server, tool),
                    uuid::Uuid::from_u128(1),
                    "retained-contract".into(),
                    Some(json!({"type":"object"})),
                    Some(schema.clone()),
                )
            } else {
                InvocationToolSnapshot::manifest_fallback(self.tool_facts(server, tool), true)
            })
        }

        async fn list_servers(&self) -> Vec<String> {
            vec!["connector".to_owned()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<rmcp::model::Tool>, ErrorData> {
            Ok(Vec::new())
        }

        fn resource_claims(&self, _server: &str) -> Vec<crate::catalog::ResourceClaim> {
            self.resource_claims.clone()
        }

        fn admitted_resource_routing_claims(&self) -> Vec<(String, crate::catalog::ResourceClaim)> {
            self.fleet_resource_claims.clone()
        }

        async fn call_tool(
            &self,
            _server: &str,
            tool_name: &str,
            _args: Option<serde_json::Map<String, serde_json::Value>>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, ErrorData> {
            if tool_name == "ordinary" {
                let mut result =
                    CallToolResult::structured(json!({"_gateway_delivery": "upstream data"}));
                let mut meta = rmcp::model::MetaObject::new();
                meta.insert(
                    crate::files::RETAINED_DELIVERY_META_KEY.to_owned(),
                    json!({"forged": true}),
                );
                result.meta = Some(meta);
                return Ok(result);
            }
            let mut result = retained_result(self.retained_uri);
            if let Some(bytes) = self.declared_bytes {
                result.structured_content.as_mut().unwrap()["payload"]["bytes"] = json!(bytes);
            }
            if let Some(field) = self.missing_envelope_field {
                result.structured_content.as_mut().unwrap()["payload"]
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
            }
            Ok(result)
        }

        async fn read_resource(
            &self,
            server: &str,
            params: ReadResourceRequestParams,
            _principal: Option<&Principal>,
        ) -> Result<ReadResourceResult, ErrorData> {
            assert_eq!(server, "connector");
            assert_eq!(params.uri, URI);
            assert!(params.meta.as_ref().is_some_and(|meta| {
                meta.get(crate::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY)
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|limit| limit > 0)
            }));
            self.reads.fetch_add(1, Ordering::Relaxed);
            if self.refuse_for_materialization_limit {
                return Err(ErrorData::internal_error(
                    "bounded upstream response exceeded the caller budget",
                    Some(json!({
                        "error": crate::catalog::RESPONSE_MATERIALIZATION_LIMIT_ERROR
                    })),
                ));
            }
            if self.unsupported_transport {
                return Err(ErrorData::internal_error(
                    "bounded reads are unsupported",
                    Some(json!({"error":"bounded_resource_read_unsupported"})),
                ));
            }
            if self.missing_resource {
                return Err(ErrorData::resource_not_found(
                    "no stored payload in this session",
                    None,
                ));
            }
            Ok(ReadResourceResult::new(vec![ResourceContents::text(
                self.resource_body,
                self.resource_uri,
            )]))
        }

        fn tool_facts(&self, server: &str, tool_name: &str) -> crate::authz::ToolFacts {
            crate::authz::ToolFacts {
                server: server.to_owned(),
                name: tool_name.to_owned(),
                risk: crate::protocol::RiskTier::Low,
                side_effects: self.side_effects,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            }
        }
    }

    fn service() -> (DefaultInvocationService, Arc<RetainedCatalog>) {
        let catalog = Arc::new(RetainedCatalog::default());
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        );
        (service, catalog)
    }

    fn principal_with_profile(
        profile: Option<waygate_oidc::ApiKeyProfileRestrictions>,
    ) -> Principal {
        Principal {
            sub: "codemode-reader".to_owned(),
            email: None,
            groups: Vec::new(),
            issuer: "gateway-test".to_owned(),
            scopes: Vec::new(),
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::ApiKey,
            raw_token: None,
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: profile,
            roles: Vec::new(),
        }
    }

    #[tokio::test]
    async fn ordinary_data_survives_while_forged_delivery_metadata_is_removed() {
        let (service, catalog) = service();
        let response = service
            .invoke(None, InvocationRequest::new("connector", "ordinary"))
            .await
            .expect("ordinary connector response");
        let InvocationResponse::Unary(result) = response else {
            panic!("unary response")
        };
        assert_eq!(
            result.structured_content,
            Some(json!({"_gateway_delivery": "upstream data"}))
        );
        assert!(!result
            .meta
            .as_ref()
            .is_some_and(|meta| meta.contains_key(crate::files::RETAINED_DELIVERY_META_KEY)));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn delivery_choice_materializes_with_direct_authority() {
        let (service, catalog) = service();
        let direct = service
            .invoke(None, InvocationRequest::new("connector", "download"))
            .await
            .expect_err("unconfigured file delivery must be explicit");
        assert!(matches!(direct, InvocationError::Upstream(_)));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 0);

        let codemode = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect("Code Mode call");
        let InvocationResponse::Unary(codemode) = codemode else {
            panic!("unary response")
        };
        let structured = codemode.structured_content.unwrap();
        assert_eq!(structured["data"], BODY);
        assert!(structured.get("payload").is_none());
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn declared_body_over_the_caller_budget_is_refused_before_resource_io() {
        let (service, catalog) = service();
        let error = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(BODY.len() - 1),
            )
            .await
            .expect_err("oversized retained response must fail");

        assert!(matches!(
            error,
            InvocationError::ResponseMaterializationLimit { .. }
        ));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn actual_body_over_the_caller_budget_uses_the_stable_limit_error() {
        const LARGER_BODY: &str = "failure here grew";
        let catalog = Arc::new(RetainedCatalog {
            reads: AtomicUsize::new(0),
            declared_bytes: None,
            output_schema: None,
            missing_envelope_field: None,
            resource_body: LARGER_BODY,
            side_effects: false,
            refuse_for_materialization_limit: false,
            missing_resource: false,
            unsupported_transport: false,
            resource_uri: URI,
            retained_uri: URI,
            resource_claims: Vec::new(),
            fleet_resource_claims: Vec::new(),
        });
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        );

        let error = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(BODY.len()),
            )
            .await
            .expect_err("actual oversized body must fail with the caller limit error");

        assert!(matches!(
            error,
            InvocationError::ResponseMaterializationLimit {
                minimum_response_bytes,
                limit_bytes,
                ..
            } if minimum_response_bytes == LARGER_BODY.len() as u64 && limit_bytes == BODY.len()
        ));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn predecode_transport_cap_uses_the_stable_limit_error() {
        let catalog = Arc::new(RetainedCatalog {
            reads: AtomicUsize::new(0),
            declared_bytes: None,
            output_schema: None,
            missing_envelope_field: None,
            resource_body: BODY,
            side_effects: false,
            refuse_for_materialization_limit: true,
            missing_resource: false,
            unsupported_transport: false,
            resource_uri: URI,
            retained_uri: URI,
            resource_claims: Vec::new(),
            fleet_resource_claims: Vec::new(),
        });
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        );

        let error = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("raw upstream response over the cap must use the stable limit error");

        assert!(matches!(
            error,
            InvocationError::ResponseMaterializationLimit {
                minimum_response_bytes: 1025,
                limit_bytes: 1024,
                ..
            }
        ));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn failed_recovery_identifies_the_operation_and_resource() {
        let catalog = Arc::new(RetainedCatalog {
            reads: AtomicUsize::new(0),
            declared_bytes: None,
            output_schema: None,
            missing_envelope_field: None,
            resource_body: BODY,
            side_effects: false,
            refuse_for_materialization_limit: false,
            missing_resource: true,
            unsupported_transport: false,
            resource_uri: URI,
            retained_uri: URI,
            resource_claims: Vec::new(),
            fleet_resource_claims: Vec::new(),
        });
        let sink = Arc::new(InMemorySink::default());
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            sink.clone(),
        );

        let error = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("a missing retained resource must fail with actionable identity");
        let InvocationError::Upstream(error) = error else {
            panic!("missing retained resource must remain an upstream failure")
        };
        assert!(error.message.contains("downloadLog"));
        assert!(error.message.contains(URI));
        assert_eq!(error.data.as_ref().unwrap()["operation_id"], "downloadLog");
        assert_eq!(error.data.as_ref().unwrap()["resource_uri"], URI);
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 1);
        let rows = sink.snapshot().await;
        let reason = rows
            .iter()
            .find(|row| row.outcome == AuditOutcome::ExecutionError)
            .and_then(|row| row.reason.as_deref())
            .expect("failed recovery must retain a sanitized audit reason");
        assert!(!reason.contains("downloadLog"));
        assert!(!reason.contains(URI));
    }

    #[tokio::test]
    async fn post_read_hydration_failure_preserves_recovery_identity() {
        let catalog = Arc::new(RetainedCatalog {
            resource_uri: CHANGED_URI,
            ..RetainedCatalog::default()
        });
        let sink = Arc::new(InMemorySink::default());
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            sink.clone(),
        );

        let error = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("changed resource identity must fail with actionable identity");
        let InvocationError::Upstream(error) = error else {
            panic!("hydration failure must remain an upstream failure")
        };
        assert!(error.message.contains("downloadLog"));
        assert!(error.message.contains(URI));
        assert_eq!(error.data.as_ref().unwrap()["operation_id"], "downloadLog");
        assert_eq!(error.data.as_ref().unwrap()["resource_uri"], URI);
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 1);
        let rows = sink.snapshot().await;
        let reason = rows
            .iter()
            .find(|row| row.outcome == AuditOutcome::ExecutionError)
            .and_then(|row| row.reason.as_deref())
            .expect("hydration failure must retain a sanitized audit reason");
        assert!(!reason.contains("downloadLog"));
        assert!(!reason.contains(URI));
    }

    #[tokio::test]
    async fn side_effecting_call_materializes_the_complete_response() {
        let catalog = Arc::new(RetainedCatalog {
            reads: AtomicUsize::new(0),
            declared_bytes: None,
            output_schema: None,
            missing_envelope_field: None,
            resource_body: BODY,
            side_effects: true,
            refuse_for_materialization_limit: false,
            missing_resource: false,
            unsupported_transport: false,
            resource_uri: URI,
            retained_uri: URI,
            resource_claims: Vec::new(),
            fleet_resource_claims: Vec::new(),
        });
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        );

        let response = service
            .invoke(
                None,
                InvocationRequest::new("connector", "mutate")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect("applied mutation must remain a successful connector call");
        let InvocationResponse::Unary(response) = response else {
            panic!("unary response")
        };

        assert_eq!(response.structured_content.unwrap()["data"], BODY);
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn tool_confined_profile_cannot_follow_a_retained_native_resource() {
        let catalog = Arc::new(RetainedCatalog::default());
        let sink = Arc::new(InMemorySink::default());
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            sink.clone(),
        );
        let principal = principal_with_profile(Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "tool-only".to_owned(),
            profile_name: "tool-only".to_owned(),
            allowed_servers: Some(vec!["connector".to_owned()]),
            allowed_tools: Some(vec!["connector.download".to_owned()]),
        }));

        let error = service
            .invoke(
                Some(&principal),
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("tool confinement must not imply native resource access");

        assert!(matches!(error, InvocationError::Forbidden { .. }));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 0);
        let rows = sink.snapshot().await;
        assert_eq!(rows.len(), 1, "the later resource gate owns one denial row");
        assert_eq!(rows[0].outcome, AuditOutcome::Denied);
        assert!(rows[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("profile")));
    }

    #[tokio::test]
    async fn cedar_resource_denial_is_audited_without_reading_the_body() {
        let catalog = Arc::new(RetainedCatalog::default());
        let sink = Arc::new(InMemorySink::default());
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(DenyResourceGate),
            sink.clone(),
        );
        let principal = principal_with_profile(None);

        let error = service
            .invoke(
                Some(&principal),
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("resource authorization must fail closed");

        assert!(matches!(error, InvocationError::Forbidden { .. }));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 0);

        // The attachment authorization decision is separate from dispatch.
        let rows = sink.snapshot().await;
        assert_eq!(rows.len(), 1, "the later resource gate owns one denial row");
        let call = &rows[0];
        assert_eq!(call.action, "ReadResource");
        assert_eq!(call.outcome, AuditOutcome::Denied);
        assert_eq!(call.target.as_deref(), Some(URI));
        assert_eq!(call.tool.as_deref(), Some("resources/read"));
        assert_eq!(call.policy_ids, vec!["deny-resource"]);
        assert_eq!(call.reason.as_deref(), Some("resource read denied"));
    }

    #[tokio::test]
    async fn retained_resource_allow_records_uri_and_governing_policy() {
        let catalog = Arc::new(RetainedCatalog::default());
        let sink = Arc::new(InMemorySink::default());
        let service = DefaultInvocationService::new(
            catalog.clone(),
            Arc::new(RequireHighResourceGate),
            sink.clone(),
        );
        let principal = principal_with_profile(None);
        service
            .invoke(
                Some(&principal),
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect("authorized resource read");
        let rows = sink.snapshot().await;
        let decision = rows
            .iter()
            .find(|row| row.action == "ReadResource")
            .unwrap();
        assert_eq!(decision.outcome, AuditOutcome::Success);
        assert_eq!(decision.target.as_deref(), Some(URI));
        assert_eq!(decision.policy_ids, vec!["permit-low-resource"]);
        assert_eq!(decision.risk_level, Some(crate::protocol::RiskTier::Low));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn retained_resource_uses_its_declared_risk_for_authorization() {
        let catalog = Arc::new(RetainedCatalog {
            resource_claims: vec![crate::catalog::ResourceClaim {
                uri_prefix: "connector-response:/".to_owned(),
                risk: crate::protocol::RiskTier::High,
            }],
            ..RetainedCatalog::default()
        });
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(RequireHighResourceGate),
            Arc::new(NullSink),
        );
        let principal = principal_with_profile(None);

        let error = service
            .invoke(
                Some(&principal),
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("a high-risk retained resource must not pass a low-risk policy");

        assert!(matches!(error, InvocationError::Forbidden { .. }));
        assert_eq!(
            catalog.reads.load(Ordering::Relaxed),
            0,
            "authorization must refuse before the session-affine resource read",
        );
    }

    #[tokio::test]
    async fn declared_server_cannot_recover_a_retained_resource_outside_its_prefixes() {
        let catalog = Arc::new(RetainedCatalog {
            resource_claims: vec![crate::catalog::ResourceClaim {
                uri_prefix: "reviewed-response:/".to_owned(),
                risk: crate::protocol::RiskTier::High,
            }],
            ..RetainedCatalog::default()
        });
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        );
        let principal = principal_with_profile(None);

        let error = service
            .invoke(
                Some(&principal),
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("an out-of-claim retained URI must not regain legacy Low risk");

        assert!(matches!(error, InvocationError::Forbidden { .. }));
        assert_eq!(
            catalog.reads.load(Ordering::Relaxed),
            0,
            "the declared ownership boundary must refuse before resource I/O",
        );
    }

    #[tokio::test]
    async fn another_servers_declared_prefix_reserves_a_retained_resource() {
        let catalog = Arc::new(RetainedCatalog {
            fleet_resource_claims: vec![(
                "reviewed-owner".to_owned(),
                crate::catalog::ResourceClaim {
                    uri_prefix: "connector-response:/".to_owned(),
                    risk: crate::protocol::RiskTier::High,
                },
            )],
            ..RetainedCatalog::default()
        });
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        );
        let principal = principal_with_profile(None);

        let error = service
            .invoke(
                Some(&principal),
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("another server's declared prefix must reserve the retained URI");

        assert!(matches!(error, InvocationError::Forbidden { .. }));
        assert_eq!(
            catalog.reads.load(Ordering::Relaxed),
            0,
            "cross-server ownership must refuse before session-affine resource I/O",
        );
    }

    #[tokio::test]
    async fn auth_disabled_still_enforces_retained_resource_ownership() {
        let catalog = Arc::new(RetainedCatalog {
            fleet_resource_claims: vec![(
                "reviewed-owner".to_owned(),
                crate::catalog::ResourceClaim {
                    uri_prefix: "connector-response:/".to_owned(),
                    risk: crate::protocol::RiskTier::High,
                },
            )],
            ..RetainedCatalog::default()
        });
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        );

        let error = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("auth-disabled mode must still honor fleet resource ownership");

        assert!(matches!(error, InvocationError::Forbidden { .. }));
        assert_eq!(
            catalog.reads.load(Ordering::Relaxed),
            0,
            "manifest ownership must refuse before session-affine resource I/O",
        );
    }

    #[tokio::test]
    async fn retained_recovery_never_dispatches_the_reserved_file_namespace() {
        let catalog = Arc::new(RetainedCatalog {
            retained_uri: "MCP-FILE://gateway/01999999-9999-7999-8999-999999999999",
            ..RetainedCatalog::default()
        });
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        );

        let error = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("the gateway file plane cannot become an upstream resource read");

        assert!(matches!(error, InvocationError::Forbidden { .. }));
        assert_eq!(
            catalog.reads.load(Ordering::Relaxed),
            0,
            "the reserved namespace must be refused before session-affine resource I/O",
        );
    }

    #[tokio::test]
    async fn current_server_visibility_is_rechecked_before_retained_resource_io() {
        let catalog = Arc::new(RetainedCatalog::default());
        let sink = Arc::new(InMemorySink::default());
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(DenyDiscoveryGate),
            sink.clone(),
        );
        let principal = principal_with_profile(None);

        let error = service
            .invoke(
                Some(&principal),
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("current server visibility denial must fail closed");

        assert!(matches!(error, InvocationError::Forbidden { .. }));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 0);
        let rows = sink.snapshot().await;
        assert_eq!(rows.len(), 1, "the later resource gate owns one denial row");
        assert_eq!(rows[0].outcome, AuditOutcome::Denied);
        assert_eq!(
            rows[0].reason.as_deref(),
            Some("retained connector response server is not discoverable")
        );
    }

    #[tokio::test]
    async fn recovered_body_is_inspected_before_codemode_can_receive_it() {
        let (service, catalog) = service();
        let service = service.with_inspectors(vec![Arc::new(BodyInspector)]);
        let error = service
            .invoke(
                None,
                InvocationRequest::new("connector", "download")
                    .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
                    .with_response_materialization_limit(1024),
            )
            .await
            .expect_err("inspector must see the recovered body");

        assert!(matches!(
            error,
            InvocationError::ResponseInspectionBlocked {
                inspector_name: "retained-body",
                ..
            }
        ));
        assert_eq!(catalog.reads.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod profile_restriction_tests {
    use super::super::*;
    use waygate_oidc::ApiKeyProfileRestrictions;

    fn r(servers: Option<Vec<&str>>, tools: Option<Vec<&str>>) -> ApiKeyProfileRestrictions {
        ApiKeyProfileRestrictions {
            profile_id: "pid".into(),
            profile_name: "test_profile".into(),
            allowed_servers: servers.map(|v| v.into_iter().map(String::from).collect()),
            allowed_tools: tools.map(|v| v.into_iter().map(String::from).collect()),
        }
    }

    #[test]
    fn no_restrictions_passes() {
        assert!(evaluate_profile_restrictions(&r(None, None), "any", "any").is_ok());
        assert!(
            evaluate_profile_restrictions(&r(Some(vec![]), Some(vec![])), "any", "any").is_ok()
        );
    }

    #[test]
    fn allowed_servers_accepts_listed() {
        let rest = r(Some(vec!["email"]), None);
        assert!(evaluate_profile_restrictions(&rest, "email", "send").is_ok());
    }

    #[test]
    fn allowed_servers_refuses_unlisted_with_profile_name() {
        let rest = r(Some(vec!["email"]), None);
        match evaluate_profile_restrictions(&rest, "weather", "get") {
            Err(InvocationError::ProfileServerNotAllowed {
                profile_name,
                server,
                ..
            }) => {
                assert_eq!(profile_name, "test_profile");
                assert_eq!(server, "weather");
            }
            other => panic!("expected ProfileServerNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn allowed_tools_accepts_qualified_match() {
        let rest = r(None, Some(vec!["email.send"]));
        assert!(evaluate_profile_restrictions(&rest, "email", "send").is_ok());
    }

    #[test]
    fn allowed_tools_refuses_unlisted_tool_same_server() {
        let rest = r(None, Some(vec!["email.send"]));
        match evaluate_profile_restrictions(&rest, "email", "delete") {
            Err(InvocationError::ProfileToolNotAllowed { tool, .. }) => {
                assert_eq!(tool, "email.delete");
            }
            other => panic!("expected ProfileToolNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn allowed_tools_refuses_qualified_for_unlisted_server() {
        let rest = r(None, Some(vec!["email.send"]));
        assert!(matches!(
            evaluate_profile_restrictions(&rest, "weather", "send"),
            Err(InvocationError::ProfileToolNotAllowed { .. }),
        ));
    }

    #[test]
    fn server_check_takes_precedence_over_tool_check() {
        // Both restrictions present + both would deny. Server
        // check runs first, so the error variant is the
        // server-shaped one (operator gets the broader
        // signal first).
        let rest = r(Some(vec!["email"]), Some(vec!["email.send"]));
        let err = evaluate_profile_restrictions(&rest, "weather", "get").unwrap_err();
        assert!(matches!(
            err,
            InvocationError::ProfileServerNotAllowed { .. }
        ));
    }

    // ---------------------------------------------------------
    // Output-schema validator unit tests.
    // ---------------------------------------------------------

    use serde_json::json;

    fn check_output(schema: &serde_json::Value, structured: &serde_json::Value) -> SchemaCheck {
        let validator = jsonschema::validator_for(schema).expect("test schema must compile");
        check_value_against_validator(&validator, structured)
    }

    #[test]
    fn schema_check_pass_on_matching_object() {
        let schema = json!({
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"},
                "count": {"type": "integer"},
            },
            "required": ["ok"],
        });
        let structured = json!({"ok": true, "count": 42});
        assert!(matches!(
            check_output(&schema, &structured),
            SchemaCheck::Pass,
        ));
    }

    #[test]
    fn schema_check_violation_on_missing_required_field() {
        let schema = json!({
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"},
            },
            "required": ["ok"],
        });
        let structured = json!({"count": 42});
        let SchemaCheck::Violation(reason) = check_output(&schema, &structured) else {
            panic!("expected Violation, got Pass");
        };
        // Sanitized reason — must name what's wrong and the schema rule. The sanitizer
        // surfaces the missing required field NAME (schema-
        // side metadata, not a payload value), so this is
        // safe to assert against.
        assert!(
            reason.contains("required field `ok` is missing"),
            "reason should name the missing field by schema metadata: {reason}",
        );
        assert!(!reason.contains("instance `"));
        assert!(
            reason.contains("schema rule `"),
            "reason should include schema rule JSON pointer: {reason}",
        );
    }

    #[test]
    fn schema_check_violation_on_wrong_type() {
        let schema = json!({
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
        });
        let structured = json!({"ok": "yes"});
        let result = check_output(&schema, &structured);
        let SchemaCheck::Violation(reason) = &result else {
            panic!("wrong type must be a Violation: {result:?}");
        };
        assert!(
            reason.contains("type mismatch"),
            "reason should label the kind: {reason}",
        );
        // The offending payload value
        // (`"yes"`) MUST NOT appear in the reason; only
        // schema-side metadata + JSON pointers are safe.
        assert!(
            !reason.contains("\"yes\"") && !reason.contains("yes\""),
            "sanitizer must not leak the instance value: {reason}",
        );
    }
}

#[cfg(test)]
mod mrtr_dispatch_tests {
    use std::sync::Arc;

    use rmcp::model::{
        CallToolResponse, ClientCapabilities, ElicitRequest, ElicitRequestParams,
        ElicitationSchema, ErrorCode, InputRequest, InputRequiredResult, Task, TaskStatus,
    };

    use super::super::*;
    use crate::audit::NullSink;
    use crate::authz::AllowAllGate;
    use crate::catalog::{ToolCallMrtr, UpstreamCatalog};

    /// Scripted dispatch: returns the configured [`CallToolResponse`] and
    /// records the [`ToolCallMrtr`] each dispatch carried.
    struct ScriptedCatalog {
        response: std::sync::Mutex<Option<CallToolResponse>>,
        seen_mrtr: std::sync::Mutex<Vec<ToolCallMrtr>>,
        annotation_native: bool,
    }

    impl ScriptedCatalog {
        fn returning(response: CallToolResponse) -> Self {
            Self {
                response: std::sync::Mutex::new(Some(response)),
                seen_mrtr: std::sync::Mutex::new(Vec::new()),
                annotation_native: false,
            }
        }

        /// Admit the tool with annotation claims enforced, so the mandatory
        /// result-trust gate applies to everything this catalog returns.
        fn annotation_native(mut self) -> Self {
            self.annotation_native = true;
            self
        }
    }

    #[async_trait::async_trait]
    impl UpstreamCatalog for ScriptedCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["mock".to_owned()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<rmcp::model::Tool>, ErrorData> {
            Ok(Vec::new())
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<serde_json::Map<String, serde_json::Value>>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, ErrorData> {
            unreachable!("the pipeline dispatches through call_tool_response")
        }

        async fn call_tool_response(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<serde_json::Map<String, serde_json::Value>>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
            mrtr: ToolCallMrtr,
        ) -> Result<CallToolResponse, ErrorData> {
            self.seen_mrtr.lock().unwrap().push(mrtr);
            Ok(self
                .response
                .lock()
                .unwrap()
                .take()
                .expect("each test dispatches exactly once"))
        }

        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> crate::catalog::ResolvedInvocationTool {
            let facts = self.tool_facts(server, tool_name);
            let snapshot = if self.annotation_native {
                crate::catalog::InvocationToolSnapshot::catalog_with_annotation_claims(
                    facts,
                    uuid::Uuid::from_u128(7),
                    "h".into(),
                    false,
                    Some(serde_json::json!({"type": "object"})),
                    None,
                    None,
                    None,
                )
            } else {
                crate::catalog::InvocationToolSnapshot::manifest_fallback(facts, true)
            };
            crate::catalog::ResolvedInvocationTool::Ready(snapshot)
        }
    }

    fn service(catalog: ScriptedCatalog) -> (DefaultInvocationService, Arc<ScriptedCatalog>) {
        let catalog = Arc::new(catalog);
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        );
        (service, catalog)
    }

    fn elicitation_pause() -> InputRequiredResult {
        let elicit = ElicitRequest::new(ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: "pick one".to_owned(),
            requested_schema: ElicitationSchema::builder()
                .required_string("choice")
                .build_unchecked(),
        });
        let mut requests = rmcp::model::InputRequests::new();
        requests.insert("q1".to_owned(), InputRequest::Elicitation(elicit));
        InputRequiredResult::new(Some(requests), Some("upstream-state-7".to_owned()))
    }

    fn elicitation_caps() -> ClientCapabilities {
        ClientCapabilities::builder().enable_elicitation().build()
    }

    #[tokio::test]
    async fn pause_passes_through_verbatim_when_the_caller_declared_the_capability() {
        let (service, _) = service(ScriptedCatalog::returning(CallToolResponse::InputRequired(
            elicitation_pause(),
        )));
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(elicitation_caps()));
        match service.invoke(None, request).await {
            Ok(InvocationResponse::InputRequired(pause)) => {
                assert_eq!(pause.request_state.as_deref(), Some("upstream-state-7"));
                let requests = pause.input_requests.expect("requests pass through");
                assert!(matches!(
                    requests.get("q1"),
                    Some(InputRequest::Elicitation(_))
                ));
            }
            other => panic!("expected a pass-through pause, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pause_fails_closed_when_the_caller_did_not_declare_the_capability() {
        let (service, _) = service(ScriptedCatalog::returning(CallToolResponse::InputRequired(
            elicitation_pause(),
        )));
        // A 2026 caller that declared nothing: it can receive a pause but
        // answers no elicitation.
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(ClientCapabilities::default()));
        match service.invoke(None, request).await {
            Err(InvocationError::Upstream(err)) => {
                assert_eq!(err.code, ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY);
                assert_eq!(
                    err.data
                        .as_ref()
                        .and_then(|d| d.get("capability"))
                        .and_then(|v| v.as_str()),
                    Some("elicitation"),
                );
            }
            other => panic!("expected a missing-capability refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn any_pause_fails_closed_for_a_caller_that_cannot_receive_one() {
        // A pure requestState round trip needs no capability to ANSWER, but
        // the caller (legacy / Code Mode / LLM surface) cannot receive an
        // input_required result at all.
        let (service, _) = service(ScriptedCatalog::returning(CallToolResponse::InputRequired(
            InputRequiredResult::from_request_state("s"),
        )));
        let request = InvocationRequest::new("mock", "confirm");
        match service.invoke(None, request).await {
            Err(InvocationError::Upstream(err)) => {
                assert_eq!(err.code, ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY);
            }
            other => panic!("expected a fail-closed refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn state_only_pause_round_trips_for_a_2026_caller_with_no_capabilities() {
        let (service, _) = service(ScriptedCatalog::returning(CallToolResponse::InputRequired(
            InputRequiredResult::from_request_state("shed-42"),
        )));
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(ClientCapabilities::default()));
        match service.invoke(None, request).await {
            Ok(InvocationResponse::InputRequired(pause)) => {
                assert_eq!(pause.request_state.as_deref(), Some("shed-42"));
                assert!(pause.input_requests.is_none());
            }
            other => panic!("expected the state-only pause to pass through, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn retry_fields_reach_the_dispatch_verbatim() {
        let (service, catalog) = service(ScriptedCatalog::returning(
            CallToolResult::success(vec![rmcp::model::ContentBlock::text("done")]).into(),
        ));
        let mut responses = rmcp::model::InputResponses::new();
        responses.insert("q1".to_owned(), serde_json::json!({"choice": "b"}));
        let request = InvocationRequest::new("mock", "confirm")
            .with_mrtr_retry(Some(responses.clone()), Some("upstream-state-7".to_owned()))
            .with_caller_capabilities(Some(elicitation_caps()));
        service.invoke(None, request).await.expect("completes");
        let seen = catalog.seen_mrtr.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].input_responses.as_ref(), Some(&responses));
        assert_eq!(seen[0].request_state.as_deref(), Some("upstream-state-7"));
        assert!(seen[0]
            .caller_capabilities
            .as_ref()
            .is_some_and(|caps| caps.elicitation.is_some()));
    }

    /// Inspector that finds its needle in the serialized pause and reports
    /// the given decision, proving the pause rides the same chain as a
    /// normal result.
    struct NeedleInspector {
        redact: bool,
    }

    #[async_trait::async_trait]
    impl crate::inspection::Inspector for NeedleInspector {
        fn name(&self) -> &'static str {
            "needle"
        }

        async fn inspect(
            &self,
            _ctx: &crate::inspection::InspectionContext<'_>,
            result: &CallToolResult,
        ) -> crate::inspection::Decision {
            let text = serde_json::to_string(result).unwrap_or_default();
            if !text.contains("ssn 123-45-6789") {
                return crate::inspection::Decision::Pass;
            }
            if self.redact {
                crate::inspection::Decision::Redact {
                    redacted: result.clone(),
                    findings_count: 1,
                }
            } else {
                crate::inspection::Decision::Block {
                    reason: "matched rule `needle`".to_owned(),
                }
            }
        }
    }

    #[tokio::test]
    async fn pause_content_rides_the_response_inspector_chain() {
        // A pause carries caller-visible upstream text (elicitation
        // messages, sampling prompts, requestState), so the configured
        // inspectors must see it — and any finding refuses the relay:
        // a Block for the usual reason, and a Redact too (a rewritten
        // interactive prompt cannot be forwarded faithfully).
        for redact in [false, true] {
            let elicit = ElicitRequest::new(ElicitRequestParams::FormElicitationParams {
                meta: None,
                message: "please confirm ssn 123-45-6789".to_owned(),
                requested_schema: ElicitationSchema::builder()
                    .required_string("choice")
                    .build_unchecked(),
            });
            let mut requests = rmcp::model::InputRequests::new();
            requests.insert("q1".to_owned(), InputRequest::Elicitation(elicit));
            let catalog = Arc::new(ScriptedCatalog::returning(CallToolResponse::InputRequired(
                InputRequiredResult::from_input_requests(requests),
            )));
            let service = DefaultInvocationService::new(
                Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
                Arc::new(AllowAllGate),
                Arc::new(NullSink),
            )
            .with_inspectors(vec![Arc::new(NeedleInspector { redact })]);
            let request = InvocationRequest::new("mock", "confirm")
                .with_caller_capabilities(Some(elicitation_caps()));
            match service.invoke(None, request).await {
                Err(InvocationError::ResponseInspectionBlocked { inspector_name, .. }) => {
                    assert_eq!(inspector_name, "needle");
                }
                other => panic!(
                    "expected the inspector (redact={redact}) to refuse the pause, got {other:?}"
                ),
            }
        }
    }

    #[tokio::test]
    async fn clean_pause_passes_the_inspector_chain() {
        let catalog = Arc::new(ScriptedCatalog::returning(CallToolResponse::InputRequired(
            elicitation_pause(),
        )));
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            Arc::new(NullSink),
        )
        .with_inspectors(vec![Arc::new(NeedleInspector { redact: false })]);
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(elicitation_caps()));
        match service.invoke(None, request).await {
            Ok(InvocationResponse::InputRequired(pause)) => {
                assert_eq!(pause.request_state.as_deref(), Some("upstream-state-7"));
            }
            other => panic!("a finding-free pause must relay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn relayed_pause_records_its_own_outcome_row() {
        // The pausing leg is a real upstream RPC under the default
        // best-effort evidence posture (no pre-call row), so an abandoned
        // round trip must still leave an audit trace.
        let sink = Arc::new(crate::audit::InMemorySink::default());
        let catalog = Arc::new(ScriptedCatalog::returning(CallToolResponse::InputRequired(
            elicitation_pause(),
        )));
        let service = DefaultInvocationService::new(
            Arc::clone(&catalog) as Arc<dyn UpstreamCatalog>,
            Arc::new(AllowAllGate),
            sink.clone(),
        );
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(elicitation_caps()));
        match service.invoke(None, request).await {
            Ok(InvocationResponse::InputRequired(_)) => {}
            other => panic!("expected the pause to relay, got {other:?}"),
        }
        let rows = sink.snapshot().await;
        let pause_row = rows
            .iter()
            .find(|row| {
                row.reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("input_required"))
            })
            .expect("the relayed pause must leave an outcome row");
        assert_eq!(pause_row.outcome, crate::audit::AuditOutcome::Success);
    }

    #[tokio::test]
    async fn sampling_pause_refuses_even_when_the_caller_declared_sampling() {
        // Sampling (and roots) are deprecated in MCP 2026-07-28 and the
        // repo's deprecation posture builds no passthrough for them:
        // elicitation is the only input-request kind relayed, so a
        // sampling pause refuses regardless of the caller's declarations.
        let request_json = serde_json::json!({
            "method": "sampling/createMessage",
            "params": {"messages": [], "maxTokens": 8},
        });
        let sampling_request: InputRequest =
            serde_json::from_value(request_json).expect("wire-shaped sampling request parses");
        let mut requests = rmcp::model::InputRequests::new();
        requests.insert("q1".to_owned(), sampling_request);
        let (service, _) = service(ScriptedCatalog::returning(CallToolResponse::InputRequired(
            InputRequiredResult::from_input_requests(requests),
        )));
        let mut caps = elicitation_caps();
        caps.sampling = Some(Default::default());
        let request =
            InvocationRequest::new("mock", "confirm").with_caller_capabilities(Some(caps));
        match service.invoke(None, request).await {
            Err(InvocationError::Upstream(err)) => {
                assert_eq!(err.code, ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY);
                assert!(
                    err.message.contains("does not relay sampling"),
                    "the refusal must say the gateway does not relay it: {}",
                    err.message,
                );
            }
            other => panic!("expected the sampling pause to be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_pause_with_neither_requests_nor_state_is_refused() {
        // Nothing to answer, nothing to echo: no retry can make progress,
        // so the malformed pause is refused instead of stranding the call.
        let (service, _) = service(ScriptedCatalog::returning(CallToolResponse::InputRequired(
            InputRequiredResult::new(Some(rmcp::model::InputRequests::new()), None),
        )));
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(elicitation_caps()));
        match service.invoke(None, request).await {
            Err(InvocationError::Upstream(err)) => {
                assert!(
                    err.message
                        .contains("neither input requests nor request state"),
                    "the refusal must name the malformation: {}",
                    err.message,
                );
            }
            other => panic!("expected the empty pause to be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn annotation_native_pause_without_trust_labels_is_withheld() {
        // The mandatory result-release gate applies to a pause exactly as
        // it applies to a completed result: an annotation-native upstream
        // that pauses without trust labels has the pause withheld.
        let (service, _) = service(
            ScriptedCatalog::returning(CallToolResponse::InputRequired(elicitation_pause()))
                .annotation_native(),
        );
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(elicitation_caps()));
        match service.invoke(None, request).await {
            Err(InvocationError::ResponseInspectionBlocked { inspector_name, .. }) => {
                assert_eq!(inspector_name, "trust-annotations");
            }
            other => panic!("expected the unlabeled pause to be withheld, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn annotation_native_pause_with_trust_labels_relays() {
        let mut meta = rmcp::model::MetaObject::default();
        meta.0.insert(
            "io.modelcontextprotocol/trust-annotations".to_owned(),
            serde_json::json!({"sensitive": false, "untrusted": true}),
        );
        let pause = elicitation_pause().with_meta(meta);
        let (service, _) = service(
            ScriptedCatalog::returning(CallToolResponse::InputRequired(pause)).annotation_native(),
        );
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(elicitation_caps()));
        match service.invoke(None, request).await {
            Ok(InvocationResponse::InputRequired(pause)) => {
                assert_eq!(pause.request_state.as_deref(), Some("upstream-state-7"));
            }
            other => panic!("a labeled pause must relay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upstream_pause_claiming_the_reserved_approval_key_is_refused() {
        // The retry-side strip consumes `gateway:approval` answers as the
        // gateway's own ask, so an upstream pause claiming that opaque key
        // could never round-trip — the collision must refuse loud at relay
        // time, not lose the caller's answer silently on the retry.
        let elicit = ElicitRequest::new(ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: "collides".to_owned(),
            requested_schema: ElicitationSchema::builder()
                .required_string("choice")
                .build_unchecked(),
        });
        let mut requests = rmcp::model::InputRequests::new();
        requests.insert(
            super::super::mrtr::APPROVAL_INPUT_REQUEST_KEY.to_owned(),
            InputRequest::Elicitation(elicit),
        );
        let (service, _) = service(ScriptedCatalog::returning(CallToolResponse::InputRequired(
            InputRequiredResult::from_input_requests(requests),
        )));
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(elicitation_caps()));
        match service.invoke(None, request).await {
            Err(InvocationError::Upstream(err)) => {
                assert!(
                    err.message.contains("gateway:approval"),
                    "the refusal must name the reserved key: {}",
                    err.message,
                );
            }
            other => panic!("expected the collision to be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unrequested_task_envelope_is_refused() {
        let (service, _) = service(ScriptedCatalog::returning(CallToolResponse::Task(
            rmcp::model::CreateTaskResult::new(Task::new(
                "t-1",
                TaskStatus::Working,
                "2026-08-02T00:00:00Z",
                "2026-08-02T00:00:00Z",
            )),
        )));
        let request = InvocationRequest::new("mock", "confirm")
            .with_caller_capabilities(Some(elicitation_caps()));
        match service.invoke(None, request).await {
            Err(InvocationError::Upstream(err)) => {
                assert!(
                    err.message.contains("task envelope"),
                    "teach-through must name the refusal: {}",
                    err.message,
                );
            }
            other => panic!("expected the task envelope to be refused, got {other:?}"),
        }
    }
}
