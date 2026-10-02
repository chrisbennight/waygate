//! Result-count contracts through the ordinary invocation and delivery pipeline.

use std::sync::{Arc, Mutex};

use rmcp::model::{CallToolResult, ErrorData, Tool};
use serde_json::{json, Map, Value};

use super::*;
use crate::audit::NullSink;
use crate::authz::AllowAllGate;
use crate::catalog::{InvocationContractIdentity, InvocationToolSnapshot, UpstreamCatalog};

struct CountCatalog {
    maximum: u64,
    side_effects: bool,
    stored_maximum: Option<u64>,
    closed_stored_output: bool,
    calls: Mutex<Vec<Map<String, Value>>>,
}

impl CountCatalog {
    fn tool(&self) -> Tool {
        Tool::new(
            "search",
            "Search wrapped text",
            Arc::new(
                json!({
            "type":"object", "properties":{
                "query":{"type":"string"},
                "limit":{"type":"integer","minimum":1,"maximum":self.maximum,"default":10},
                "extract_count":{"type":"integer","minimum":0,"maximum":10}},
            "required":["query"]})
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .with_raw_output_schema(Arc::new(
            json!({
                "type":"object", "x-fastmcp-wrap-result":true,
                "properties":{"result":{"type":"string"}},"required":["result"]
            })
            .as_object()
            .unwrap()
            .clone(),
        ))
    }

    fn snapshot(&self) -> InvocationToolSnapshot {
        let mut facts = self.tool_facts("connector", "search");
        facts.side_effects = self.side_effects;
        let tool = self.tool();
        let mut input = json!(tool.input_schema);
        if let Some(maximum) = self.stored_maximum {
            input["properties"]["limit"]["maximum"] = maximum.into();
        }
        let mut output = json!(tool.output_schema.as_ref().unwrap());
        if self.closed_stored_output {
            output["additionalProperties"] = false.into();
        }
        InvocationToolSnapshot::manifest_fallback_with_contract(
            facts,
            true,
            None,
            Some(input),
            Some(output),
            None,
            None,
        )
        .with_published_definition(Some(tool))
    }
}

#[async_trait::async_trait]
impl UpstreamCatalog for CountCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["connector".into()]
    }

    async fn list_tools(&self, _: &str) -> Result<Vec<Tool>, ErrorData> {
        Ok(vec![self.tool()])
    }

    async fn resolve_invocation_tool(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> crate::catalog::ResolvedInvocationTool {
        crate::catalog::ResolvedInvocationTool::Ready(self.snapshot())
    }

    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: Option<Map<String, Value>>,
        _: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
    ) -> Result<CallToolResult, ErrorData> {
        assert_eq!((server, tool), ("connector", "search"));
        assert_eq!(admitted, Some(&self.snapshot().contract_identity()));
        self.calls.lock().unwrap().push(args.unwrap());
        Ok(CallToolResult::structured(
            json!({"result":"original result"}),
        ))
    }
}

fn service(maximum: u64, side_effects: bool) -> (DefaultInvocationService, Arc<CountCatalog>) {
    let catalog = Arc::new(CountCatalog {
        maximum,
        side_effects,
        stored_maximum: None,
        closed_stored_output: false,
        calls: Mutex::default(),
    });
    let service =
        DefaultInvocationService::new(catalog.clone(), Arc::new(AllowAllGate), Arc::new(NullSink));
    (service, catalog)
}

fn request(arguments: Value) -> InvocationRequest {
    InvocationRequest::new("connector", "search")
        .with_arguments(Some(arguments.as_object().unwrap().clone()))
}

#[tokio::test]
async fn native_count_pipeline_clamps_and_publishes_the_same_contract() {
    let (service, catalog) = service(1024, false);
    let snapshot = catalog.snapshot();
    let published = crate::discovery::CatalogTool::from_upstream_snapshot("connector", snapshot)
        .expect("published count contract");
    let input = json!(published.definition.input_schema);
    assert!(jsonschema::validator_for(&input)
        .unwrap()
        .is_valid(&json!({"query":"fixture","limit":2048})));
    assert_eq!(
        input["properties"]["limit"]["x-mcp-result-count"]["upstreamMaximum"],
        1024
    );

    let response = service
        .invoke(
            None,
            request(json!({"query":"fixture","limit":2048,"extract_count":2})),
        )
        .await
        .unwrap();
    let InvocationResponse::Unary(result) = response else {
        panic!("unary result")
    };
    let output = result.structured_content.as_ref().unwrap();
    assert_eq!(output["result"], "original result");
    assert_eq!(
        output["_gateway_counts"]["limit"],
        json!({
            "requested":2048,"effective":1024,"upstreamMaximum":1024,"returned":null,"clamped":true
        })
    );
    assert!(
        jsonschema::validator_for(&json!(published.definition.output_schema.unwrap()))
            .unwrap()
            .is_valid(output)
    );
    assert_eq!(
        *catalog.calls.lock().unwrap(),
        vec![json!({"query":"fixture","limit":1024,"extract_count":2})
            .as_object()
            .unwrap()
            .clone()]
    );
}

#[tokio::test]
async fn native_count_pipeline_preserves_defaults_and_rejects_invalid_counts_and_budgets() {
    let (service, catalog) = service(1024, false);
    for arguments in [
        json!({"query":"fixture"}),
        json!({"query":"fixture","limit":10}),
    ] {
        let response = service
            .invoke(None, request(arguments.clone()))
            .await
            .unwrap();
        let InvocationResponse::Unary(result) = response else {
            panic!("unary result")
        };
        assert!(result
            .structured_content
            .unwrap()
            .get("_gateway_counts")
            .is_none());
        assert_eq!(
            catalog.calls.lock().unwrap().last().unwrap(),
            arguments.as_object().unwrap()
        );
    }
    for arguments in [
        json!({"query":"fixture","limit":0}),
        json!({"query":"fixture","limit":-1}),
        json!({"query":"fixture","limit":2048,"extract_count":11}),
    ] {
        assert!(service.invoke(None, request(arguments)).await.is_err());
    }
    assert_eq!(catalog.calls.lock().unwrap().len(), 2);
    let (service, catalog) = self::service(1024, true);
    assert!(service
        .invoke(None, request(json!({"query":"fixture","limit":2048})))
        .await
        .is_err());
    assert!(catalog.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn native_count_ceiling_changes_invalidate_admitted_contracts() {
    let (_, previous) = service(1024, false);
    let expected = previous.snapshot().contract_identity();
    let (service, current) = service(512, false);
    assert_ne!(expected, current.snapshot().contract_identity());
    assert!(service
        .invoke(
            None,
            request(json!({"query":"fixture","limit":2048})).with_expected_contract(expected)
        )
        .await
        .is_err());
    assert!(current.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn stored_ceiling_does_not_hide_live_ceiling_changes_from_cached_calls() {
    let (_, previous) = service(1024, false);
    let expected = previous.snapshot().contract_identity();
    let current = Arc::new(CountCatalog {
        maximum: 512,
        side_effects: false,
        stored_maximum: Some(1024),
        closed_stored_output: false,
        calls: Mutex::default(),
    });
    assert_ne!(expected, current.snapshot().contract_identity());
    let service =
        DefaultInvocationService::new(current.clone(), Arc::new(AllowAllGate), Arc::new(NullSink));
    assert!(service
        .invoke(
            None,
            request(json!({"query":"fixture","limit":2048})).with_expected_contract(expected)
        )
        .await
        .is_err());
    assert!(current.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn closed_stored_output_keeps_counts_within_the_admitted_contract() {
    let catalog = Arc::new(CountCatalog {
        maximum: 1024,
        side_effects: false,
        stored_maximum: None,
        closed_stored_output: true,
        calls: Mutex::default(),
    });
    let published =
        crate::discovery::CatalogTool::from_upstream_snapshot("connector", catalog.snapshot())
            .unwrap();
    assert_eq!(
        published.definition.input_schema["properties"]["limit"]["maximum"],
        1024
    );
    let output = json!(published.definition.output_schema.as_ref().unwrap());
    let validator = jsonschema::validator_for(&output).unwrap();
    assert!(validator.is_valid(&json!({"result":"original result"})));
    assert!(!validator.is_valid(&json!({
        "result":"original result", "_gateway_counts":{"limit":{}}
    })));
    let service =
        DefaultInvocationService::new(catalog.clone(), Arc::new(AllowAllGate), Arc::new(NullSink));
    assert!(service
        .invoke(None, request(json!({"query":"fixture","limit":2048})))
        .await
        .is_err());
    assert!(catalog.calls.lock().unwrap().is_empty());
    let response = service
        .invoke(None, request(json!({"query":"fixture","limit":10})))
        .await
        .unwrap();
    let InvocationResponse::Unary(result) = response else {
        panic!("unary result")
    };
    assert_eq!(
        result.structured_content.unwrap(),
        json!({"result":"original result"})
    );
    assert_eq!(catalog.calls.lock().unwrap().len(), 1);
}

#[derive(Default)]
struct CountFiles {
    body: Mutex<Vec<u8>>,
}

#[async_trait::async_trait]
impl crate::files::FileOutputProcessor for CountFiles {
    fn inline_response_threshold_bytes(&self) -> Option<usize> {
        Some(1)
    }
    fn retained_response_max_bytes(&self) -> Option<usize> {
        Some(4096)
    }

    async fn prepare_retained(
        &self,
        _: crate::files::FileOutputContext,
        body: crate::files::RetainedFileBody,
    ) -> Result<crate::files::PreparedRetainedFile, ErrorData> {
        let size = body.bytes.len() as u64;
        *self.body.lock().unwrap() = body.bytes;
        Ok(crate::files::PreparedRetainedFile {
            file: crate::files::FileValue {
                uri: "mcp-file://gateway/00000000-0000-4000-8000-000000000001".into(),
                name: None,
                mime_type: Some(body.media_type),
                size: Some(size),
                digest: None,
            },
            batch_id: "count-test".into(),
        })
    }

    async fn prepare(
        &self,
        _: crate::files::FileOutputContext,
        result: CallToolResult,
    ) -> Result<crate::files::PreparedFileOutput, ErrorData> {
        Ok(crate::files::PreparedFileOutput {
            result,
            batch_id: None,
            file_count: 0,
        })
    }

    async fn publish(&self, _: &str, _: usize) -> Result<(), ErrorData> {
        Ok(())
    }
    async fn discard(&self, _: &str) {}
}

#[tokio::test]
async fn native_count_reports_follow_the_complete_response_into_retained_delivery() {
    let (service, catalog) = service(1024, false);
    let files = Arc::new(CountFiles::default());
    let service = service.with_file_output_processor(Some(files.clone()));
    let principal = Principal {
        sub: "count-reader".into(),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: vec![],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::ApiKey,
        raw_token: None,
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
        roles: vec![],
    };
    let response = service
        .invoke(
            Some(&principal),
            request(json!({"query":"fixture","limit":2048})),
        )
        .await
        .unwrap();
    let InvocationResponse::Unary(compact) = response else {
        panic!("unary result")
    };
    let retained: CallToolResult = serde_json::from_slice(&files.body.lock().unwrap()).unwrap();
    assert_eq!(
        retained.structured_content.as_ref().unwrap()["_gateway_counts"]["limit"]["effective"],
        1024
    );
    assert_eq!(
        retained.structured_content.unwrap()["result"],
        "original result"
    );
    assert!(compact
        .structured_content
        .as_ref()
        .unwrap()
        .get("_gateway_counts")
        .is_none());
    assert!(crate::retained_delivery::validator()
        .is_valid(compact.structured_content.as_ref().unwrap()));
    assert_eq!(catalog.calls.lock().unwrap().len(), 1);
}
