use super::*;
use waygate_mcp::files::{FileInputContext, FileInputOutcome, FileInputProcessor};

const OWNED: &str = "d10f706f-7e77-4ea0-a418-a0ee670f0462";
const FORGED: &str = "05367a35-6460-48b1-9002-dea8f908c4e3";

struct RecoveryFiles(Option<Value>);

#[async_trait]
impl FileInputProcessor for RecoveryFiles {
    fn admit(
        &self,
        _: Option<&Value>,
        _: Option<&jsonschema::Validator>,
        _: &mut Option<Map<String, Value>>,
        _: Option<&BTreeMap<String, Value>>,
        _: &[String],
    ) -> Result<(), McpError> {
        Ok(())
    }

    async fn prepare(
        &self,
        context: FileInputContext,
        _: Option<&Value>,
        _: &mut Option<Map<String, Value>>,
    ) -> Result<bool, McpError> {
        assert_eq!(context.principal.as_ref().unwrap().sub, reader().sub);
        match &self.0 {
            Some(data) => Err(McpError::invalid_params("file refused", Some(data.clone()))),
            None => Ok(true),
        }
    }

    async fn prepare_continuation(
        &self,
        _: FileInputContext,
        _: &mut BTreeMap<String, Value>,
        _: &[String],
    ) -> Result<bool, McpError> {
        Ok(false)
    }

    async fn finish(&self, context: &FileInputContext, _: FileInputOutcome) -> Vec<String> {
        assert_eq!(context.principal.as_ref().unwrap().sub, reader().sub);
        if self.0.is_none() {
            vec![OWNED.into()]
        } else {
            vec![]
        }
    }
}

struct StripFileFacts;
#[async_trait]
impl waygate_mcp::inspection::Inspector for StripFileFacts {
    fn name(&self) -> &'static str {
        "strip-file-facts"
    }
    async fn inspect(
        &self,
        _: &waygate_mcp::inspection::InspectionContext<'_>,
        _: &CallToolResult,
    ) -> waygate_mcp::inspection::Decision {
        let mut result = CallToolResult::structured(
            json!({"result":"refused", "error":{"code":"invalid_file_input","message":"safe detail"}}),
        );
        result.is_error = Some(true);
        waygate_mcp::inspection::Decision::Redact {
            redacted: result,
            findings_count: 1,
        }
    }
}

async fn client_error(failure: Option<Value>, tool_error: Option<Value>, redact: bool) -> Value {
    let mut catalog = FakeCatalog::with_tools(&[("printable", "ingest", false)]);
    catalog.replace_input_schema("printable", "ingest", json!({
        "type":"object", "properties":{"value":{"type":"string", "x-mcp-file":{}}}, "required":["value"]
    }));
    catalog.file_error = tool_error;
    let contract = catalog.contract_identity("printable", "ingest");
    let catalog: SharedCatalog = Arc::new(catalog);
    let authz: SharedAuthz = Arc::new(SelectiveAuthz);
    let mut invocation =
        DefaultInvocationService::new(catalog.clone(), authz.clone(), Arc::new(NullSink))
            .with_file_input_processor(Some(Arc::new(RecoveryFiles(failure))));
    if redact {
        invocation = invocation.with_inspectors(vec![Arc::new(StripFileFacts)]);
    }
    let tools = CodeModeTools::new(catalog, authz, Arc::new(invocation));
    let error = tools
        .invoke_direct(
            &reader(),
            "printable",
            "ingest",
            json!({"value":"mcp-file://gateway/owned-source"}),
            contract,
            test_hierarchy(1),
        )
        .await
        .expect_err("file refusal remains an error");
    // Use the production parent frame codec before the production runner bridge.
    let frame = ParentFrame::CallResult {
        id: 1,
        result: Err(error),
    };
    let encoded = serde_json::to_vec(&frame).unwrap();
    let ParentFrame::CallResult {
        result: Err(error), ..
    } = serde_json::from_slice(&encoded).unwrap()
    else {
        panic!("error frame")
    };
    let result = crate::process_mode::execute_recovery_error_for_test(error);
    assert_eq!(result[0], result[1], "synchronous and started calls agree");
    assert_eq!(result[0]["code"], "upstream");
    assert_eq!(result[0]["hasData"], false);
    assert_eq!(result[0]["isError"], true);
    result[0].clone()
}

#[tokio::test]
async fn preauthorization_file_recovery_is_actionable_without_a_delivery_row() {
    for (category, reason, limit, value) in [
        ("invalid_file_input", "file_too_large", "max_bytes", 1048576),
        (
            "invalid_file_input",
            "unsupported_type",
            "max_bytes",
            1048576,
        ),
        (
            "temporarily_unavailable",
            "upload_capacity_exhausted",
            "capacity",
            20,
        ),
        (
            "temporarily_unavailable",
            "receipt_capacity",
            "capacity",
            128,
        ),
    ] {
        let mut data = json!({"error":category, "reason":reason, "stage":"authorize_upload",
            "publication_attempted":false, "retryable":true, "retry_after_seconds":5,
            "uri":"mcp-file://printable/private", "url":"https://private.invalid/token",
            "token":"unreleased-credential", "message":"raw diagnostic", "delivery_ids":[FORGED]});
        data[limit] = json!(value);
        if matches!(reason, "file_too_large" | "unsupported_type") {
            let constraints = waygate_mcp::files::FileInputDescriptor {
                max_size: Some(value),
                accept: Some(vec![".stl".into()]),
                ..Default::default()
            };
            let local = crate::file_transfer::enforce_file_input_constraint(
                &constraints,
                Some("application/octet-stream"),
                Some("model.part"),
                if reason == "file_too_large" {
                    value + 1
                } else {
                    1
                },
            )
            .unwrap_err();
            let facts = local.data.unwrap();
            assert_eq!(facts["reason"], reason);
            assert_eq!(facts["publication_attempted"], false);
            assert_eq!(facts["retryable"], false);
            if reason == "file_too_large" {
                assert_eq!(facts["max_bytes"], value);
            }
            for (key, value) in facts.as_object().unwrap() {
                data[key] = value.clone();
            }
        }
        let observed = client_error(Some(data), None, false).await;
        let detail = &observed["fileRecovery"];
        assert_eq!(detail["category"], category);
        assert_eq!(detail["reason"], reason);
        assert_eq!(detail["stage"], "authorize_upload");
        assert_eq!(detail["publication_attempted"], false);
        assert_eq!(
            detail["retryable"],
            !matches!(reason, "file_too_large" | "unsupported_type")
        );
        assert_eq!(detail["retry_after_seconds"], 5);
        assert_eq!(detail[limit], value);
        assert!(detail.get("delivery_ids").is_none());
        let text = observed.to_string();
        for excluded in [
            "mcp-file:",
            "https:",
            "unreleased-credential",
            "raw diagnostic",
            FORGED,
        ] {
            assert!(!text.contains(excluded), "excluded file data escaped");
        }
    }
}

#[tokio::test]
async fn inspected_file_recovery_preserves_publication_uncertainty_and_owned_handles() {
    for publication in [Some(false), Some(true), None] {
        let mut error = json!({"code":"invalid_file_input", "message":"safe detail", "stage":"ingest",
            "delivery_ids":[FORGED], "uri":"mcp-file://printable/private", "token":"unreleased-credential"});
        if let Some(value) = publication {
            error["publication_attempted"] = json!(value);
        }
        let observed = client_error(None, Some(error), false).await;
        let detail = &observed["fileRecovery"];
        assert_eq!(detail["stage"], "ingest");
        assert_eq!(detail["delivery_ids"], json!([OWNED]));
        assert_eq!(
            detail.get("publication_attempted").cloned(),
            publication.map(Value::Bool)
        );
        assert_eq!(
            observed["toolError"],
            json!({"code":"invalid_file_input","message":"safe detail"})
        );
        assert!(!observed.to_string().contains(FORGED));
        assert!(!observed.to_string().contains("mcp-file:"));
        assert!(!observed.to_string().contains("unreleased-credential"));
    }
}

#[tokio::test]
async fn recovery_does_not_resurrect_facts_removed_by_inspection() {
    let observed = client_error(
        None,
        Some(json!({"code":"invalid_file_input", "message":"safe detail",
        "stage":"ingest", "publication_attempted":true})),
        true,
    )
    .await;
    let detail = &observed["fileRecovery"];
    assert!(detail.get("publication_attempted").is_none());
    assert!(detail.get("stage").is_none());
    assert_eq!(detail["delivery_ids"], json!([OWNED]));
}

#[test]
fn arbitrary_transport_error_data_cannot_claim_file_recovery() {
    let error = project_connector_result(Err(waygate_invocation::InvocationError::Upstream(
        McpError::internal_error("transport failed", Some(json!({"error":"temporarily_unavailable",
            "reason":"upload_capacity_exhausted", "stage":"authorize_upload", "publication_attempted":false,
            "file_recovery":{"reason":"unsupported_type"}, "uri":"mcp-file://private/token", "delivery_ids":[FORGED]}))),
    ))).unwrap_err();
    let observed = crate::process_mode::execute_recovery_error_for_test(error);
    assert_eq!(observed[0]["fileRecovery"], Value::Null);
    assert_eq!(observed[0]["message"], "transport failed");
    assert!(!observed.to_string().contains(FORGED));
    assert!(!observed.to_string().contains("mcp-file:"));
}
