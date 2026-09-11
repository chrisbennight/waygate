use std::sync::Arc;

use rmcp::model::{JsonObject, Tool};
use serde::Serialize;
use serde_json::json;
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::{CatalogTool, ToolFacts};

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    RemoteHttp,
    LocalUpstream,
    GatewayLocal,
}

#[derive(Clone)]
pub struct CorpusRecord {
    pub tool: CatalogTool,
    pub provenance: Provenance,
}

pub struct EvaluationScenario {
    pub id: &'static str,
    pub intent: &'static str,
    pub expected: &'static [&'static str],
    pub query_shape: QueryShape,
    pub invocation_steps: &'static [InvocationStep],
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryShape {
    DirectVocabulary,
    VocabularyGap,
    ExactSelector,
}

pub struct InvocationStep {
    pub tool: &'static str,
    pub query: &'static str,
    pub expected_outcome: &'static str,
}

fn schema(required: &[&str]) -> Arc<JsonObject> {
    let properties = required
        .iter()
        .map(|name| ((*name).to_owned(), json!({"type": "string"})))
        .collect::<JsonObject>();
    Arc::new(
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
        .as_object()
        .cloned()
        .expect("schema is an object"),
    )
}

fn upstream(
    server: &str,
    name: &str,
    title: &str,
    description: &str,
    provenance: Provenance,
    side_effects: bool,
) -> CorpusRecord {
    let tool = Tool::new(name.to_owned(), description.to_owned(), schema(&["query"]))
        .with_title(title.to_owned());
    CorpusRecord {
        tool: CatalogTool::upstream(
            server,
            &tool,
            ToolFacts {
                server: server.to_owned(),
                name: name.to_owned(),
                risk: if side_effects {
                    RiskTier::High
                } else {
                    RiskTier::Low
                },
                side_effects,
                pii: false,
                requires_approval: side_effects,
                requires_approval_known: true,
            },
        )
        .expect("evaluation fixture schema must satisfy catalog admission"),
        provenance,
    }
}

fn builtin(namespace: &str, name: &str, title: &str, description: &str) -> CorpusRecord {
    let qualified = format!("{namespace}.{name}");
    CorpusRecord {
        tool: CatalogTool::builtin(
            namespace,
            Tool::new(qualified, description.to_owned(), schema(&["query"]))
                .with_title(title.to_owned()),
            RiskTier::Low,
            false,
            false,
        ),
        provenance: Provenance::GatewayLocal,
    }
}

pub fn representative_corpus() -> Vec<CorpusRecord> {
    vec![
        upstream(
            "kagi",
            "kagi_search_fetch",
            "Search the web",
            "Find web sources for a natural-language query.",
            Provenance::RemoteHttp,
            false,
        ),
        upstream(
            "kagi",
            "kagi_extract",
            "Extract a web page",
            "Extract readable page content from an HTTPS URL.",
            Provenance::RemoteHttp,
            false,
        ),
        upstream(
            "knowledge",
            "list_citations",
            "List stored citations",
            "Catalog cached online information. It cannot discover live web sources.",
            Provenance::RemoteHttp,
            false,
        ),
        upstream(
            "github",
            "create_issue",
            "Create an issue",
            "Create a tracked repository issue with a title and body.",
            Provenance::RemoteHttp,
            true,
        ),
        upstream(
            "github",
            "get_file_contents",
            "Read repository content",
            "Read one file from a repository revision.",
            Provenance::RemoteHttp,
            false,
        ),
        upstream(
            "grafana",
            "query_loki",
            "Query service logs",
            "Investigate recent service errors in structured logs.",
            Provenance::RemoteHttp,
            false,
        ),
        upstream(
            "payments",
            "refund_charge",
            "Refund a charge",
            "Refund a customer payment charge.",
            Provenance::RemoteHttp,
            true,
        ),
        upstream(
            "crm",
            "lookup_purchase",
            "Look up a purchase",
            "Find purchaser records when support is asked to reimburse a customer. Returns customer payment metadata but cannot refund a charge.",
            Provenance::RemoteHttp,
            false,
        ),
        upstream(
            "local-fs",
            "read_file",
            "Read a local file",
            "Read a bounded file from an allowed local workspace.",
            Provenance::LocalUpstream,
            false,
        ),
        upstream(
            "local-fs",
            "find_document",
            "Find document metadata",
            "Locate nearby document metadata in an allowed local workspace. Returns file names but does not open or read file content.",
            Provenance::LocalUpstream,
            false,
        ),
        upstream(
            "local-admin",
            "tail_logs",
            "Read local service logs",
            "Inspect recent errors from a local service log stream.",
            Provenance::LocalUpstream,
            false,
        ),
        builtin(
            "gateway-discovery",
            "search",
            "Search governed tools",
            "Find authorized upstream and gateway-local tools across sources.",
        ),
        builtin(
            "gateway-discovery",
            "inspect",
            "Inspect a governed tool",
            "Inspect the exact current governed tool contract and schema.",
        ),
        builtin(
            "gateway-observe",
            "triage_digest",
            "Triage gateway health",
            "Summarize gateway health, recent errors, and operational evidence.",
        ),
    ]
}

pub fn representative_scenarios() -> Vec<EvaluationScenario> {
    vec![
        EvaluationScenario {
            id: "unknown_server_web_research",
            intent: "find web sources and extract page content",
            expected: &["kagi.kagi_search_fetch", "kagi.kagi_extract"],
            query_shape: QueryShape::DirectVocabulary,
            invocation_steps: &[
                InvocationStep {
                    tool: "kagi.kagi_search_fetch",
                    query: "MCP retrieval evaluation",
                    expected_outcome: "web_results:MCP retrieval evaluation",
                },
                InvocationStep {
                    tool: "kagi.kagi_extract",
                    query: "https://example.invalid/retrieval-evaluation",
                    expected_outcome: "extracted:https://example.invalid/retrieval-evaluation",
                },
            ],
        },
        EvaluationScenario {
            id: "cross_server_incident_triage",
            intent: "investigate recent service errors and logs",
            expected: &[
                "grafana.query_loki",
                "local-admin.tail_logs",
                "gateway-observe.triage_digest",
            ],
            query_shape: QueryShape::DirectVocabulary,
            invocation_steps: &[
                InvocationStep {
                    tool: "grafana.query_loki",
                    query: "gateway errors",
                    expected_outcome: "remote_logs:gateway errors",
                },
                InvocationStep {
                    tool: "local-admin.tail_logs",
                    query: "gateway errors",
                    expected_outcome: "local_logs:gateway errors",
                },
                InvocationStep {
                    tool: "gateway-observe.triage_digest",
                    query: "gateway errors",
                    expected_outcome: "health_digest:gateway errors",
                },
            ],
        },
        EvaluationScenario {
            id: "gateway_local_contract_inspection",
            intent: "inspect the exact governed tool contract",
            expected: &["gateway-discovery.inspect"],
            query_shape: QueryShape::DirectVocabulary,
            invocation_steps: &[InvocationStep {
                tool: "gateway-discovery.inspect",
                query: "kagi.kagi_search_fetch",
                expected_outcome: "inspected:kagi.kagi_search_fetch",
            }],
        },
        EvaluationScenario {
            id: "exact_selector",
            intent: "github.get_file_contents",
            expected: &["github.get_file_contents"],
            query_shape: QueryShape::ExactSelector,
            invocation_steps: &[InvocationStep {
                tool: "github.get_file_contents",
                query: "docs/tool-discovery.md",
                expected_outcome: "repository_file:docs/tool-discovery.md",
            }],
        },
        EvaluationScenario {
            id: "local_upstream_file_read",
            intent: "read a local workspace file",
            expected: &["local-fs.read_file"],
            query_shape: QueryShape::DirectVocabulary,
            invocation_steps: &[InvocationStep {
                tool: "local-fs.read_file",
                query: "docs/tool-discovery.md",
                expected_outcome: "file_read:docs/tool-discovery.md",
            }],
        },
        EvaluationScenario {
            id: "vocabulary_gap_web_lookup",
            intent: "discover live online information",
            expected: &["kagi.kagi_search_fetch"],
            query_shape: QueryShape::VocabularyGap,
            invocation_steps: &[InvocationStep {
                tool: "kagi.kagi_search_fetch",
                query: "MCP retrieval evaluation",
                expected_outcome: "web_results:MCP retrieval evaluation",
            }],
        },
        EvaluationScenario {
            id: "vocabulary_gap_refund",
            intent: "reimburse purchaser",
            expected: &["payments.refund_charge"],
            query_shape: QueryShape::VocabularyGap,
            invocation_steps: &[InvocationStep {
                tool: "payments.refund_charge",
                query: "charge-fixture-42",
                expected_outcome: "charge_refunded:charge-fixture-42",
            }],
        },
        EvaluationScenario {
            id: "vocabulary_gap_local_document",
            intent: "open nearby document",
            expected: &["local-fs.read_file"],
            query_shape: QueryShape::VocabularyGap,
            invocation_steps: &[InvocationStep {
                tool: "local-fs.read_file",
                query: "docs/tool-discovery.md",
                expected_outcome: "file_read:docs/tool-discovery.md",
            }],
        },
    ]
}

pub fn qualified(tool: &CatalogTool) -> String {
    tool.identity.qualified_name()
}

pub fn contract_bytes(tools: &[CatalogTool]) -> usize {
    tools
        .iter()
        .map(|tool| {
            serde_json::to_vec(&tool.definition)
                .expect("tool definition serializes")
                .len()
        })
        .sum()
}
