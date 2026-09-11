//! Compare the production lexical ranker with a deterministic local semantic
//! candidate over one already-authorized catalog projection.
//!
//! The candidate is evaluation-only: it derives latent semantic vectors from
//! the current catalog text in process, fuses that ordering with the production
//! BM25 ordering, and performs no network or model-provider call. The report is
//! evidence for a product decision, not an automatic promotion mechanism.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use rmcp::model::{CallToolResult, JsonObject, Tool};
use rmcp::ErrorData as McpError;
use serde::Serialize;
use serde_json::{json, Value};
use waygate_mcp::catalog::{
    InvocationContractIdentity, InvocationToolSnapshot, ResolvedInvocationTool,
};
use waygate_mcp::{
    rank_visible_tools, AllowAllGate, AuthorizedCatalog, BuiltinCatalog, BuiltinRegistry,
    BuiltinTools, CatalogChannel, CatalogTool, CatalogToolSource, DefaultInvocationService,
    InvocationError, InvocationRequest, InvocationResponse, InvocationService, NullSink,
    SharedBuiltinTools, UpstreamCatalog,
};

mod discovery_evaluation_support;
use discovery_evaluation_support::{
    contract_bytes, qualified, representative_corpus, representative_scenarios, EvaluationScenario,
    InvocationStep, Provenance, QueryShape,
};

const RESULT_LIMIT: usize = 5;
const LATENT_COMPONENTS: usize = 4;
const RRF_OFFSET: f64 = 60.0;

#[derive(Clone)]
struct FixtureCatalog {
    tools: Vec<CatalogTool>,
}

impl FixtureCatalog {
    fn upstream_tool(&self, server: &str, name: &str) -> Option<&CatalogTool> {
        self.tools.iter().find(|tool| {
            matches!(&tool.identity.source, CatalogToolSource::Upstream(source) if source == server)
                && tool.identity.name == name
        })
    }

    fn snapshot(&self, server: &str, name: &str) -> Option<InvocationToolSnapshot> {
        let tool = self.upstream_tool(server, name)?;
        let mut definition = tool.definition.clone();
        definition.name = tool.identity.name.clone().into();
        Some(
            InvocationToolSnapshot::manifest_fallback(tool.facts.clone(), true)
                .with_published_definition(Some(definition)),
        )
    }
}

#[async_trait]
impl UpstreamCatalog for FixtureCatalog {
    async fn list_servers(&self) -> Vec<String> {
        self.tools
            .iter()
            .filter_map(|tool| match &tool.identity.source {
                CatalogToolSource::Upstream(server) => Some(server.clone()),
                CatalogToolSource::Builtin(_) => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        Ok(self
            .tools
            .iter()
            .filter(|tool| {
                matches!(&tool.identity.source, CatalogToolSource::Upstream(source) if source == server)
            })
            .map(|tool| {
                let mut definition = tool.definition.clone();
                definition.name = tool.identity.name.clone().into();
                definition
            })
            .collect())
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        self.snapshot(server, tool_name).map_or_else(
            || ResolvedInvocationTool::Unavailable {
                server: server.to_owned(),
                tool: tool_name.to_owned(),
            },
            ResolvedInvocationTool::Ready,
        )
    }

    async fn call_tool(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<JsonObject>,
        _principal: Option<&waygate_oidc::Principal>,
        admitted: Option<&InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        let snapshot = self
            .snapshot(server, tool_name)
            .ok_or_else(|| McpError::invalid_params("fixture tool is unavailable", None))?;
        if admitted != Some(&snapshot.contract_identity()) {
            return Err(McpError::invalid_params(
                "fixture contract changed before dispatch",
                None,
            ));
        }
        fixture_result(&format!("{server}.{tool_name}"), args.as_ref())
            .map(CallToolResult::structured)
            .ok_or_else(|| McpError::invalid_params("fixture arguments are not executable", None))
    }
}

struct FixtureBuiltins {
    catalog: BuiltinCatalog,
}

#[async_trait]
impl BuiltinTools for FixtureBuiltins {
    fn namespace(&self) -> &str {
        &self.catalog.namespace
    }

    fn catalog(&self) -> BuiltinCatalog {
        self.catalog.clone()
    }

    async fn list_tools(&self, _principal: Option<&waygate_oidc::Principal>) -> Vec<Tool> {
        self.catalog.definitions()
    }

    async fn call(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        _principal: Option<&waygate_oidc::Principal>,
    ) -> Result<CallToolResult, McpError> {
        fixture_result(
            &format!("{}.{}", self.catalog.namespace, tool),
            arguments.as_ref(),
        )
        .map(CallToolResult::structured)
        .ok_or_else(|| McpError::invalid_params("fixture arguments are not executable", None))
    }
}

struct EvaluationGateway {
    authorized: AuthorizedCatalog,
    invocation: DefaultInvocationService,
    builtins: Vec<SharedBuiltinTools>,
    principal: waygate_oidc::Principal,
}

enum FixtureInvokeOutcome {
    Completed(Value),
    ApprovalRequired,
}

impl EvaluationGateway {
    fn new(catalog: &[CatalogTool]) -> Self {
        let upstream: Arc<dyn UpstreamCatalog> = Arc::new(FixtureCatalog {
            tools: catalog.to_vec(),
        });
        let authz = Arc::new(AllowAllGate);
        let mut by_namespace = BTreeMap::<String, Vec<CatalogTool>>::new();
        for tool in catalog {
            if let CatalogToolSource::Builtin(namespace) = &tool.identity.source {
                by_namespace
                    .entry(namespace.clone())
                    .or_default()
                    .push(tool.clone());
            }
        }
        let builtins = by_namespace
            .into_iter()
            .map(|(namespace, tools)| {
                Arc::new(FixtureBuiltins {
                    catalog: BuiltinCatalog::new(
                        namespace,
                        "evaluation",
                        "Deterministic evaluation fixture",
                        tools,
                    ),
                }) as SharedBuiltinTools
            })
            .collect::<Vec<_>>();
        let registry = BuiltinRegistry::default();
        registry.replace(&builtins);
        Self {
            authorized: AuthorizedCatalog::new(Arc::clone(&upstream), authz.clone(), registry),
            invocation: DefaultInvocationService::new(upstream, authz, Arc::new(NullSink)),
            builtins,
            principal: waygate_oidc::Principal {
                sub: "retrieval-evaluation".to_owned(),
                email: None,
                groups: vec!["evaluation".to_owned()],
                issuer: "https://evaluation.invalid".to_owned(),
                scopes: vec!["mcp:read".to_owned(), "mcp:invoke".to_owned()],
                tenant: waygate_core::TenantId::default(),
                auth_method: waygate_oidc::AuthMethod::Oauth,
                raw_token: None,
                scim: None,
                enrichment_blocked: None,
                api_key_profile_restrictions: None,
                roles: vec!["reader".to_owned()],
            },
        }
    }

    async fn inspect(&self, selected: &CatalogTool) -> Option<CatalogTool> {
        self.authorized
            .visible_tool(
                Some(&self.principal),
                CatalogChannel::Direct,
                &selected.identity.source,
                &selected.identity.name,
            )
            .await
    }

    async fn invoke(
        &self,
        inspected: &CatalogTool,
        arguments: JsonObject,
    ) -> Option<FixtureInvokeOutcome> {
        let result = match &inspected.identity.source {
            CatalogToolSource::Upstream(server) => {
                let expected = inspected.invocation_snapshot()?.contract_identity();
                match self
                    .invocation
                    .invoke(
                        Some(&self.principal),
                        InvocationRequest::new(server, &inspected.identity.name)
                            .with_arguments(Some(arguments))
                            .with_expected_contract(expected),
                    )
                    .await
                {
                    Ok(InvocationResponse::Unary(result)) => result,
                    Err(InvocationError::ApprovalRequired { .. }) => {
                        return Some(FixtureInvokeOutcome::ApprovalRequired)
                    }
                    Err(_) => return None,
                    Ok(InvocationResponse::InputRequired(_))
                    | Ok(InvocationResponse::UnaryValue(_))
                    | Ok(InvocationResponse::Stream(_)) => return None,
                }
            }
            CatalogToolSource::Builtin(namespace) => {
                let builtin = self
                    .builtins
                    .iter()
                    .find(|builtin| builtin.namespace() == namespace)?;
                builtin
                    .call(
                        &inspected.identity.name,
                        Some(arguments),
                        Some(&self.principal),
                    )
                    .await
                    .ok()?
            }
        };
        result
            .structured_content
            .map(FixtureInvokeOutcome::Completed)
    }
}

fn fixture_result(tool: &str, arguments: Option<&JsonObject>) -> Option<Value> {
    let query = arguments?.get("query")?.as_str()?;
    let outcome = match tool {
        "kagi.kagi_search_fetch" => format!("web_results:{query}"),
        "kagi.kagi_extract" => format!("extracted:{query}"),
        "github.get_file_contents" => format!("repository_file:{query}"),
        "grafana.query_loki" => format!("remote_logs:{query}"),
        "payments.refund_charge" => format!("charge_refunded:{query}"),
        "local-fs.read_file" => format!("file_read:{query}"),
        "local-admin.tail_logs" => format!("local_logs:{query}"),
        "gateway-discovery.inspect" => format!("inspected:{query}"),
        "gateway-observe.triage_digest" => format!("health_digest:{query}"),
        _ => return None,
    };
    Some(json!({"outcome": outcome}))
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Strategy {
    LexicalBaseline,
    LocalLsaHybrid,
}

#[derive(Serialize)]
struct ExpectedRank {
    name: String,
    rank: Option<usize>,
}

#[derive(Serialize)]
struct ScenarioReport {
    id: &'static str,
    intent: &'static str,
    query_shape: QueryShape,
    expected_ranks: Vec<ExpectedRank>,
    top_results: Vec<String>,
    reciprocal_rank: f64,
    recall_at_limit: f64,
    expected_contract_term_overlap: usize,
    exact_contracts_inspected: bool,
    intended_arguments_validated: bool,
    oracle_invocation_paths_completed: bool,
    approval_gate_enforced: bool,
    retrieval_and_invocation_smoke_completed: bool,
    selected_contract_bytes: usize,
    ranking_duration_microseconds: u64,
}

#[derive(Serialize)]
struct ResourceReport {
    index_build_duration_microseconds: u64,
    estimated_index_bytes: usize,
    vocabulary_terms: usize,
    latent_components: usize,
}

#[derive(Serialize)]
struct StrategyReport {
    strategy: Strategy,
    scenarios: Vec<ScenarioReport>,
    mean_reciprocal_rank: f64,
    mean_recall_at_limit: f64,
    retrieval_and_invocation_smoke_scenarios: usize,
    total_ranking_duration_microseconds: u64,
    resource: ResourceReport,
}

#[derive(Serialize)]
struct ComparisonReport {
    mean_reciprocal_rank_delta: f64,
    mean_recall_at_limit_delta: f64,
    retrieval_and_invocation_smoke_scenarios_delta: isize,
    ranking_duration_microseconds_delta: i128,
    estimated_index_bytes_delta: isize,
    candidate_improves_retrieval_evidence: bool,
}

#[derive(Serialize)]
struct LifecycleReport {
    same_authorized_catalog_projection: bool,
    authorization_isolation_passed: bool,
    exact_selector_passed: bool,
    add_rebuild_includes_new_tool: bool,
    description_rebuild_changes_model: bool,
    remove_rebuild_excludes_removed_tool: bool,
    unavailable_candidate_matches_lexical_fallback: bool,
}

#[derive(Serialize)]
struct DataHandlingReport {
    query_and_tool_text_leave_process: bool,
    external_model_or_provider: bool,
    new_dependency: bool,
    reproducibility: &'static str,
}

#[derive(Serialize)]
struct EvaluationScopeReport {
    retrieval_metrics_are_component_level: bool,
    invocation_steps_are_oracle_selected: bool,
    independent_tool_selection_evaluated: bool,
    end_to_end_task_completion_evaluated: bool,
}

#[derive(Serialize)]
struct DecisionReport {
    recorded_decision: &'static str,
    rationale: Vec<&'static str>,
    production_adoption_requires: Vec<&'static str>,
}

#[derive(Serialize)]
struct EvaluationReport {
    contract_version: &'static str,
    result_limit: usize,
    catalog_tools: usize,
    corpus_by_provenance: BTreeMap<&'static str, usize>,
    strategies: Vec<StrategyReport>,
    comparison: ComparisonReport,
    vocabulary_gap_scenarios_are_discriminating: bool,
    vocabulary_gap_queries_are_in_candidate_vocabulary: bool,
    semantic_candidate_is_exercised_on_vocabulary_gaps: bool,
    governed_invocation_path_is_exercised: bool,
    approval_boundary_is_exercised: bool,
    lifecycle: LifecycleReport,
    data_handling: DataHandlingReport,
    evaluation_scope: EvaluationScopeReport,
    decision: DecisionReport,
    contract_checks_passed: bool,
}

struct LatentComponent {
    term_vector: Vec<f64>,
}

struct LocalLsaModel {
    vocabulary: Vec<String>,
    inverse_document_frequency: Vec<f64>,
    document_coordinates: Vec<Vec<f64>>,
    components: Vec<LatentComponent>,
    fingerprint: u64,
}

impl LocalLsaModel {
    fn build(catalog: &[CatalogTool]) -> Self {
        let documents = catalog.iter().map(candidate_terms).collect::<Vec<_>>();
        let mut document_frequency = BTreeMap::<String, usize>::new();
        for document in &documents {
            for term in document.iter().collect::<BTreeSet<_>>() {
                *document_frequency.entry(term.clone()).or_default() += 1;
            }
        }
        let vocabulary = document_frequency.keys().cloned().collect::<Vec<_>>();
        let term_index = vocabulary
            .iter()
            .enumerate()
            .map(|(index, term)| (term.as_str(), index))
            .collect::<HashMap<_, _>>();
        let document_count = documents.len() as f64;
        let inverse_document_frequency = vocabulary
            .iter()
            .map(|term| {
                let containing = document_frequency.get(term).copied().unwrap_or_default() as f64;
                ((document_count + 1.0) / (containing + 1.0)).ln() + 1.0
            })
            .collect::<Vec<_>>();
        let matrix = documents
            .iter()
            .map(|document| {
                let mut frequencies = HashMap::<&str, usize>::new();
                for term in document {
                    *frequencies.entry(term).or_default() += 1;
                }
                let mut row = vec![0.0; vocabulary.len()];
                for (term, frequency) in frequencies {
                    if let Some(index) = term_index.get(term) {
                        row[*index] =
                            (1.0 + (frequency as f64).ln()) * inverse_document_frequency[*index];
                    }
                }
                row
            })
            .collect::<Vec<_>>();
        let gram = matrix
            .iter()
            .map(|left| matrix.iter().map(|right| dot(left, right)).collect())
            .collect::<Vec<Vec<f64>>>();
        let (eigenvalues, eigenvectors) = jacobi_eigendecomposition(gram);
        let mut ordered = eigenvalues
            .into_iter()
            .enumerate()
            .filter(|(_, value)| value.is_finite() && *value > 1e-9)
            .collect::<Vec<_>>();
        ordered.sort_by(|left, right| right.1.total_cmp(&left.1));
        ordered.truncate(LATENT_COMPONENTS.min(catalog.len()));

        let mut document_coordinates = vec![Vec::new(); catalog.len()];
        let mut components = Vec::new();
        for (column, eigenvalue) in ordered {
            let singular_value = eigenvalue.sqrt();
            let document_vector = eigenvectors
                .iter()
                .map(|row| row[column])
                .collect::<Vec<_>>();
            let mut term_vector = vec![0.0; vocabulary.len()];
            for (term, value) in term_vector.iter_mut().enumerate() {
                *value = matrix
                    .iter()
                    .zip(&document_vector)
                    .map(|(document, component)| document[term] * component)
                    .sum::<f64>()
                    / singular_value;
            }
            for (document, coordinate) in document_coordinates.iter_mut().enumerate() {
                coordinate.push(singular_value * document_vector[document]);
            }
            components.push(LatentComponent { term_vector });
        }

        let fingerprint = vocabulary
            .iter()
            .flat_map(|term| term.as_bytes().iter().copied().chain([0]))
            .fold(0xcbf29ce484222325_u64, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
            });
        let fingerprint = matrix.iter().flatten().fold(fingerprint, |hash, value| {
            (hash ^ value.to_bits()).wrapping_mul(0x100000001b3)
        });
        Self {
            vocabulary,
            inverse_document_frequency,
            document_coordinates,
            components,
            fingerprint,
        }
    }

    fn semantic_ranks(&self, query: &str) -> Vec<(usize, f64)> {
        let term_index = self
            .vocabulary
            .iter()
            .enumerate()
            .map(|(index, term)| (term.as_str(), index))
            .collect::<HashMap<_, _>>();
        let mut frequencies = HashMap::<String, usize>::new();
        for term in tokens(query) {
            *frequencies.entry(term).or_default() += 1;
        }
        let mut query_vector = vec![0.0; self.vocabulary.len()];
        for (term, frequency) in frequencies {
            if let Some(index) = term_index.get(term.as_str()) {
                query_vector[*index] =
                    (1.0 + (frequency as f64).ln()) * self.inverse_document_frequency[*index];
            }
        }
        let query_coordinates = self
            .components
            .iter()
            .map(|component| dot(&query_vector, &component.term_vector))
            .collect::<Vec<_>>();
        let mut ranked = self
            .document_coordinates
            .iter()
            .enumerate()
            .filter_map(|(index, coordinates)| {
                let score = cosine(&query_coordinates, coordinates);
                (score.is_finite() && score > 0.0).then_some((index, score))
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        ranked
    }

    fn query_has_known_terms(&self, query: &str) -> bool {
        let vocabulary = self
            .vocabulary
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let query_terms = tokens(query);
        !query_terms.is_empty()
            && query_terms
                .iter()
                .all(|term| vocabulary.contains(term.as_str()))
    }

    fn estimated_bytes(&self) -> usize {
        let scalar_count = self.inverse_document_frequency.len()
            + self
                .document_coordinates
                .iter()
                .map(Vec::len)
                .sum::<usize>()
            + self
                .components
                .iter()
                .map(|component| component.term_vector.len())
                .sum::<usize>();
        scalar_count * std::mem::size_of::<f64>()
            + self.vocabulary.iter().map(String::len).sum::<usize>()
    }
}

fn tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn candidate_terms(tool: &CatalogTool) -> Vec<String> {
    let mut terms = tokens(&tool.identity.qualified_name());
    terms.extend(tokens(tool.identity.source.name()));
    if let Some(title) = tool.definition.title.as_deref() {
        terms.extend(tokens(title));
    }
    if let Some(description) = tool.definition.description.as_deref() {
        terms.extend(tokens(description));
    }
    terms
}

fn dot(left: &[f64], right: &[f64]) -> f64 {
    left.iter()
        .zip(right)
        .map(|(left, right)| left * right)
        .sum()
}

fn cosine(left: &[f64], right: &[f64]) -> f64 {
    let denominator = dot(left, left).sqrt() * dot(right, right).sqrt();
    if denominator <= f64::EPSILON {
        0.0
    } else {
        dot(left, right) / denominator
    }
}

fn jacobi_eigendecomposition(mut matrix: Vec<Vec<f64>>) -> (Vec<f64>, Vec<Vec<f64>>) {
    let size = matrix.len();
    let mut vectors = vec![vec![0.0; size]; size];
    for (index, row) in vectors.iter_mut().enumerate() {
        row[index] = 1.0;
    }
    for _ in 0..size.saturating_mul(size).saturating_mul(64) {
        let mut pivot = None;
        let mut row = 0;
        while row < size {
            let mut column = row + 1;
            while column < size {
                let magnitude = matrix[row][column].abs();
                if pivot.is_none_or(|(_, _, largest)| magnitude > largest) {
                    pivot = Some((row, column, magnitude));
                }
                column += 1;
            }
            row += 1;
        }
        let Some((left, right, magnitude)) = pivot else {
            break;
        };
        if magnitude <= 1e-10 {
            break;
        }
        let angle =
            0.5 * (2.0 * matrix[left][right]).atan2(matrix[right][right] - matrix[left][left]);
        let cosine = angle.cos();
        let sine = angle.sin();
        let left_diagonal = matrix[left][left];
        let right_diagonal = matrix[right][right];
        let cross = matrix[left][right];
        let mut index = 0;
        while index < size {
            if index == left || index == right {
                index += 1;
                continue;
            }
            let left_value = matrix[index][left];
            let right_value = matrix[index][right];
            let rotated_left = cosine * left_value - sine * right_value;
            let rotated_right = sine * left_value + cosine * right_value;
            matrix[index][left] = rotated_left;
            matrix[left][index] = rotated_left;
            matrix[index][right] = rotated_right;
            matrix[right][index] = rotated_right;
            index += 1;
        }
        matrix[left][left] = cosine * cosine * left_diagonal - 2.0 * sine * cosine * cross
            + sine * sine * right_diagonal;
        matrix[right][right] = sine * sine * left_diagonal
            + 2.0 * sine * cosine * cross
            + cosine * cosine * right_diagonal;
        matrix[left][right] = 0.0;
        matrix[right][left] = 0.0;
        for row in &mut vectors {
            let left_value = row[left];
            let right_value = row[right];
            row[left] = cosine * left_value - sine * right_value;
            row[right] = sine * left_value + cosine * right_value;
        }
    }
    (
        (0..size).map(|index| matrix[index][index]).collect(),
        vectors,
    )
}

fn hybrid_rank(
    query: &str,
    catalog: &[CatalogTool],
    semantic_model: Option<&LocalLsaModel>,
) -> Vec<CatalogTool> {
    let lexical = rank_visible_tools(query, catalog.to_vec());
    let normalized_query = query.to_lowercase();
    if lexical.len() == 1 && lexical[0].identity.qualified_name().to_lowercase() == normalized_query
    {
        return lexical;
    }
    let Some(semantic_model) = semantic_model else {
        return lexical;
    };
    let mut scores = HashMap::<String, f64>::new();
    for (rank, tool) in lexical.iter().enumerate() {
        *scores.entry(qualified(tool)).or_default() += 1.0 / (RRF_OFFSET + rank as f64 + 1.0);
    }
    for (rank, (index, _)) in semantic_model.semantic_ranks(query).into_iter().enumerate() {
        *scores.entry(qualified(&catalog[index])).or_default() +=
            1.0 / (RRF_OFFSET + rank as f64 + 1.0);
    }
    let mut ranked = catalog
        .iter()
        .filter_map(|tool| {
            scores
                .get(&qualified(tool))
                .map(|score| (tool.clone(), *score))
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(left_tool, left_score), (right_tool, right_score)| {
        right_score
            .total_cmp(left_score)
            .then_with(|| qualified(left_tool).cmp(&qualified(right_tool)))
    });
    ranked.into_iter().map(|(tool, _)| tool).collect()
}

async fn evaluate_scenario(
    scenario: &EvaluationScenario,
    gateway: &EvaluationGateway,
    ranker: impl FnOnce(&str) -> Vec<CatalogTool>,
) -> ScenarioReport {
    let started = Instant::now();
    let ranked = ranker(scenario.intent);
    let duration = started.elapsed();
    let names = ranked.iter().map(qualified).collect::<Vec<_>>();
    let expected_ranks = scenario
        .expected
        .iter()
        .map(|expected| ExpectedRank {
            name: (*expected).to_owned(),
            rank: names
                .iter()
                .position(|candidate| candidate == expected)
                .map(|rank| rank + 1),
        })
        .collect::<Vec<_>>();
    let reciprocal_rank = expected_ranks
        .iter()
        .filter_map(|expected| expected.rank)
        .min()
        .map_or(0.0, |rank| 1.0 / rank as f64);
    let recalled = expected_ranks
        .iter()
        .filter(|expected| expected.rank.is_some_and(|rank| rank <= RESULT_LIMIT))
        .count();
    let expected_tools_in_working_set = expected_ranks
        .iter()
        .all(|expected| expected.rank.is_some_and(|rank| rank <= RESULT_LIMIT));
    let expected_contract_term_overlap = expected_term_overlap(scenario, &ranked);
    let (
        exact_contracts_inspected,
        intended_arguments_validated,
        oracle_invocation_paths_completed,
        approval_gate_enforced,
    ) = evaluate_oracle_invocation_paths(gateway, &ranked, scenario.invocation_steps).await;
    let retrieval_and_invocation_smoke_completed = expected_tools_in_working_set
        && exact_contracts_inspected
        && intended_arguments_validated
        && oracle_invocation_paths_completed;
    ScenarioReport {
        id: scenario.id,
        intent: scenario.intent,
        query_shape: scenario.query_shape,
        expected_ranks,
        top_results: names.into_iter().take(RESULT_LIMIT).collect(),
        reciprocal_rank,
        recall_at_limit: recalled as f64 / scenario.expected.len().max(1) as f64,
        expected_contract_term_overlap,
        exact_contracts_inspected,
        intended_arguments_validated,
        oracle_invocation_paths_completed,
        approval_gate_enforced,
        retrieval_and_invocation_smoke_completed,
        selected_contract_bytes: contract_bytes(
            &ranked.into_iter().take(RESULT_LIMIT).collect::<Vec<_>>(),
        ),
        ranking_duration_microseconds: u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
    }
}

fn expected_term_overlap(scenario: &EvaluationScenario, ranked: &[CatalogTool]) -> usize {
    let query_terms = tokens(scenario.intent).into_iter().collect::<BTreeSet<_>>();
    ranked
        .iter()
        .filter(|tool| scenario.expected.contains(&qualified(tool).as_str()))
        .flat_map(candidate_terms)
        .filter(|term| query_terms.contains(term))
        .collect::<BTreeSet<_>>()
        .len()
}

// The scenario supplies the expected tool and arguments. This verifies that a
// retrieved capability can traverse the governed gateway path; it does not
// evaluate independent client selection or end-to-end task success.
async fn evaluate_oracle_invocation_paths(
    gateway: &EvaluationGateway,
    ranked: &[CatalogTool],
    steps: &[InvocationStep],
) -> (bool, bool, bool, bool) {
    let mut exact_contracts_inspected = true;
    let mut intended_arguments_validated = true;
    let mut oracle_invocation_paths_completed = true;
    let mut approval_gate_enforced = false;
    for step in steps {
        let Some(tool) = ranked
            .iter()
            .take(RESULT_LIMIT)
            .find(|tool| qualified(tool) == step.tool)
        else {
            return (false, false, false, false);
        };
        let Some(inspected) = gateway.inspect(tool).await else {
            return (false, false, false, false);
        };
        let inspected_contract = serde_json::to_value(&inspected.definition);
        exact_contracts_inspected &= inspected_contract.is_ok();
        let arguments = json!({"query": step.query});
        let schema = Value::Object(inspected.definition.input_schema.as_ref().clone());
        let arguments_are_valid = jsonschema::validator_for(&schema)
            .is_ok_and(|validator| validator.is_valid(&arguments));
        intended_arguments_validated &= arguments_are_valid;
        let arguments = arguments.as_object().cloned().unwrap_or_default();
        let invocation_completed = arguments_are_valid
            && match gateway.invoke(&inspected, arguments).await {
                Some(FixtureInvokeOutcome::Completed(result)) => {
                    result.get("outcome").and_then(Value::as_str) == Some(step.expected_outcome)
                }
                Some(FixtureInvokeOutcome::ApprovalRequired) => {
                    approval_gate_enforced = true;
                    false
                }
                None => false,
            };
        oracle_invocation_paths_completed &= invocation_completed;
    }
    (
        exact_contracts_inspected,
        intended_arguments_validated,
        oracle_invocation_paths_completed,
        approval_gate_enforced,
    )
}

async fn strategy_report(
    strategy: Strategy,
    scenarios: &[EvaluationScenario],
    catalog: &[CatalogTool],
    gateway: &EvaluationGateway,
    semantic_model: Option<&LocalLsaModel>,
    resource: ResourceReport,
) -> StrategyReport {
    let mut reports = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        reports.push(
            evaluate_scenario(scenario, gateway, |query| match strategy {
                Strategy::LexicalBaseline => rank_visible_tools(query, catalog.to_vec()),
                Strategy::LocalLsaHybrid => hybrid_rank(query, catalog, semantic_model),
            })
            .await,
        );
    }
    let count = reports.len().max(1) as f64;
    StrategyReport {
        strategy,
        mean_reciprocal_rank: reports
            .iter()
            .map(|scenario| scenario.reciprocal_rank)
            .sum::<f64>()
            / count,
        mean_recall_at_limit: reports
            .iter()
            .map(|scenario| scenario.recall_at_limit)
            .sum::<f64>()
            / count,
        retrieval_and_invocation_smoke_scenarios: reports
            .iter()
            .filter(|scenario| scenario.retrieval_and_invocation_smoke_completed)
            .count(),
        total_ranking_duration_microseconds: reports
            .iter()
            .map(|scenario| scenario.ranking_duration_microseconds)
            .sum(),
        scenarios: reports,
        resource,
    }
}

fn lifecycle_report(catalog: &[CatalogTool], model: &LocalLsaModel) -> LifecycleReport {
    let restricted = catalog
        .iter()
        .filter(|tool| qualified(tool) != "payments.refund_charge")
        .cloned()
        .collect::<Vec<_>>();
    let restricted_model = LocalLsaModel::build(&restricted);
    let authorization_isolation_passed = [
        rank_visible_tools("refund customer charge", restricted.clone()),
        hybrid_rank(
            "refund customer charge",
            &restricted,
            Some(&restricted_model),
        ),
    ]
    .into_iter()
    .flatten()
    .all(|tool| qualified(&tool) != "payments.refund_charge");

    let exact_selector_passed = hybrid_rank("github.get_file_contents", catalog, Some(model))
        .first()
        .is_some_and(|tool| qualified(tool) == "github.get_file_contents");

    let before_add = catalog
        .iter()
        .filter(|tool| qualified(tool) != "kagi.kagi_extract")
        .cloned()
        .collect::<Vec<_>>();
    let before_add_model = LocalLsaModel::build(&before_add);
    let after_add_model = LocalLsaModel::build(catalog);
    let add_rebuild_includes_new_tool = before_add_model.document_coordinates.len() + 1
        == after_add_model.document_coordinates.len()
        && hybrid_rank("extract readable web page", catalog, Some(&after_add_model))
            .iter()
            .any(|tool| qualified(tool) == "kagi.kagi_extract");

    let mut changed = catalog.to_vec();
    if let Some(tool) = changed
        .iter_mut()
        .find(|tool| qualified(tool) == "payments.refund_charge")
    {
        tool.definition.description = Some(
            "Reverse a settled transaction and return customer funds."
                .to_owned()
                .into(),
        );
    }
    let changed_model = LocalLsaModel::build(&changed);
    let description_rebuild_changes_model = changed_model.fingerprint != model.fingerprint;

    let removed = catalog
        .iter()
        .filter(|tool| qualified(tool) != "local-admin.tail_logs")
        .cloned()
        .collect::<Vec<_>>();
    let removed_model = LocalLsaModel::build(&removed);
    let remove_rebuild_excludes_removed_tool =
        hybrid_rank("local service logs", &removed, Some(&removed_model))
            .iter()
            .all(|tool| qualified(tool) != "local-admin.tail_logs");

    let unavailable_candidate_matches_lexical_fallback =
        representative_scenarios().into_iter().all(|scenario| {
            let lexical = rank_visible_tools(scenario.intent, catalog.to_vec())
                .iter()
                .map(qualified)
                .collect::<Vec<_>>();
            let fallback = hybrid_rank(scenario.intent, catalog, None)
                .iter()
                .map(qualified)
                .collect::<Vec<_>>();
            lexical == fallback
        });

    LifecycleReport {
        same_authorized_catalog_projection: model.document_coordinates.len() == catalog.len(),
        authorization_isolation_passed,
        exact_selector_passed,
        add_rebuild_includes_new_tool,
        description_rebuild_changes_model,
        remove_rebuild_excludes_removed_tool,
        unavailable_candidate_matches_lexical_fallback,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let records = representative_corpus();
    let corpus_by_provenance = records.iter().fold(BTreeMap::new(), |mut counts, record| {
        let label = match record.provenance {
            Provenance::RemoteHttp => "remote_http",
            Provenance::LocalUpstream => "local_upstream",
            Provenance::GatewayLocal => "gateway_local",
        };
        *counts.entry(label).or_default() += 1;
        counts
    });
    let catalog = records
        .iter()
        .map(|record| record.tool.clone())
        .collect::<Vec<_>>();
    let gateway = EvaluationGateway::new(&catalog);
    let scenarios = representative_scenarios();
    let baseline = strategy_report(
        Strategy::LexicalBaseline,
        &scenarios,
        &catalog,
        &gateway,
        None,
        ResourceReport {
            index_build_duration_microseconds: 0,
            estimated_index_bytes: 0,
            vocabulary_terms: 0,
            latent_components: 0,
        },
    )
    .await;
    let build_started = Instant::now();
    let model = LocalLsaModel::build(&catalog);
    let build_duration = build_started.elapsed();
    let candidate = strategy_report(
        Strategy::LocalLsaHybrid,
        &scenarios,
        &catalog,
        &gateway,
        Some(&model),
        ResourceReport {
            index_build_duration_microseconds: u64::try_from(build_duration.as_micros())
                .unwrap_or(u64::MAX),
            estimated_index_bytes: model.estimated_bytes(),
            vocabulary_terms: model.vocabulary.len(),
            latent_components: model.components.len(),
        },
    )
    .await;
    let candidate_improves_retrieval_evidence = candidate.mean_reciprocal_rank
        > baseline.mean_reciprocal_rank
        || candidate.mean_recall_at_limit > baseline.mean_recall_at_limit;
    let vocabulary_gap_scenarios = baseline
        .scenarios
        .iter()
        .filter(|scenario| scenario.query_shape == QueryShape::VocabularyGap)
        .collect::<Vec<_>>();
    let vocabulary_gap_scenarios_are_discriminating = !vocabulary_gap_scenarios.is_empty()
        && vocabulary_gap_scenarios
            .iter()
            .all(|scenario| scenario.expected_contract_term_overlap == 0)
        && vocabulary_gap_scenarios
            .iter()
            .any(|scenario| scenario.reciprocal_rank < 1.0);
    let vocabulary_gap_queries_are_in_candidate_vocabulary = scenarios
        .iter()
        .filter(|scenario| scenario.query_shape == QueryShape::VocabularyGap)
        .all(|scenario| model.query_has_known_terms(scenario.intent));
    let semantic_candidate_is_exercised_on_vocabulary_gaps = scenarios
        .iter()
        .filter(|scenario| scenario.query_shape == QueryShape::VocabularyGap)
        .all(|scenario| {
            let semantic = model.semantic_ranks(scenario.intent);
            let lexical = rank_visible_tools(scenario.intent, catalog.clone())
                .into_iter()
                .map(|tool| qualified(&tool))
                .collect::<Vec<_>>();
            !semantic.is_empty()
                && semantic
                    .iter()
                    .map(|(index, _)| qualified(&catalog[*index]))
                    .collect::<Vec<_>>()
                    != lexical
        });
    let governed_invocation_path_is_exercised =
        [&baseline, &candidate].into_iter().all(|strategy| {
            strategy.scenarios.iter().any(|scenario| {
                scenario.exact_contracts_inspected
                    && scenario.intended_arguments_validated
                    && scenario.oracle_invocation_paths_completed
                    && scenario.retrieval_and_invocation_smoke_completed
            })
        });
    let approval_boundary_is_exercised = candidate.scenarios.iter().any(|scenario| {
        scenario.query_shape == QueryShape::VocabularyGap
            && scenario.approval_gate_enforced
            && !scenario.retrieval_and_invocation_smoke_completed
    });
    let comparison = ComparisonReport {
        mean_reciprocal_rank_delta: candidate.mean_reciprocal_rank - baseline.mean_reciprocal_rank,
        mean_recall_at_limit_delta: candidate.mean_recall_at_limit - baseline.mean_recall_at_limit,
        retrieval_and_invocation_smoke_scenarios_delta: candidate
            .retrieval_and_invocation_smoke_scenarios
            as isize
            - baseline.retrieval_and_invocation_smoke_scenarios as isize,
        ranking_duration_microseconds_delta: i128::from(
            candidate.total_ranking_duration_microseconds,
        ) - i128::from(
            baseline.total_ranking_duration_microseconds,
        ),
        estimated_index_bytes_delta: candidate.resource.estimated_index_bytes as isize
            - baseline.resource.estimated_index_bytes as isize,
        candidate_improves_retrieval_evidence,
    };
    let lifecycle = lifecycle_report(&catalog, &model);
    let contract_checks_passed = lifecycle.same_authorized_catalog_projection
        && lifecycle.authorization_isolation_passed
        && lifecycle.exact_selector_passed
        && lifecycle.add_rebuild_includes_new_tool
        && lifecycle.description_rebuild_changes_model
        && lifecycle.remove_rebuild_excludes_removed_tool
        && lifecycle.unavailable_candidate_matches_lexical_fallback
        && vocabulary_gap_scenarios_are_discriminating
        && vocabulary_gap_queries_are_in_candidate_vocabulary
        && semantic_candidate_is_exercised_on_vocabulary_gaps
        && governed_invocation_path_is_exercised
        && approval_boundary_is_exercised;
    let report = EvaluationReport {
        contract_version: "gateway-retrieval-strategy-evaluation-v4",
        result_limit: RESULT_LIMIT,
        catalog_tools: catalog.len(),
        corpus_by_provenance,
        strategies: vec![baseline, candidate],
        comparison,
        vocabulary_gap_scenarios_are_discriminating,
        vocabulary_gap_queries_are_in_candidate_vocabulary,
        semantic_candidate_is_exercised_on_vocabulary_gaps,
        governed_invocation_path_is_exercised,
        approval_boundary_is_exercised,
        lifecycle,
        data_handling: DataHandlingReport {
            query_and_tool_text_leave_process: false,
            external_model_or_provider: false,
            new_dependency: false,
            reproducibility: "deterministic local TF-IDF matrix, Jacobi SVD, and reciprocal-rank fusion over the exact authorized corpus",
        },
        evaluation_scope: EvaluationScopeReport {
            retrieval_metrics_are_component_level: true,
            invocation_steps_are_oracle_selected: true,
            independent_tool_selection_evaluated: false,
            end_to_end_task_completion_evaluated: false,
        },
        decision: DecisionReport {
            recorded_decision: if candidate_improves_retrieval_evidence {
                "reopen_production_adoption_evaluation"
            } else {
                "retain_lexical_baseline"
            },
            rationale: if candidate_improves_retrieval_evidence {
                vec![
                    "the candidate improves representative retrieval evidence",
                    "production adoption still requires accepted lifecycle, data-boundary, fallback, and operating evidence",
                ]
            } else {
                vec![
                    "both strategies have the same retrieval quality on the representative scenarios",
                    "the local semantic hybrid does not improve representative component-level retrieval evidence",
                    "the candidate adds derived index state, rebuild work, memory, and another failure mode",
                    "the production lexical path preserves exact selectors and has no model-provider data boundary",
                ]
            },
            production_adoption_requires: vec![
                "the benefit survives a representative sample of the governed operational catalog and realistic hard negatives",
                "the selected production candidate improves end-to-end task completion without authorization or exact-selector regressions",
                "model lifecycle, data handling, freshness, fallback, latency, and resource costs have an accepted operating design",
            ],
        },
        contract_checks_passed,
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    if !report.contract_checks_passed {
        return Err("retrieval strategy contract check failed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jacobi_decomposition_reconstructs_diagonal_eigenvalues() {
        let (values, vectors) = jacobi_eigendecomposition(vec![vec![2.0, 1.0], vec![1.0, 2.0]]);
        let mut values = values;
        values.sort_by(f64::total_cmp);
        assert!((values[0] - 1.0).abs() < 1e-8);
        assert!((values[1] - 3.0).abs() < 1e-8);
        assert!((dot(&vectors[0], &vectors[1])).abs() < 1e-8);
    }

    #[test]
    fn unavailable_semantic_candidate_is_exactly_the_lexical_ordering() {
        let catalog = representative_corpus()
            .into_iter()
            .map(|record| record.tool)
            .collect::<Vec<_>>();
        let lexical = rank_visible_tools("investigate service errors", catalog.clone())
            .iter()
            .map(qualified)
            .collect::<Vec<_>>();
        let fallback = hybrid_rank("investigate service errors", &catalog, None)
            .iter()
            .map(qualified)
            .collect::<Vec<_>>();
        assert_eq!(fallback, lexical);
    }

    #[test]
    fn hybrid_exact_selector_cannot_be_displaced() {
        let catalog = representative_corpus()
            .into_iter()
            .map(|record| record.tool)
            .collect::<Vec<_>>();
        let model = LocalLsaModel::build(&catalog);
        let ranked = hybrid_rank("github.get_file_contents", &catalog, Some(&model));
        assert_eq!(ranked.len(), 1);
        assert_eq!(qualified(&ranked[0]), "github.get_file_contents");
    }

    #[test]
    fn vocabulary_gap_scenarios_exercise_distinct_semantic_evidence() {
        let catalog = representative_corpus()
            .into_iter()
            .map(|record| record.tool)
            .collect::<Vec<_>>();
        let model = LocalLsaModel::build(&catalog);
        for scenario in representative_scenarios()
            .into_iter()
            .filter(|scenario| scenario.query_shape == QueryShape::VocabularyGap)
        {
            assert_eq!(
                expected_term_overlap(&scenario, &catalog),
                0,
                "{} must remain a real vocabulary-gap query",
                scenario.id
            );
            assert!(model.query_has_known_terms(scenario.intent));
            let semantic = model
                .semantic_ranks(scenario.intent)
                .into_iter()
                .map(|(index, _)| qualified(&catalog[index]))
                .collect::<Vec<_>>();
            let lexical = rank_visible_tools(scenario.intent, catalog.clone())
                .iter()
                .map(qualified)
                .collect::<Vec<_>>();
            assert!(!semantic.is_empty());
            assert_ne!(semantic, lexical);
            assert!(scenario
                .expected
                .iter()
                .all(|expected| semantic.iter().any(|name| name == expected)));
        }
    }

    #[test]
    fn fixture_dispatch_is_tool_specific() {
        let arguments = json!({"query": "same input"}).as_object().cloned().unwrap();
        assert_ne!(
            fixture_result("kagi.kagi_search_fetch", Some(&arguments)),
            fixture_result("local-fs.read_file", Some(&arguments)),
        );
        assert!(fixture_result("knowledge.list_citations", Some(&arguments)).is_none());
    }

    #[tokio::test]
    async fn oracle_smoke_requires_inspection_validation_and_fixture_invocation() {
        let catalog = representative_corpus()
            .into_iter()
            .map(|record| record.tool)
            .collect::<Vec<_>>();
        let gateway = EvaluationGateway::new(&catalog);
        let scenario = representative_scenarios()
            .into_iter()
            .find(|scenario| scenario.id == "exact_selector")
            .expect("exact-selector evaluation scenario exists");
        let report = evaluate_scenario(&scenario, &gateway, |query| {
            rank_visible_tools(query, catalog.clone())
        })
        .await;
        assert!(report.exact_contracts_inspected);
        assert!(report.intended_arguments_validated);
        assert!(report.oracle_invocation_paths_completed);
        assert!(report.retrieval_and_invocation_smoke_completed);
    }

    #[tokio::test]
    async fn mutating_fixture_does_not_bypass_the_approval_gate() {
        let catalog = representative_corpus()
            .into_iter()
            .map(|record| record.tool)
            .collect::<Vec<_>>();
        let gateway = EvaluationGateway::new(&catalog);
        let scenario = representative_scenarios()
            .into_iter()
            .find(|scenario| scenario.id == "vocabulary_gap_refund")
            .expect("refund evaluation scenario exists");
        let model = LocalLsaModel::build(&catalog);
        let report = evaluate_scenario(&scenario, &gateway, |query| {
            hybrid_rank(query, &catalog, Some(&model))
        })
        .await;
        assert!(report.exact_contracts_inspected);
        assert!(report.intended_arguments_validated);
        assert!(report.approval_gate_enforced);
        assert!(!report.oracle_invocation_paths_completed);
        assert!(!report.retrieval_and_invocation_smoke_completed);
    }
}
