//! Reads an upstream's complete tool catalog at dial time, and holds a
//! spec-violating definition to its own tool instead of letting it take
//! the whole catalog down.
//!
//! MCP carries a tool result in `CallToolResult.structuredContent`, which
//! the spec defines as a JSON object, so an advertised `outputSchema` must
//! have a root of `type: "object"`. A strict client validates the entire
//! `tools/list` response in one pass, so a single tool with an array root
//! or a bare `oneOf` makes the client discard EVERY tool the gateway
//! serves — thousands of working tools lost to one broken upstream, with
//! nothing in the gateway's own logs to say why.
//!
//! Each offending tool is published with its `outputSchema` cleared. The
//! field is optional in MCP, so the tool stays advertisable and callable;
//! only an output contract that was never satisfiable in the first place
//! is lost. Nothing is invented — a malformed field is declined, never
//! replaced with a synthesized one.
//!
//! Stripping cannot move a tool's drift hash: `waygate_catalog::schema_hash`
//! digests name, description, and *input* schema only.

use rmcp::model::Tool;
use serde_json::Value;

/// Normalize one connection's PUBLISHED tool set, recording what was refused.
///
/// Deliberately applied to the published view rather than to the raw
/// `tools/list` result. The reviewed behavior hash covers `output_schema`,
/// and annotation-mode admission plus the per-call drift check both compare
/// that hash against what the upstream advertises — so normalizing before
/// those checks would change a tool's identity, invalidate an operator's
/// existing approval, and quarantine the very tool this module exists to
/// keep. Identity stays the descriptor the upstream advertised; only what
/// clients are shown is normalized.
pub(super) fn normalize_connection(server: &str, conn: &mut super::Connection) {
    // Judge each published tool against the descriptor the upstream
    // ADVERTISED, not the copy about to be stripped. The multi-lane
    // intersection may already have cleared a published schema because the
    // serving lanes disagreed, and scanning the published copy would then
    // find nothing to report — leaving the log, audit rows, count, and gauge
    // all at zero while a live lane is emitting an invalid contract.
    let rejected = advertised_refusals(&conn.tools, &conn.live_tools);
    strip_nonconforming_output_schemas(&mut conn.tools);
    // Idempotent: a multi-lane commit normalizes the publishing lane and
    // then every sibling, so re-running over an unchanged set must not
    // re-log what the operator has already been told.
    if rejected != conn.rejected_output_schemas {
        report(server, &rejected, conn.tools.len());
    }
    conn.rejected_output_schemas = rejected;

    // Input schemas are observed, never altered. A root union conforms to
    // the protocol, so rewriting it would change a contract the upstream
    // owns and would punish the clients that consume it correctly. The
    // operator is told instead, under the same idempotence rule.
    let unregisterable = unregisterable_input_schemas(&conn.tools);
    if unregisterable != conn.unregisterable_input_schemas {
        report_unregisterable(server, &unregisterable);
    }
    conn.unregisterable_input_schemas = unregisterable;
}

/// Published tools whose input schema applies a composition keyword at its
/// root. Restricted to published tools for the same reason as
/// [`advertised_refusals`]: a withheld tool is not part of the inventory an
/// operator is serving.
///
/// A schema without the MCP object root is skipped even when it carries a
/// composition keyword. That tool is withheld from `tools/list` outright, so
/// counting it here would report a client-visible incompatibility for
/// something no client is offered — two different defects with two different
/// fixes. This signal covers only schemas that conform and are served.
fn unregisterable_input_schemas(published: &[Tool]) -> Vec<UnregisterableInputSchema> {
    published
        .iter()
        .filter(|tool| waygate_mcp::tool_schema::input_schema_has_object_root(&tool.input_schema))
        .filter_map(|tool| {
            let keyword = waygate_mcp::tool_schema::root_composition_keyword(&tool.input_schema)?;
            Some(UnregisterableInputSchema {
                tool: tool.name.to_string(),
                keyword,
            })
        })
        .collect()
}

/// Name each unregisterable tool in the log; the gauge carries only the
/// per-server count, because upstream tool names are unbounded.
fn report_unregisterable(server: &str, unregisterable: &[UnregisterableInputSchema]) {
    if unregisterable.is_empty() {
        return;
    }
    for entry in unregisterable {
        tracing::warn!(
            server = %server,
            tool = %entry.tool,
            keyword = %entry.keyword,
            "upstream published an input schema applying a composition \
             keyword at its root; the schema is valid MCP and is served \
             verbatim, but the tool-calling APIs that consume tools/list \
             refuse the definition, so this tool is unreachable for such \
             clients. Fix the upstream: declare mutually exclusive \
             arguments as independent optional properties and enforce the \
             exclusion when the call is handled",
        );
    }
    tracing::warn!(
        server = %server,
        unregisterable = unregisterable.len(),
        "upstream is publishing tool definitions some clients cannot register",
    );
}

/// One published tool whose input schema no strict tool-calling client can
/// register, retained so re-normalizing an unchanged set does not re-log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UnregisterableInputSchema {
    /// Unqualified upstream tool name.
    pub(super) tool: String,
    /// The composition keyword found at the schema root.
    pub(super) keyword: &'static str,
}

/// One entry per PUBLISHED tool whose advertised output schema could not
/// describe a `structuredContent` object. Restricted to published tools: a
/// refusal on a tool the gateway withholds is not something an operator is
/// serving, and reporting it would overstate the serving inventory.
fn advertised_refusals(published: &[Tool], advertised: &[Tool]) -> Vec<RejectedOutputSchema> {
    published
        .iter()
        .filter_map(|tool| {
            let source = advertised
                .iter()
                .find(|candidate| candidate.name == tool.name)?;
            let schema = source.output_schema.as_ref()?;
            if schema.get("type") == Some(&Value::String("object".to_owned())) {
                return None;
            }
            Some(RejectedOutputSchema {
                tool: tool.name.to_string(),
                observed_type: describe_root_type(schema.get("type")),
            })
        })
        .collect()
}

/// Name each refusal in the log, which is where the per-tool identity
/// lives — the metric is labelled by server only, and is published from
/// the across-lane union once the connection is installed, not from this
/// single lane's view.
fn report(server: &str, rejected: &[RejectedOutputSchema], total: usize) {
    if rejected.is_empty() {
        return;
    }
    for entry in rejected {
        tracing::warn!(
            server = %server,
            tool = %entry.tool,
            observed_type = %entry.observed_type,
            "upstream advertised an output schema whose root is not \
             type: \"object\"; publishing the tool without an output \
             contract. A strict MCP client rejects the entire tools/list \
             response over one such tool — fix the upstream definition",
        );
    }
    tracing::warn!(
        server = %server,
        rejected = rejected.len(),
        total,
        "upstream is publishing spec-violating tool definitions",
    );
}

/// One tool whose advertised output schema was refused, retained so the
/// operator can see which upstream published it and what it sent instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RejectedOutputSchema {
    /// Unqualified upstream tool name.
    pub(super) tool: String,
    /// The root `type` the upstream declared, rendered for an operator:
    /// a JSON type name, or `absent` when the root omitted `type`
    /// entirely (the shape an untagged/internally tagged enum produces).
    pub(super) observed_type: String,
}

impl RejectedOutputSchema {
    /// Build one directly, for tests that exercise the refusal record's
    /// ordering rather than the listing that produces these.
    #[cfg(test)]
    pub(super) fn for_test(tool: &str, observed_type: &str) -> Self {
        Self {
            tool: tool.to_owned(),
            observed_type: observed_type.to_owned(),
        }
    }

    /// The unqualified upstream tool name this refusal belongs to.
    pub(super) fn tool(&self) -> &str {
        &self.tool
    }
}

/// Clear every non-conforming `output_schema` in `tools`, returning one
/// entry per tool stripped. An empty result is the steady state.
pub(super) fn strip_nonconforming_output_schemas(tools: &mut [Tool]) -> Vec<RejectedOutputSchema> {
    let mut rejected = Vec::new();
    for tool in tools {
        let Some(schema) = tool.output_schema.as_ref() else {
            continue;
        };
        if schema.get("type") == Some(&Value::String("object".to_owned())) {
            continue;
        }
        rejected.push(RejectedOutputSchema {
            tool: tool.name.to_string(),
            observed_type: describe_root_type(schema.get("type")),
        });
        tool.output_schema = None;
    }
    rejected
}

/// Render a schema root's `type` for an operator-facing log or audit
/// reason. A non-string `type` (the array form JSON Schema allows, e.g.
/// `["object", "null"]`) is reported verbatim so the operator sees what
/// the upstream actually sent.
fn describe_root_type(ty: Option<&Value>) -> String {
    match ty {
        None => "absent".to_owned(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rmcp::model::Tool;
    use serde_json::{json, Map, Value};

    use super::{
        strip_nonconforming_output_schemas, unregisterable_input_schemas, RejectedOutputSchema,
        UnregisterableInputSchema,
    };

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().cloned().expect("object schema")
    }

    fn tool(name: &str, output_schema: Option<Value>) -> Tool {
        let t = Tool::new(
            name.to_owned(),
            "test tool".to_owned(),
            Arc::new(object(json!({"type": "object"}))),
        );
        match output_schema {
            Some(schema) => t.with_raw_output_schema(Arc::new(object(schema))),
            None => t,
        }
    }

    fn input_tool(name: &str, input_schema: Value) -> Tool {
        Tool::new(
            name.to_owned(),
            "test tool".to_owned(),
            Arc::new(object(input_schema)),
        )
    }

    /// A root union is reported and the tool is left untouched; a union
    /// nested inside a property is what clients consume fine, so only the
    /// root placement counts.
    #[test]
    fn root_input_unions_are_reported_without_being_altered() {
        let tools = vec![
            input_tool(
                "revoke",
                json!({
                    "type": "object",
                    "properties": {"id": {"type": "integer"}, "name": {"type": "string"}},
                    "oneOf": [{"required": ["id"]}, {"required": ["name"]}]
                }),
            ),
            input_tool(
                "merged",
                json!({"type": "object", "allOf": [{"type": "object"}]}),
            ),
            input_tool(
                "nested",
                json!({
                    "type": "object",
                    "properties": {"value": {"anyOf": [{"type": "string"}]}}
                }),
            ),
            input_tool("plain", json!({"type": "object", "properties": {}})),
            // Withheld from tools/list for lacking the object root, so it is
            // not a client-visible incompatibility and must not be counted.
            input_tool("rootless", json!({"anyOf": [{"required": ["id"]}]})),
        ];

        let found = unregisterable_input_schemas(&tools);

        assert_eq!(
            found,
            vec![
                UnregisterableInputSchema {
                    tool: "revoke".to_owned(),
                    keyword: "oneOf",
                },
                UnregisterableInputSchema {
                    tool: "merged".to_owned(),
                    keyword: "allOf",
                },
            ]
        );
    }

    /// The two shapes a real upstream produced, plus the roots that are
    /// legitimate and must survive untouched.
    #[test]
    fn only_non_object_roots_are_stripped() {
        // `Vec<T>` output; `#[serde(tag = ...)]` enum output; a root whose
        // `type` is the array form JSON Schema permits; conforming; absent.
        let mut tools = vec![
            tool(
                "batch_update",
                Some(json!({"type": "array", "items": {"type": "object"}})),
            ),
            tool(
                "mutate",
                Some(json!({"oneOf": [{"type": "object"}, {"type": "object"}]})),
            ),
            tool("nullable", Some(json!({"type": ["object", "null"]}))),
            tool(
                "conforming",
                Some(json!({"type": "object", "properties": {"id": {"type": "string"}}})),
            ),
            tool("no_schema", None),
        ];

        let rejected = strip_nonconforming_output_schemas(&mut tools);

        assert_eq!(
            rejected,
            vec![
                RejectedOutputSchema {
                    tool: "batch_update".to_owned(),
                    observed_type: "array".to_owned(),
                },
                RejectedOutputSchema {
                    tool: "mutate".to_owned(),
                    observed_type: "absent".to_owned(),
                },
                RejectedOutputSchema {
                    tool: "nullable".to_owned(),
                    observed_type: "[\"object\",\"null\"]".to_owned(),
                },
            ]
        );
        assert!(tools[0].output_schema.is_none());
        assert!(tools[1].output_schema.is_none());
        assert!(tools[2].output_schema.is_none());
        assert_eq!(
            tools[3].output_schema.as_deref(),
            Some(&object(
                json!({"type": "object", "properties": {"id": {"type": "string"}}})
            )),
            "a conforming schema must survive byte-for-byte"
        );
        assert!(tools[4].output_schema.is_none());
    }

    /// The tool itself stays advertisable — only its output contract is
    /// dropped. A client that loses the schema can still call the tool.
    #[test]
    fn stripping_preserves_the_rest_of_the_definition() {
        let mut tools = vec![tool("batch_update", Some(json!({"type": "array"})))];
        let before = tools[0].clone();

        strip_nonconforming_output_schemas(&mut tools);

        assert_eq!(tools[0].name, before.name);
        assert_eq!(tools[0].description, before.description);
        assert_eq!(tools[0].input_schema, before.input_schema);
    }

    /// Drift detection keys on the input contract, so refusing an output
    /// schema must not make a tool look like it changed. Guards against a
    /// future `schema_hash` that folds the output schema in and would
    /// silently quarantine every stripped tool.
    #[test]
    fn stripping_does_not_move_the_drift_hash() {
        let mut tools = vec![tool("batch_update", Some(json!({"type": "array"})))];
        let before = waygate_catalog::schema_hash(
            tools[0].name.as_ref(),
            tools[0].description.as_deref(),
            &tools[0].input_schema,
        );

        strip_nonconforming_output_schemas(&mut tools);

        let after = waygate_catalog::schema_hash(
            tools[0].name.as_ref(),
            tools[0].description.as_deref(),
            &tools[0].input_schema,
        );
        assert_eq!(before, after);
    }
}
