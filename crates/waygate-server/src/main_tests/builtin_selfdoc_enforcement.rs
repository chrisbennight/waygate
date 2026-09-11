//! Ubiquitous self-documentation guard across EVERY built-in namespace.
//!
//! The per-namespace tests (`*_advertise_output_schema_and_title`,
//! `*_output_schemas_validate_sample_content`) own the namespace-specific
//! detail — read_only polarity and content↔schema validation. This single
//! test is the cross-cutting invariant: every built-in tool the gateway
//! serves, in ANY namespace, must be self-documenting on the wire (SOP
//! `docs/agents/mcp-tool-docs.md`). When you add a new built-in namespace,
//! add its `tool_defs()` here — that one line is the whole cost of keeping
//! the guarantee ubiquitous.
use rmcp::model::Tool;

/// Every tool the gateway serves from a reserved built-in namespace.
fn all_builtin_tools() -> Vec<Tool> {
    let mut tools = crate::mcp_builtin::surface_catalog().definitions();
    tools.extend(crate::mcp_codemode::surface_catalog().definitions());
    tools.extend(crate::mcp_observe::surface_catalog().definitions());
    tools.extend(crate::mcp_control::surface_catalog().definitions());
    tools.extend(crate::mcp_files::surface_catalog().definitions());
    tools.extend(waygate_mcp::server::skill_tools::surface_catalog().definitions());
    tools
}

#[test]
fn every_builtin_tool_is_self_documenting() {
    let tools = all_builtin_tools();
    assert!(!tools.is_empty(), "no built-in tools enumerated");
    for t in &tools {
        assert!(
            waygate_mcp::tool_schema::input_schema_has_object_root(&t.input_schema),
            "{} input_schema must declare an MCP object root",
            t.name,
        );
        // An object root may legally carry a composition keyword, but the
        // tool-calling APIs that consume `tools/list` refuse such a definition
        // and the tool never reaches the client at all. Express mutually
        // exclusive arguments as independent optional properties and enforce
        // the exclusion in the handler.
        assert_eq!(
            waygate_mcp::tool_schema::root_composition_keyword(&t.input_schema),
            None,
            "{} input_schema applies a composition keyword at its root",
            t.name,
        );
        let input_schema =
            serde_json::to_value(t.input_schema.as_ref()).expect("input_schema serializes");
        assert!(
            jsonschema::validator_for(&input_schema).is_ok(),
            "{} input_schema is not a valid JSON Schema",
            t.name,
        );
        assert!(
            waygate_mcp::tool_schema::inspector_portable_schema(&input_schema),
            "{} input_schema has an MCP Inspector portability finding",
            t.name,
        );
        // SOP point 5 — a human-readable title.
        assert!(t.title.is_some(), "{} missing title", t.name);
        // SOP point 4 — an output_schema so a client predicts the result
        // shape from tools/list alone. This holds for EVERY built-in tool,
        // reads and writes alike (not just reads).
        assert!(
            t.output_schema.is_some(),
            "{} missing output_schema",
            t.name
        );
        // SOP point 6 — behavioral annotations, with read_only_hint set so a
        // client knows whether the tool mutates (the value itself is
        // namespace-specific and asserted by the per-namespace tests).
        assert!(
            t.annotations
                .as_ref()
                .and_then(|a| a.read_only_hint)
                .is_some(),
            "{} missing read_only_hint annotation",
            t.name
        );
        // The advertised schema must itself be a compilable JSON Schema — a
        // malformed schema is as useless to a client as none at all.
        let schema = serde_json::to_value(t.output_schema.as_ref().unwrap())
            .expect("output_schema serializes");
        assert!(
            jsonschema::validator_for(&schema).is_ok(),
            "{} output_schema is not a valid JSON Schema",
            t.name
        );
        assert!(
            waygate_mcp::tool_schema::inspector_portable_schema(&schema),
            "{} output_schema has an MCP Inspector portability finding",
            t.name,
        );
    }
}
