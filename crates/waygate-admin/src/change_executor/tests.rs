//! Registry/validation tests, split out of `change_executor.rs`.

use super::*;
use waygate_oidc::Scope;

#[test]
fn action_catalog_keys_match_registry() {
    // The catalog and the executor allowlist must list exactly the same
    // actions: one proposable but absent from the catalog would have no
    // advertised params schema; one in the catalog but not registered
    // couldn't execute. Either is a drift bug this guards against.
    let reg = registry();
    let catalog_keys: Vec<&str> = reg
        .action_catalog()
        .into_iter()
        .map(|e| e.action_type)
        .collect();
    assert_eq!(
        catalog_keys,
        reg.action_types(),
        "action_param_schemas() and builtin_executors() disagree — add the new action to both",
    );
}

#[test]
fn every_file_backed_param_names_a_string_field_of_its_action_schema() {
    // A `FileBackedParam` pointer is a claim about the action's params shape:
    // the resolved document is written there and the executor reads it from
    // there. Rename or retype the field and the declaration goes quietly dead —
    // the upload path would still be advertised, the `_file` key would still be
    // accepted and stripped, and the executor would then fail on missing
    // params. Walk the advertised schema and prove each pointer still lands on
    // a string.
    let reg = registry();
    let mut checked = 0;
    for action_type in reg.action_types() {
        let specs = reg.file_params(action_type);
        if specs.is_empty() {
            continue;
        }
        let schema = reg
            .params_schema(action_type)
            .unwrap_or_else(|| panic!("{action_type} has no advertised params schema"));
        for spec in specs {
            let field =
                resolve_schema_pointer(&schema, &schema, spec.pointer).unwrap_or_else(|missing| {
                    panic!(
                        "{action_type}: file-backed pointer {} does not exist in the params \
                         schema (stopped at {missing})",
                        spec.pointer
                    )
                });
            assert!(
                accepts_a_string(field),
                "{action_type}: {} must accept a string to receive a text document, but the \
                 schema says {}",
                spec.pointer,
                field.get("type").unwrap_or(&serde_json::Value::Null),
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "no action declares a file-backed param; the upload path is unreachable",
    );
}

/// Follow a JSON pointer through a schemars-generated schema, stepping into
/// `properties` and following `$ref`s into `$defs`. Returns the terminal field
/// schema, or the pointer prefix where the walk failed.
fn resolve_schema_pointer<'a>(
    root: &'a serde_json::Value,
    schema: &'a serde_json::Value,
    pointer: &str,
) -> Result<&'a serde_json::Value, String> {
    let mut node = deref(root, schema);
    let mut walked = String::new();
    for token in pointer.trim_start_matches('/').split('/') {
        walked.push('/');
        walked.push_str(token);
        node = node
            .get("properties")
            .and_then(|props| props.get(token))
            .ok_or_else(|| walked.clone())?;
        node = deref(root, node);
    }
    Ok(node)
}

fn deref<'a>(root: &'a serde_json::Value, schema: &'a serde_json::Value) -> &'a serde_json::Value {
    let Some(reference) = schema.get("$ref").and_then(|r| r.as_str()) else {
        return schema;
    };
    reference
        .strip_prefix("#/$defs/")
        .and_then(|name| root.get("$defs")?.get(name))
        .unwrap_or(schema)
}

/// Whether a schema node admits a string. An optional document field is
/// rendered `["string", "null"]`, which still receives the resolved text.
fn accepts_a_string(field: &serde_json::Value) -> bool {
    match field.get("type") {
        Some(serde_json::Value::String(t)) => t == "string",
        Some(serde_json::Value::Array(types)) => types.iter().any(|t| t == "string"),
        _ => false,
    }
}

#[test]
fn preview_action_validates_and_reports_requirement() {
    // Unknown action ⇒ None (the caller teaches the valid set).
    assert!(preview_action("api_key.delete_everything", &serde_json::json!({})).is_none());

    // Well-formed params ⇒ valid, no errors, with the action's approval bar
    // and params schema surfaced for the maker.
    let ok = preview_action(
        "rate_limit.update",
        &serde_json::json!({
            "policy_id": "00000000-0000-0000-0000-000000000000",
            "bucket_capacity": 10,
        }),
    )
    .expect("registered action");
    assert!(ok.valid && ok.errors.is_empty(), "errors: {:?}", ok.errors);
    assert!(ok.required_approvals >= 1 && !ok.eligible_role.is_empty());
    assert!(ok.params_schema.is_object());

    // Missing a required field ⇒ invalid, with a non-empty payload-safe
    // message — the SAME validator the propose path uses, so the two agree.
    let bad =
        preview_action("rate_limit.update", &serde_json::json!({})).expect("registered action");
    assert!(!bad.valid && !bad.errors.is_empty());
}

#[test]
fn membership_actions_split_ordinary_from_privileged_approval_bars() {
    let registry = registry();
    let ordinary = [
        "rbac.assignment.grant",
        "rbac.assignment.revoke",
        "rbac.group_mapping.grant",
        "rbac.group_mapping.revoke",
    ];
    let privileged = [
        "rbac.assignment.grant_privileged",
        "rbac.assignment.revoke_privileged",
        "rbac.group_mapping.grant_privileged",
        "rbac.group_mapping.revoke_privileged",
    ];
    for action in ordinary {
        let executor = registry.get(action).expect("ordinary membership action");
        let requirement = executor.requirement();
        assert_eq!(requirement.required_approvals, 1);
        assert_eq!(requirement.eligible_role, DEFAULT_ELIGIBLE_ROLE);
        assert!(requirement.factors.is_empty());
        assert!(requirement.cooldown_seconds.is_none());
        assert!(executor.requires_target_etag());
    }
    for action in privileged {
        let executor = registry.get(action).expect("privileged membership action");
        let requirement = executor.requirement();
        assert_eq!(requirement.required_approvals, 1);
        assert_eq!(requirement.eligible_role, DEFAULT_ELIGIBLE_ROLE);
        assert!(requirement.factors.is_empty());
        assert_eq!(requirement.cooldown_seconds, Some(300));
        assert!(executor.requires_target_etag());
    }
}

#[test]
fn tenant_and_audit_actions_registered_and_tenant_update_is_display_name_only() {
    let reg = registry();
    // Tenant-update and audit-retention/routing actions are proposable. The
    // drift test guarantees action_types() and the catalog agree, so a
    // registered executor here also has an advertised params schema.
    for at in [
        "tenant.update",
        "audit.retention.set",
        "audit.retention.clear",
        "audit.routing.set",
        "audit.routing.clear",
    ] {
        assert!(reg.get(at).is_some(), "{at} must be a registered executor");
    }

    // Defensible-subset doctrine (docs/agents/hitl-control-plane.md): a
    // maker may rename its OWN tenant but must NOT change `status`
    // (active/suspended) through propose — self-suspend is a lockout
    // footgun — and `tenant.delete` is not proposable at all (its cascade
    // would erase the executing change request). Pin it at the wire
    // surface: the `tenant.update` params schema exposes `display_name` and
    // nothing else (no `status`, no foreign `id`), so the constraint can't
    // be silently widened by adding a field to the params struct.
    let schema = reg
        .params_schema("tenant.update")
        .expect("tenant.update registered");
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("tenant.update params is an object schema with properties");
    assert!(
        props.contains_key("display_name"),
        "tenant.update must accept display_name",
    );
    assert!(
        !props.contains_key("status"),
        "tenant.update must NOT accept status — suspend/activate stays \
         operator-only (no self-suspend via the propose path)",
    );
    assert!(
        reg.get("tenant.delete").is_none(),
        "tenant.delete must not be proposable (cascade self-delete footgun)",
    );
}

#[test]
fn every_action_has_a_nonempty_object_params_schema() {
    // A client reads the params shape off the wire. An empty or
    // non-object schema would defeat that.
    for entry in registry().action_catalog() {
        let schema = &entry.params_schema;
        assert_eq!(
            schema.get("type").and_then(|t| t.as_str()),
            Some("object"),
            "{}: params schema is not an object: {schema}",
            entry.action_type,
        );
        let props = schema
            .get("properties")
            .and_then(|p| p.as_object())
            .unwrap_or_else(|| panic!("{}: params schema has no `properties`", entry.action_type));
        assert!(
            !props.is_empty(),
            "{}: params schema has zero properties",
            entry.action_type,
        );
    }
}

#[test]
fn params_schema_reflects_executor_struct_fields() {
    // Spot-check representative actions across the tiers: the schema's
    // property names are the serde field names the executor deserializes,
    // so this pins schema == struct — a wrong type in the catalog table or
    // a renamed field would fail here.
    let by_type: std::collections::HashMap<&str, Value> = registry()
        .action_catalog()
        .into_iter()
        .map(|e| (e.action_type, e.params_schema))
        .collect();
    let assert_props = |action: &str, fields: &[&str]| {
        let props = by_type[action]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{action}: no properties"));
        for f in fields {
            assert!(
                props.contains_key(*f),
                "{action}: schema missing property `{f}`",
            );
        }
    };
    assert_props(
        "rate_limit.update",
        &["policy_id", "bucket_capacity", "refill_per_second"],
    );
    assert_props("api_key.mint", &["name", "sub", "scopes", "ttl"]);
    assert_props(
        "break_glass.mint",
        &["issued_to", "reason", "scope_pattern", "ttl_seconds"],
    );
    assert_props("peer.create", &["peer_name", "issuer", "jwks_url"]);
    for action in ["peer.create", "peer.update"] {
        assert!(by_type[action]["properties"].get("trust_tier").is_none());
        assert_eq!(by_type[action]["additionalProperties"], false);
    }
    assert_props("upstream.reconnect", &["server", "clear_quarantine"]);
    assert_props("upstream.refresh_catalog", &["server"]);
    assert_props("upstream.quarantine.clear", &["server"]);
    assert_props(
        "catalog.server.unquarantine",
        &["server_id", "expected_name", "reason"],
    );
    assert_props("config.reload", &["target"]);
}

#[test]
fn governed_operational_actions_are_registered_with_default_approval() {
    let reg = registry();
    for action in [
        "upstream.reconnect",
        "upstream.refresh_catalog",
        "upstream.quarantine.clear",
        "catalog.server.unquarantine",
        "config.reload",
    ] {
        let executor = reg
            .get(action)
            .unwrap_or_else(|| panic!("{action} must be registered"));
        assert_eq!(executor.action_type(), action);
        let requirement = executor.requirement();
        assert_eq!(requirement.required_approvals, 1);
        assert_eq!(requirement.eligible_role, DEFAULT_ELIGIBLE_ROLE);
        assert!(requirement.factors.is_empty());
    }
}

#[test]
fn governed_operational_params_validate_before_queueing() {
    for (action, params) in [
        (
            "upstream.reconnect",
            serde_json::json!({"server": "fetchlayer", "clear_quarantine": true}),
        ),
        (
            "upstream.refresh_catalog",
            serde_json::json!({"server": "fetchlayer"}),
        ),
        (
            "upstream.quarantine.clear",
            serde_json::json!({"server": "fetchlayer"}),
        ),
        (
            "catalog.server.unquarantine",
            serde_json::json!({
                "server_id": "00000000-0000-0000-0000-000000000000",
                "expected_name": "grounded-docs",
                "reason": "manifest and observed catalog match"
            }),
        ),
        ("config.reload", serde_json::json!({"target": "both"})),
    ] {
        let preview = preview_action(action, &params).expect("registered action");
        assert!(preview.valid, "{action}: {:?}", preview.errors);
    }

    let bad_target = preview_action("config.reload", &serde_json::json!({"target": "unknown"}))
        .expect("registered action");
    assert!(!bad_target.valid);

    let missing_server =
        preview_action("upstream.reconnect", &serde_json::json!({})).expect("registered action");
    assert!(!missing_server.valid);

    let empty_server = preview_action("upstream.reconnect", &serde_json::json!({"server": ""}))
        .expect("registered action");
    assert!(!empty_server.valid);

    let missing_reason = preview_action(
        "catalog.server.unquarantine",
        &serde_json::json!({
            "server_id": "00000000-0000-0000-0000-000000000000",
            "expected_name": "grounded-docs"
        }),
    )
    .expect("registered action");
    assert!(!missing_reason.valid);

    let executor = registry()
        .get("catalog.server.unquarantine")
        .expect("registered action");
    assert!(
        executor.requires_target_etag(),
        "durable recovery must fail closed without a versioned target witness",
    );
}

#[test]
fn registry_resolves_rate_limit_update_and_rejects_unknown() {
    let r = registry();
    assert_eq!(
        r.get("rate_limit.update").map(|e| e.action_type()),
        Some("rate_limit.update"),
    );
    assert!(r.get("nope.unknown").is_none());
}

#[test]
fn registry_resolves_all_standard_non_secret_executors() {
    // The standard non-secret tier of the propose allowlist. Each must
    // resolve (so it's proposable) and report the same
    // action_type it's keyed under.
    let r = registry();
    for action in [
        "rate_limit.create",
        "rate_limit.delete",
        "oauth_consent.revoke",
        "group.create_local",
        "group.delete_local",
        "scope.create_local",
        "scope.delete_local",
        "api_key_profile.create",
        "api_key_profile.delete",
    ] {
        assert_eq!(
            r.get(action).map(|e| e.action_type()),
            Some(action),
            "{action} must be registered and self-identify",
        );
        // Standard tier inherits the single-operator default bar.
        let req = r.get(action).unwrap().requirement();
        assert_eq!(req.required_approvals, 1, "{action} is single-approver");
        assert_eq!(req.eligible_role, DEFAULT_ELIGIBLE_ROLE);
        assert!(req.factors.is_empty());
        assert!(req.cooldown_seconds.is_none());
    }
}

#[test]
fn local_catalog_actions_advertise_and_validate_their_params() {
    let group = preview_action(
        "group.create_local",
        &serde_json::json!({"display_name": "incident-responders"}),
    )
    .expect("group.create_local registered");
    assert!(group.valid, "group params: {:?}", group.errors);

    let scope = preview_action(
        "scope.create_local",
        &serde_json::json!({
            "name": "example-security:triage",
            "description": "Read synthetic security findings"
        }),
    )
    .expect("scope.create_local registered");
    assert!(scope.valid, "scope params: {:?}", scope.errors);

    let group_delete = preview_action(
        "group.delete_local",
        &serde_json::json!({
            "group_id": Uuid::nil(),
            "display_name": "incident-responders"
        }),
    )
    .expect("group.delete_local registered");
    assert!(
        group_delete.valid,
        "group delete params: {:?}",
        group_delete.errors
    );

    let scope_delete = preview_action(
        "scope.delete_local",
        &serde_json::json!({
            "scope_id": Uuid::nil(),
            "name": "example-security:triage"
        }),
    )
    .expect("scope.delete_local registered");
    assert!(
        scope_delete.valid,
        "scope delete params: {:?}",
        scope_delete.errors
    );

    let missing_name = preview_action("group.create_local", &serde_json::json!({}))
        .expect("group.create_local registered");
    assert!(!missing_name.valid, "display_name must be required");

    for (action, params) in [
        (
            "group.create_local",
            serde_json::json!({"display_name": " \t\n"}),
        ),
        ("scope.create_local", serde_json::json!({"name": " \t\n"})),
    ] {
        let whitespace_only =
            preview_action(action, &params).expect("local catalog action registered");
        assert!(
            !whitespace_only.valid,
            "{action} must reject a normalized-empty name before approval"
        );
    }

    let unknown_field = preview_action(
        "scope.create_local",
        &serde_json::json!({"name": "example-security:triage", "tenant_id": "other"}),
    )
    .expect("scope.create_local registered");
    assert!(
        !unknown_field.valid,
        "tenant selection must not be caller-controlled"
    );

    let registry = registry();
    assert!(registry
        .get("group.delete_local")
        .expect("group delete registered")
        .requires_target_etag());
    assert!(registry
        .get("scope.delete_local")
        .expect("scope delete registered")
        .requires_target_etag());
}

#[test]
fn agent_config_lifecycle_actions_advertise_the_tool_allowlist_and_witness_bar() {
    let reg = registry();
    let create = reg
        .get("agent_config.create")
        .expect("agent_config.create registered");
    assert!(!create.requires_target_etag());
    for action in ["agent_config.update", "agent_config.delete"] {
        let executor = reg
            .get(action)
            .unwrap_or_else(|| panic!("{action} registered"));
        assert!(executor.requires_target_etag(), "{action} must fail closed");
        assert_eq!(executor.requirement().required_approvals, 1);
    }

    let config = serde_json::json!({
        "name": "triage",
        "kind": "classification",
        "model_alias": "reasoning-default",
        "instructions": "Summarize security findings.",
        "allowed_tools": ["gateway-observe.query_audit", "example-security.list_alerts"],
        "max_steps": 6,
        "max_tool_calls": 12,
        "token_budget": 4000,
        "enabled": true
    });
    let create_preview = preview_action("agent_config.create", &config).expect("registered");
    assert!(
        create_preview.valid,
        "create params: {:?}",
        create_preview.errors
    );
    let update_preview = preview_action(
        "agent_config.update",
        &serde_json::json!({"agent_id": Uuid::nil(), "config": config}),
    )
    .expect("registered");
    assert!(
        update_preview.valid,
        "update params: {:?}",
        update_preview.errors
    );
    let delete_preview = preview_action(
        "agent_config.delete",
        &serde_json::json!({"agent_id": Uuid::nil()}),
    )
    .expect("registered");
    assert!(
        delete_preview.valid,
        "delete params: {:?}",
        delete_preview.errors
    );

    let maker_selected_tenant = preview_action(
        "agent_config.create",
        &serde_json::json!({
            "name": "triage",
            "kind": "chat",
            "model_alias": "reasoning-default",
            "allowed_tools": [],
            "max_steps": 1,
            "max_tool_calls": 1,
            "enabled": false,
            "tenant_id": "other"
        }),
    )
    .expect("registered");
    assert!(
        !maker_selected_tenant.valid,
        "tenant selection must not be caller-controlled"
    );

    for required_field in ["allowed_tools", "enabled"] {
        let mut incomplete = config.clone();
        incomplete
            .as_object_mut()
            .expect("agent config fixture is an object")
            .remove(required_field);
        let create = preview_action("agent_config.create", &incomplete).expect("registered");
        assert!(
            !create.valid,
            "create must require the complete replacement field `{required_field}`"
        );

        let update = preview_action(
            "agent_config.update",
            &serde_json::json!({"agent_id": Uuid::nil(), "config": incomplete}),
        )
        .expect("registered");
        assert!(
            !update.valid,
            "update must require the complete replacement field `{required_field}`"
        );
    }
}

#[test]
fn api_key_profile_lifecycle_advertises_complete_constraints_and_delete_witness() {
    let reg = registry();
    let create = reg
        .get("api_key_profile.create")
        .expect("api_key_profile.create registered");
    let delete = reg
        .get("api_key_profile.delete")
        .expect("api_key_profile.delete registered");
    assert!(!create.requires_target_etag());
    assert!(delete.requires_target_etag());
    assert_eq!(create.requirement().required_approvals, 1);
    assert_eq!(delete.requirement().required_approvals, 1);

    let create_preview = preview_action(
        "api_key_profile.create",
        &serde_json::json!({
            "name": "example-security-readonly",
            "description": "Bounded synthetic security triage",
            "max_ttl_seconds": 3600,
            "allowed_scopes": ["mcp:invoke"],
            "allowed_servers": ["example-security"],
            "allowed_tools": ["example-security.list_alerts"],
            "requires_reason": true,
            "requires_owner": true
        }),
    )
    .expect("api_key_profile.create registered");
    assert!(
        create_preview.valid,
        "create params: {:?}",
        create_preview.errors
    );
    let create_props = create_preview.params_schema["properties"]
        .as_object()
        .expect("create params properties");
    for field in [
        "name",
        "max_ttl_seconds",
        "allowed_scopes",
        "allowed_servers",
        "allowed_tools",
        "requires_reason",
        "requires_owner",
    ] {
        assert!(create_props.contains_key(field), "schema missing `{field}`");
    }
    assert!(!create_props.contains_key("tenant_id"));

    let delete_preview = preview_action(
        "api_key_profile.delete",
        &serde_json::json!({"profile_id": Uuid::nil()}),
    )
    .expect("api_key_profile.delete registered");
    assert!(
        delete_preview.valid,
        "delete params: {:?}",
        delete_preview.errors
    );

    let maker_selected_tenant = preview_action(
        "api_key_profile.create",
        &serde_json::json!({
            "name": "example-security-readonly",
            "max_ttl_seconds": 3600,
            "allowed_scopes": ["mcp:invoke"],
            "tenant_id": "other"
        }),
    )
    .expect("api_key_profile.create registered");
    assert!(
        !maker_selected_tenant.valid,
        "tenant selection must not be caller-controlled"
    );
}

#[test]
fn standard_non_secret_param_shapes_parse() {
    let del: RateLimitDeleteParams =
        serde_json::from_value(serde_json::json!({ "policy_id": Uuid::nil() })).unwrap();
    assert_eq!(del.policy_id, Uuid::nil());

    let r = registry();
    assert!(r.get("inspection_rule.create").is_none());
    assert!(r.get("inspection_rule.update").is_none());

    let rev: OAuthConsentRevokeParams = serde_json::from_value(serde_json::json!({
        "principal_sub": "user-7",
        "client_id": "https://app.example/cimd.json",
    }))
    .unwrap();
    assert_eq!(rev.principal_sub, "user-7");
    assert_eq!(rev.client_id, "https://app.example/cimd.json");
}

#[test]
fn registry_resolves_all_elevated_tier_executors() {
    // The elevated tier of the allowlist (peers, rbac
    // roles, inspection-rule delete). Each must resolve and self-identify;
    // none declares a non-default bar yet (factor/role enforcement is not
    // wired, so the requirement_enforceable latch keeps them single-op).
    let r = registry();
    for action in [
        "inspection_rule.delete",
        "peer.create",
        "peer.update",
        "peer.delete",
        "rbac.role.create",
        "rbac.role.update",
    ] {
        assert_eq!(
            r.get(action).map(|e| e.action_type()),
            Some(action),
            "{action} must be registered and self-identify",
        );
        let req = r.get(action).unwrap().requirement();
        assert_eq!(req.required_approvals, 1, "{action} is single-approver");
        assert_eq!(req.eligible_role, DEFAULT_ELIGIBLE_ROLE);
        assert!(req.factors.is_empty());
        assert!(req.cooldown_seconds.is_none());
    }
}

#[test]
fn reject_privileged_role_scopes_blocks_control_plane_grants() {
    // Ordinary / read-only scopes pass — role management stays proposable.
    assert!(reject_privileged_role_scopes(&[
        "mcp:read".into(),
        "mcp:invoke".into(),
        "scim:read".into(),
        "some:custom:tool".into(),
    ])
    .is_ok());
    // Each control-plane authority scope is refused (BadParams -> 422),
    // even when mixed with benign ones — no propose-path escalation.
    for s in [
        Scope::McpAdmin.as_str(),
        Scope::McpPropose.as_str(),
        Scope::ScimWrite.as_str(),
    ] {
        let err = reject_privileged_role_scopes(&["mcp:read".into(), s.into()]).unwrap_err();
        assert!(
            matches!(err, ExecError::BadParams(_)),
            "{s} must be rejected as BadParams, got {err:?}",
        );
    }
}

#[test]
fn registry_resolves_upstream_session_revoke() {
    // The Tier-A upstream-session revoke executor resolves and
    // its params parse; single-operator default like the other elevated
    // executors.
    let r = registry();
    let e = r.get("upstream_session.revoke").expect("registered");
    assert_eq!(e.action_type(), "upstream_session.revoke");
    assert_eq!(e.requirement().required_approvals, 1);
    let p: UpstreamSessionRevokeParams = serde_json::from_value(serde_json::json!({
        "sub": "user-7",
        "upstream_issuer": "https://idp.example",
    }))
    .unwrap();
    assert_eq!(p.sub, "user-7");
    assert_eq!(p.upstream_issuer, "https://idp.example");
}

#[test]
fn registry_resolves_break_glass_executors() {
    // break-glass mint + revoke. Both resolve, self-identify, and inherit
    // the single-operator default. Mint is proposable because the review
    // UI surfaces the captured params to the approver.
    let r = registry();
    for action in ["break_glass.mint", "break_glass.revoke"] {
        let e = r.get(action).expect("registered");
        assert_eq!(e.action_type(), action);
        assert_eq!(e.requirement().required_approvals, 1);
    }
    let mint: MintRequest = serde_json::from_value(serde_json::json!({
        "issued_to": "alice",
        "reason": "incident #42",
        "scope_pattern": "example-messages.send",
        "ttl_seconds": 900,
    }))
    .unwrap();
    assert_eq!(mint.issued_to, "alice");
    assert_eq!(mint.scope_pattern, "example-messages.send");
    assert!(mint.requires_amr.is_empty());
    let rev: BreakGlassRevokeParams =
        serde_json::from_value(serde_json::json!({ "token_id": Uuid::nil() })).unwrap();
    assert_eq!(rev.token_id, Uuid::nil());
}

#[test]
fn registry_resolves_api_key_revoke() {
    // api_key.revoke resolves, self-identifies, single-operator
    // default; params take the api_key id.
    let r = registry();
    let e = r.get("api_key.revoke").expect("registered");
    assert_eq!(e.action_type(), "api_key.revoke");
    assert_eq!(e.requirement().required_approvals, 1);
    let p: ApiKeyRevokeParams =
        serde_json::from_value(serde_json::json!({ "api_key_id": Uuid::nil() })).unwrap();
    assert_eq!(p.api_key_id, Uuid::nil());
}

#[test]
fn registry_resolves_rbac_role_delete() {
    // rbac.role.delete completes the role CRUD triad. It resolves,
    // self-identifies, and inherits the single-operator default bar — the
    // same posture as role.create/update (single-approver avoids the
    // satisfiability latch refusing it in a single-admin deployment). Like
    // create/update it also carries the control-plane-scope guard: it
    // refuses to delete a role granting mcp:admin / mcp:propose / scim:write
    // (a protected approver-set change), exercised by the
    // `rbac_role_delete_refuses_control_plane_role` integration test. Params
    // take the target role id.
    let r = registry();
    let e = r.get("rbac.role.delete").expect("registered");
    assert_eq!(e.action_type(), "rbac.role.delete");
    assert_eq!(e.requirement().required_approvals, 1);
    assert_eq!(e.requirement().eligible_role, DEFAULT_ELIGIBLE_ROLE);
    let p: RbacRoleDeleteParams =
        serde_json::from_value(serde_json::json!({ "id": Uuid::nil() })).unwrap();
    assert_eq!(p.id, Uuid::nil());
}

#[test]
fn registry_resolves_policy_publish_and_rollback() {
    // policy.publish + policy.rollback are tenant-scoped turnstile
    // operations (the maker's own tenant). Both resolve, self-identify, and
    // inherit the single-operator default bar; params parse.
    let r = registry();
    for action in ["policy.publish", "policy.rollback"] {
        let e = r.get(action).expect("registered");
        assert_eq!(e.action_type(), action);
        assert_eq!(e.requirement().required_approvals, 1);
        assert_eq!(e.requirement().eligible_role, DEFAULT_ELIGIBLE_ROLE);
    }
    let pub_p: PolicyPublishParams =
        serde_json::from_value(serde_json::json!({ "bundle_id": Uuid::nil() })).unwrap();
    assert_eq!(pub_p.bundle_id, Uuid::nil());
    let rb_p: PolicyRollbackParams =
        serde_json::from_value(serde_json::json!({ "version": 3 })).unwrap();
    assert_eq!(rb_p.version, 3);
}

#[test]
fn registry_resolves_policy_fragment_upsert_with_required_witness() {
    let r = registry();
    let e = r.get("policy.upsert_fragment").expect("registered");
    assert_eq!(e.action_type(), "policy.upsert_fragment");
    assert!(
        e.requires_target_etag(),
        "approval must bind to the live policy set captured at proposal"
    );
    assert_eq!(e.requirement().required_approvals, 1);
    let p: PolicyUpsertFragmentParams = serde_json::from_value(serde_json::json!({
        "base_hash": "policy-snapshot",
        "statement": "@id(\"example-security-alerts\") permit(principal, action, resource);"
    }))
    .unwrap();
    assert_eq!(p.base_hash, "policy-snapshot");
    assert!(p.statement.contains("example-security-alerts"));
    assert!(p.author.is_none());
}

#[test]
fn registry_resolves_manifest_publish_and_rollback() {
    // manifest.publish + manifest.rollback are the server-manifest
    // twins of the policy executors — tenant-scoped turnstile operations.
    // Both resolve, self-identify, single-operator bar; params parse.
    let r = registry();
    for action in ["manifest.publish", "manifest.rollback"] {
        let e = r.get(action).expect("registered");
        assert_eq!(e.action_type(), action);
        assert_eq!(e.requirement().required_approvals, 1);
        assert_eq!(e.requirement().eligible_role, DEFAULT_ELIGIBLE_ROLE);
        assert!(
            e.requires_target_etag(),
            "{action} must bind approval to the selected target and live manifest baseline"
        );
    }
    let pub_p: ManifestPublishParams =
        serde_json::from_value(serde_json::json!({ "bundle_id": Uuid::nil() })).unwrap();
    assert_eq!(pub_p.bundle_id, Uuid::nil());
    let rb_p: ManifestRollbackParams =
        serde_json::from_value(serde_json::json!({ "version": 5 })).unwrap();
    assert_eq!(rb_p.version, 5);
}

#[test]
fn registry_resolves_manifest_stage_and_publish() {
    // The inline-content authoring twin of manifest.publish: resolves,
    // self-identifies, single-operator bar, and its params parse (content
    // required, author optional).
    let r = registry();
    let e = r.get("manifest.stage_and_publish").expect("registered");
    assert_eq!(e.action_type(), "manifest.stage_and_publish");
    assert!(e.requires_target_etag());
    assert_eq!(e.requirement().required_approvals, 1);
    assert_eq!(e.requirement().eligible_role, DEFAULT_ELIGIBLE_ROLE);
    let p: ManifestStageAndPublishParams = serde_json::from_value(serde_json::json!({
        "base_hash": "manifest-snapshot",
        "content": "- name: x\n  transport: http\n  url: http://x/mcp\n"
    }))
    .unwrap();
    assert_eq!(p.base_hash, "manifest-snapshot");
    assert!(p.content.contains("name: x"));
    assert!(p.author.is_none());
}

#[test]
fn registry_resolves_manifest_upsert_servers() {
    // The small-params authoring path: resolves, self-identifies,
    // single-operator bar, and its params parse (content required, author
    // optional) — content is a PARTIAL set, merged into the live set at
    // execute.
    let r = registry();
    let e = r.get("manifest.upsert_servers").expect("registered");
    assert_eq!(e.action_type(), "manifest.upsert_servers");
    assert!(e.requires_target_etag());
    assert_eq!(e.requirement().required_approvals, 1);
    assert_eq!(e.requirement().eligible_role, DEFAULT_ELIGIBLE_ROLE);
    let p: ManifestUpsertServersParams = serde_json::from_value(serde_json::json!({
        "base_hash": "manifest-snapshot",
        "content": "- name: x\n  transport: http\n  url: http://x/mcp\n"
    }))
    .unwrap();
    assert_eq!(p.base_hash, "manifest-snapshot");
    assert!(p.content.contains("name: x"));
    assert!(p.author.is_none());
}

#[test]
fn registry_resolves_manifest_remove_servers() {
    let r = registry();
    let e = r.get("manifest.remove_servers").expect("registered");
    assert_eq!(e.action_type(), "manifest.remove_servers");
    assert!(e.requires_target_etag());
    assert_eq!(e.requirement().required_approvals, 1);
    assert_eq!(e.requirement().eligible_role, DEFAULT_ELIGIBLE_ROLE);
    let p: ManifestRemoveServersParams = serde_json::from_value(serde_json::json!({
        "base_hash": "manifest-snapshot",
        "server_names": ["alpha", "beta"]
    }))
    .unwrap();
    assert_eq!(p.base_hash, "manifest-snapshot");
    assert_eq!(p.server_names, ["alpha", "beta"]);
    assert!(p.author.is_none());
}

#[test]
fn elevated_tier_param_shapes_parse() {
    let peer_create: CreatePeerRequest = serde_json::from_value(serde_json::json!({
        "peer_name": "east-gw",
        "issuer": "https://east.example",
        "jwks_url": "https://east.example/jwks",
    }))
    .unwrap();
    assert_eq!(peer_create.peer_name, "east-gw");

    let peer_update: PeerUpdateParams = serde_json::from_value(serde_json::json!({
        "id": Uuid::nil(),
        "peer_name": "updated",
    }))
    .unwrap();
    assert_eq!(peer_update.id, Uuid::nil());
    assert_eq!(peer_update.peer_name.as_deref(), Some("updated"));
    assert!(peer_update.issuer.is_none());

    let role_update: RbacRoleUpdateParams = serde_json::from_value(serde_json::json!({
        "id": Uuid::nil(),
        "name": "triage",
        "scopes": ["mcp:read", "mcp:propose"],
    }))
    .unwrap();
    assert_eq!(role_update.name, "triage");
    assert_eq!(role_update.scopes.len(), 2);
    assert!(role_update.description.is_none());

    let rule_del: InspectionRuleDeleteParams =
        serde_json::from_value(serde_json::json!({ "id": Uuid::nil() })).unwrap();
    assert_eq!(rule_del.id, Uuid::nil());
}

#[test]
fn rate_limit_params_parse_optional_fields() {
    let only_id: RateLimitUpdateParams =
        serde_json::from_value(serde_json::json!({ "policy_id": Uuid::nil() })).unwrap();
    assert!(only_id.bucket_capacity.is_none() && only_id.refill_per_second.is_none());
    let both: RateLimitUpdateParams = serde_json::from_value(serde_json::json!({
        "policy_id": Uuid::nil(),
        "bucket_capacity": 100,
        "refill_per_second": 5.0,
    }))
    .unwrap();
    assert_eq!(both.bucket_capacity, Some(100));
    assert_eq!(both.refill_per_second, Some(5.0));
}

#[test]
fn default_requirement_is_single_operator_bar() {
    // An executor that doesn't override requirement() inherits the
    // single-approver default — the bar every action had before
    // per-action resolution, so existing behaviour is preserved.
    let req = RateLimitUpdateExecutor.requirement();
    assert_eq!(req.required_approvals, 1);
    assert_eq!(req.eligible_role, DEFAULT_ELIGIBLE_ROLE);
    assert!(req.factors.is_empty());
    assert!(req.cooldown_seconds.is_none());
}

#[test]
fn etag_of_is_stable_and_sensitive() {
    // The freshness token must be deterministic for identical target
    // state (so an unchanged target matches across propose/execute) and
    // shift for ANY field change (so an out-of-band edit is detected).
    let a = etag_of(&serde_json::json!({ "name": "triage", "scopes": ["a", "b"] }));
    let a2 = etag_of(&serde_json::json!({ "name": "triage", "scopes": ["a", "b"] }));
    let changed_scope = etag_of(&serde_json::json!({ "name": "triage", "scopes": ["a", "c"] }));
    let changed_name = etag_of(&serde_json::json!({ "name": "other", "scopes": ["a", "b"] }));
    assert_eq!(a, a2, "identical fields must hash to the same token");
    assert_ne!(a, changed_scope, "a changed scope must shift the token");
    assert_ne!(a, changed_name, "a changed name must shift the token");
}

#[test]
fn requirement_override_is_honored() {
    // The trait lets a higher-risk action raise its own bar — the seam
    // propose_core resolves through. The maker can't reach it: the
    // requirement is read from the executor, never from the request.
    struct StrictExecutor;
    #[async_trait]
    impl ActionExecutor for StrictExecutor {
        fn action_type(&self) -> &'static str {
            "test.strict"
        }
        fn requirement(&self) -> ApprovalRequirement {
            ApprovalRequirement {
                required_approvals: 2,
                eligible_role: "tenant-admins".into(),
                factors: vec!["mfa".into()],
                cooldown_seconds: None,
            }
        }
        async fn execute(
            &self,
            _state: &Arc<AdminState>,
            _tenant_id: &str,
            _actor: &Principal,
            _params: &Value,
        ) -> Result<ExecOutcome, ExecError> {
            unreachable!("requirement-resolution test never executes")
        }
    }
    let req = StrictExecutor.requirement();
    assert_eq!(req.required_approvals, 2);
    assert_eq!(req.eligible_role, "tenant-admins");
    assert_eq!(req.factors, vec!["mfa".to_string()]);
}

#[test]
fn peer_update_params_reject_unenforced_authority_choices() {
    for label in ["restricted", "full"] {
        assert!(
            serde_json::from_value::<PeerUpdateParams>(serde_json::json!({
                "id": Uuid::nil(), "trust_tier": label
            }))
            .is_err()
        );
    }
}
