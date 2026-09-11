//! Stable canonical hashes for live MCP tool schemas and behavior contracts.
//!
//! Inputs are normalized so the hash is invariant under JSON-object
//! key ordering — two upstreams that emit the same logical schema with
//! differently-ordered keys produce the same `schema_hash`. The output
//! is a hex-encoded SHA-256 digest of:
//!
//! ```text
//!   "schema-v1" \x00 name \x00 description \x00 canonical-json(input_schema)
//! ```
//!
//! The `schema-v1` prefix discriminates this hash from
//! [`manifest_classification_hash`]'s `manifest-v1` (the importer
//! has no live schema to hash, so it falls back to a tuple of
//! classification fields). The `\x00` separators prevent
//! concatenation collisions.
//!
//! "Canonical-JSON" here = recursively sort object keys (BTreeMap)
//! before serializing. JSON arrays preserve their order (significant
//! per the JSON Schema spec for things like `enum` / `oneOf`).
//! [`behavior_hash`] extends the historical schema identity with the output
//! schema and security metadata used for admission and drift detection.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Compute the stable schema hash for a live MCP tool.
///
/// `name` is the tool name as advertised by the upstream
/// (`Tool.name`). `description` is the optional human description.
/// `input_schema` is the JSON-schema object the upstream returned
/// (`Tool.input_schema`, an rmcp `JsonObject` = `serde_json::Map`).
pub fn schema_hash(
    name: &str,
    description: Option<&str>,
    input_schema: &Map<String, Value>,
) -> String {
    let mut h = Sha256::new();
    h.update(b"schema-v1\x00");
    h.update(name.as_bytes());
    h.update(b"\x00");
    h.update(description.unwrap_or("").as_bytes());
    h.update(b"\x00");
    let canon = canonicalize_object(input_schema);
    // `serde_json::to_string` on a BTreeMap-backed Value yields
    // sorted-key JSON; serialization is total over Value so unwrap
    // is sound (no IO, no custom serializer).
    let s = serde_json::to_string(&canon).unwrap_or_default();
    h.update(s.as_bytes());
    digest_hex(h)
}

/// Compute the catalog version identity for a legacy manifest-classified tool.
///
/// The hash identifies the manifest generation that produced a catalog row;
/// it does not assert that the catalog's current classification still equals
/// the manifest tuple. Operators may deliberately override those catalog
/// facts without changing this source-generation identity.
pub fn manifest_classification_hash(
    name: &str,
    risk: &str,
    side_effects: bool,
    pii: bool,
    discriminator: Option<&str>,
    operations: &[ClassifiedOperation<'_>],
) -> String {
    let mut h = Sha256::new();
    h.update(b"manifest-v1\x00");
    h.update(name.as_bytes());
    h.update(b"\x00");
    h.update(risk.as_bytes());
    h.update(b"\x00");
    h.update([u8::from(side_effects)]);
    h.update([u8::from(pii)]);
    // Per-operation refinement extends the identity rather than replacing it.
    //
    // The extension is skipped entirely for a tool classified by name alone,
    // so its digest is byte-identical to the one this function produced before
    // refinement existed. That matters: the digest is a version identity, and
    // a changed one asks an operator to approve again. Every tool in a fleet
    // suddenly wanting re-approval because a field was added elsewhere would
    // be noise, and noise is how a real re-approval gets waved through.
    if discriminator.is_some() || !operations.is_empty() {
        h.update(b"\x00operations-v1\x00");
        h.update(discriminator.unwrap_or("").as_bytes());
        // Sorted, so the manifest's listing order is not part of the identity:
        // reordering two entries is not a decision an operator made.
        let mut sorted: Vec<&ClassifiedOperation<'_>> = operations.iter().collect();
        sorted.sort_by(|left, right| left.value.cmp(right.value));
        for operation in sorted {
            h.update(b"\x00");
            h.update(operation.value.as_bytes());
            h.update(b"\x00");
            h.update(operation.risk.as_bytes());
            h.update([u8::from(operation.side_effects), u8::from(operation.pii)]);
        }
    }
    digest_hex(h)
}

/// One operation's classification as it enters the version identity.
///
/// Borrowed because every caller already holds the strings; this type exists
/// to keep the hash's argument list readable, not to own anything.
#[derive(Debug, Clone, Copy)]
pub struct ClassifiedOperation<'a> {
    pub value: &'a str,
    pub risk: &'a str,
    pub side_effects: bool,
    pub pii: bool,
}

/// Compute the stable hash of every security-relevant field advertised by a
/// live MCP tool.
///
/// Unlike the historical [`schema_hash`], this includes the output schema,
/// standard MCP annotations, and the namespaced tool metadata — callers pass
/// the complete `Tool._meta` object, so a claim under ANY namespace (the
/// action-metadata extension or a sibling) participates. A gateway may
/// therefore use it as a quarantine boundary: changing behavior claims is
/// treated exactly like changing a callable schema and requires catalog
/// review.
pub fn behavior_hash(
    name: &str,
    description: Option<&str>,
    input_schema: &Map<String, Value>,
    output_schema: Option<&Map<String, Value>>,
    annotations: Option<&Value>,
    namespaced_metadata: Option<&Value>,
) -> String {
    let mut h = Sha256::new();
    h.update(b"behavior-v1\x00");
    h.update(name.as_bytes());
    h.update(b"\x00");
    h.update(description.unwrap_or("").as_bytes());
    let input_value = Value::Object(input_schema.clone());
    let output_value = output_schema.map(|schema| Value::Object(schema.clone()));
    for value in [
        Some(&input_value),
        output_value.as_ref(),
        annotations,
        namespaced_metadata,
    ] {
        h.update(b"\x00");
        let canonical = value.map(canonicalize).unwrap_or(Value::Null);
        let serialized = serde_json::to_string(&canonical).unwrap_or_default();
        h.update(serialized.as_bytes());
    }
    digest_hex(h)
}

fn digest_hex(h: Sha256) -> String {
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Compute a stable digest of one admitted schema value.
///
/// The catalog's historical [`schema_hash`] intentionally covers the tool
/// name, description, and input schema only. Validator caches must add this
/// digest to their key so any schema-only approval change cannot reuse a stale
/// positive or negative compilation result.
pub fn validator_schema_hash(schema: &Value) -> String {
    let mut h = Sha256::new();
    h.update(b"validator-schema-v1\x00");
    let canonical = canonicalize(schema);
    let serialized = serde_json::to_string(&canonical).unwrap_or_default();
    h.update(serialized.as_bytes());
    digest_hex(h)
}

fn canonicalize_object(m: &Map<String, Value>) -> Value {
    let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
    for (k, v) in m {
        sorted.insert(k.clone(), canonicalize(v));
    }
    Value::Object(sorted.into_iter().collect())
}

fn canonicalize(v: &Value) -> Value {
    match v {
        Value::Object(m) => canonicalize_object(m),
        Value::Array(a) => Value::Array(a.iter().map(canonicalize).collect()),
        _ => v.clone(),
    }
}

/// Stable canonical hash of MCP tool *call arguments*,
/// used by HITL approval-grant binding so an approval for
/// `send({to: "alice", body: "..."})` can't be replayed against
/// `send({to: "#general", body: "..."})`.
///
/// Hashes a SHA-256 of `"args-v1" \x00 canonical-json(args)`. The
/// `args-v1` prefix discriminates this from
/// [`schema_hash`]'s `schema-v1` and [`manifest_classification_hash`]'s
/// `manifest-v1`,
/// so a collision across hash spaces is structurally impossible.
/// Canonical-JSON is the same key-sorted form `schema_hash` uses —
/// arrays preserve order (JSON arrays are ordered), objects sort by
/// key recursively.
///
/// `args` is the arguments map as it arrived from the rmcp call
/// (`Option<&serde_json::Map<String, Value>>`, matching MCP's
/// `CallToolRequestParam.arguments`). `None` and `Some({})` hash to
/// the same value so a missing-args call and an explicit-empty-args
/// call match the same grant — an operator writing "approve this
/// tool with no arguments" covers both call shapes.
pub fn argument_hash(args: Option<&Map<String, Value>>) -> String {
    let mut h = Sha256::new();
    h.update(b"args-v1\x00");
    let canonical = match args {
        None => "{}".to_string(),
        Some(m) => serde_json::to_string(&canonicalize_object(m)).unwrap_or_default(),
    };
    h.update(canonical.as_bytes());
    digest_hex(h)
}

/// Bind a one-time approval to both the reviewed tool behavior and arguments.
///
/// The catalog tool id is stable across approved versions, so argument binding
/// alone would let a still-live grant survive a behavior-contract change. This
/// digest is what the grant store places in its historical `argument_hash`
/// column for newly minted grants.
pub fn approval_binding_hash(tool_behavior_hash: &str, argument_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"approval-binding-v1\x00");
    h.update(tool_behavior_hash.as_bytes());
    h.update(b"\x00");
    h.update(argument_hash.as_bytes());
    digest_hex(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn schema_hash_is_stable() {
        let schema = obj(json!({
            "type": "object",
            "properties": {"a": {"type": "string"}, "b": {"type": "number"}}
        }));
        assert_eq!(
            schema_hash("send", Some("send a thing"), &schema),
            schema_hash("send", Some("send a thing"), &schema),
        );
    }

    #[test]
    fn schema_hash_invariant_under_key_reorder() {
        // Same logical schema, different key order at every level → same hash.
        let a = obj(json!({
            "type": "object",
            "properties": {
                "alpha": {"type": "string", "minLength": 1},
                "beta": {"type": "number"}
            }
        }));
        let b = obj(json!({
            "properties": {
                "beta": {"type": "number"},
                "alpha": {"minLength": 1, "type": "string"}
            },
            "type": "object"
        }));
        assert_eq!(schema_hash("send", None, &a), schema_hash("send", None, &b),);
    }

    #[test]
    fn schema_hash_sensitive_to_changes() {
        let base = obj(json!({"type": "object", "properties": {"a": {"type": "string"}}}));
        let h = schema_hash("send", Some("desc"), &base);

        // Different name.
        assert_ne!(h, schema_hash("recv", Some("desc"), &base));

        // Different description.
        assert_ne!(h, schema_hash("send", Some("desc2"), &base));
        assert_ne!(h, schema_hash("send", None, &base));

        // Different schema content (added property).
        let augmented = obj(json!({
            "type": "object",
            "properties": {"a": {"type": "string"}, "b": {"type": "number"}}
        }));
        assert_ne!(h, schema_hash("send", Some("desc"), &augmented));

        // Different schema content (changed type).
        let typed = obj(json!({"type": "object", "properties": {"a": {"type": "number"}}}));
        assert_ne!(h, schema_hash("send", Some("desc"), &typed));
    }

    #[test]
    fn schema_hash_array_order_is_significant() {
        // JSON Schema `enum` and `oneOf` rely on array order being
        // meaningful; the hasher must NOT sort arrays.
        let a = obj(json!({"enum": ["a", "b"]}));
        let b = obj(json!({"enum": ["b", "a"]}));
        assert_ne!(schema_hash("t", None, &a), schema_hash("t", None, &b));
    }

    #[test]
    fn behavior_hash_is_canonical_and_covers_security_metadata() {
        let input = obj(json!({"properties": {"b": {}, "a": {}}, "type": "object"}));
        let reordered = obj(json!({"type": "object", "properties": {"a": {}, "b": {}}}));
        let output = obj(json!({"type": "object"}));
        let annotations = json!({
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        });
        let action = json!({
            "outcome": "benign",
            "requiresReview": false
        });
        let base = behavior_hash(
            "read",
            Some("read"),
            &input,
            Some(&output),
            Some(&annotations),
            Some(&action),
        );
        assert_eq!(
            base,
            behavior_hash(
                "read",
                Some("read"),
                &reordered,
                Some(&output),
                Some(&annotations),
                Some(&action),
            )
        );
        assert_ne!(
            base,
            behavior_hash(
                "read",
                Some("read"),
                &input,
                Some(&output),
                Some(&json!({"readOnlyHint": false})),
                Some(&action),
            )
        );
        assert_ne!(
            base,
            behavior_hash(
                "read",
                Some("read"),
                &input,
                Some(&output),
                Some(&annotations),
                Some(&json!({"outcome": "consequential", "requiresReview": true})),
            )
        );
        assert_ne!(
            base,
            behavior_hash(
                "read",
                Some("read"),
                &input,
                None,
                Some(&annotations),
                Some(&action),
            )
        );
    }

    #[test]
    fn validator_schema_hash_is_canonical_and_sensitive() {
        let a = json!({
            "type": "object",
            "properties": {
                "alpha": {"type": "string"},
                "beta": {"type": "integer"}
            }
        });
        let reordered = json!({
            "properties": {
                "beta": {"type": "integer"},
                "alpha": {"type": "string"}
            },
            "type": "object"
        });
        let changed = json!({"type": "string"});

        assert_eq!(validator_schema_hash(&a), validator_schema_hash(&reordered));
        assert_ne!(validator_schema_hash(&a), validator_schema_hash(&changed));
    }

    #[test]
    fn schema_hash_separator_no_collision() {
        // ("a", Some("bc")) vs ("ab", Some("c")) — separators must prevent collision.
        let s = obj(json!({}));
        assert_ne!(
            schema_hash("a", Some("bc"), &s),
            schema_hash("ab", Some("c"), &s),
        );
    }

    #[test]
    fn argument_hash_is_stable() {
        let v = obj(json!({"to": "alice", "body": "hi"}));
        assert_eq!(argument_hash(Some(&v)), argument_hash(Some(&v)));
    }

    #[test]
    fn argument_hash_invariant_under_key_reorder() {
        let a = obj(json!({"to": "alice", "body": "hi"}));
        let b = obj(json!({"body": "hi", "to": "alice"}));
        assert_eq!(argument_hash(Some(&a)), argument_hash(Some(&b)));
    }

    #[test]
    fn argument_hash_sensitive_to_value_changes() {
        let base = obj(json!({"to": "alice", "body": "hi"}));
        let h = argument_hash(Some(&base));
        assert_ne!(
            h,
            argument_hash(Some(&obj(json!({"to": "bob", "body": "hi"}))))
        );
        assert_ne!(
            h,
            argument_hash(Some(&obj(json!({"to": "alice", "body": "hello"}))))
        );
        // Argument-array order IS significant (the same hashing rule
        // schema_hash uses — JSON Schema's `enum`/`oneOf` rely on it,
        // and for arguments, list order is meaningful too).
        assert_ne!(
            argument_hash(Some(&obj(json!({"items": ["a", "b"]})))),
            argument_hash(Some(&obj(json!({"items": ["b", "a"]}))))
        );
    }

    #[test]
    fn argument_hash_none_equals_empty_object() {
        // A grant minted for "no arguments" must match callers who
        // omit args entirely OR send an explicit {} — both are the
        // same "empty call" from the operator's perspective.
        let none = argument_hash(None);
        let empty = argument_hash(Some(&obj(json!({}))));
        assert_eq!(none, empty);
    }

    #[test]
    fn argument_hash_distinct_from_schema_hash() {
        // The prefix discriminator must keep the two hash spaces
        // disjoint even when the canonical-JSON body collides.
        let same_body = obj(json!({"type": "object"}));
        let arg_h = argument_hash(Some(&same_body));
        let schema_h = schema_hash("type", Some("object"), &same_body);
        assert_ne!(arg_h, schema_h);
    }

    #[test]
    fn approval_binding_changes_with_behavior_or_arguments() {
        let base = approval_binding_hash("behavior-a", "arguments-a");
        assert_eq!(base, approval_binding_hash("behavior-a", "arguments-a"));
        assert_ne!(base, approval_binding_hash("behavior-b", "arguments-a"));
        assert_ne!(base, approval_binding_hash("behavior-a", "arguments-b"));
    }

    fn operation(value: &str, risk: &str) -> ClassifiedOperation<'static> {
        // Leaked so the borrowed view can be built inline in these tests; a
        // test binary's lifetime is the process.
        ClassifiedOperation {
            value: Box::leak(value.to_string().into_boxed_str()),
            risk: Box::leak(risk.to_string().into_boxed_str()),
            side_effects: false,
            pii: false,
        }
    }

    #[test]
    fn a_tool_without_operations_keeps_its_pre_refinement_digest() {
        // The digest is a stored version identity: a changed one asks an
        // operator to approve again. Adding per-operation refinement must
        // therefore leave every unrefined tool's digest untouched, or the
        // whole fleet would ask for re-approval at once and the real
        // re-approvals would be lost in the noise.
        //
        // Derived independently from the documented manifest-v1 layout
        // (prefix, name, NUL, risk, NUL, side_effects byte, pii byte) rather
        // than by calling this function, so it fails if the layout drifts.
        assert_eq!(
            manifest_classification_hash("gitea.api.read", "high", true, false, None, &[]),
            "fb14a4819d7dd4c68e3f04e020264d4402f85e120ef34b06b6e9587eb5d81575"
        );
    }

    #[test]
    fn naming_a_discriminator_changes_the_digest() {
        // Opting a tool into per-operation review is a decision, and the
        // catalog should ask for approval of it even before any operation is
        // named.
        assert_ne!(
            manifest_classification_hash("api.read", "high", true, false, None, &[]),
            manifest_classification_hash(
                "api.read",
                "high",
                true,
                false,
                Some("operation_id"),
                &[]
            )
        );
    }

    #[test]
    fn manifest_operations_hash_independently_of_listing_order() {
        // Reordering two entries in the manifest is not a decision anyone
        // made, so it must not cost a re-approval.
        let forward = [
            operation("repo.get", "low"),
            operation("repo.delete", "high"),
        ];
        let reversed = [
            operation("repo.delete", "high"),
            operation("repo.get", "low"),
        ];
        assert_eq!(
            manifest_classification_hash("api", "high", true, false, Some("op"), &forward),
            manifest_classification_hash("api", "high", true, false, Some("op"), &reversed)
        );
    }

    #[test]
    fn each_operation_field_participates_in_the_digest() {
        let base = [operation("repo.delete", "high")];
        let digest = manifest_classification_hash("api", "critical", true, true, Some("op"), &base);

        for changed in [
            [operation("repo.remove", "high")],
            [operation("repo.delete", "critical")],
            [ClassifiedOperation {
                side_effects: true,
                ..operation("repo.delete", "high")
            }],
            [ClassifiedOperation {
                pii: true,
                ..operation("repo.delete", "high")
            }],
        ] {
            assert_ne!(
                digest,
                manifest_classification_hash("api", "critical", true, true, Some("op"), &changed),
                "a changed operation classification must change the digest"
            );
        }

        // Dropping an operation, and adding one, are both changes.
        assert_ne!(
            digest,
            manifest_classification_hash("api", "critical", true, true, Some("op"), &[])
        );
        assert_ne!(
            digest,
            manifest_classification_hash(
                "api",
                "critical",
                true,
                true,
                Some("op"),
                &[
                    operation("repo.delete", "high"),
                    operation("repo.get", "low")
                ]
            )
        );
    }

    #[test]
    fn operation_fields_do_not_collide_across_their_separators() {
        // ("ab", "c") and ("a", "bc") are different classifications and must
        // not share a digest through concatenation.
        assert_ne!(
            manifest_classification_hash(
                "api",
                "high",
                false,
                false,
                Some("op"),
                &[operation("ab", "c")]
            ),
            manifest_classification_hash(
                "api",
                "high",
                false,
                false,
                Some("op"),
                &[operation("a", "bc")]
            )
        );
        // A discriminator's boundary with the first operation, likewise.
        assert_ne!(
            manifest_classification_hash(
                "api",
                "high",
                false,
                false,
                Some("op"),
                &[operation("id", "low")]
            ),
            manifest_classification_hash(
                "api",
                "high",
                false,
                false,
                Some("opid"),
                &[operation("", "low")]
            )
        );
    }
}
