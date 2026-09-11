# Cedar policy golden tests

Each `*.json` file in this directory is a single test case the
`policy_golden.rs` harness reads, builds a `Principal` / `Action` /
`ResourceSpec` from, evaluates against the representative `policies/` Cedar fixture set
(`crates/waygate-authz/tests/fixtures/policies/`), and asserts:

- `expected.decision` matches the verdict (`"Allow"`, `"Deny"`,
  `"StepUpRequired"`).
- (optional) every string in `expected.reason_contains` appears in at
  least one of `AuthzResult.reasons` — proves the `@reason("...")`
  annotation on the fired forbid policy is still present and surfacing
  through the JSON-RPC data envelope.
- (optional) every string in `expected.policy_id_contains` appears in
  at least one `AuthzResult.policy_ids` entry.

## Test-case schema

```json
{
  "name": "human-readable test name (also surfaces in failure messages)",
  "description": "optional paragraph documenting WHY this case exists",
  "principal": {
    "sub": "alice",
    "email": "alice@example.test",                  // optional
    "groups": ["mcp-users", "pii-readers"],         // optional, default []
    "scopes": ["mcp:invoke"],                       // optional, default ["mcp:invoke"]
    "auth_method": "oauth",                         // "oauth" or "api_key"
    "tenant": "default",                            // optional, default "default"
    "scim": {                                       // optional, omit for non-SCIM principals
      "user_id": "scim-uuid",
      "user_name": "alice",
      "external_id": "alice@example.test",          // optional
      "active": true,
      "groups": [{"display_name": "Engineering"}],  // optional
      "attrs": {}                                   // optional
    }
  },
  "action": {
    "kind": "CallTool",                             // or SearchTools / ListTools / etc.
    "name": "example-messages.messages.send",                  // required when kind = CallTool
    "risk": "high"                                  // "low" | "medium" | "high"; required when kind = CallTool
  },
  "resource": {
    "kind": "Tool",                                 // "Tool" or "Server"
    "server": "example-messages",
    "name": "messages.send",                         // required when kind = Tool
    "risk": "high",                                 // required when kind = Tool
    "side_effects": true,                           // optional, default false
    "pii": false                                    // optional, default false
  },
  "expected": {
    "decision": "Deny",
    "reason_contains": ["mcp:invoke:high"],         // optional
    "policy_id_contains": []                        // optional
  }
}
```

## When to add a golden

Add a case whenever:

- A new representative forbid lands in `policies/` — the golden pins which
  principal-shape it blocks and which it lets through, so a future
  policy refactor that drops the forbid can't silently regress.
- A code review surfaces an authorization deny pattern that wasn't
  previously covered — express it with synthetic identities in a golden
  so the fix stays pinned.
- A `@reason("...")` annotation gets edited — assert the new text via
  `reason_contains` so a future operator can't strip the annotation
  without the test failing with a pointed message.

Goldens are read-only: the harness never writes back.  Names matter —
they appear verbatim in test failures.
