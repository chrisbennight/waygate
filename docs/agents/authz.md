# Authorization (Cedar)

> **Status:** policy-authoring how-to. The strategy + decision record live in
> [`docs/authorization-model.md`](../authorization-model.md); this file is the
> hands-on guide for writing Cedar policies. The Cedar engine, gate, and
> entity-build code in [`crates/waygate-authz/`](../../crates/waygate-authz/) are
> the code of record.

## PII enforcement

Legacy (`classification_mode: manifest`) per-tool YAML carries a `pii: bool` flag on each
`ToolClassification` entry (see
[`crates/waygate-manifest-types/src/lib.rs`](../../crates/waygate-manifest-types/src/lib.rs)).
That compatibility path propagates the flag end-to-end:

1. **Pool → ToolFacts.** `UpstreamPool::tool_facts()` reads
   `ToolClassification.pii` from the manifest snapshot and stamps it on
   the [`ToolFacts`](../../crates/waygate-mcp/src/authz.rs) handed to
   the authz gate.
2. **ToolFacts → Cedar entity.** `CedarGate::may_call_tool` forwards
   `pii` through `ToolSpec` into the Cedar `Tool` entity's
   [`pii` attribute](../../crates/waygate-authz/src/cedar.rs).
   Policies can reference `resource.pii` directly.
3. **Cedar entity → audit row.** Every `AuditEvent` for a tool-call
   carries `pii: Option<bool>` (see
   [`crates/waygate-evidence/src/audit.rs`](../../crates/waygate-evidence/src/audit.rs))
   and persists it on the `audit_log` row's `pii` column (migration
   `0005_audit_pii.sql`). PII tools are queryable in audit reports.
4. **Admin UI.** The `/admin/tools` page shows the PII flag alongside
   risk + side-effects so operators can audit the classification at
   a glance.

The representative fixture policy
[`policies/15-pii-default.cedar`](../../crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar)
demonstrates how a deployment can **forbid API-key callers from invoking PII
tools**, with an explicit opt-in via group membership:

```cedar
forbid (
    principal,
    action == Action::"CallTool",
    resource
)
when {
    resource has pii && resource.pii && principal.auth_method == "api_key"
}
unless {
    principal has groups && (
        principal.groups.contains("mcp-admins")
        || principal.groups.contains("pii-readers")
    )
};
```

Rationale: API keys are static long-lived bearers with no MFA, no IdP
step-up, and no per-call attestation; a leaked key gives a stranger
identity-laundered access to whatever the key authorises. Interactive
OAuth callers go through Authentik (or the gateway's built-in CIMD AS),
can be MFA-forced, and are revocable at the IdP — that's the right
access mode for PII. Operators who need a service-account API key with
PII access enroll the key's subject in `pii-readers` (or `mcp-admins`).

The `unless` clause can also grant **narrower, server-scoped** exemptions for
single-purpose service roles. For example
[`policies/20-example-message-roles.cedar`](../../crates/waygate-authz/tests/fixtures/policies/20-example-message-roles.cedar)
exempts `message-sender` for the synthetic messaging service's **send** tools
only and `message-reader` for its low-risk **reads** only — so those keys reach
the service's PII-tagged tools without gaining PII access on another server.

This is a default, not a hard gate. Operators free to override:

- Delete `15-pii-default.cedar` to remove the restriction entirely.
- Replace it with a more granular per-server allow-list.
- Layer additional `forbid` rules — e.g. `unless` clauses that also
  require an `mcp:invoke:pii` scope.

The simulator at `/admin/policies` accepts a `pii` checkbox on the
simulated Tool resource so authors can dry-run rule changes before
shipping them.

For `classification_mode: mcp_annotations`, do not author a second PII
classification in the manifest. The MCP server supplies behavior claims and
result-level `sensitive` / `untrusted` trust annotations. The gateway derives
`side_effects` from `!readOnlyHint` and temporarily projects protected input or
output into the Cedar `pii` field. For annotation-native tools,
`resource.pii` therefore means “the admitted contract handles protected data,”
not specifically that the server declared personally identifiable
information. Unknown sensitivity classifier values are protected rather than
rejected.

The gateway catalog still owns `risk`, roles, and additional approval
requirements; Cedar and the result-release gate decide what the server's claims
mean for this deployment. Results missing explicit trust booleans are withheld,
as are results that claim sensitivity not anticipated by the admitted
contract. An authorized sensitive result is returned with its complete trust
metadata intact. There is no permissive fallback, and there is no blanket
prohibition on typed sensitive capability.

A deployment may make a Cedar service grant the complete direct-call write
control for one upstream by setting `approval_mode: policy_only` in its served
manifest. That explicit opt-in suppresses annotation-native `requiresReview`
and catalog `requires_approval` for the upstream; it does not grant access and
does not disable Cedar approval overlays. Pair a behavior-based group permit
with a confinement forbid so every side-effecting tool requires the service
role and newly added typed operations inherit the same rule. Omitting the field
uses the fail-closed `per_call` default, and no upstream name has special
approval semantics. Sensitivity remains independently governed by the
cross-cutting PII overlay.
The synthetic `example-deployer` fixture demonstrates that pattern with a
`deploy-operators` permit and matching confinement forbid.
See [Upstream MCP servers — Classification authority](upstreams.md#classification-authority-claims-are-not-policy).

## Invocation approval bindings

For a complete recipient-aware example, see
[Send internally; approve external email](../../examples/email-policy/README.md).
It uses `context.email_recipients.valid` and `.domains`, derived from all
explicit To, Cc, and Bcc arguments, with the same parser in the live invocation
path and dashboard simulator. The example describes the required tool envelope
contract and the limits of recipient-domain checks.

One-time invocation grants are matched against principal, catalog tool
identity, expiry, normalized arguments, and the admitted behavior hash. The
admin API accepts either arguments or their raw canonical digest **plus the
reviewed `behavior_hash`** — the behavior the approver reviewed. Minting refuses
with `409` when that reviewed hash differs from the tool's current approved
behavior, so a version reassigned between review and approval never binds a
human decision to an unreviewed contract; otherwise it combines the argument
digest with that hash before storage. The invocation path computes the same
binding before its atomic claim.

The reviewed `behavior_hash` is the approved tool-version identity, so what a
change must alter to reuse an approval depends on the classification mode. For
annotation-native tools it is the full behavior hash — name, description, input
and output schema, standard annotations, and namespaced metadata — so any schema,
annotation, or action-metadata change cannot reuse an approval issued for the
previous behavior, even when the call arguments are identical, and cannot be
silently approved forward either. For manifest tools the reviewed contract is the
classification tuple (name, risk, side-effects, pii); the manifest supplies no
reviewed input schema (the catalog stores it `NULL`), so a classification change
invalidates the approval, while live input-schema drift is governed by drift
quarantine rather than by the approval binding. The historical
database/API field remains named `argument_hash` for compatibility, but returned
stored values are behavior-and-argument binding digests. Approval-needed
notifications carry the raw canonical argument digest and the reviewed
`behavior_hash` so the admin endpoint can bind exactly what was reviewed.

## Built-in namespace governance (Tier 3 forbid-overlay)

The gateway answers three of its **own** MCP namespaces locally rather
than proxying them: `gateway-admin.*` (HITL propose), `gateway-observe.*`
(read plane), and `gateway-control.*` (direct control). Each one
**self-gates** on a coarse OAuth scope inside its handler — `mcp:propose`,
`mcp:observe`, `mcp:admin` respectively (see
[`crates/waygate-mcp/src/builtin.rs`](../../crates/waygate-mcp/src/builtin.rs)).
That scope is the **authoritative floor** and is enforced regardless of any
Cedar policy.

Tier 3 layers Cedar **on top of** that floor so an operator can write
policy that *further restricts* a built-in — e.g. "only the on-call group
may call `gateway-control.quarantine_server`", or "nobody may touch the
control plane outside a change window". The enforcement point is
`GatewayServer::authorize_builtin_overlay`
([`crates/waygate-mcp/src/server.rs`](../../crates/waygate-mcp/src/server.rs)),
which runs **before** the built-in handler so a forbidden call never
executes its side effect.

### The overlay can only narrow — it never grants

This is deliberately **not** the deny-by-default model the upstream tool
plane uses. Built-ins ship no `permit` policies of their own, so a
deny-by-default would lock every built-in out the moment an operator's
policy set simply didn't mention them — the opposite of the gateway's
"a broken or empty policy set must not lock the operator out" posture.
Instead the overlay reads the Cedar verdict as a **forbid-overlay**:

| Cedar verdict | Overlay action | Why |
|---|---|---|
| `Allow` | proceed | a permit named the built-in (or its low-risk default permit applied) |
| **determining `forbid`** (non-empty `policy_ids`) | **block** | operator policy narrows the floor — applies even to a caller the scope floor would admit |
| **clean baseline deny** (empty `policy_ids` — engine evaluated, no policy mentioned it) | proceed | no governance authored; the scope floor governs (no lockout) |
| `StepUpRequired` | block with an `insufficient_scope` hint | operator (or the default step-up policy) gated the built-in behind a scope |
| **engine error** (`BuiltinAuthz::Indeterminate`) | **fail closed (block)** | the authorization engine could not decide — never wave a side effect through on an unknown verdict |

The discriminator for the first three is Cedar's determining-policy set: a
fired `forbid` lands in `policy_ids`, an implicit default-deny does not. The
**fail-closed row is the subtle one**: the production Cedar engine maps an
engine/build error to a `Deny` with *empty* `policy_ids` — byte-identical to a
clean baseline deny — and a *request-time evaluation* error (an undefined
attribute, a type mismatch) merely drops the erroring policy, again leaving an
empty-`policy_ids` Deny. If the overlay read only that, either failure would
look like "no governance → proceed" and **fail open**. So the overlay does not
call `may_call_tool`; it calls `AuthzGate::authorize_builtin_call`, whose
Cedar-backed impl consults the engine's *error-preserving* path
(`AuthzEngine::try_evaluate_facts` → `CedarEngine::evaluate_facts_strict`, which
surfaces *both* a build error and a `diagnostics().errors()` evaluation error as
`AuthzOutcome::EngineError`) and returns `Indeterminate`, on which the overlay
fails closed. Two further wiring points keep that guarantee whole:

- The production gate is wrapped — `BreakGlassGate(CedarGate(..))` whenever a DB
  pool is configured. `BreakGlassGate` **forwards** `authorize_builtin_call` to
  its inner gate (it does *not* extend the single-use-token override to built-in
  governance), so the strict fail-closed path runs in DB-backed deployments too.
- The lenient `evaluate_facts` (the upstream tool plane) also fails closed on an
  erroring **`forbid`** — see *Unevaluatable policies* below. Strict goes further
  and refuses on an erroring `permit` too, because a built-in has no Cedar permit
  of its own and so cannot tell a dropped one from "no governance authored".

(Pinned at the engine/gate layer by `cedar.rs`'s
`forbid_on_gateway_control_fires_with_policy_ids_even_for_admin` /
`ungoverned_gateway_control_denies_by_baseline_with_empty_policy_ids` /
`builtin_strict_path_fails_closed_on_policy_evaluation_error`, `gate.rs`'s
`builtin_call_engine_error_maps_to_indeterminate` /
`builtin_call_clean_baseline_deny_proceeds`, and `break_glass_gate.rs`'s
`break_glass_forwards_indeterminate_unchanged`; at the dispatch layer by
`waygate_server.rs`'s `builtin_overlay_*` tests including
`builtin_overlay_fails_closed_on_engine_error`.)

A caller that lacks the namespace scope is still refused by the **self-gate
floor** even when no Cedar policy applies — the overlay only ever *adds*
restriction, never removes the floor.

Every overlay denial (`Forbidden` / `StepUpRequired` / the fail-closed
`Indeterminate`) emits a chained-best-effort `CallTool` audit row — `Denied` /
`StepUpRequired` outcome, with the namespace, tool, risk, PII flag, and fired
`policy_ids` — so a blocked control-plane call shows up in the activity feed at
parity with an upstream Cedar denial, not just in the logs.

### Resource shape

Built-in calls authorize over the same `Tool` entity as upstream tools, so
the full attribute vocabulary is available. `resource.server` is the
reserved namespace (`"gateway-admin"` / `"gateway-observe"` /
`"gateway-control"`), `resource.name` the bare tool name, and
`resource.risk` / `resource.side_effects` / `resource.pii` come from each
namespace's static descriptor (`describe()` — the same classification the
operator-visibility view renders; `gateway-control` tools are `High` +
side-effecting, the `gateway-admin` pollers carry `pii` because they return
an approver identity).

Native MCP reads authorize a distinct `Resource` entity. Its
`resource.server` attribute names the owning upstream and `resource.uri`
contains the exact, unmodified MCP URI, allowing policies to permit or forbid
one resource independently of others on that server. `resource.risk` comes
from the manifest URI-prefix declaration; an undeclared legacy upstream that
is found by catalog enumeration remains low risk. This makes ordinary
step-up policy apply to resource reads without publishing a Cedar context
attribute the request path cannot populate truthfully. `ListResources` remains
a server-level action. API-key profiles with a populated `allowed_tools` list
do not expose native resources because an exact tool grant cannot imply access
to a separate data surface. The synthetic fixture's
`example-catalog-product-resources` service grant permits authenticated
principals that can already discover the Example catalog to list its resources
and read exactly the `example-catalog://example-guides/design-v1` and
`example-catalog://example-guides/render-v1` guides.

Gateway-served Agent Skills use separate `ListSkills`, `FetchSkillResource`,
and `ReadSkill` actions, also evaluated against a `Resource` entity. A lazy
supporting-resource read first evaluates `FetchSkillResource` against immutable
Git provenance before the gateway contacts the source. If that permits, the
gateway loads the one indexed blob and evaluates `ReadSkill` against the
SHA-256 of those exact bytes before returning them. Policies that allow dynamic
supporting resources therefore permit both actions.

Skill resources add the immutable `source_origin`, `artifact_digest`,
`source_path`, and `source_object` attributes. A specific content read also
carries `skill_uri`, `revision_digest`, and `content_digest`; the pre-fetch
decision deliberately omits `content_digest` because the bytes do not exist at
that boundary. These are verified gateway facts, not frontmatter claims. The
representative `20-example-gateway-skills.cedar` policy demonstrates an
origin-bound grant. A generic MCP resource permit does not grant skill
discovery or reads, and changing the source or content changes the policy facts
and the content-bound approval identity.

### What the representative fixture set demonstrates for built-ins

The image ships no policy set. A deployment must author or adopt policies in
its own `GATEWAY_POLICIES_DIR`; the checked-in files are examples and test
fixtures, not runtime defaults. Built-ins are rendered as Cedar `Tool`
resources, so a deployment that adopts the representative fixture set gets
the following behavior:

- **Low-risk built-ins** — `gateway-observe.*` and the `gateway-admin` pollers
  (`get_change_status` / `list_my_changes`) — match
  [`10-role-allow.cedar`](../../crates/waygate-authz/tests/fixtures/policies/10-role-allow.cedar)'s
  `resource.risk == "low"` permit ⇒ `Allow` ⇒ proceed *for an interactive
  (OAuth) caller holding the namespace scope.*
- **PII-tagged built-ins under an API key.** Several of those low-risk built-ins
  carry `pii` — `gateway-observe.query_audit` / `triage_digest` (they return a
  principal `sub` / break-glass `issued_to`+`reason`) and the `gateway-admin`
  pollers (they return the approver identity). Because the overlay renders
  built-ins as Cedar `Tool` resources,
  [`15-pii-default.cedar`](../../crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar) — which `forbid`s
  an **API-key** caller from any `resource.pii` tool unless it is in
  `mcp-admins` / `pii-readers` — fires for them too. So an API-key principal
  holding only the namespace scope is **denied** those PII-tagged built-ins by
  that fixture policy (a determining forbid ⇒ `Forbidden`, not bypassable by
  step-up), exactly as for an upstream PII tool. The example illustrates a
  posture for static long-lived API keys: keep them away from identity-bearing
  data unless an operator enrolls the key's subject in `pii-readers`. An
  interactive OAuth caller is unaffected by that example forbid.
- **`gateway-admin.propose_change`** (Medium) is not step-up-gated by the
  representative fixture set;
  with no permit naming it for a non-admin it denies by clean baseline ⇒
  proceed (the `mcp:propose` floor governs). Admins match the admin permit.
- **`gateway-control.*`** is classified **High**, but the representative
  [`30-step-up.cedar`](../../crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar) `forbid`s only
  `resource.name == "delete_dataset"` — `high` no longer implies step-up, so it
  does **not** gate the control plane. Under that example set,
  `gateway-control.*` is governed by the admin permit plus the `mcp:admin` floor
  enforced in the handler: a non-admin without a permit naming it denies by
  clean baseline; an admin matches the admin permit. If you want the control
  plane to *also* require a fresh
  `mcp:invoke:high`, add it to the step-up overlay explicitly (name it in
  `30-step-up.cedar`) — it is no longer implied by `risk: high`.

### Example: lock the control plane to an operator group

To go further and require that `gateway-control.*` only be reachable by an
explicit operator group, drop a file like `50-gateway-control.cedar` into
`GATEWAY_POLICIES_DIR`:

```cedar
@reason("control plane is change-managed; join `control-operators` to call it")
forbid (
    principal,
    action == Action::"CallTool",
    resource
)
when { resource.server == "gateway-control" }
unless { principal in Group::"control-operators" };
```

Because `forbid` overrides `permit`, this binds even a member of
`mcp-admins` unless they are also in `control-operators`. Narrow it further
with `resource.name == "quarantine_server"`, a step-up `unless {
principal.scopes.contains("mcp:invoke:high") }` (scopes are exposed on the
`principal` entity, not the request `context`, which the gateway leaves empty —
see [`30-step-up.cedar`](../../crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar)), or a time-window
condition, exactly as you would for an upstream tool. The `/admin/policies`
simulator accepts a `server` of `gateway-control` so you can dry-run the rule
before
shipping it.



## Unevaluatable policies (guard optional attributes with `has`)

Cedar has **skip-on-error** semantics: a policy whose condition raises a runtime
error — most often an attribute that isn't on the entity, referenced without a
`has` guard — is dropped from the decision entirely and reported in
`diagnostics().errors()`. Cedar does this deliberately, so one broken policy
cannot take down an entire policy set.

That is safe for a `permit` and dangerous for a `forbid`. A dropped permit can
only *remove* an allow, and default-deny already covers it. A dropped forbid
*removes a restriction*: the guardrail silently vanishes and any matching permit
— the baseline read-only permit, a group grant — carries the call through to
`Allow`. The gateway therefore refuses a request whose forbid could not be
evaluated, on **every** path including the upstream tool plane, rather than
deciding it without the rule the operator wrote. The failure surfaces as a
`CedarError::Eval`, which the engine's `AuthzEngine` impl maps to a deny
carrying no diagnostic text, plus a `tracing::error!` naming the offending
policy id. An erroring permit keeps skip-on-error and is logged at `warn`.

For a policy author the rule is simply: **any attribute that is not always
present must be guarded.** The entity builder stamps `server` / `name` / `risk`
/ `side_effects` / `pii` on every Tool, `groups` / `scopes` / `auth_method` /
`tenant` / `roles` / `scim_present` on every User, and `channel` /
`approval_present` on every `CallTool` context — those are unconditional.
Everything else needs a guard, in one of two strengths:

**Guarded by `principal.scim_present` alone.** These are stamped on every
principal a SCIM row matched, so a short-circuiting `&&` behind `scim_present`
is sufficient — which is how `16-scim-active.cedar` is written:

- `principal.scim_user_name`, `principal.scim_active`, `principal.scim_groups`.

**Needs its own `has` guard.** `scim_present` does *not* imply these; the
builder omits each one when it has nothing to put there, so a SCIM-matched
principal can still lack them:

- `principal.scim_external_id` — omitted unless the IdP sent an external id.
- `principal.scim_attrs` — omitted unless at least one custom attribute
  converted to a Cedar type (nested objects and floats are dropped), and each
  key inside the record needs `principal.scim_attrs has <key>` as well.
- `principal.email` — omitted when the token carries no email claim.
- `resource.operation` — present only when the call selected one.
- `resource.uri` — `Resource` entities only; `context.client_id` — EMA only.

```cedar
// Wrong: denies nothing for a principal with no email, and now denies
// everything for one, because the rule cannot be evaluated.
forbid (principal, action, resource)
when { principal.email == "contractor@example.com" };

// Right.
forbid (principal, action, resource)
when { principal has email && principal.email == "contractor@example.com" };
```

Attach a policy test to the draft (see *Policy tests as publish gates*) covering
the fact shape that lacks the attribute — the test runner evaluates strictly, so
an unguarded reference fails the publish instead of reaching the tool plane.

## The authorization model (decision guide)

**Start at [`docs/authorization-model.md`](../authorization-model.md)** — the
strategy layer: the two-axis model (durable **authorization** via group/role
`permit`s vs ephemeral **freshness** via step-up scopes), the authority map, the
risk taxonomy, and the policy invariants. This section is the policy-author's
quick reference; that doc is the *why*.

### Where a new permission lives — Part A: the action's shape (stop at the first match)

1. **Read-only / non-mutating** → `risk: low`, `side_effects: false`. The
   baseline permit in [`10-role-allow.cedar`](../../crates/waygate-authz/tests/fixtures/policies/10-role-allow.cedar)
   already opens it. Add nothing.
2. **Destructive** (mutates, sends, deletes) → `side_effects: true`, `risk: low`,
   scoped to a group with a role `permit`
   ([`20-example-message-roles.cedar`](../../crates/waygate-authz/tests/fixtures/policies/20-example-message-roles.cedar)). **No
   step-up.** The baseline permits read-only tools with
   `resource is Tool && risk == "low" && !resource.side_effects`; side-effecting
   tools require a matching role permit. Models have a separate low-risk baseline.
3. **Administrative** (manages the gateway / identities / policies / control
   plane) → `risk: high`, gated by an **admin permit**. **Reserve `high` for
   this** — not for "anything destructive." `high` does not imply step-up: [`30-step-up.cedar`](../../crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar)
   gates only the explicit canary set (today `delete_dataset`); name a tool there if
   it must *also* require a fresh `mcp:invoke:high`.
**Part B — orthogonal, always apply** (not "stop at first match" branches):

- **Data sensitivity:** does Y expose PII? Set `pii: true` **regardless of shape** —
  a *read-only* PII tool is item 1 **and** `pii: true`, or
  [`15-pii-default.cedar`](../../crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar) (fires only on
  `resource.pii`) won't keep API-key callers away from it. Never let item 1's "Add
  nothing" skip the PII flag.
- **Tenant scope-bundle:** a Postgres RBAC **role** (admin CRUD), not a
  hand-authored policy.

**Don't:** gate step-up *eligibility* at the IdP (emit step-up scopes openly,
express *who may use them* as a Cedar `permit`); use `risk: high` to mean merely
"dangerous" (that's `side_effects` + a permit); or add an authorization-bearing
group that no `permit` references.

### Invariants

1. deployed `GATEWAY_DASHBOARD_ALLOWED_STEP_UP_SCOPES` ⊇ the code default (or absent).
2. step-up (`mcp:invoke:high`) is a sparse per-tool overlay — `30-step-up.cedar`
   gates exactly the canary set (today only `delete_dataset`); `risk: high` is
   reserved for administrative surfaces, gated by an admin permit, not step-up.
3. no manifest classifies a tool `medium`; `required_scope_for(Medium)` returns
   `None`. The representative fixtures enforce this with
   `per_upstream_policies.rs::no_manifest_classifies_a_tool_medium`.
4. every authorization-bearing group is referenced by a `permit`.
5. a risk-tier downgrade removes a control → a reviewed security event.

## Policy annotations (stable ids + layered grouping)

Every policy under `policies/*.cedar` carries Cedar `@annotation`s that give it
a stable identity and human-facing metadata. Annotations have **zero effect on
evaluation** (Cedar takes no opinion on annotation keys); they exist for the
operator and the dashboard.

| Annotation | Required | Purpose |
| --- | --- | --- |
| `@id("kebab-slug")` | yes, unique | Stable, human-meaningful policy id. |
| `@layer("…")` | yes | Grouping axis for the layered Policies view. |
| `@description("…")` | recommended | One-line human description. |
| `@tags("a, b, c")` | optional | Free-form tags (comma-separated). |
| `@reason("…")` | forbids | Surfaced to denied callers + audit. |

- **`@id` is a durable contract.** The loader re-keys each policy by its `@id`
  (see below), so the id flows straight into `AuthzResult.policy_ids` →
  `diagnostics().reason()`, the simulator response, and **every `audit_log`
  row**. That linkage is what lets the dashboard deep-link a fired policy back
  to its definition and answer "which decisions matched this policy". Renaming
  an `@id` orphans the historical audit rows that referenced the old id — treat
  it like any other stable identifier (rename only deliberately). Un-annotated
  fragments (dev mode, not-yet-migrated bundles) still load, keeping Cedar's
  positional `policyN`.
- **`@layer` is the evaluation-layer grouping.** The representative fixture set stacks as:
  `deny-default` (floor — `00-deny-by-default.cedar`, intentionally empty, so no
  policy object) → `baseline` (`10-role-allow`) → `pii-overlay` (`15`) →
  `scim-overlay` (`16`) → `service-grants` (`20-*`) → `step-up-overlay` (`30`) →
  `approval-overlay` (`35-codemode-approval`).
  Cedar evaluation is order-independent (forbid wins, permits union), so the
  layer is for human reading and the dashboard's layered view, not eval order.
- **The loader re-keys by `@id`.** `CedarEngine::from_source`
  (`reidentify_from_annotations`) covers BOTH the on-disk loader and the bundle
  path. A **duplicate `@id` is a hard load error** (`CedarError::DuplicateId`),
  so a duplicate can never silently merge two rules in the UI or the audit. The
  error is just another load failure, so it follows the standard failure
  isolation in "Policy load & reload semantics" below: at boot it aborts
  startup; on SIGHUP `resolve_policies` first tries to **recover** a good bundle
  from the `policy_bundles` ledger (installing the *recovered* engine), and only
  keeps the previous in-memory set when **both** disk and ledger recovery fail.
  It does not, by itself, guarantee the previously-installed set stays in force.
- **Two guards keep the set complete** (mirrors the migration-version guards):
  `scripts/check-policy-annotations.sh` (compile-free CI fast-fail) and the
  `waygate-authz` `every_on_disk_policy_has_stable_id_and_layer` test (runs
  under `cargo test`, so PR CI and the image build both block on it).

## Approval overlay (per-call human approval by policy)

The engine infers a fourth verdict, `ApprovalRequired`, the same way it infers
step-up: on a `CallTool` deny it re-evaluates with `context.approval_present`
flipped to `true`, and when only that flip stands between the caller and an
allow, the pipeline gates dispatch on a live per-call approval grant instead
of flatly denying. A caller without the underlying permit keeps the flat deny
— the overlay can only ever *narrow* an allow behind a grant, never widen
authorization.

Two context attributes exist on every `CallTool` evaluation for this:

- `context.channel` — `"direct"` for ordinary client calls and every nested
  Code Mode call. Stamped by the gateway, never from client-supplied data.
- `context.approval_present` — always `false` in the real evaluation; the
  approval inference flips it. Author approval overlays as
  `forbid … when { … && !context.approval_present }` so the escape hatch is
  explicit in the policy text. **Permits must never condition on
  `approval_present`** — approval narrows an existing authorization, it
  cannot create one. The engine enforces this: the inference runs only when
  the real evaluation fired a determining forbid, and it refuses (leaving
  the flat deny) when any permit determining the flipped allow references
  `approval_present`.

The catalog's per-tool `requires_approval` flag remains an
additional floor on every channel; Cedar's verdict and the flag each
independently require the grant claim.

All Code Mode source forms dispatch nested calls through the ordinary
direct channel. They therefore receive the same Cedar decision and approval
requirements as a direct call by the same principal; there is no separate
Code Mode mutation-admission switch.

**Stacked gates ladder.** A call blocked by both a step-up rule and an
approval overlay is not flat-denied: the engine reports `StepUpRequired`
first (only when flipping the scope *and* `approval_present` together would
allow, under the same narrowing-only guards), and once the caller
re-authorizes with the scope, the ordinary inference surfaces
`ApprovalRequired`. A call whose only gate is the approval overlay always
reports `ApprovalRequired`, whatever its risk tier — the engine never
invents a step-up Cedar did not declare.

An approval overlay naming a **built-in** tool fails closed as `Forbidden`
(built-ins have no grant-claiming dispatch stage), and break-glass never
converts `ApprovalRequired` into an allow — the governed override path for an
approval gate is the grant itself.

Every admin evaluation surface carries the simulated context: the
`/admin/policies` simulator has a channel select, the REST
`SimulateRequest` takes an optional `context` block
(`{"channel": "direct", "approval_present": false}`), attached policy
tests can assert `"expect": {"decision": "approval_required"}`, and the
decision-impact replay excludes nested-call rows because the audit row records
their hierarchy but not the gateway-stamped authorization channel. That keeps
the historical report honest rather than guessing which authorization channel
an older execution used. Current Code Mode executions all use direct authority.

## Policy load & reload semantics

- **Tenant selection.** The default tenant is file-backed: it loads
  `policies/*.cedar`, using the default tenant's ledger bundle only for recovery.
  Each non-default tenant is ledger-backed and evaluates against its own latest
  published bundle. Boot compiles the complete non-default tenant snapshot and
  fails closed if it cannot be read or compiled. The policy doorbell and poll
  rebuild that snapshot and replace it atomically only after every bundle
  compiles; a failed refresh keeps the previous tenant engines and marks policy
  health degraded. A tenant with no published bundle falls back to the default
  engine. Publishing, seeding, or deleting a tenant bundle rings the same
  doorbell; it never writes the default tenant's policy directory. Caller-facing
  policy listings, the REST/dashboard/MCP simulators, policy review, and impact
  replay select the same tenant engine as live authorization, so neither source
  nor diagnostic traces cross the tenant boundary. Scope-catalog reconciliation
  unions references from the default and every tenant engine. Tenant deletion
  removes the registry row and its policy bundles in one transaction, then
  rings the doorbell after commit even when no bundle row was found so every
  replica rebuilds from the current database state. The fleet snapshot excludes
  bundles without a current tenant registry row, and the migration removes
  legacy orphan bundles left by the earlier best-effort cleanup path before
  adding a cascading tenant foreign key. The lifecycle transaction locks the
  tenant row, so concurrent bundle inserts finish before the cascade or fail
  after it; they cannot create fresh residue. Tenant identifiers remain reusable
  after deletion, and a clean recreation starts without policy history from the
  prior record. The existing bearer-layer availability contract is unchanged:
  active tenant lookups retain their bounded cache and registry read failures do
  not turn a database outage into a fleet-wide lockout.
- **Add / edit / remove all take effect on reload — no restart.** The swap
  installs EXACTLY the new policy set, so it is not just additive: editing a
  `permit`/`forbid` changes the decision, and *deleting* a `permit` (or a whole
  `.cedar` file) removes the allowance it granted — a call that the old set
  permitted is denied on the next reload (SIGHUP / dashboard Reload / doorbell).
  Live MCP sessions are not dropped. The removal direction is pinned by
  `waygate-authz/src/cedar.rs::removing_a_permit_takes_effect_on_reload`, which
  evaluates Allow, `ReloadableCedar::reload`s a set with the permit gone, and
  asserts the same call now denies. (Edits/additions are covered implicitly by
  the golden-decision suite running against each set.)
- SIGHUP reload semantics: atomic-swap via `ReloadableCedar`. Failure
  isolation has two distinct outcomes under file-as-truth (don't conflate
  them): (a) a broken on-disk set that `resolve_policies` **recovers** from the
  `policy_bundles` ledger installs the *recovered* engine (a `RECOVERED:` audit
  reason + loud `WARN`), it does **not** keep the previous set; (b) the previous
  in-memory set is kept **only** when reload errors outright — both disk AND
  ledger recovery failed — so there is nothing safe to swap to.
- **Default-tenant file-as-truth load.** `resolve_policies` in
  `waygate-server/src/reload.rs` makes the on-disk `policies/*.cedar` the SOURCE
  OF TRUTH at boot and SIGHUP; the durable `policy_bundles` store is consulted
  ONLY to recover an unreadable on-disk set (history / rollback ledger, no
  longer the boot source). A dashboard / REST publish or rollback MIRRORS the
  chosen bundle back onto `policies/*.cedar` (the boot/SIGHUP source) before
  recording the ledger transition — `AdminState::mirror_policy_bundle_to_disk`
  → `waygate_policy::write_policy_bundle_to_dir` — so the HTTP surface and the
  on-disk set converge instead of the publish being silently dropped on the
  next reload. See
  [`Runtime configuration source of truth`](../server-config-source-of-truth.md#writes-and-concurrency).
- **In-place editing toggle + writable-volume requirement.** On a clean boot
  with an empty `policy_bundles` ledger the gateway auto-seeds v1 from the
  on-disk set (#489), so the dashboard editor appears without
  `--import-policies`. `GATEWAY_POLICY_EDITING` (default ON; `0`/`false`/`no`/
  `off` ⇒ read-only) gates the dashboard + REST mutation surface — enforced at
  the routes, the REST handlers, AND inside `publish_bundle_core` /
  `rollback_bundle_core` / `upsert_policy_fragment_core` so an approved HITL
  policy mutation can't bypass it (#490). Because a publish mirrors onto
  `policies/*.cedar`,
  editing requires `GATEWAY_POLICIES_DIR` to be a **persistent writable volume**
  (an ephemeral dir may be writable but would not survive
  a restart); a boot write-probe auto-disables editing on a read-only dir. See
  [`Runtime configuration source of truth`](../server-config-source-of-truth.md#operational-requirements).
- **Proposable fragment authoring.** `policy.upsert_fragment` accepts exactly one
  Cedar statement with a required `@id`, merges it into the live default-tenant
  set using the verified segmenter, preserves the active bundle's attached
  tests, and stages/publishes the reconstructed full bundle. Proposal captures
  the live-set hash; execution requires the same base and threads it into the
  cross-replica turnstile. A recent-decision impact replay is mandatory before
  the draft is staged, so an unavailable preview dependency fails without a
  draft or disk write. Both approval queues show the exact merged effect and
  suppress approval while that preview is blocked. Their shared approval core
  requires the preview acknowledgement and recomputes the captured effect
  before any approval write, so direct REST calls cannot bypass the preview.
- Authoring + testing workflow: golden-test fixtures, the policy simulator
  UI under `/admin`.

## Policy tests as publish gates

An operator can attach **assertions** to a policy draft — "this principal,
calling this tool, must be DENIED" — that run against the draft's Cedar content
**before** it is published. If any assertion fails, the publish is REJECTED
(HTTP 422) and the prior published set is kept untouched. This mirrors the
load-time invariant above: a draft that would behave wrongly can't replace a
working set, exactly as a broken `.cedar` keeps the previous set on reload.

- **Where they live.** Tests ride on the bundle in the reserved `tests JSONB`
  column of `policy_bundles` (migration 0012 — no new migration). The store
  (`waygate-policy`) round-trips the column as opaque `serde_json::Value` and
  stays content-agnostic; the typed `PolicyTestCase` shape and the runner live
  in `waygate-admin` (`crates/waygate-admin/src/policy_tests.rs`), which already
  owns the Cedar evaluator.

- **The gate.** `publish_bundle_core`
  (`crates/waygate-admin/src/policy_bundles.rs`) runs the attached tests AFTER
  the draft-status check and BEFORE the irreversible `mirror_then` disk write
  (validate-before-side-effect). A failing test returns 422 *before* anything
  reaches `policies/*.cedar`, so the prior published set stays live. The blocked
  publish is audited (`AuditOutcome::Denied`). A **malformed** stored test blob
  fails CLOSED — it 422s, never an `unwrap()` panic and never "no tests, publish
  freely".

- **Preview without publishing.** `POST /api/v1/policy_bundles/{id}/run_tests`
  runs the attached tests against the bundle's own content and returns a
  `PolicyTestReport` (pass/fail counts + per-case detail + a fired-policy trace
  on failures). It is read-only, so it is gated on `mcp:observe` (with
  `mcp:admin` satisfying it), the same tier as `POST /api/v1/policies/simulate`
  — NOT the `mcp:admin` the mutating bundle endpoints use.

### Test-case JSON schema

A draft's `tests` is a JSON array of cases. Each case is:

```json
{
  "name": "high-risk call must be denied",
  "request": {
    "principal": { "sub": "alice", "groups": ["mcp-users"] },
    "action":    { "type": "call_tool", "name": "wire_money", "risk": "high" },
    "resource":  { "type": "tool", "server": "bank", "name": "wire_money",
                   "risk": "high", "side_effects": true }
  },
  "expect": {
    "decision": "deny",
    "reason_contains": "forbidden",
    "policy_id_contains": "forbid-high-call"
  }
}
```

- `request` is the exact wire shape of `POST /api/v1/policies/simulate`
  (`SimulateRequest`): `principal` / `action` / `resource`.
- `expect.decision` is `"allow"` | `"deny"` | `"step_up"` (required).
- `expect.reason_contains` / `expect.policy_id_contains` are optional extra
  constraints: when set, some fired policy's `@reason` / `@id` must contain the
  substring, so an operator can pin not just *deny* but *denied by THIS overlay
  for THIS reason*.
- An empty / absent `tests` array imposes no gate (a draft with no attached
  tests publishes freely). A non-parsing draft fails
  every case (and so blocks), belt-and-suspenders behind `create_draft`'s own
  parse check.

## In the meantime

- **Engine:**
  [`crates/waygate-authz/src/lib.rs`](../../crates/waygate-authz/src/lib.rs)
  — `ReloadableCedar`, `Engine` trait, `AuthzAction`, `ResourceSpec`.
- **Cedar adapter:**
  [`crates/waygate-authz/src/cedar.rs`](../../crates/waygate-authz/src/cedar.rs)
  — entity construction (`build_entities`), policy compilation, decision
  mapping.
- **Gate:**
  [`crates/waygate-authz/src/gate.rs`](../../crates/waygate-authz/src/gate.rs)
  — the `AuthzGate` impl that wraps the engine for callers in
  `waygate-mcp`.
- **Policies on disk:** [`policies/`](../../crates/waygate-authz/tests/fixtures/policies/) — `00-deny-by-default.cedar`,
  `10-role-allow.cedar`, `20-*.cedar` per-service, `30-step-up.cedar`.
- **Per-call facts:** `ToolFacts` is built in
  [`crates/waygate-upstream/src/pool/mod.rs`](../../crates/waygate-upstream/src/pool/mod.rs)
  (`tool_facts()`); consumed in
  [`crates/waygate-mcp/src/authz.rs`](../../crates/waygate-mcp/src/authz.rs)
  (`AuthzGate::may_call_tool`).

## See also

- [`docs/agents/identity.md`](identity.md) — how `Principal` lands in the
  Cedar entity (auth_method, groups, scopes).
- [`docs/agents/upstreams.md`](upstreams.md) — manifest schema where
  classifications (risk / side_effects / pii) are authored.
