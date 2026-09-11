# Authorization model — the strategy behind the Cedar policies

The gateway uses Cedar for authorization and OAuth scopes for capability access
and fresh authentication. See [policy authoring](agents/authz.md) for configuration.

## 1. The one idea: two orthogonal axes

Authorization here is the composition of **two independent axes**. Keeping them
separate is the whole model; conflating them is what produced the inconsistencies
this document exists to prevent.

| Axis | Question it answers | Mechanism | Lifetime | Cedar shape |
|---|---|---|---|---|
| **Authorization** | *Is this identity allowed to do this at all?* | group / role membership → a Cedar `permit` | durable (membership) | `permit (principal in Group::"…")` |
| **Freshness** | *Did this caller re-prove their identity just now?* | an ephemeral **step-up scope** obtained via a fresh IdP login | per-token (minted fresh on step-up) | `forbid (…) when { !principal.scopes.contains("…") }` |

This follows the authentication-vs-authorization split in
[RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html). Our step-up scope
(`mcp:invoke:high`) is a proxy for a recent, intentional IdP login: obtaining
it uses `prompt=login`, and Cedar checks for its presence. The IdP chooses the
authentication method; the gateway neither requests nor validates an
MFA-specific ACR.

**The rule that falls out of the two axes:**

- **Destructive** operations are an *authorization* problem → gated by a **role
  permit**. The synthetic `message-sender` fixture demonstrates the control;
  no step-up is implied.
- **Administrative** operations are *also* an authorization problem → `risk:
  high`, gated by an **admin permit**. `high` does **not** imply step-up.
- **Step-up is decoupled from the risk tier** and applied as a *sparse
  per-tool overlay*, not a tier: exactly the tools named in
  [`30-step-up.cedar`](../crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar) carry it — today only
  `delete_dataset` (the synthetic canary that exercises the re-auth path). Every other tool,
  `high` included, is permit-gated only.

## 2. Where a permission can live (the authorities)

Six authorities feed a Cedar decision. Each owns a *different kind* of fact;
picking the wrong one is the recurring mistake.

| Authority | Source of truth | Owns | Reaches Cedar as |
|---|---|---|---|
| **OAuth scope** | Authentik scope-mapping · API-key mint · RBAC-role union | capability **floors** (`mcp:read/invoke/admin/propose/observe`) and **step-up** elevations (`mcp:invoke:high`) | `principal.scopes` + handler self-gate floors |
| **Group** (OIDC `groups` claim) | Authentik group membership | the **authorization axis** — durable roles | `principal in Group::"X"` |
| **RBAC role** (Postgres, per-tenant) | `gateway_roles` + assignments + group-mappings | a tenant-local **bundle of scopes** | unions `granted_scopes` into `principal.scopes`; sets `principal.roles` |
| **risk tier** | gateway catalog (legacy manifests seed it) | which permit applies (low → open baseline / role; high → admin). Upstream annotations cannot set or override it. Step-up is a separate per-tool overlay, not a tier property (§4). | `resource.risk` |
| **ABAC cross-cuts** | legacy manifest (`pii`) or reviewed MCP trust claims · token type (`auth_method`) · SCIM (`scim_active`) · `tenant` | data sensitivity, credential strength, lifecycle, isolation | `resource.pii`, `principal.auth_method`, `principal.scim_*`, tenant scope |
| **break-glass** | single-use DB token | one-shot emergency override | `BreakGlassGate` wrapping the engine |

**Two distinct "group" concepts — do not confuse them:** `principal.groups`
drives Cedar `Group::"…"` permits. For OAuth principals it is the OIDC groups
claim; for API keys it is a catalog-validated group-name set. Neither is
trusted as tenant-local RBAC membership. SCIM-provisioned users reach Postgres
`group_role_mappings` through `principal.scim.groups` UUIDs, intersected with
their current durable membership on every protected-role resolution. RBAC
mappings mint *scopes*; they do not add Cedar group membership.

MCP annotations are a seventh input but not a seventh authority: they are
untrusted behavioral/data claims normalized by the gateway. The catalog and
Cedar decide whether a claim is admitted and what control it triggers. The
server never grants itself a lower risk tier, an authorization role, or an
approval exemption. See
[`docs/agents/upstreams.md`](agents/upstreams.md#classification-authority-claims-are-not-policy).

Every committed SCIM group create, replace, membership patch, or delete clears
the process-local SCIM and RBAC caches before follow-up audit or rendering
work, which gives ordinary-role changes prompt convergence on that replica.
RBAC resolutions containing `mcp:admin`, `mcp:propose`, or `scim:write` are
never cached, and their group path rechecks durable SCIM membership in
Postgres. A committed protected-membership revocation is therefore observed
across replicas on the next role resolution rather than waiting for a TTL.

### Entity attributes available to a policy

Built in [`crates/waygate-authz/src/cedar.rs`](../crates/waygate-authz/src/cedar.rs)
(`build_entities`) — that function is the authoritative, complete set; the
policy-relevant attributes (a non-exhaustive selection — e.g. `scim_external_id`
is also added when present) are:

- **principal**: `email`, `groups`, `roles`, `scopes`, `auth_method` (`"oauth"` |
  `"api_key"` | `"peer_assertion"` — the last is a Tier-C federated peer),
  `tenant`, `scim_present`, `scim_active`, and SCIM detail fields
  (`scim_user_name`, `scim_groups`, `scim_attrs`).
- **resource** (`Tool` *and* `Model` carry the same shape): `server`, `name`,
  `risk`, `side_effects`, `pii`.

> Scopes live on the **principal**, not the request `context` (the gateway
> leaves `context` empty). A step-up condition is
> `unless { principal.scopes.contains("mcp:invoke:high") }`.

## 3. The decision tree — "I need to let X do Y; where does it live?"

**Part A — classify the action's shape** (mutually exclusive; stop at the first match):

1. **Is Y read-only / non-mutating?** → it is `risk: low`, `side_effects: false`.
   The baseline permit ([`10-role-allow.cedar`](../crates/waygate-authz/tests/fixtures/policies/10-role-allow.cedar))
   already opens it to everyone with base access. **Add nothing.**
2. **Is Y destructive (mutates state, sends, deletes)?** → classify
   `side_effects: true`, keep `risk: low`, and scope it to a group with a role
   `permit` (the [`20-example-message-roles.cedar`](../crates/waygate-authz/tests/fixtures/policies/20-example-message-roles.cedar)
   least-privilege role pattern). **No step-up.**
   The baseline permits `risk == "low" && !resource.side_effects`; a
   side-effecting tool requires a matching role permit.
3. **Is Y administrative (manages the gateway, identities, policies, the control
   plane)?** → classify `risk: high`, gated by a role/admin permit. Reserve
   `high` for administration. Step-up is **decoupled** from the tier (§4/§6):
   `high` does **not** automatically require step-up. The only step-up-gated tool
   is the `delete_dataset` canary, via a narrow name-keyed forbid in
   [`30-step-up.cedar`](../crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar). (`gateway-control.*` is the
   canonical administrative surface: `mcp:admin` floor + admin permit.)
**Part B — orthogonal dimensions** that apply *on top of* whatever shape Part A
picked. These are **not** "stop at the first match" branches — always evaluate
them:

- **Data sensitivity (`pii`).** Does Y expose PII? Set `pii: true` **regardless of
  its read/destructive/admin shape.** A *read-only* PII tool is still Part A item 1
  (`risk: low`, `side_effects: false`) **and** `pii: true` — without the flag,
  [`15-pii-default.cedar`](../crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar) (which only fires on
  `resource.pii`) won't keep API-key callers away from it. Never let item 1's
  "Add nothing" mean "skip the PII flag."
- **Tenant scope-bundle.** If the grant is "this tenant's principals get a bundle
  of scopes," use a Postgres RBAC **role** (admin CRUD under `/admin`), not a
  hand-authored policy.

**Anti-patterns this tree exists to stop:**

- Do **not** gate step-up *eligibility* at the IdP (a SkipObject group-gated
  scope-mapping). Emit step-up scopes openly; express *who may use them* as a
  Cedar `permit` referencing a group — visible to the `/admin/policies`
  simulator and the audit log.
- Do **not** reach for `risk: high` to mean "dangerous." `high` means
  *administrative*. A dangerous-but-routine action is `side_effects: true` +
  a permit (axis 1), not step-up (axis 2).
- Do **not** add an authorization-bearing Authentik group that **no Cedar
  `permit` references.** An IdP group that nothing in `policies/` consumes is
  invisible to policy and grants nothing legible.

## 4. Risk taxonomy

| tier | meaning | how access is gated |
|---|---|---|
| `low` | everything that is not administrative | reads: open baseline permit; destructive (`side_effects:true`): role permit |
| `high` | **administrative** only | role/admin permit (no automatic step-up) |

**Step-up is decoupled from the tier**. `high` does not imply a
step-up prompt; it is a separate, sparse overlay applied per-tool via a
name-keyed forbid in [`30-step-up.cedar`](../crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar). The only
step-up-gated tool is the `delete_dataset` canary (irreversible synthetic data
deletion) — kept as one exercised instance so the fresh IdP re-auth flow stays
warm without sprinkling step-up across every administrative or destructive
action. See §6.

`RiskTier::Medium` is a quarantine threshold, not an authorization scope.
The example authorization policies classify tools as `low` or `high`.

## 5. Scopes: two kinds, one list

The scope list mixes two semantically different things — name them when you read
them:

- **Capability floors** — `mcp:read`, `mcp:invoke`, `mcp:admin`, `mcp:propose`,
  `mcp:observe`. Coarse, durable, enforced at the handler self-gate *and* via
  Cedar role permits. A built-in namespace self-gates on its floor regardless of
  any policy (see [`authz.md`](agents/authz.md) § built-in governance).
- **Step-up elevations** — `mcp:invoke:high`. Ephemeral and issued through a
  fresh IdP login, the axis-2 freshness proof.

## 6. Models are not step-up-gated

A model invocation is an **authorization** concern (who may use which model),
not a freshness one. Reserve step-up for administration. Model access is gated by
a Cedar `permit` on a group (e.g. a future `premium-models` group) — *not* by a
`llm:invoke:*` step-up scope. For example, restrict an expensive model with
a `permit (principal in Group::"premium-models", action, resource is Model)`
policy and the corresponding model classification.

## 7. Policy invariants

1. The deployed `GATEWAY_DASHBOARD_ALLOWED_STEP_UP_SCOPES` **⊇ the gateway code
   default** — or the override is absent and the code default governs.
2. Step-up (`mcp:invoke:high`) is a **sparse per-tool overlay**, not a tier:
   `30-step-up.cedar` gates exactly an explicit canary set (today only
   `delete_dataset`). `risk: high` is reserved for administrative surfaces and is
   gated by an admin **permit**, *not* by step-up — the two axes are decoupled.
3. No manifest classifies a tool `medium`. Enforced by
   `per_upstream_policies.rs::no_manifest_classifies_a_tool_medium`.
4. Every authorization-bearing group is referenced by a Cedar `permit`. An IdP
   group consumed by no policy is a defect.
5. Lowering a tool/model's risk tier **removes a control** and is a reviewed
   security event (it is how an LLM-plane step-up was once silently disabled).
6. **No `side_effects: true` tool is reachable by a groupless principal.** Every
   mutating / outbound-effect tool requires an explicit per-server operator or
   writer group (or admin); the baseline grants only read-only (`!side_effects`)
   tools. Enforced today (manifest-driven)
   by `per_upstream_policies.rs::no_side_effecting_tool_is_reachable_by_a_groupless_principal`,
   so a new side-effecting tool on any upstream is covered automatically.

## See also

- [`docs/agents/authz.md`](agents/authz.md) — Cedar policy authoring how-to,
  PII enforcement, built-in namespace governance.
- [`docs/agents/identity.md`](agents/identity.md) — how `Principal`
  (auth_method, groups, scopes, scim) is built and validated.
- [`docs/agents/break-glass.md`](agents/break-glass.md) — the one-shot override.
- The operator's private deployment documentation should describe the IdP side
  (providers, scope mappings, and groups).
