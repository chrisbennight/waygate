# Human-in-the-loop control-plane changes

Load this doc when changing anything under a new `waygate-changeset`
crate, the `change_requests` migration, the `mcp:propose` scope gate in
`crates/waygate-admin/src/scope.rs`, the dashboard review queue, or any
admin handler that grows a "propose instead of execute" path
(`api_keys.rs`, `rate_limit_policies.rs`, `policies.rs`,
`upstream_sessions.rs`).

Related: this is the **control-plane** sibling of the **data-plane** HITL
that already ships — per-call `approval_grants`
(`crates/waygate-admin/src/approval_grants.rs`,
`dashboard_approvals.rs`, `templates/approvals.html`), the
`ApprovalHub` WebSocket (`crates/waygate-admin/src/hitl_ws.rs`), and the
single-use claim idiom from break-glass
([`docs/agents/break-glass.md`](break-glass.md)). This design **reuses
that proven machinery**; it is not greenfield.

## The gap this closes

Every admin mutation — minting an API key (`api_keys.rs::mint`), editing
a Cedar policy (`policies.rs`), changing rate limits, revoking an
upstream session (`upstream_sessions.rs::revoke_session`) — is gated by a
flat `mcp:admin` scope in `scope.rs::require_scope()`. An automated
caller (Claude over MCP) cannot hold `mcp:admin` safely: an agent that
can rewrite its own Cedar policy or mint itself an admin key has no
meaningful guardrail. So today the only two options are "give the agent
admin" (unacceptable) or "the agent can't touch the control plane at all"
(the current wall).

This design adds the missing middle: the agent holds a **propose-only**
credential and a **human's dashboard approval** is what executes a
privileged change. The agent proposes; a human checks; the gateway
executes server-side. Proposal authority never implies approval authority.

## Shape: one spine, two optional layers

- **Spine (always on): a CIBA-shaped backchannel authorization flow.**
  Works for any caller — Claude over MCP, a REST script, a future second
  agent — with no client capabilities required.
- **Accelerator (optional): URL-mode MCP elicitation** to send the
  *present* operator straight to the approval page.
- **Shortcut (optional): form-mode MCP elicitation** for the low-risk
  `confirm` tier, executed in-session with no backchannel round-trip.

Cedar classifies every proposed action into a tier; the agent never
learns which tier applies (the elicitation decoupling principle — the
classification lives in the gateway, never in the agent's prompt).

> The built-in `gateway-admin.*` namespace exposes proposal, preview, status,
> and result tools. `propose_change` returns a binding code and approval URL
> for the agent to show the user. Client elicitation is not implemented;
> approval takes place in the dashboard.

## Proposal and approval as distinct authorities

A new scope `mcp:propose` sits beside `mcp:read` / `mcp:invoke` /
`mcp:admin`. An automated caller is granted `mcp:read + mcp:propose`:

- `mcp:propose` can **create** change requests and read their status.
- `mcp:propose` can **never execute**. Execution requires a human
  dashboard session (`mcp:admin`). Additional approval factors apply only
  when an executor explicitly captures them in its requirement.

`scope.rs` already rejects peer-assertion auth from admin even when the
scope is present; the propose gate is added in the same place. A propose-only
agent therefore cannot approve. A dashboard admin who creates a proposal in
the UI may also approve it when eligible, and counts toward the captured
distinct-admin quorum. That keeps `count = 1` satisfiable in a single-operator
deployment without giving an automated proposer execution authority.

## CIBA, mapped onto the gateway

The key equivalence: **CIBA `auth_req_id` ≡ our change-request handle ≡
Vault Control-Group wrapping-token accessor** — an opaque reference to a
*paused privileged request that an independently authorized admin approves out
of band*. We adopt the CIBA interaction shape and grant-type ergonomics; the
payload being authorized is a captured admin mutation, not a login.

```
propose_change(action, params, justification, login_hint, binding_message)
  → Cedar classify → render_preview → capture intent + target_etag
  → INSERT change_requests(status=pending) → notify approver(s)
  ← { change_request_id (=auth_req_id), status:"pending",
      binding_code:"AMBER-OTTER", approval_url, expires_in:900, interval:5 }

get_change_status(change_request_id)            # the CIBA poll
  ← "authorization_pending"   (honor slow_down → larger interval)
  ← "approved" + execution result   (gateway executed server-side)
  ← "denied"   + human reason
  ← "expired"
```

- **Delivery modes.** `poll` is the default (MCP `get_change_status`,
  with `slow_down` back-pressure so an eager poller can't hammer).
  `ping`/`push` to a registered notification endpoint serve REST/webhook
  automation. URL-mode elicitation is the client-side "ping" for the
  operator who is present.
- **binding_message + binding_code.** A short human-legible code
  (`AMBER-OTTER`) plus a one-line action summary, generated at propose,
  returned to the agent *and* shown on the approval page. The human
  confirms the code matches — the anti-confusion / anti-substitution
  control (CIBA `binding_message`, Vault accessor-reference).
- **Execute-on-approval, not token-on-approval (default).** Approval
  executes the captured intent **server-side**; the agent's poll returns
  the *result*. The agent only ever holds a propose credential + a read
  handle — it never receives a privileged token, so a compromised or
  injected agent has nothing to misuse. Token-on-approval stays a
  variant for genuinely multi-step actions, but is not the default.
- **Confidential client.** The propose credential authenticates as a
  confidential client (private_key_jwt / mTLS), per CIBA — not a bearer
  the agent could leak.

## Classification and tiers (Cedar)

An action registry tags each admin op with a risk class. Cedar
maps `(principal, action_type, params)` to one of:

| Tier | Meaning | Friction |
|---|---|---|
| `auto` | execute now | none (never reaches a human) |
| `confirm` | in-session confirm | form-mode elicitation, one tap |
| `approve` | human approval | dashboard, one click |
| `approve_factor` | human approval + an explicitly configured signed factor | dashboard + fresh factor evidence |
| `approve_2of_n` | multiple humans | dashboard + distinct approvers |
| `deny` | refused | — |

This is Vault's `controlled_capabilities` + factor `approvals = N` and
Teleport's risk-tiered routing, expressed in the existing Cedar engine
(`crates/waygate-authz/src/cedar.rs`, which already returns
`StepUpRequired`).

## Captured approval requirement

Two independent controls make up the approval boundary:

- **Authority separation** — `mcp:propose` can enqueue but cannot approve;
  approval requires an eligible `mcp:admin` dashboard session.
- **Reviewer quorum (`count = N`)** — exactly N distinct eligible admins must
  approve. An eligible admin proposer may count once; repeated approval by the
  same admin never increases the tally. Counts greater than one therefore
  opt into additional human review.

Each action class resolves a requirement, **captured onto the
change_request row at propose time** so config edited mid-flight cannot
weaken a pending request:

```
approval_requirement = {
  count:    N,                              # distinct approvals (default 1)
  eligible: <role/group>,                   # default: dashboard-admins
  factors:  [mfa | passkey],                # what each approval presents
  cooldown: <duration?>                     # minimum proposal age before approval
}
```

Resolved today from the action-executor registry default and per-action
override, then re-validated at execute against the *captured* requirement.
Cedar and deployment-level reviewer-count overrides are unsupported; no
environment variable changes the reviewer count.

**Status (per-action resolution wired):** `propose_core` resolves the
requirement from the action's executor — `ActionExecutor::requirement()`
(`change_executor/mod.rs`) — never from the `ProposeRequest`, so a maker
structurally cannot weaken its own bar. The trait default is the
single-operator bar (one approval from `DEFAULT_ELIGIBLE_ROLE =
dashboard-admins`, no extra factors); a higher-risk executor overrides
`requirement()` to raise `count` / `eligible_role` / `factors`.

**Enforcement boundary (fail-closed).** A requirement dimension is allowed
at propose only once it's actually enforced at approve, so a
declared-but-unenforced bar can never read as protected while executing on a
weaker gesture. `propose_core` **refuses at propose**
(`requirement_enforceable`) any resolved requirement that trips an unsupported
dimension — a fail-closed `500`, not a queued pending row.
The check destructures `ApprovalRequirement` so a newly-added field can't
silently slip the latch (it won't compile until classified).

- **`count ≥ 2` — ENFORCED.** `approve_and_execute_core` routes a
  multi-approver change to `ChangeRequestStore::record_approval`, after every
  approver has passed the common role/factor/cooldown boundary. The store
  collects N **distinct eligible-admin** approvals in the `change_request_approvals`
  ledger (a repeat approval by the same human can't inflate the tally) and
  atomically flips `pending → approved` only when the quorum is met; execution
  fires on that flip. `count = 1` stays the single-`UPDATE` `try_approve`
  fast path. A partial approval returns the still-`pending` change without
  executing. Per-approval `ChangeRequestApprove` audits are post-commit (the
  shared issue-#151 posture), so the fail-closed `ChangeRequestExecute` audit
  re-derives and names **every** distinct approver from the ledger via
  `list_approvers` — no M-of-N change can reach `executed` without a durable
  audit attributing each approver who counted toward its quorum, even if an
  individual partial-approval audit had failed.
- **`eligible_role` — ENFORCED.** The default `dashboard-admins` role denotes
  the existing non-peer `mcp:admin` checker gate. A non-default role must be
  present exactly in the approver's server-derived `Principal.roles` before
  any approval store mutation.
- **`mfa` / `passkey` factors — ENFORCED only when explicitly captured.**
  Signed ID-token `auth_time`, `amr`, and `acr` claims are normalized into the
  encrypted dashboard session. A factor-protected approval requires evidence
  no older than five minutes. The dashboard reauthorization flow forces
  `prompt=login`, but does not request or compare an MFA ACR; authenticator
  policy belongs to the IdP, and passkey evidence is not promoted into MFA.
  Bearer-only REST approval has no dashboard session and therefore fails closed
  for factor-protected rows. Unknown factors and `break_glass` remain refused at
  propose; no approval-time presentation channel exists for them. No shipped
  executor currently captures an `mfa` requirement.
- **`cooldown_seconds` — ENFORCED.** Approval is unavailable until
  `created_at + cooldown`; denial stays available throughout. Measuring from
  the immutable proposal timestamp makes the delay restart- and replica-safe.
  Proposal TTL must be strictly longer than the cooldown.

The latch still rejects malformed or unsupported bars. Cedar-override and
deployment-config legs remain to-do — today the leg in effect is the registry
(executor) default.

### Proposable actions today

The executor registry (`waygate-admin/src/change_executor/mod.rs`) IS the propose
allowlist — `validate_propose` rejects any `action_type` not registered, so a
maker can only queue an intent that can actually execute. Each executor is a
thin adapter over the same `*_core`/store method the dashboard/REST handler
calls, so validation, conflict mapping, and the durable audit can't drift
between the direct-admin and propose paths.

| `action_type` | Tier | Side effect | Secret? |
|---|---|---|---|
| `rate_limit.create` | standard | new rate-limit policy | no |
| `rate_limit.update` | standard | mutate capacity/refill | no |
| `rate_limit.delete` | standard | remove a policy | no |
| `oauth_consent.revoke` | standard | soft-revoke a consent grant (idempotent) | no |
| `inspection_rule.delete` | elevated | remove an inspection rule | no |
| `peer.create` | elevated | register a federated peer | no |
| `peer.update` | elevated | mutate a federated peer's fields | no |
| `peer.delete` | elevated | deregister a federated peer | no |
| `rbac.role.create` | elevated | create an RBAC role | no |
| `rbac.role.update` | elevated | replace an RBAC role's name/scopes | no |
| `rbac.role.delete` | elevated | delete an RBAC role (assignments/mappings cascade by FK; missing target fails closed) | no |
| `rbac.assignment.grant` | elevated | grant a principal an ordinary RBAC role | no |
| `rbac.assignment.revoke` | elevated | revoke a principal's ordinary RBAC role assignment | no |
| `rbac.assignment.grant_privileged` | protected | grant a principal a control-plane RBAC role | no |
| `rbac.assignment.revoke_privileged` | protected | revoke a principal's control-plane RBAC role assignment | no |
| `rbac.group_mapping.grant` | elevated | grant an ordinary RBAC role through a SCIM-provisioned group | no |
| `rbac.group_mapping.revoke` | elevated | revoke an ordinary RBAC role from a SCIM-provisioned group | no |
| `rbac.group_mapping.grant_privileged` | protected | grant a control-plane RBAC role through a SCIM-provisioned group | no |
| `rbac.group_mapping.revoke_privileged` | protected | revoke a control-plane RBAC role from a SCIM-provisioned group | no |
| `group.create_local` | standard | register a tenant-local group without shadowing a SCIM-provisioned name | no |
| `group.delete_local` | standard | delete an unreferenced tenant-local group; SCIM groups are never eligible | no |
| `scope.create_local` | standard | register a tenant-local capability scope | no |
| `scope.delete_local` | standard | delete an unreferenced tenant-local scope; global built-in/policy scopes are never eligible | no |
| `agent_config.create` | standard | create a tenant agent configuration, including its reviewed tool allowlist and runtime limits | no |
| `agent_config.update` | standard | fully replace a tenant agent configuration and lifecycle state | no |
| `agent_config.delete` | standard | delete a tenant agent configuration | no |
| `api_key_profile.create` | standard | create an immutable tenant API-key profile with its complete scope, server, tool, TTL, reason, and owner constraints | no |
| `api_key_profile.delete` | standard | delete a tenant API-key profile only when no live key references it | no |
| `tenant.update` | standard | rename the maker's own tenant (display name only; `status` stays operator-only) | no |
| `audit.retention.set` | elevated | set the maker's tenant's per-category audit-retention window | no |
| `audit.retention.clear` | elevated | clear the maker's tenant's per-category audit-retention policy (idempotent) | no |
| `audit.routing.set` | elevated | (re)configure the maker's tenant's evidence-exporter routing | no |
| `audit.routing.clear` | elevated | remove the maker's tenant's evidence-exporter routing row (idempotent) | no |
| `upstream_session.revoke` | elevated | revoke a Tier-A upstream session (idempotent) | no |
| `upstream.reconnect` | standard | recover a disconnected upstream; optionally clear drift quarantine after recovery succeeds | no |
| `upstream.refresh_catalog` | elevated | replace an upstream MCP session and republish its live classified tool inventory | no |
| `upstream.quarantine.clear` | standard | clear one upstream's in-process drift quarantine | no |
| `tool_contract.approve` | standard | accept one exact observed tool replacement and update its annotation approval hash when required | no |
| `catalog.server.unquarantine` | elevated | restore one exact, reviewed durable catalog server from `quarantined` to `live` | no |
| `config.reload` | standard | ring the policy and/or manifest fleet reload doorbell for the maker's tenant | no |
| `break_glass.mint` | elevated | mint a single-use, scope-pinned, ≤24h Cedar override token | no |
| `break_glass.revoke` | elevated | hard-delete a break-glass token (idempotent) | no |
| `api_key.mint` | elevated | mint an API key | yes (burn-on-read) |
| `api_key.revoke` | elevated | revoke an API key (tenant-bound, idempotent) | no |
| `policy.publish` | elevated | publish a draft policy bundle (mirror-then-ledger; the caller's tenant) | no |
| `policy.rollback` | elevated | roll a tenant's policy forward to a previously-published version's content | no |
| `policy.upsert_fragment` | elevated | merge one `@id`-addressed Cedar statement into the live default-tenant set, require impact replay, then stage and publish the reconstructed full bundle | no |
| `manifest.publish` | elevated | publish a draft server-manifest bundle (turnstile + mirror-to-disk; the caller's tenant) | no |
| `manifest.rollback` | elevated | roll a tenant's server-manifest set forward to a previously-published version | no |
| `manifest.stage_and_publish` | elevated | stage a manifest set from inline YAML and publish it in one step against an inspected default-tenant live-set hash | no |
| `manifest.upsert_servers` | elevated | merge a partial set into the inspected default-tenant live set and publish it (small params; add/replace by `name`) | no |
| `manifest.remove_servers` | elevated | remove selected names from the inspected default-tenant live set and publish the server-side reconstructed set | no |

The three `upstream.*` operational actions act on the in-memory upstream pool
of the replica that executes the approved change. They are intended for
targeted recovery; another replica with a healthy, distinct upstream session
stays unchanged until it independently re-dials or the action is executed
there. `config.reload` is different: it rings the tenant's Postgres
policy/manifest doorbell, which every replica listens to, and the periodic
pointer poll remains the missed-notification backstop. The result
reports which configured doorbells actually fired and `fleet_wide: true` when
at least one did. REST, direct `gateway-control`, and these executors share the
same core operations, including the invariant that reconnect clears process-local
quarantine only after a successful re-dial. Durable tool-change quarantine
requires an exact `tool_contract.approve` decision; these runtime controls
cannot release it. Read the action context to inspect the replacement and
capture its generation and hashes before proposing acceptance.
A forced catalog refresh whose replacement
session cannot initialize fails the governed change loudly; the pool keeps the
prior session and inventory active.

`catalog.server.unquarantine` is a separate durable lifecycle operation. Its
proposal binds the tenant-scoped server UUID, reviewed name, `quarantined`
status, and row `updated_at`; approval performs a compare-and-swap to `live`
and writes the matching catalog approval record in the same transaction. If
the row changes while approval is pending, execution fails closed and the
operator must inspect and re-propose. The direct catalog `approve` route
retains its legacy transitions except that it rejects `quarantined` rows, so it
cannot bypass this recovery gate. This action does not reconnect the upstream
or clear the pool's separate per-tool drift quarantine.

Every action except the four protected RBAC membership actions inherits the
single-operator default bar ([`DEFAULT_ELIGIBLE_ROLE`], one approval, no
factors). Protected direct and group membership grants/revokes require one
eligible dashboard admin and a 300-second proposal cooldown. They do not add
an MFA requirement; the IdP owns authentication-method policy. The approval
boundary can enforce distinct-approver M-of-N, exact non-default roles,
explicitly configured fresh factor evidence, and proposal-age cooldowns;
unsupported factors still fail the proposal latch. Existing executors remain
at the default until their risk-specific bars are assigned in focused action
changes.
`rbac.role.delete` likewise ships at the single-operator default — it
completes the `rbac.role.{create,update,delete}` triad at the same bar
create/update use. Like create/update it carries the control-plane-scope guard
(it refuses to delete a role that grants
`mcp:admin` / `mcp:propose` / `scim:write`, as that is a protected approver-set
change — see below). `policy.publish` / `policy.rollback` likewise
ship at the single-operator default; they are tenant-scoped (a maker publishes
or rolls back **their own tenant's** policy bundle, resolved from the approver's
principal — no cross-tenant reach) and run the same `publish_bundle_core` /
`rollback_bundle_core` the REST handlers call, so the mirror-then-ledger
turnstile, the draft/version prechecks, and the audit are identical on the
direct-admin and propose paths. A lost turnstile, a no-op (content already
live), or a non-draft / never-published target maps to a precondition failure
(the change is durably `failed`); a disk-ahead double-fault maps to a loud store
error. `manifest.publish` / `manifest.rollback` are the
server-manifest twins of the policy executors — same tenant-scoping, the same
locked publish/rollback cores in `manifest_bundles.rs`, and the same fail-closed
execution mapping (a target that becomes non-draft or missing
after preview, or a lost turnstile, → precondition failure; a no-op
disk-already-current → bad-params; a mirror failure → loud store error).
`manifest.stage_and_publish` is the inline-content
authoring twin: an agent proposes the full manifest-set YAML, the approver
reviews its expected service impact (`manifest_change_preview` projects configured
tool additions/removals, post-publication catalog/runtime/drift barriers, and
remaining operator actions). Historical decision replay is supporting evidence,
and the console labels it not applicable when a candidate adds or removes tools
without reclassifying an existing tool. On approval the shared core validates →
stages a draft → publishes it — so an agent authors a manifest change through the
HITL flow instead of editing `servers/*.yaml` on the NFS volume directly
(which leaves the ledger stale). It enters the same locked publish body as the
dashboard path, passing the agent-inspected `base_hash` into the turnstile CAS,
then into the conditional filesystem commit. The latter rechecks and preserves
the live files at the actual mutation boundary, so a raw NFS edit that bypasses
the database pointer is not overwritten. Replicas compare reload candidates
with that freshly advanced pointer and retain their previous complete set while
the multi-file commit is in progress. A synced marker is present before any live
YAML is moved; if the writer process dies, boot and reload treat the marked
directory as incomplete and use the existing ledger-recovery path instead of
activating it. The marker clears only after the replacement or rollback is
verified. The mirror / ledger / audit ordering otherwise stays identical, and a
stale replacement is refused for re-preparation. A bad or empty set fails before
staging. The set rides in the change-request `params` under the document cap
(`DOCUMENT_MAX_PROPOSE_PARAMS_BYTES`), and may be uploaded rather than inlined
(see "Uploading a document instead of inlining it" below);
`manifest.upsert_servers` carries only the changed servers
— a partial set merged into the live on-disk set server-side, so the `params`
scale with the change, not the whole set — and is the small-params path for
large deployments and single-server edits (add/replace by `name`).
`manifest.remove_servers` is the matching small-params removal path: it removes
only selected current names and reconstructs the full set server-side. Their
previews replay the exact reconstructed classification effect, so the approver
reviews what will land. The typed manifest effect returned by
`gateway-admin.preview_change` keeps four questions separate: the configured
capability delta (including newly added tools, which have no historical
baseline), a bounded prospective Cedar sample for added and reclassified tools,
bounded authorization replay for observed calls to reclassified tools, and
projected availability across the runtime pool, catalog lifecycle, and
preserved drift quarantine. The prospective sample deduplicates recent caller
contexts and evaluates each candidate tool-level fallback plus its declared
operation refinements using the facts the runtime would authorize. It reports
per-target verdict totals and states when contexts or targets were omitted; it
is evidence about representative access, not a complete user inventory.
Annotation-native targets are explicitly indeterminate because their live
side-effect and sensitivity facts derive from reviewed MCP claims that are not
encoded in the manifest draft; the preview never substitutes the legacy flags.
For operation-aware tools, the tool-level fallback is also indeterminate:
admissible undeclared operation strings retain the fallback facts but remain
visible to Cedar, so a single synthetic operation value cannot represent every
possible policy verdict. Declared operations are still evaluated individually.
Historical replay likewise treats a null operation on an operation-aware tool
as non-replayable because null also identifies rows written before operation
capture existed and the original discriminator argument is unavailable.
Both evidence types carry explicit applicability reasons, so no
recent callers or zero replayed rows never reads as proof that a newly added
capability is harmless. The effect also reports remaining operator follow-up and states that fleet
activation is asynchronous; publication alone is not proof that every replica
has connected, admitted, or removed the tools. Because the availability plane
contains gateway-wide live state, it is returned only for the default tenant;
MCP observers must also satisfy the maker/admin floor, peer exclusion, profile
confinement, and Cedar server-discovery boundary. The authenticated dashboard
approval queue remains the observer-less trusted caller. All live-disk authoring
actions are default-tenant-only while the manifest directory remains
gateway-wide. Both approval queues require the operator to check “I reviewed the
effect preview.” The shared REST/dashboard approval core then recomputes that
captured manifest effect before consuming any approval. Missing acknowledgement,
invalid candidate content, a blocked execution precondition, or an unavailable
replay or effective-service projection leaves the request pending. Existing API
clients may still send the former `policy_preview_acknowledged` field name; new
clients use the action-neutral `effect_preview_acknowledged` name. Default-tenant
full-set draft publish and rollback requests capture both the selected bundle
fingerprint and the live on-disk manifest hash; their queue preview and write
turnstile use that same witness, so an intervening manifest change requires a
fresh proposal rather than changing the effect being acknowledged. Non-default
manifest tenants retain their ledger-only publish/rollback behavior: the preview
states that no gateway-wide runtime activation occurs and the witness contains
only the tenant-local target fingerprint. Non-default policy publishes activate
the tenant's Cedar engine from its latest published ledger bundle; they do not
alter the default tenant's on-disk set.

After execution, the `/changes` history keeps the publication receipt separate
from fleet activation evidence. Default-tenant manifest executors record the
canonical on-disk hash that replicas heartbeat, and the dashboard compares that
hash plus the published version with the existing fresh replica rows. It says
verified only when every fresh observed replica matches and no observed replica
is stale; mixed, absent, stale, or unreadable heartbeat evidence remains pending
or unavailable and links to the Server manifests fleet view. Older receipts
without the activation fingerprint degrade explicitly to unavailable.
Non-default manifest history labels activation not applicable because those
publishes update only the tenant ledger. Tenant policy activation is driven by
the policy doorbell with the periodic poll as a backstop.

`policy.upsert_fragment` is the corresponding small-params policy-authoring
path. Its params carry exactly one complete Cedar statement with a required
`@id`; the gateway replaces that id when present or appends it when new while
preserving every unrelated live policy. Proposal captures the live policy-set
hash, both approval queues render the exact reconstructed full-set compile,
attached-test, and decision-replay preview, and execution refuses if the live
set changed after proposal. The same visible acknowledgement and shared
REST/dashboard approval core apply: the gateway recomputes the captured effect
before consuming any approval, and an unavailable or unsuccessful preview leaves
the request pending. Impact replay runs again at execution, before a draft is
staged. The process-local write lock and exact-base turnstile CAS close the
remaining read-to-publish race across replicas. The action is default-tenant-only
because fragment editing operates on the default tenant's live on-disk policy
set; other tenants publish complete bundles through their ledger-backed runtime
engines.

Agents prepare these state-dependent proposals entirely through the maker MCP
surface. `describe_action(action_type)` returns the exact params schema and, when
needed, a validating worked params object plus a `get_action_context` selector
schema and selector example. The context read uses the live on-disk
policy/manifest directories rather than assuming the newest ledger row is
effective. A listing call returns bounded
server names or policy `@id` values plus the complete live-set hash; selecting
one returns the full manifest or exact Cedar statement the agent must preserve
or replace. The agent copies that `base_hash` into policy-fragment, full-manifest,
manifest-upsert, or manifest-removal proposal params. Proposal capture refuses a
hash that no longer matches disk; approval rechecks it; and the existing publish
turnstile uses the same witness at the authoritative mutation boundary. Manifest
publication also carries it into the conditional filesystem commit, which
preserves a raw edit that bypasses the pointer. Publish and rollback context
instead uses filtered, database-bounded ledger pages and returns the selected
bundle's complete source. Manifest secret references remain references and are
never resolved through this read. Before proposing, the agent can pass those
prepared params to `preview_change`. The tool reruns the proposal's
current-target capture and serialized params-size limit and, for policy and
manifest actions, returns the same compile, attached-test, and bounded
decision-replay effect used by the human review queues. For a manifest
candidate containing `classification_mode: mcp_annotations` servers, the
effect additionally carries an `observed` section (default tenant; maker
floor — `mcp:propose` or `mcp:admin`, never peer-asserted; withheld
entirely when the caller's API-key profile confines them away from the
server or to a subset of its tools, or when Cedar denies the caller
discovery of the server or any of its live tools, because the report is
deliberately the complete raw live catalog and is never filtered): per-tool
live behavior
hashes from the connected sessions, each compared to the draft's
`approved_behavior_hash`, plus the `would_quarantine` admission prediction.
A candidate that also changes the server's connection shape gets a refusal
note instead of a prediction. The runbook is in `docs/agents/upstreams.md`. Replay consumes the
existing per-tenant MCP `call` quota when the quota service is configured. A
stale `base_hash` is therefore a structured `valid: false` result that teaches
the agent to refresh `get_action_context`; a current candidate carries the
actual policy/manifest effect (or an explicit `note` / `blocked` reason when a
replay dependency or execution precondition is unavailable). The proposal and
execution paths still recheck freshness because preview is only a read. MCP
availability notes are canonicalized so store, database, and filesystem
diagnostics remain on the operator surfaces. `mcp:propose` authorizes inspection of this
operator-authored control-plane configuration; it does not semantically
declassify arbitrary strings. Manifests must keep credential values out of YAML
and use governed references. As defense-in-depth, live and ledger selections
refuse URL userinfo, unparseable URLs, and high-confidence credential-shaped
literals; live listings apply that literal check to every server name before
returning any names. Benign URL queries and stdio arguments remain available as
ordinary operational configuration. This discovery path requires only the
maker's `mcp:propose` scope, so it does not rely on repository access, dashboard
scraping, or the separate `mcp:admin` REST surface. Live-disk authoring context is
default-tenant-only because those actions operate on the default tenant's policy
directory and the gateway-wide manifest directory. Other tenants' publish and
rollback context comes from their own durable bundle ledgers; their policy
bundles become live through the tenant-engine registry, while their manifests
remain ledger-only.

`tenant.update` lets a maker rename **its own** tenant — `display_name`
only, reusing `update_tenant_core` (so the `validate_display_name` bound, the
bearer-layer status-cache invalidation, and the fail-closed `tenants.update`
audit match the REST PATCH). It is deliberately display-name-only: a maker
cannot set `status` (suspending your own tenant through the single-approval
propose path is a self-lockout footgun), and it captures a freshness token over
the target's current `display_name`, so an out-of-band rename during the pending
window is refused rather than clobbered. The audit-config quartet
`audit.retention.set` / `.clear` and `audit.routing.set` / `.clear`
configure the maker's own tenant's evidence-retention windows and exporter
routing, reusing `set_retention_core` / `clear_retention_core` /
`set_routing_core` / `clear_routing_core` — so the same validation and the
**target-tenant-chained, fail-closed** `audit_retention.*` / `audit_routing.*`
AdminMutation audit apply on the propose path (a maker must not silently reroute
or shrink a tenant's evidence without a chain-covered row). The `.clear` variants
are idempotent (clearing an absent policy/route is already the desired end-state,
so it records nothing and still reports success).

**Tenant lifecycle (create/delete)** is not proposable: there is no
operator-tenant to authorize cross-tenant lifecycle, and
`change_requests.tenant_id` cascades on tenant delete, so a self-tenant delete
would erase its own in-flight change request + audit mid-execution.
**`confidential_client.*`** (register/update/delete of OAuth clients) is **not
proposable** either: confidential clients are global/cross-tenant operator
infrastructure with no tenant scope to confine a maker to, so registering or
mutating one through the tenant-scoped propose path is an authority mismatch — an
operator manages them via the direct admin API.

`rbac.role.create` / `rbac.role.update` / `rbac.role.delete` are proposable for
**ordinary** scope sets only. create/update refuse any role whose *proposed*
scopes include the control-plane authority scopes `mcp:admin` / `mcp:propose` /
`scim:write` (`reject_privileged_role_scopes`, checked before the store write);
delete refuses when the *target* role carries one of them (the executor
prefetches the role and checks its scopes before the irreversible delete). A role's scopes merge into every assignee's `Principal.scopes`, so
granting one of those through the single-approval propose path would be a
privilege escalation, and *deleting* a role that carries one manipulates the
approver/maker/provisioning set — both are **approver-set changes**, which the
protected/meta class below holds is not agent-proposable. An operator can still
grant or delete such roles via the direct admin API.

Direct and group role-membership changes are split into explicit ordinary and
protected action types. `rbac.assignment.grant` / `.revoke` and
`rbac.group_mapping.grant` / `.revoke` accept only roles without
`mcp:admin` / `mcp:propose` / `scim:write`. Their `_privileged` counterparts
accept only roles carrying at least one of those scopes and freeze the stronger
cooldown and approval bar onto the request. A wrong-class proposal
is rejected before enqueue with an error naming the correct action, so the
maker cannot choose a weaker bar for a privileged role.
Group-mapping actions accept only SCIM-provisioned groups. Local API-key
catalog groups remain Cedar labels and cannot inherit an RBAC role mapping.

Every membership proposal requires a target witness. Grants capture the exact
role version; direct revokes also bind the assignment identity, and group
revokes bind the mapping generation. Execution rechecks the witness and passes
the original immutable token into a conditional store mutation. The store
locks the reviewed role row through the insert or delete and includes the
assignment/mapping generation in the mutation predicate, closing both the
pending-window stale-write case and the final validation-to-write race. A
missing, replaced, or changed target fails the governed change without a side
effect. The `rbac_assignment` and `rbac_group_mapping` observe resources expose
the identifiers a maker needs to build a valid revoke proposal.

`group.create_local` / `group.delete_local` and `scope.create_local` /
`scope.delete_local` close the identity-catalog lifecycle gap for makers. All
four actions are tenant-bound by the change request rather than caller-supplied
tenant params. Creation calls the same shared mutation cores as the dashboard
forms and normalizes names server-side. Group creation refuses names already
owned by either a local or SCIM-provisioned group; scope creation refuses names
already visible through a global built-in/policy row or a tenant-local row.

Deletion accepts the target id plus its human-readable name from the matching
observe row, then verifies that pair so the approval screen identifies the
reviewed target. Only `source='local'` rows owned by the maker's tenant are
eligible: a SCIM group or global built-in/policy scope fails closed. Proposal
captures a required generation/version witness and refuses a target that is
already referenced. Approval rechecks that witness, and the original reviewed
version is bound into a row-locking store delete that repeats the reference
checks. Group deletion is blocked by SCIM-user membership, live API-key labels,
or role mappings; scope deletion is blocked by live API-key or role references.
Catalog-checked API-key mint/grant writes lock and validate the referenced rows
inside the same transaction as their write. Scope deletion takes a brief table
lock before checking free-form role scope arrays, ordering overlapping role
writes without changing their documented ability to carry an uncataloged
string. Those locks serialize the array-backed references with deletion even
though they cannot use ordinary foreign keys. A changed, promoted, referenced,
missing, or cross-tenant target survives and the governed change fails loudly.

The `gateway-observe` resource catalog exposes matching `group` and `scope`
rows, ids, names, source, versions where mutable, and reference counts to
callers with `mcp:observe` or `mcp:admin`. The canonical `mcp:read +
mcp:propose` maker instead reads the change-request status and execution result;
catalog inspection requires separately granting that caller `mcp:observe`.

`agent_config.create`, `agent_config.update`, and `agent_config.delete` govern
the tenant agent lifecycle through the same validated cores used by the
dashboard. The tenant always comes from the frozen change request; it is never
accepted in proposal params. Create and full-replacement update expose the
complete non-secret configuration for review, including instructions,
`allowed_tools`, runtime limits, token budget, and enabled state. The
observe-tier `agent_config` resource is the readable twin and exposes the
identifiers and current configuration needed to prepare a proposal.

Update and delete capture the target's structured `updated_at` version when the
proposal is created. Approval rechecks that version, and the original witness
is also part of the store mutation predicate. A configuration changed after
review cannot be overwritten or deleted through a stale approval, including a
change in the final validation-to-write window. These actions use the default
single-operator approval bar.

`api_key_profile.create` and `api_key_profile.delete` govern the complete
API-key-profile mutation lifecycle. Profiles intentionally have no update
operation: their constraints are evaluated when keys are minted, so editing a
profile would not retroactively narrow already-issued keys. A changed profile
must be created under a new identity, affected keys rotated, and the retired
profile deleted. Create exposes every non-secret constraint for review,
including `allowed_tools`; the tenant comes only from the frozen change
request. The observe-tier `api_key_profile` resource exposes tenant-scoped
profile ids and current constraints needed to prepare either proposal.

Delete captures the profile id and `updated_at` version when proposed and
fails closed if the tenant-scoped target is missing or disappears before
approval. Approval rechecks the current version, and the original reviewed
`updated_at` is also part of the final `DELETE` predicate, so an update in the
recapture-to-delete window preserves the newer row. The shared delete core
preserves the database trigger that atomically blocks deletion while any live
key references the profile, including a key minted in the final
validation-to-delete window. Both actions use the default single-operator
approval bar.

`break_glass.revoke` (hard-deleting an override) is low-harm — the worst a
mistaken approval does is drop an override early, after which the affected
principal falls back to the normal Cedar deny; no privilege is *gained*. So it
is proposable today.

### Approvers see the captured params

Approval review is only meaningful if the human approver can see **what** they are
authorizing, not just the `action_type` and a maker-written `justification`
(a maker could otherwise propose one subject / scope / TTL
while writing a benign justification). Both approval surfaces — the `/changes`
pending table (a full-width detail row per change) and the `/decisions` queue
(under each change-request item) — render the captured `params` as pretty JSON,
always visible above the Approve button. Rendering is the raw stored `params`
(askama auto-escapes, so it's injection-safe). The params are rendered in
**full, never truncated** — a hidden field is exactly the blind-approval hole
this closes, and there is no admin-reachable endpoint that re-serves the
captured params as a fallback (the status poll omits them and is maker-gated). The visual size is bounded by CSS instead: the review well has
a `max-height` and scrolls, so a large payload stays fully in the DOM for the
reviewer to scroll through. The shared renderer is
`dashboard_changes::render_params`.

Because the render is complete (never truncated), `validate_propose` bounds
`params` **at the source** and the approval surfaces bound the aggregate render.
Actions carrying only scalars use `DEFAULT_MAX_PROPOSE_PARAMS_BYTES`; actions
carrying an authored *document* — a manifest set, a Cedar statement, an agent
instruction addendum — use the larger `DOCUMENT_MAX_PROPOSE_PARAMS_BYTES`,
because their own validators accept documents the scalar bound cannot hold.
`/changes` renders a bounded number of pending rows per paginated
page; the unified Decisions inbox renders the same page and links to that full
queue when more remain. A propose above its action's cap is refused, so one row
stays bounded; pagination ensures a queue of maximum rows cannot deny access to
the decision surface (`pending_page_preserves_the_original_aggregate_params_bound`
ties the page size and the largest cap together). The bound lives at propose and
pagination, not at display, so the approver always sees the full intent.

### Uploading a document instead of inlining it

A maker should not have to push a whole manifest set or a long instruction
through MCP JSON-RPC and the model's context just to propose it. Actions whose
`gateway-admin.describe_action` row carries a non-empty `file_params` accept
their document as a file instead: upload it with
`gateway-files.prepare_upload`, then send the returned `mcp-file://gateway/<id>`
URI at the listed `upload_field` (`content_file`, `statement_file`,
`instructions_file`) in place of the text field.

The substitution happens at submission, in `waygate_admin::param_files`, before
anything else runs — before the freshness witness, before schema validation,
before the row is stored. **The stored params are always the resolved form.**
That is what keeps every existing property intact: the approver reviews the
document itself rather than a pointer, the file's retention window cannot expire
out from under an approved change, and the executor keeps reading one shape. The
`_file` key never reaches storage, which is also why it does not appear in the
action's `params_schema` — that schema describes the params a proposal
carries — and `describe_action` is where a client learns the key exists.

Reading the file is not weakened by holding its URI. `ProposalFileReader` (impl:
`waygate-server`'s `StoredTextFileReader`) resolves it through the same file
plane as a download: owner-scoped lookup plus the caller's credential-profile
restrictions, with an unowned file reported exactly like an absent one. The
gateway never fetches a caller-supplied URL — only its own
`mcp-file://gateway/` namespace is treated as a file, and a reference left
anywhere else in `params` is refused rather than stored and executed verbatim.
Provenance (URI, digest, byte count) is recorded on the fail-closed
`ChangeRequestPropose` audit entry, which is the only durable link from the
reviewed text back to the upload.

Inline submission is unaffected by any of this, including on a gateway with no
file storage configured; only a submission that actually names a file is
refused there.

`preview_change` resolves uploads the same way, so a candidate that previews
clean submits identically.

`break_glass.mint` — proposing a *Cedar override*, the most powerful
non-destructive action — is now proposable, gated on exactly this prerequisite:
minting through propose adds a meaningful captured review ceremony over the
direct admin mint only if the approver sees `issued_to` / `scope_pattern` /
`reason` / `ttl_seconds` before approving, and the review UI now surfaces
those params on both approval surfaces. Routing through propose strictly
*adds* captured review over the direct admin mint; the override stays tightly
bounded — single-use, ≤24h,
scope-pinned, `issued_to`-bound — and fail-closed-audited (`BreakGlassMint` plus
the `ChangeRequestExecute` record). `requires_amr` must be empty (the runtime
can't enforce it yet — `mint_token_core` refuses non-empty), so a maker can't
mint a "requires MFA" token the gate would ignore. The token `id` is the admin's
revoke handle, not a bearer string, so it's returned in `execution_result`
exactly as the direct mint returns it.

### Single-user mode

Per-action executor defaults use `count: 1`, so a single-operator deployment works
without a second operator. An executor can opt up in code; deployment-level
reviewer-count configuration is not implemented yet. The protected RBAC
membership actions add **time for review** rather than a second-human
requirement, which a lone operator can satisfy:

- **proposal-age cooldown** — approval is blocked until a notified time while
  denial remains available; this defends against an impulsive or
  injection-induced rubber-stamp without a second person.

The shipped protected RBAC requirement uses `count: 1`, `factors: []`, and a
five-minute cooldown.

### Protected/meta controls

Protected RBAC membership actions are agent-proposable with the captured
cooldown described above. Changing the approval mechanism or its configuration
remains outside the proposal registry, so an agent cannot propose a weaker bar
for its own future requests.

## Human approval UX

Design principle: **the human approves an effect they understand, with
friction proportional to risk, on a surface the agent cannot reach.**

### Journey: notification → decision

- **At the desktop:** a live WS toast + a badge count on a **Review** nav
  item (reuse `ApprovalHub` in `hitl_ws.rs`), and the link the agent
  printed in the session transcript.
- **Away from the desk:** an out-of-band push (config webhook →
  chat/email) carrying *action summary + binding code + requester +
  risk tier + countdown + deep link* — but **not** full sensitive params,
  and a **link, not an approve button**. Following Teleport's secure
  pattern, the notification routes to the authenticated dashboard;
  approval happens behind login + step-up, never by replying to an
  unauthenticated channel.

### The approval detail page (the heart)

```
┌──────────────────────────────────────────────────────────────┐
│  ⬤ HIGH RISK            Change #42 · expires in 12:48 ⏱       │
│  Mint API key for service account  svc-billing                │
│  Binding: AMBER-OTTER   ← confirm this matches what the agent told you │
├──────────────────────────────────────────────────────────────┤
│  Requested by  claude-code  (propose credential, not admin)   │
│  Justification "CI needs read-only catalog access for the     │
│                 nightly sync job"                             │
│  When          2026-06-09 14:21 · trace 0c9f… → view audit    │
├──────────────────────────────────────────────────────────────┤
│  WILL DO                                                       │
│   • subject:   svc-billing                                    │
│   • scopes:    mcp:read    read catalog + entity states       │
│                mcp:invoke  call low-risk tools                 │
│   • ttl:       90 days                                        │
│   • can reach: example-mailbox.*, example-messages.send_msg, catalog.* (12 tools) │
│   ✓ no high-risk scopes      ✓ no admin scope                 │
│  Preview reflects current state as of 14:23  (fresh ✓)        │
├──────────────────────────────────────────────────────────────┤
│   [ Deny — reason required ]          [ Approve ▸ step-up ]   │
└──────────────────────────────────────────────────────────────┘
```

- **Plain-language title + risk chip + live countdown.** Read *what
  happens*, not a tool name. Risk is color + icon + position so critical
  never looks routine.
- **Who & why.** Requester is normally the propose-only agent identity; an
  admin proposal created in the dashboard may name the approver too.
  Justification is required and non-empty. Trace link to the full audit.
- **The preview is the product**, server-rendered from the *captured
  intent*, never from agent prose (the agent can be prompt-injected — its
  self-description is untrusted). Per class:
  - `api_key.mint`: exact scopes with a one-line gloss each, TTL, and a
    "this key can reach …" expansion — approve *capability*, not a
    string.
  - `policy.edit`: a unified Cedar **diff**, a **compile badge** (red =
    "won't compile, cannot approve"), and a **simulation panel** from the
    existing policy simulator ("would now ALLOW X→Y that was denied") —
    approve the *effect*, not the syntax.
  - `upstream_session.revoke`: whose session, which upstream, "forces
    `alice` to re-auth to example-mailbox; N in-flight calls may fail."
- **Freshness banner.** "fresh ✓" when the target etag still matches
  propose time; a loud banner if it moved ("⚠ the policy was edited 3m
  ago"), forcing re-review and blocking critical tiers until re-proposed.
  The race-window guard, made visible.
- **Risk-scaled decision controls** — friction matches gravity:
  - `approve` → one click.
  - `approve_factor` → Approve disabled until the explicitly required signed
    factor evidence is fresh.
  - protected/critical → type the binding code to enable Approve (defeats
    reflexive clicking) **plus** the configured count and cooldown.
  - **Deny** is one click but requires a **reason**, returned to the
    agent (real feedback loop) and audited.
- **After the decision:** PRG back to the queue; row moves to History;
  the agent's next poll gets the outcome. An execution-result panel shows
  what changed — or "approved but execution failed: <error>" with retry,
  **never** a silent success.

### The queue (triage)

Three buckets mirroring `/admin/approvals` — **Pending (needs you)**,
**Recently decided**, **Expired-unactioned** — sorted risk-desc then
expiry-asc, filterable by risk / action / requester, with a live WS
badge. Empty state: "Nothing waiting. Claude can propose changes; they'll
appear here."

### Approval-fatigue defense

Routing trivia to a human trains rubber-stamping of the dangerous thing.
So: **auto-tier ruthlessly** (low-risk executes without a human, or with
a one-time form-confirm); **no "approve all"** for privileged tiers
(batch *deny* is fine); per-request notifications only for high/critical,
a badge + optional digest for the rest.

### Mobile ("approve from my phone")

The detail page is responsive (diff collapses to summary-first with "show
full diff"); the typed-binding-code confirm is a good deliberate mobile
gesture; step-up via **passkey/WebAuthn (Touch/Face ID)** is the best
mobile re-auth. The dashboard records that signed ID-token assurance in its
encrypted session rather than widening every `Principal` authentication path.
The notification deep-link → OAuth login + step-up → lands on the request.

### Agent-side surface

Even without elicitation, `propose_change` makes the agent surface the
binding code + URL in the transcript ("Queued change #42 to mint a key
for svc-billing — code AMBER-OTTER — approve: <url>. I'll wait."), then
report transitions (pending → approved/here's the one-time value →
denied: reason → expired, re-propose?). Dual-surface (transcript link +
phone push) means approval from wherever the operator is.

## Safety invariants

- **Atomic single-use claim** — `UPDATE … WHERE status='pending'
  RETURNING`, check rows-affected before doing anything (the break-glass
  idiom). A double-click or two approvers cannot double-execute.
- **Validate everything before the irreversible call; side-effects
  last.** Re-check params, scope match, ownership at *execute* time.
- **Freshness guard.** `capture_target_etag` captures an opaque target witness
  at propose and stores it in `change_requests.target_etag`;
  `execute_approved` re-captures it just before the side effect and refuses
  (`409` → durably `failed`, "target changed since propose; re-propose") when it
  moved. The `target_etag` column is an action-specific
  opaque token, not a universal hash contract, and only the owning executor may
  interpret its value. Most mutable-target executors use a one-way sha256 of
  mutable fields:
  `rate_limit.update`, `rbac.role.update`,
  `peer.update`, `tenant.update`, and the natural-key audit-config actions.
  The one-way tokens are safe to persist even when the hashed fields are
  sensitive. Creates, content-independent identity deletes, and ordinary
  policy/manifest publish turnstiles otherwise opt out or use their own CAS.
  Policy-fragment and manifest-authoring proposals instead require the
  preparation-context `base_hash`, reject it when already stale, and bind the
  same witness into their existing publish CAS. Manifest authoring also binds
  it to the conditional filesystem commit so a write outside the database
  turnstile cannot be overwritten.
  Both REST and built-in MCP propose paths capture the baseline. Legacy
  capture remains best-effort at propose and strict at execute; executors whose
  safety depends on a witness opt into `requires_target_etag()` so a parse,
  missing-target, or store-read failure rejects the proposal before enqueue.
  RBAC direct/group membership actions use that strict path and store a
  structured, non-secret role/assignment/mapping version witness. They pass the
  original witness into row-locking conditional mutations, so safety does not
  depend on a second read immediately before an unconditional write.
- **Configured quorum server-side.** Count N distinct eligible approver subs;
  an eligible admin proposer may count once. Record requester and approver(s)
  in audit. A propose-only requester still cannot approve because approval
  requires independent admin authority.
- **Broken policy must never lock out.** A `policy.edit` executes through
  the same validate-then-swap path as SIGHUP; bad Cedar rejected, old set
  kept.
- **Execution failure fails loud** → `status='failed'` with the captured
  error, never a "done" tombstone.
- **Secrets returned once, never logged** (break-glass already does this).
  Implemented as the burn-on-read channel below.
- **Denial reason returned to the agent**; **expiry → auto-deny +
  audit**; **`slow_down` back-pressure** on polling.

### Secret-return channel (burn-on-read)

A secret-producing action — today `api_key.mint` — must hand the maker a
plaintext secret (the `mcpgw_…` key) it then stores in a secret manager. The
secret must NOT sit in `execution_result` (surfaced on every poll + the
decision view) or any log. The channel:

- An executor returns `ExecOutcome { result, secret: Option<Vec<u8>> }`
  (`waygate-admin/src/change_executor/mod.rs`). `result` carries only a
  **non-sensitive fingerprint** (key id + public prefix + `secret_available:
  true`); the plaintext rides `secret`.
- On the executed transition, `execute_approved` encrypts `secret` with the
  `GATEWAY_CHANGE_SECRET_KEY` AES-256-GCM keyring (reusing
  `waygate_oidc::upstream_crypto::UpstreamCrypto`) and
  persists the ciphertext in the side table
  `change_request_secrets` (`migrations/0044`), NOT on the `change_requests`
  row — so none of the 23-column poll/list/decision queries can carry it.
- The maker retrieves it **once**, by either of two equivalent surfaces — the
  REST endpoint `GET /api/v1/admin/change_requests/{id}/secret`, or the built-in
  MCP tool `gateway-admin.get_change_secret` (so an agent over MCP doesn't have
  to shell out to `curl` for the one value the poll withholds). Both delegate to
  the same `retrieve_secret_core` (`mcp:propose`, maker-scoped — another maker's
  id is a 404, not a 403; the change must have `executed`). The read is a
  single-use atomic burn (`try_burn_secret`: `UPDATE … SET retrieved_at =
  now() WHERE … AND retrieved_at IS NULL RETURNING`); a second read is a 409
  (`secret already retrieved`). The REST response carries `no-store` headers,
  exactly like the dashboard reveal; the MCP tool delivers the plaintext in the
  structured result's `secret` field (the response payload to an authorized
  maker — never a log line; the audit stays fingerprint-only). The reveal tool
  is classified `Medium` (not `High`): a propose-only agent cannot satisfy a
  step-up *factor*, so a `High`→step-up mapping would make the secret
  unretrievable over MCP and re-open this gap — its sensitivity is carried by
  `side_effects` (the burn) + `pii` (a live credential) instead.

  The MCP result is intentionally asymmetric: plaintext appears only in
  `CallToolResult.structuredContent.secret`; text `content` is a non-secret
  burn notice, not serialized output. The safe consumer order is: validate
  that the secure destination is ready **before** calling; call exactly once;
  persist the complete `CallToolResult` or `structuredContent` immediately;
  only then inspect or interpret the result. The successful call has already
  burned the stored value:

  ```json
  {
    "content": [{"type": "text", "text": "[non-secret burn notice]"}],
    "structuredContent": {"secret": "[REDACTED]"}
  }
  ```

  The earlier `execution_result.secret_available: true` fingerprint records
  that execution produced a secret. It is historical and does not prove that
  the burn-on-read value remains retrievable.
- **Fail-closed:** if `GATEWAY_CHANGE_SECRET_KEY` is unset, a secret-producing
  executor refuses at execute (`ExecError::Unavailable`) *before any side
  effect* — no orphan key the maker could never retrieve. The retrieval audit
  (`ChangeRequestSecretRetrieve`) is best-effort (the burn is irreversible, so
  a fail-closed audit there would lose the just-claimed secret; the mint
  itself is already fail-closed-audited at execute).

## Implementation map

| Concern | Location |
|---|---|
| Schema + invariants doc | `migrations/0039_change_requests.sql` |
| Store + types (atomic claim, lifecycle, requirement) | new `waygate-changeset` crate |
| Action registry (`render_preview`, `execute`) | `waygate-changeset` + per-class adapters in `waygate-admin` |
| `mcp:propose` gate | `crates/waygate-admin/src/scope.rs` |
| Classification | `crates/waygate-authz/src/cedar.rs` |
| REST: propose / status / list | `crates/waygate-admin/src/change_requests.rs` (new) |
| MCP tool surface | `waygate_mcp::BuiltinTools` trait + `GatewayServer::with_builtin_tools` (the seam, in `crates/waygate-mcp/src/builtin.rs`); the `gateway-admin` namespace impl in `crates/waygate-server/src/mcp_builtin.rs`, with state preparation in `mcp_action_context.rs` + `waygate-admin/src/change_context.rs`, the shared change-request cores for proposal/polling, and `retrieve_secret_core` for the `get_change_secret` burn-on-read reveal. (In `waygate-server`, not `waygate-admin`, so the REST crate keeps `rmcp` dev-only.) |
| Dashboard queue + detail | `crates/waygate-admin/src/dashboard_changes.rs` + templates |
| Notify (out-of-band) | `ChangeRequestNotifier` trait + payload in `crates/waygate-admin/src/change_notify.rs` (fired best-effort from `propose_core`); `WebhookChangeNotifier` impl in `crates/waygate-server/src/change_notify.rs` behind `GATEWAY_HITL_WEBHOOK_URL`. |
| Audit | existing evidence sink, `EvidenceCategory::AdminMutation`, actions `ChangeRequestPropose/Approve/Execute/Deny` |

## See also

- [`docs/agents/break-glass.md`](break-glass.md) — the single-use claim
  idiom and the separate `requires_amr` / `Principal.amr` work needed by
  break-glass token minting.
- [`docs/agents/authz.md`](authz.md) — Cedar tiers and `StepUpRequired`.
- [`docs/agents/identity.md`](identity.md) — `mcp:*` scopes and the
  confidential-client model the propose credential uses.
- [`docs/agents/dashboard-ui.md`](dashboard-ui.md) — askama + htmx split
  the review queue reuses.
- Standards referenced: OpenID CIBA Core 1.0 (backchannel authorization,
  `auth_req_id`, `binding_message`, poll/ping/push); HashiCorp Vault
  Control Groups (`controlled_capabilities`, factor approvals); MCP
  elicitation (form vs URL mode, sensitive-info rule); Teleport Access
  Requests (time-boxed JIT, ChatOps routing).
