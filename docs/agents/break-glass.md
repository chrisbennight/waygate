# Break-glass override tokens

Reach for this doc when changing anything under
`crates/waygate-authz/src/break_glass*.rs`,
`crates/waygate-admin/src/break_glass.rs`, the
`break_glass_tokens` migration, or the invocation pipeline's
authorize stage that consults break-glass before falling
through to Cedar denial.

## What it is

A single-use, time-bound, scope-pinned override the gateway
honours when a tool call would otherwise be denied by the
Cedar policy gate. Think "the on-call needs to delete the
bad row NOW and the normal RBAC chain takes an hour." The
token is minted ahead of time by an admin, used once by a
named principal, and burned on use — every step durably
audited.

> **AMR / MFA gating is unavailable.** The mint handler rejects non-empty
> `requires_amr` with HTTP 400. Break-glass tokens are scope-pinned, time-bound,
> and single-use; they do not enforce an MFA claim. Leave `requires_amr` empty.

## Why this exists instead of "just loosen the policy"

Temporarily relaxing a Cedar policy to unblock an incident
has three failure modes break-glass avoids:

1. **The policy change outlives the incident.** Operator
   forgets to revert; the gateway runs forever in the
   weakened state.
2. **No per-call attribution.** A relaxed
   `forbid (...) unless (...)` accepts the incident call
   AND every other matching call until it's reverted.
   Audit can't distinguish.
3. **Cedar source has to be re-published.** SIGHUP + policy
   bundle publish is heavier than a single admin POST
   during an incident.

Break-glass is operator-side authorization that explicitly
admits "we're going around the policy this once" as a
first-class concept rather than hiding it inside Cedar source
edits.

## Where the pieces live

| Concern | Location |
|---|---|
| Schema + admin-CRUD invariants doc | `migrations/0029_break_glass.sql` |
| Token store + gate logic | `crates/waygate-authz/src/break_glass.rs`, `crates/waygate-authz/src/break_glass_gate.rs` |
| Admin REST surface | `crates/waygate-admin/src/break_glass.rs` (`/api/v1/admin/break_glass`) |
| Authorize-stage consultation | Invocation pipeline's `authorize` stage (in `waygate-mcp::invocation`) |

## Row shape — what each field controls

```sql
break_glass_tokens (
    id              UUID,             -- surrogate so admin revoke can target by URL
    tenant_id       TEXT,             -- FK tenants(id) ON DELETE CASCADE
    issued_to       TEXT,             -- principal sub the token mints FOR (the operator who will use it)
    issued_by       TEXT,             -- admin sub who minted (separate so the audit trail captures both ends)
    reason          TEXT NOT NULL CHECK (length(reason) > 0),  -- "incident #4711 — delete corrupted billing row"
    scope_pattern   TEXT,             -- literal server.tool FQN OR `server.*` wildcard
    requires_amr    TEXT[] NOT NULL DEFAULT '{}',  -- reserved; mint handler refuses non-empty today
    expires_at      TIMESTAMPTZ,      -- short TTL, operator picks per ceremony
    used_at         TIMESTAMPTZ,      -- NULL until the single use lands
    created_at      TIMESTAMPTZ
    -- No `revoked_at` column: admin DELETE /api/v1/admin/break_glass/{id}
    --   hard-deletes the row (the conditional UPDATE on use checks
    --   existence, so a deleted row is unusable). The deletion event
    --   lands in audit as `AdminMutation` action="BreakGlassRevoke",
    --   which is the kept-state-elsewhere disambiguation the
    --   migration header documents.
    -- No `used_by` column: the principal who consumed the token is
    --   captured in the matching `AdminMutation` audit row's principal
    --   fields (action="BreakGlassUse"), so the table itself only
    --   tracks the row-state ("was it consumed yet?"). Joining the
    --   audit row's `principal_sub` to the token's `id` gives the
    --   audit pivot without duplicating the column on the live row.
);
```

### `scope_pattern` semantics

Tested with prefix-or-equality, NO regex / glob library:

- `example-messages.send_message` → exact match against one tool
- `example-messages.*` → any tool on the `example-messages` upstream
- `""` → matches NO tool. The admin handler refuses to
  mint empty patterns; the runtime `scope_pattern_matches`
  helper returns `false` for an empty pattern as
  defense-in-depth (so a legacy row or hand-rolled SQL
  insert can't accidentally widen blast radius). Pinned
  by the `scope_pattern_empty_matches_nothing` test. An
  "any tool" mint shape would need a deliberate future
  schema + handler change, not a side-effect of permissive
  validation.

The pattern language addresses tools and nothing else, so
**break-glass does not reach native MCP resource reads.** A
resource is identified by a URI, which no `server.tool`
pattern can name; reusing the tool pattern against one would
hand every token minted for a tool an unintended reach over
an upstream's data surface. `BreakGlassGate` therefore
delegates `authorize_resource_read` to the inner gate
untouched — Cedar's verdict stands, and the read never
consumes the single-use token the operator minted for a
dispatch. Overriding a resource deny needs a scope model that
names URI space; until one exists this pass-through is the
behaviour, pinned by the
`break_glass_does_not_override_or_burn_a_token_on_a_resource_read`
test.

### `requires_amr` (reserved; not enforceable today)

Token-side gate, future. The intent is for the principal's
JWT `amr` claim (a JSON array of authentication-method
strings per RFC 8176) to be matched against this field at
use-time so operators can require MFA on the bearer.

Today, the admin handler **refuses any non-empty
`requires_amr`** with a structured 400 because `Principal`
doesn't carry an `amr` field yet. The use-time check
short-circuits to "no AMR check" regardless of column
contents. The schema reserves the field so the eventual
plumbing doesn't need a migration; operators
must leave the field empty until then.

### Single-use atomicity

Use lands via a two-step claim — see
`crates/waygate-authz/src/break_glass.rs` for the
authoritative shape.

**Step 1 — candidate select** picks rows matching
`(tenant_id, issued_to, used_at IS NULL, expires_at >
now())` and filters in-process for `scope_pattern_matches`
against the resolved tool FQN. The tenant + named-principal
gates live here.

**Step 2 — atomic single-use UPDATE** races concurrent
callers for the chosen token id:

```sql
UPDATE break_glass_tokens
   SET used_at = now()
 WHERE id = $token_id
   AND used_at IS NULL          -- single-use guarantee
   AND expires_at > now()       -- re-check expiry under the lock
RETURNING id, tenant_id, issued_to, issued_by, reason,
          scope_pattern, requires_amr, expires_at,
          used_at, created_at;
```

Only one concurrent caller wins; `rows_affected = 0` means
the call falls through to the original Cedar deny. There's
no second-chance. Admin DELETE is a hard row delete — a
deleted row simply fails the existence check on the next
attempted use.

The tenant / principal / scope_pattern gates live at the
candidate-select stage (Step 1) precisely because the
UPDATE shouldn't repeat them: the WHERE clause only
re-checks the conditions that can change between the
SELECT and the UPDATE (`used_at`, `expires_at`). The
identity bindings can't change for a given row id, so the
UPDATE keeps them out of the race window.

### Advisory surfaces never claim

The claim runs only on `authorize_tool_call` — the
once-per-dispatch call. Every advisory evaluation goes
through a non-consuming path instead: discovery filters use
`may_call_tool` / `may_call_tool_on_channel` (delegated to
the inner gate — Cedar's raw verdict, never the override),
and the pre-parse routing-header gate uses
`AuthzGate::probe_tool_call`, whose `BreakGlassGate`
override runs the Step-1 candidate scan *without* Step 2:
an inner Deny with a live matching token probes as "could
allow" (so the gate passes the request to the pipeline,
where the real claim happens), and a probe lookup error
leans the same way. A new consuming decorator must override
`probe_tool_call` the same way it overrides
`may_call_tool`, or an advisory probe will burn per-call
authority the dispatch needed.

## Mint runbook

1. **Admin authenticates** with `mcp:admin` scope (per the
   require_admin gate). Open the dashboard or POST directly
   to `/api/v1/admin/break_glass`.
2. **Body:** `issued_to`, `reason`, `scope_pattern`,
   `ttl_seconds` (mint refuses > 24h — break-glass is for
   incidents, not standing overrides). `requires_amr` MUST
   be empty today (see "AMR not yet enforceable" above).
3. **Response carries the token id.** The id is the
   admin's handle for revoke (`DELETE /api/v1/admin/break_glass/{id}`).
   It is NOT a bearer string and NOT something the recipient
   needs at use-time. Tell the recipient out-of-band
   ("I minted a break-glass for you on tool X, expires in Y
   minutes") so they know to retry the call; the gate
   auto-discovers their candidate.
4. **Recipient calls the tool normally** with their usual
   bearer. The gate consults `BreakGlassStore::list_candidates(tenant,
   sub, fq_tool_name)` — that lookup filters rows by
   `tenant_id = caller.tenant`, `issued_to = caller.sub`,
   `used_at IS NULL`, `expires_at > now()`, then in-memory
   filters by `scope_pattern_matches`. The recipient never
   sends the token id; the gate finds the matching candidate
   by (tenant, sub, FQN) automatically. If exactly one
   candidate matches, the row is atomically burned and the
   call proceeds.
5. **No matching candidate** (wrong sub, expired, no token
   for this tool, already used) → fall through to the
   original Cedar deny. The recipient sees the normal
   "permission denied" they'd have seen without break-glass.

## Audit attribution

Every break-glass interaction records evidence — all under
`EvidenceCategory::AdminMutation` so the operator-side
ceremony stays cleanly separated from the regular
`Invocation` row that any tool call produces:

- Mint → `action = "BreakGlassMint"`, reason carrying the
  sanitized identifiers (token id, issued_to,
  scope_pattern, expires_at).
- Use → `action = "BreakGlassUse"`, reason carrying
  `token=… issued_to=… issued_by=… scope_pattern=…` plus
  the tool / risk / pii facts of the call that was
  overridden. The fact that this is an `AdminMutation`
  row (not `Invocation`) is deliberate — the override is
  an admin-class event even though the principal triggering
  it is a regular user.
- Revoke (admin DELETE) → `action = "BreakGlassRevoke"`.

SIEM rules / audit queries that pivot on the action string
must use the exact verbs above. They're imperative ("Mint",
"Use", "Revoke") not past-tense — verified against
`BreakGlassGate::try_override` in `crates/waygate-authz/src/break_glass_gate.rs`
and `mint_token_core` / `revoke_token_core` in
`crates/waygate-admin/src/break_glass.rs`.

Failed uses (wrong `sub`, expired token, no matching row)
do not consume the token and follow the regular Cedar-deny
path; the original deny lands as the standard
`Invocation`-category row from the dispatch pipeline. There is no separate failed-attempt event.

## Invariants the code enforces

- **Per-tenant by construction.** Every read / write is
  tenant-scoped; the FK cascade means a deleted tenant
  takes its tokens.
- **`reason` is NOT NULL.** Schema-enforced. Minting without
  a reason defeats the audit purpose; the database refuses.
- **Empty `scope_pattern` refused at mint.** Schema permits
  it but the admin handler returns 400 — see "scope_pattern
  semantics" above.
- **Single-use via conditional UPDATE.** No application-
  level "is it used?" check; the UPDATE WHERE clause is
  the only enforcement, atomic with the use.
- **Named `issued_to` match enforced at candidate select.**
  The token mints FOR a specific principal; another
  principal can't use it because `list_candidates(tenant,
  sub, fq_tool_name)` filters by `issued_to = caller.sub`
  at the SELECT (`PgBreakGlassStore::list_candidates` in
  `crates/waygate-authz/src/break_glass.rs`).
  The atomic UPDATE doesn't re-check this — it only
  re-checks conditions that can race
  (`used_at IS NULL`, `expires_at > now()`). The identity
  binding can't change for a given row, so it stays out of
  the lock window deliberately.
- **`requires_amr` reserved.** Schema accepts the column,
  mint handler refuses non-empty values (no `amr` field on
  `Principal`). Leave this field empty.

## Current limitations

Token delivery is operator-managed. Multiple-administrator co-signing is not
implemented. The mint handler records issuer and recipient but does not require
them to differ; deployments needing separation must enforce it operationally.

## See also

- [`docs/agents/identity.md`](identity.md) — authentication methods and available factor evidence.
- [`docs/compliance.md`](../compliance.md) — CC6.5 (emergency
  access) control mapping.
- `migrations/0029_break_glass.sql` — schema with the
  invariants doc.
