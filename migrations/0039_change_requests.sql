-- HITL control-plane PR-1: change-request durable primitive.
--
-- ## What
--
-- One row per agent-proposed control-plane change (mint an API key,
-- edit a policy, revoke an upstream session). The row captures the
-- INTENT — the action type, the parameters, a rendered preview, and a
-- freshness etag — without executing it. A human reviews the row in the
-- dashboard and approves or denies; only on approval does the captured
-- intent execute (server-side, PR-2). This is the control-plane sibling
-- of the data-plane `approval_grants` table: same "propose -> human
-- checks -> act" shape, but the thing being authorized is a gateway
-- admin mutation rather than an upstream tool call.
--
-- See docs/agents/hitl-control-plane.md for the full design (CIBA-shaped
-- backchannel, the `mcp:propose` maker credential, the human approval
-- UX, and the safety invariants this schema encodes).
--
-- ## Why a captured intent instead of a privileged token to the agent
--
-- An automated caller (Claude over MCP) must never hold `mcp:admin`: an
-- agent that can mint itself an admin key or rewrite its own Cedar
-- policy has no guardrail. So the agent holds a propose-only credential
-- and creates a row here; a human's dashboard approval is what executes.
-- Execute-on-approval keeps every privileged side effect server-side —
-- the agent only ever reads back a result, never a token it could
-- misuse if injected.
--
-- ## Shape
--
-- - `id` is a client-generated UUIDv7 (time-ordered) so the poll / list
--   surfaces order naturally and the `binding_code` can be derived from
--   the id before insert (see gateway-changeset::binding_code_from_uuid).
--   It doubles as the CIBA `auth_req_id` the agent polls on.
-- - `tenant_id` FKs `tenants(id)` ON DELETE CASCADE — a deleted tenant
--   takes its in-flight change requests with it. Same cascade as
--   break_glass / oauth_consent.
-- - `requested_by` is the propose-credential `sub` (the agent). Distinct
--   from `approver_sub` (the human who decided) so the audit trail —
--   and the four-eyes guarantee — captures both ends. The maker can
--   never be the checker (enforced in the approve UPDATE below).
-- - `action_type` is the registry key ("api_key.mint",
--   "rate_limit.update"); `params` is the captured intent the executor
--   replays; `preview` is the human-rendered summary computed at propose
--   time (nullable until PR-2 wires per-class renderers).
-- - `target_etag` is the freshness guard: a hash of the target resource
--   at propose time. Execution re-checks it; if the target moved between
--   propose and approve, the change is refused ("preconditions changed,
--   re-propose"). The race-window guard, made durable.
-- - `justification` is the agent-supplied reason. Required, non-empty:
--   an unjustified privileged change defeats the review purpose.
-- - `binding_code` is the CIBA `binding_message` short code shown on
--   both the agent side and the approval page so the human confirms
--   they're approving the change they think they are.
-- - The approval REQUIREMENT is captured here, frozen at propose time so
--   config edited mid-flight can't weaken a pending request:
--     * `required_approvals` — distinct human approvals needed (default
--       1; single-operator deployments just work, multi-user opt up).
--     * `eligible_role` — which role may approve.
--     * `required_factors` — what each approval must present
--       (mfa / passkey / break_glass).
--     * `cooldown_seconds` — optional notified delay before execute
--       (the single-user "second look" in lieu of a second human;
--       PR-6).
--   The load-time satisfiability guard (required_approvals <= |eligible
--   pool|) lives in gateway-changeset::requirement_satisfiable so a
--   deployment can't configure itself into a lockout.
-- - `status` is the lifecycle. `pending` is the only state the maker can
--   create; every transition out of `pending` is a single-use atomic
--   UPDATE (the break_glass try_claim idiom) so a double-click or two
--   approvers can't double-act. `approved` is the (optional, cooldown)
--   waypoint before `executing` -> `executed` / `failed`; `denied` and
--   `expired` are terminal refusals.
-- - `execution_result` / `error_message` capture the outcome so a failed
--   execution surfaces loudly (`status = 'failed'`) rather than being
--   silently tombstoned as done.

CREATE TABLE change_requests (
    id                 UUID PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    requested_by       TEXT NOT NULL,
    client_id          TEXT,
    action_type        TEXT NOT NULL CHECK (length(action_type) > 0),
    params             JSONB NOT NULL,
    preview            JSONB,
    target_etag        TEXT,
    justification      TEXT NOT NULL CHECK (length(justification) > 0),
    binding_code       TEXT NOT NULL,
    required_approvals INTEGER NOT NULL DEFAULT 1 CHECK (required_approvals >= 1),
    eligible_role      TEXT NOT NULL CHECK (length(eligible_role) > 0),
    required_factors   TEXT[] NOT NULL DEFAULT '{}',
    cooldown_seconds   INTEGER CHECK (cooldown_seconds IS NULL OR cooldown_seconds >= 0),
    status             TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'approved', 'executing',
                                           'executed', 'failed', 'denied', 'expired')),
    approver_sub       TEXT,
    denied_reason      TEXT,
    execution_result   JSONB,
    error_message      TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    decided_at         TIMESTAMPTZ,
    executed_at        TIMESTAMPTZ
);

-- Hot path: the dashboard review queue's "Pending (needs you)" bucket
-- and the agent's poll both filter to in-flight requests. Partial index
-- on `status = 'pending'` keeps the working set small as terminal rows
-- accumulate. Mirrors break_glass_active_by_principal.
CREATE INDEX change_requests_pending_by_tenant
    ON change_requests (tenant_id, created_at DESC)
    WHERE status = 'pending';
