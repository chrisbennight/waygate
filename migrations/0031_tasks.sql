-- Phase 11 PR11-2: MCP Tasks primitive persistence.
--
-- ## What
--
-- New `task_states` table holding the state of a
-- long-running tool call. The MCP Tasks primitive
-- (post-2025-11 spec draft) lets a tool return
-- immediately with a task id; the client then polls or
-- subscribes for completion. The gateway needs durable
-- per-task state so a restart, a refresh-token rotation,
-- or a client reconnect doesn't lose the task's status
-- or its result URL.
--
-- ## Why this PR is persistence-only
--
-- The MCP spec is still settling the wire shape for
-- Tasks (polling vs. event stream, result envelope,
-- resume protocol). Shipping the wire integration today
-- would bake in a guess that the spec might contradict.
-- The persistence layer is the part we CAN commit to:
-- it's the substrate every transport shape would write
-- to. PR11-2c will wire the InvocationService write-
-- through once the spec stabilizes; PR11-2d adds the
-- client-facing read/subscribe endpoints.
--
-- ## Shape
--
-- - `id` UUID surrogate so the admin REST + future
--   client API can address a task without quoting the
--   composite key.
-- - `tenant_id` FKs `tenants(id)` with ON DELETE CASCADE
--   — a hard-deleted tenant takes its task history with
--   it. Matches the same cascade pattern as
--   oauth_consent, break_glass_tokens, etc.
-- - `principal_sub` is the OIDC sub of the user who
--   started the task. Read-only — a task can't change
--   hands.
-- - `tool_id` FKs `mcp_tools(id)` with ON DELETE
--   RESTRICT (not CASCADE) — an operator who retires a
--   tool shouldn't silently lose every task that ran
--   against it. The audit trail value outweighs the
--   "let me drop this row cleanly" UX.
-- - `arguments_hash` is the canonical argument hash
--   (same shape as `gateway_catalog::argument_hash` and
--   the approval_grants binding). Lets a future "did
--   this call already get approved?" lookup pivot on
--   the hash rather than the raw arguments.
-- - `status` is the lifecycle enum; CHECK constraint
--   keeps it canonical even when an operator pokes the
--   row by hand.
-- - `result_url` is where the client picks up the
--   completed result (e.g. a presigned S3 URL or a
--   gateway-relative `/api/v1/tasks/{id}/result`).
--   Nullable until the task finishes.
-- - `resume_token` is the opaque value a resumable task
--   echoes back to continue (spec TBD). Nullable
--   until/unless the task transitions to `resumable`.
-- - `error_message` carries the non-success failure
--   detail. Free-text, populated only on `failed`.
--
-- ## Indexes
--
-- Two hot-path lookups the admin REST + future client
-- API drive:
--
-- 1. "show me my tasks" — `(tenant_id, principal_sub,
--    created_at DESC)`. Used by the admin REST list
--    surface.
-- 2. "what tasks are still in flight" — partial index
--    on `(tenant_id, status, created_at DESC) WHERE
--    status IN ('pending','running','resumable')`.
--    Used by the future per-task background worker
--    (which doesn't exist yet but needs the index to be
--    cheap when it lands).

CREATE TABLE task_states (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub   TEXT NOT NULL,
    tool_id         UUID NOT NULL REFERENCES mcp_tools(id) ON DELETE RESTRICT,
    arguments_hash  TEXT NOT NULL,
    status          TEXT NOT NULL
                    CHECK (status IN ('pending','running','succeeded','failed','cancelled','resumable')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    result_url      TEXT,
    resume_token    TEXT,
    error_message   TEXT
);

CREATE INDEX task_states_by_principal
    ON task_states (tenant_id, principal_sub, created_at DESC);

CREATE INDEX task_states_in_flight
    ON task_states (tenant_id, status, created_at DESC)
    WHERE status IN ('pending', 'running', 'resumable');

-- updated_at auto-bump on UPDATE (same pattern as
-- tenants.touch_updated_at) so the admin's "last
-- changed" column stays accurate without callers
-- remembering to set it.
CREATE OR REPLACE FUNCTION task_states_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER task_states_touch_updated_at_trg
    BEFORE UPDATE ON task_states
    FOR EACH ROW
    EXECUTE FUNCTION task_states_touch_updated_at();

-- AERB PR #179 rounds 1+2 medium:
-- task_states.tenant_id and task_states.tool_id are
-- independent FKs because mcp_tools doesn't carry
-- tenant_id directly (it lives on mcp_servers, one hop
-- through mcp_tools.server_id). Without an extra
-- check, a caller bug (or a future write-through with
-- the wrong actor.tenant plumbed in) could insert a
-- task row whose tenant_id and tool_id point at
-- different tenants in a way the catalog wouldn't
-- otherwise permit — leaking the cross-tenant
-- identifier through the admin read API.
--
-- The SQL-layer defense: a BEFORE INSERT/UPDATE
-- trigger that joins through mcp_tools → mcp_servers
-- and accepts when EITHER:
--   (a) the new row's tenant_id matches the owning
--       server's tenant_id (the common case), OR
--   (b) the owning server is `visibility = 'global'`.
-- Case (b) is mandatory because the catalog
-- explicitly lets any tenant invoke a global-visible
-- server (crates/gateway-catalog/src/store.rs:
-- `resolve_tool` accepts `(s.visibility = 'global' OR
-- s.tenant_id = $1)`). A task recorded under the
-- *calling* tenant for a global-server tool is the
-- legitimate shape — the admin in the calling tenant
-- must see their own invocations. Round 1's trigger
-- was too strict (would have blocked the global path
-- AERB flagged in round 2).
--
-- Same shape as scim_user_groups_tenant_match
-- (migration 0020) and group_role_mappings_tenant_match
-- (migration 0021), extended with the global-visibility
-- carve-out.
--
-- Defense-in-depth: PR11-2c will also gate writes at
-- the application layer (the InvocationService already
-- knows the actor's tenant + the resolved server's
-- visibility). The trigger catches the bug class
-- regardless of caller.
CREATE OR REPLACE FUNCTION task_states_tenant_match() RETURNS TRIGGER AS $$
DECLARE
    tool_tenant     TEXT;
    tool_visibility TEXT;
BEGIN
    SELECT s.tenant_id, s.visibility
      INTO tool_tenant, tool_visibility
      FROM mcp_tools t
      JOIN mcp_servers s ON s.id = t.server_id
     WHERE t.id = NEW.tool_id;
    IF tool_tenant IS NULL THEN
        RAISE EXCEPTION
            'task_states.tool_id % does not resolve to an mcp_tools row',
            NEW.tool_id;
    END IF;
    -- Allow same-tenant OR global-visibility owning
    -- server. Reject everything else.
    IF tool_tenant <> NEW.tenant_id AND tool_visibility <> 'global' THEN
        RAISE EXCEPTION
            'task_states tenant_id % does not match owning server tenant_id % (server visibility=%)',
            NEW.tenant_id, tool_tenant, tool_visibility;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER task_states_tenant_match_trg
    BEFORE INSERT OR UPDATE ON task_states
    FOR EACH ROW
    EXECUTE FUNCTION task_states_tenant_match();
