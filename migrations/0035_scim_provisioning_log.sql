-- D5a-2: SCIM provisioning-log timeline.
--
-- ## What
--
-- New `scim_provisioning_log` table holding a structured
-- per-event record of every SCIM mutation the gateway processes
-- (`scim_users.create` / `.replace` / `.delete`, the equivalent
-- group ops, and group-membership patches). The existing
-- `audit_log` already captures these as generic AdminMutation
-- events with a stringified `reason`; the new table is the
-- Entra-style "Steps / Modified-Properties / Troubleshooting"
-- timeline an operator opens to ask:
--
-- - "What did Okta push for alice@example.com on Friday?"
-- - "Which 6 users got deprovisioned in the last hour?"
-- - "Why did the last SCIM PATCH on the `ops` group fail?"
--
-- audit_log's free-form `reason` string answers the same
-- questions only through grep; this table answers them
-- structurally.
--
-- ## Why a dedicated table (not a view over audit_log)
--
-- SCIM-specific structure: the modified-properties bag and the
-- target snapshot (display name + external id at the time of
-- the event, NOT FK-joined to a row that may since have been
-- deleted) don't have a home in audit_log's column shape.
-- Forensic value of "show me everything we did to user X" is
-- much higher when the join is index-bound on `(target_kind,
-- target_id)` than when it requires a regex over the reason
-- string.
--
-- ## Shape
--
-- - `id` UUID surrogate so future per-row drill-downs can
--   address an entry without quoting `(tenant, ts, target_id,
--   action)`.
-- - `tenant_id` FKs `tenants(id) ON DELETE CASCADE`. Same
--   per-tenant cascade as the rest of the surfaces.
-- - `target_kind` discriminates user vs. group rows so the
--   per-user / per-group filters can index-scan via the
--   composite key.
-- - `target_id` is a *soft* reference (no FK) — when a user
--   or group is deleted we want the "X was deleted" entry
--   itself to survive, so the FK would either delete the
--   history or block the deletion. A soft reference matches
--   the audit-log posture: history outlives the resource.
-- - `target_display` + `target_external_id` are snapshots at
--   the time of the event so a future viewer can identify
--   "which user was that" without joining the (possibly
--   gone) scim_users row.
-- - `actor_sub` + `actor_email` snapshot the operator (or
--   service-account principal) at the time. Nullable because
--   system-initiated paths (e.g. tenant cleanup) don't carry
--   a principal.
-- - `outcome` is `success` / `error`. The matching
--   `error_message` column carries the operator-visible error
--   string when outcome=error (`NULL` when success).
-- - `detail` JSONB carries the structured per-action payload:
--   `before` / `after` snapshots for replace, list of changed
--   member ids for membership patches, etc. Schema-free so
--   a future writer adds a key without a migration — same
--   forward-compat posture as `playground_scenarios.body`.
--
-- ## Indexes
--
-- - `(tenant_id, ts DESC)` for the main per-tenant timeline
--   page (newest first, paginated by `before=<ts>`).
-- - `(tenant_id, target_kind, target_id, ts DESC)` for the
--   per-target drawer (show me everything we did to user X).

CREATE TABLE scim_provisioning_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    target_kind         TEXT NOT NULL
                        CHECK (target_kind IN ('user', 'group')),
    target_id           UUID NOT NULL,
    target_display      TEXT NOT NULL,
    target_external_id  TEXT,
    action              TEXT NOT NULL,
    outcome             TEXT NOT NULL
                        CHECK (outcome IN ('success', 'error')),
    actor_sub           TEXT,
    actor_email         TEXT,
    error_message       TEXT,
    detail              JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX scim_provisioning_log_tenant_ts
    ON scim_provisioning_log (tenant_id, ts DESC);

CREATE INDEX scim_provisioning_log_target
    ON scim_provisioning_log (tenant_id, target_kind, target_id, ts DESC);
