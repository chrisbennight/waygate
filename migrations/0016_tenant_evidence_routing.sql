-- Phase 7 PR7-6: per-tenant evidence export routing.
--
-- Today the recorder enqueues one `evidence_outbox` row per
-- `target_sink` listed in the gateway's
-- `GATEWAY_EVIDENCE_OUTBOX_TARGETS` env var — every audit
-- event, regardless of tenant, fans out to every configured
-- target. That's a single-tenant assumption: it precludes
-- operators from saying "tenant ACME's events go to OCSF
-- only; tenant ZETA's go to OCSF + S3."
--
-- This migration adds a per-tenant routing table the recorder
-- consults in the same transaction as the audit + outbox
-- inserts. The recorder's decision:
--
--   - No rows for this tenant: fall back to
--     `outbox_targets` from the env var. Preserves pre-PR7-6
--     behavior for every existing deployment.
--   - Rows exist for this tenant: enqueue only for the
--     enabled `exporter_name`s, intersected with the
--     gateway's configured `outbox_targets` (an operator
--     can't route to an exporter the gateway doesn't know
--     about). Disabling every row for a tenant means that
--     tenant's events get NO outbox rows — useful for
--     temporary per-tenant suppression without taking the
--     whole pipeline offline.
--
-- The PK is `(tenant_id, exporter_name)` so an operator can't
-- accidentally create two routing rows for the same target
-- (which would either fan out twice or surface a
-- non-deterministic disabled/enabled decision).
--
-- `config JSONB` is exporter-specific (auth headers, batch
-- size, alert thresholds, region, etc.). PR7-6 carries it
-- through unchanged; subsequent exporter PRs (OCSF / Syslog
-- / ECS / S3) interpret it when they're added. Default
-- `'{}'::jsonb` lets operators add a routing row before any
-- exporter-specific config is required.

CREATE TABLE tenant_evidence_routing (
    tenant_id      TEXT NOT NULL,
    exporter_name  TEXT NOT NULL,
    config         JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, exporter_name)
);

-- The recorder's lookup is `WHERE tenant_id = $1` then a
-- single-tenant filter in-app to distinguish "no rows" from
-- "rows but all disabled" (the two cases mean different
-- things). PK index on (tenant_id, exporter_name) already
-- covers the lookup since tenant_id is the leading column —
-- no additional index needed.
