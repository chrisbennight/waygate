-- Phase 7 PR7-8b (round 2) — retention sweep bypass for the
-- audit_log no-mutate trigger, role-based design.
--
-- PR7-4 (migration 0015) installed a BEFORE UPDATE/DELETE/TRUNCATE
-- trigger that blocks every mutation of audit_log so the
-- tamper-evidence chain stays append-only. PR7-8b ships the
-- retention sweep that DELETEs rows past a retention cutoff; the
-- sweep needs a controlled DELETE path through the guard.
--
-- AERB PR #135 round 1 high (security): the round-1 design used
-- a session GUC (`app.retention_sweep_authorized = 'true'`) for
-- the bypass. Any caller holding the gateway's DB credential
-- could `SET LOCAL` that GUC and bypass — the bypass surface was
-- "anyone who can SET", which is every SQL caller. Round 2 moves
-- the bypass to a role check that only a SECURITY DEFINER wrapper
-- can satisfy: the trigger now permits UPDATE/DELETE only when
-- `current_user = 'audit_log_sweep_role'`, and that role is
-- assumable only by going through `audit_log_sweep_delete()`,
-- whose ownership puts the SECURITY DEFINER tag in front of it.
--
-- This is what was originally scoped as PR7-8c (the role
-- hardening). It landed bundled into PR7-8b because AERB
-- (rightly) didn't accept the standalone regression: shipping
-- 8b's mechanics with a documented "8c will harden" relies on
-- 8c actually landing, which isn't guaranteed mid-flight.
--
-- ## Trigger rewrite
--
-- The trigger function is rewritten so the bypass test is a
-- role check, not a GUC. There is no `SET LOCAL` an operator
-- can abuse — manually setting any session variable doesn't
-- change `current_user`. TRUNCATE is still never bypassed
-- (a sweep is per-row DELETEs, never whole-table erasure).
--
-- ## Bypass role + function
--
-- A dedicated role `audit_log_sweep_role` is created NOLOGIN.
-- It has `DELETE` and `SELECT` on `audit_log` (the SELECT is
-- so the SECURITY DEFINER function can run its marker-coverage
-- precondition check) and nothing else. Critically, NOBODY is
-- granted role MEMBERSHIP — the role exists purely as a
-- SECURITY DEFINER function owner. Without explicit
-- `GRANT audit_log_sweep_role TO <role>` (which this migration
-- never issues), no logged-in role can `SET ROLE` to it.
--
-- The wrapper function `audit_log_sweep_delete(p_tenant TEXT,
-- p_ids UUID[])` is SECURITY DEFINER and owned by
-- `audit_log_sweep_role`. Inside the function, `current_user`
-- is the owner role; outside, `current_user` is whoever's
-- logged in. The trigger sees `current_user` and gates on it.
--
-- EXECUTE on the function is REVOKED from PUBLIC and GRANTed
-- only to `current_user` — the role that ran the migration.
-- In typical single-role gateway deploys (the gateway DB user
-- runs migrations AND connects at runtime) this is automatic
-- and no operator action is needed.
--
-- AERB PR #135 round 2 high (security): the round-2 design
-- left a no-op REVOKE+GRANT-back-to-PUBLIC; any DB role that
-- could connect could call the function. That defeated the
-- whole role-based bypass. Round 3 drops the PUBLIC grant.
--
-- Multi-role deploys (separate admin role applies migrations,
-- separate app role connects at runtime) must run, post-
-- migration:
--
--     GRANT EXECUTE ON FUNCTION
--         audit_log_sweep_delete(TEXT, UUID[])
--         TO <gateway_role>;
--
-- without that grant the sweep returns permission-denied.
--
-- The threat surface AERB highlighted (any SQL caller could
-- `SET LOCAL` and bypass) closes: the bypass requires going
-- through the function, and the function refuses to delete
-- any `p_id` that is not already referenced in some
-- `retention_sweep` marker's `deleted_rows` payload for the
-- tenant. The Rust sweep writes its markers BEFORE calling
-- the function (in the same TX), so the markers are visible
-- to the check. A caller bypassing the Rust layer to invoke
-- the raw function must FIRST INSERT a real `retention_sweep`
-- row whose `deleted_rows` covers the target row_hashes — the
-- deletion is then on the audit trail (the marker) and the
-- chain still verifies via PR7-8a's walker.
--
-- ## Privilege requirements at migration time
--
-- AERB PR #135 round 3 medium (impact): this migration calls
-- CREATE ROLE and ALTER FUNCTION OWNER, both of which require
-- privileges the typical migration role has but a hardened
-- migration role may not. Specifically:
--
--   - CREATE ROLE requires CREATEROLE or superuser.
--   - ALTER FUNCTION ... OWNER TO requires the migration role
--     to be a member of the target owner role.
--
-- Deployments where the migration role lacks these can
-- pre-create the role out-of-band:
--
--     -- as a superuser, before applying this migration:
--     CREATE ROLE audit_log_sweep_role NOLOGIN;
--     GRANT audit_log_sweep_role TO <migration_role>;
--
-- The DO block below uses `IF NOT EXISTS`, so the migration
-- succeeds when the role is pre-created. The membership
-- grant lets `ALTER FUNCTION ... OWNER TO` succeed.

-- Step 1: rewrite the trigger function. GUC checks are gone.
CREATE OR REPLACE FUNCTION audit_log_no_mutate() RETURNS TRIGGER AS $$
BEGIN
    -- TRUNCATE is statement-level and never honoured; OLD/NEW
    -- aren't set for it. `TG_OP = 'TRUNCATE'` always reaches
    -- the RAISE below.
    IF TG_OP IN ('UPDATE', 'DELETE')
       AND current_user = 'audit_log_sweep_role' THEN
        RETURN COALESCE(OLD, NEW);
    END IF;
    RAISE EXCEPTION
        'audit_log is append-only (tamper-evidence chain); UPDATE/DELETE denied';
END;
$$ LANGUAGE plpgsql;

-- Step 2: the bypass role. NOLOGIN so nobody can connect as it
-- directly; nobody is granted membership so nobody can `SET ROLE`
-- to it. The role exists only as the SECURITY DEFINER wrapper's
-- owner.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_log_sweep_role') THEN
        CREATE ROLE audit_log_sweep_role NOLOGIN;
    END IF;
END;
$$;

GRANT DELETE ON audit_log TO audit_log_sweep_role;
-- SELECT so the function's marker-coverage precondition can
-- run (it reads marker rows and joins against candidate ids).
GRANT SELECT ON audit_log TO audit_log_sweep_role;

-- Step 3: the wrapper. SECURITY DEFINER → runs as the function's
-- owner regardless of who called. `current_user` inside is the
-- owner (`audit_log_sweep_role`); the trigger sees that and
-- permits the DELETE. Outside the function, `current_user` is
-- whoever logged in, and the trigger blocks.
--
-- `search_path` is pinned to `pg_catalog` to defeat the classic
-- SECURITY DEFINER injection where a caller plants a malicious
-- `audit_log` table in their own schema; the pinned search_path
-- forces unqualified references to resolve in pg_catalog +
-- public only.
CREATE OR REPLACE FUNCTION audit_log_sweep_delete(p_tenant TEXT, p_ids UUID[])
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    deleted_count BIGINT;
    covered_count INT;
    expected_count INT;
BEGIN
    -- AERB PR #135 round 3 high (security): refuse the call
    -- unless EVERY p_id is referenced in some retention_sweep
    -- marker's deleted_rows JSON for this tenant. The Rust
    -- sweep INSERTs markers BEFORE calling this function (in
    -- the same TX), so the markers are visible. A caller
    -- bypassing the Rust layer to invoke this function
    -- directly must FIRST INSERT a real retention_sweep row
    -- whose deleted_rows covers each target row_hash — the
    -- deletion is then on the audit trail (the marker) and
    -- the chain still verifies via PR7-8a's walker.
    --
    -- The deeper "INSERT-capable attacker pre-writes both
    -- marker and DELETE" case stays out of scope here — same
    -- threat PR7-8a flagged as gated by future role-separation
    -- work (gateway holds EXECUTE on this function but NOT
    -- INSERT on audit_log; that's a separate deployment
    -- model beyond PR7-8b's mechanics).
    expected_count := COALESCE(array_length(p_ids, 1), 0);
    IF expected_count = 0 THEN
        RETURN 0;
    END IF;
    -- AERB PR #135 round 4 high (security): the inner SELECT
    -- requires the marker row itself to be chain-bearing
    -- (`row_hash IS NOT NULL`). A non-chain row_hash-NULL
    -- forgery is rejected here regardless of what its
    -- `reason` claims.
    --
    -- Limitation: this PL/pgSQL check cannot replicate PR7-8a's
    -- invariant 2 (`recompute_row_hash(m) == m.row_hash`) —
    -- doing so would require porting `canonical_audit_bytes`
    -- and the SHA-256 chain-hash to PL/pgSQL byte-for-byte,
    -- which is a substantial maintainability cost (one
    -- divergence and the sweep silently breaks). For a
    -- forged marker whose `row_hash` is bogus, the function
    -- here passes the check but PR7-8a's adapter rejects the
    -- marker at admission and the walker reports
    -- `BrokenLink` at the target's gap — i.e. the bypass is
    -- DETECTABLE at verify time, even though the function
    -- can't PREVENT it at delete time.
    --
    -- The "INSERT-capable adversary forges a fully chain-
    -- consistent marker AND deletes" case (the marker passes
    -- invariant 2 because the attacker computed it correctly)
    -- requires role-separating the recorder so the gateway
    -- doesn't have INSERT on audit_log either. That's a
    -- substantial deployment refactor sized as a separate PR
    -- in the architecture plan and is intentionally not
    -- bundled here.
    SELECT COUNT(*) INTO covered_count
      FROM public.audit_log al
     WHERE al.id = ANY(p_ids)
       AND al.tenant_id = p_tenant
       AND al.row_hash IS NOT NULL
       AND al.row_hash IN (
           SELECT jsonb_array_elements(m.reason::jsonb -> 'deleted_rows') ->> 'row_hash'
             FROM public.audit_log m
            WHERE m.tenant_id = p_tenant
              AND m.category  = 'retention_sweep'
              AND m.reason   IS NOT NULL
              AND m.row_hash IS NOT NULL
       );
    IF covered_count <> expected_count THEN
        RAISE EXCEPTION
            'audit_log_sweep_delete: marker-coverage precondition violated: % of % p_ids covered by chain-bearing retention_sweep markers',
            covered_count, expected_count;
    END IF;

    -- AERB PR #135 round 1 high (design-goal): defense in
    -- depth — the function REFUSES to delete marker rows
    -- even if a caller passes marker ids. Markers carry the
    -- chain bridges PR7-8a's verifier needs for older
    -- retention gaps; deleting them would make previously
    -- valid chains unverifiable. The Rust caller has its own
    -- `FORBIDDEN_SWEEP_CATEGORY` check at
    -- `run_retention_sweep` entry; this `AND category != ...`
    -- predicate is the last-line guarantee at the only DELETE
    -- path the DB exposes.
    DELETE FROM public.audit_log
     WHERE tenant_id = p_tenant
       AND id = ANY(p_ids)
       AND category != 'retention_sweep';
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;

ALTER FUNCTION audit_log_sweep_delete(TEXT, UUID[]) OWNER TO audit_log_sweep_role;
REVOKE EXECUTE ON FUNCTION audit_log_sweep_delete(TEXT, UUID[]) FROM PUBLIC;

-- Auto-grant to the role that ran the migration; that's the
-- gateway DB user in typical single-role deployments. The DO
-- block + format(%I) safely quotes the current_user
-- identifier. Multi-role deployments must add their own
-- `GRANT EXECUTE ... TO <gateway_role>` after this migration.
DO $$
BEGIN
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION audit_log_sweep_delete(TEXT, UUID[]) TO %I',
        current_user
    );
END;
$$;
