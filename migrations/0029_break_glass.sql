-- Phase 11 PR11-7: break-glass override tokens.
--
-- ## What
--
-- One row per minted break-glass token. When a tool call
-- would otherwise be denied by the Cedar gate, the
-- invocation pipeline's `authorize` stage consults this
-- table; if a usable row matches the call AND the
-- principal's `amr` list satisfies `requires_amr`, the
-- row is atomically marked `used_at = now()` and the
-- call proceeds. Single-use by construction: the
-- conditional UPDATE only fires when `used_at IS NULL`.
--
-- ## Why
--
-- Emergency operator override. A real incident response
-- ("the on-call needs to delete the bad row NOW; the
-- normal RBAC chain takes an hour") needs a path the
-- operator can authorize themselves through, with the
-- audit trail screaming so an after-action review can
-- see exactly what happened. Without this, the
-- alternative is "loosen the Cedar policy temporarily,"
-- which is significantly harder to audit (the policy
-- change can outlive the incident; no per-call
-- attribution).
--
-- ## Shape
--
-- - `id` is a UUID surrogate so admin revoke can target
--   a single row without quoting the composite key in
--   the URL path.
-- - `tenant_id` FKs `tenants(id)` with ON DELETE CASCADE
--   so a hard-deleted tenant takes its break-glass
--   tokens with it. Same cascade pattern as
--   `oauth_consent` (PR10-1a) and the other tenant-scoped
--   tables onboarding cleans up.
-- - `issued_to` is the principal `sub` the token is
--   minted FOR (the operator who will use it). Distinct
--   from `issued_by` (the admin who minted it) so the
--   audit trail captures both ends of the ceremony.
-- - `reason` is free-text from the minting admin
--   ("incident #4711 — delete corrupted billing row").
--   Required, not nullable: minting a break-glass token
--   without a reason defeats the audit purpose.
-- - `scope_pattern` is a literal `server.tool` FQN or a
--   `server.*` wildcard. The runtime check tests the
--   resolved tool's FQN against the pattern with a
--   simple prefix-or-equality match (no regex / glob
--   library, no Cedar — the operator's typo would
--   otherwise burn the only single-use token they
--   minted on a mismatched policy expression). Empty
--   string means "any tool" — recorded by the schema
--   but the admin handler refuses to mint it; a future
--   "super-emergency" toggle could relax that.
-- - `requires_amr` is the set of AMR values
--   (`hwk`/`mfa`/`pwd`/…) the principal's JWT `amr`
--   claim MUST contain at use-time. Operators who want
--   "MFA-required" pass `{"mfa"}`. Empty array means
--   "no AMR check" (acceptable when the token's other
--   gates — short TTL, narrow scope_pattern, named
--   issued_to — are already tight). The runtime check
--   is a SUBSET test: every entry in requires_amr must
--   appear in the principal's amr.
-- - `expires_at` is a hard wall-clock cutoff
--   independent of single-use. A token can be issued
--   today and still be unusable tomorrow if it expires
--   in between. Operators should keep TTLs short (15
--   min is typical for incident-response).
-- - `used_at` is the single-use marker. The runtime
--   claim is `UPDATE … SET used_at = now() WHERE id =
--   $1 AND used_at IS NULL AND expires_at > now()
--   RETURNING …`; rows_affected = 1 ⇒ this caller
--   claimed it, 0 ⇒ already used / already expired /
--   revoked.
-- - No `revoked_at` column: the admin DELETE endpoint
--   does a real DELETE rather than a soft-revoke. The
--   audit event (`break_glass.revoke`, AdminMutation)
--   captures the revocation; keeping the row would
--   add a "was this revoked or used" disambiguation
--   the audit log already covers.

CREATE TABLE break_glass_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issued_to     TEXT NOT NULL,
    issued_by     TEXT NOT NULL,
    reason        TEXT NOT NULL CHECK (length(reason) > 0),
    scope_pattern TEXT NOT NULL,
    requires_amr  TEXT[] NOT NULL DEFAULT '{}',
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hot-path lookup: "does this (tenant, principal_sub)
-- have any usable token matching this scope?" The
-- runtime claim picks the matching row, then the
-- conditional UPDATE serializes the claim across racing
-- requests. Partial index on `used_at IS NULL` keeps
-- the read set small once tokens accumulate.
CREATE INDEX break_glass_active_by_principal
    ON break_glass_tokens (tenant_id, issued_to)
    WHERE used_at IS NULL;
