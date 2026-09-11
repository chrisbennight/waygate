-- Phase 9 PR9-d: API-key mint profiles.
--
-- Pre-PR9-d, operators could mint api_keys with any scope set,
-- any TTL (including never), any sub. That was fine for a
-- single-operator deployment but it doesn't compose with multi-
-- tenant + RBAC + SCIM — a help-desk admin shouldn't be able to
-- accidentally mint an mcp:admin-scoped key from the dashboard.
--
-- A "profile" is a per-tenant template that bounds what the
-- minter can choose. Profiles are operator-authored; the mint
-- handler validates each new key against the profile's
-- allowed_scopes / max_ttl_seconds / requires_owner /
-- requires_reason fields and refuses on overflow.
--
-- ## Default profiles (seeded per tenant in PR9-d2)
--
-- The plan calls for `read_only`, `developer`, `service_account`
-- seeded into every new tenant via PR8-f's onboarding side-
-- effect path. Importantly there's no default `admin` profile —
-- operators must explicitly create one. This makes
-- "mint a key that can do anything" a deliberate step rather
-- than a one-click default.
--
-- ## Existing api_keys rows
--
-- Pre-PR9-d keys have NULL profile_id. They keep working — the
-- profile validation runs only at MINT time. The dashboard UI
-- (lands separately) flags these as "legacy / no profile" so
-- operators can rotate at their own pace.

CREATE TABLE api_key_profiles (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    name              TEXT NOT NULL,
    -- Description renders in the dashboard's profile picker so
    -- operators understand "what is this profile for" without
    -- staring at the scope list. Optional but encouraged.
    description       TEXT,
    -- Inclusive upper bound on the minted key's TTL, in seconds.
    -- 0 is disallowed (a never-expiring key issued via a profile
    -- defeats the purpose). Operators wanting non-expiring keys
    -- can still go through the legacy dashboard mint path until
    -- a future PR removes it.
    max_ttl_seconds   INT NOT NULL CHECK (max_ttl_seconds > 0),
    -- Whitelist of scopes the minter may choose from. Mint
    -- handler refuses if the requested scope set is not a
    -- subset of this. TEXT[] for direct SQL filtering;
    -- normalisation (sort/dedup) is the caller's responsibility.
    allowed_scopes    TEXT[] NOT NULL,
    -- Optional whitelist of upstream server names. NULL ⇒ any
    -- server is allowed. Empty array ⇒ NO server allowed (which
    -- nobody would create, but the CHECK below makes the
    -- distinction obvious to operators).
    allowed_servers   TEXT[],
    -- Optional whitelist of fully-qualified tool names
    -- (<server>.<tool>). NULL ⇒ any tool allowed (within the
    -- allowed_servers constraint). Empty array ⇒ none.
    allowed_tools     TEXT[],
    -- When true, mint handler requires the operator to supply
    -- a `reason` string. PR8-f-style audit captures it on the
    -- ApiKeyMinted row.
    requires_reason   BOOLEAN NOT NULL DEFAULT true,
    -- When true, mint handler requires `owner` to identify the
    -- responsible party for this key (a sub, email, or Slack
    -- handle). Forces operators to attribute keys rather than
    -- leaving them as orphan service accounts.
    requires_owner    BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- (tenant_id, name) so an operator gets a "profile already
    -- exists" 409 instead of duplicate rows on a fat-finger.
    UNIQUE (tenant_id, name),
    -- Empty whitelist is almost certainly an operator typo —
    -- the row would refuse every mint attempt. Refuse at SQL
    -- so the operator gets a clear error at create time.
    CONSTRAINT api_key_profiles_nonempty_scopes
        CHECK (cardinality(allowed_scopes) > 0)
);

-- Touch trigger for updated_at, matches the pattern PR8-e
-- established for the tenants table.
CREATE OR REPLACE FUNCTION api_key_profiles_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER api_key_profiles_touch_updated_at_trg
    BEFORE UPDATE ON api_key_profiles
    FOR EACH ROW
    EXECUTE FUNCTION api_key_profiles_touch_updated_at();

-- Wire api_keys to profiles. `profile_id` is nullable so existing
-- (pre-PR9-d) rows keep working. The dashboard surfaces "legacy
-- / no profile" badging on them. `ON DELETE SET NULL` matches
-- the "deleting a profile doesn't kill existing keys" semantic
-- — the keys retain their granted scopes but lose the link to
-- the template they were minted from.
ALTER TABLE api_keys
    ADD COLUMN profile_id UUID REFERENCES api_key_profiles(id) ON DELETE SET NULL,
    -- Required when the profile says `requires_owner = true`.
    -- The mint handler enforces; the column itself is nullable
    -- so pre-PR9-d rows stay valid.
    ADD COLUMN owner TEXT,
    -- Required when the profile says `requires_reason = true`.
    -- Persisted so the audit trail carries the operator's
    -- stated reason at mint time, not just the inferred one.
    ADD COLUMN reason TEXT,
    -- Hint to the dashboard: when set, this key is approaching
    -- (or past) its rotation deadline. Operator-set at mint
    -- time based on the profile's `max_ttl_seconds`. No
    -- enforcement here — just a visibility surface that
    -- future PRs can drive renewal nudges from.
    ADD COLUMN rotation_due_at TIMESTAMPTZ;

CREATE INDEX api_keys_profile_id_idx ON api_keys (profile_id);
