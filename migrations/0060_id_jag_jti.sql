-- EMA ID-JAG replay defense (PR-2 / ID-JAG redeem at the Resource AS).
--
-- The jwt-bearer redeem path (`POST /oauth/token`,
-- grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer) records each redeemed
-- ID-JAG's `jti` here exactly once. Replay defense is a conditional INSERT
-- (`ON CONFLICT (jti) DO NOTHING`) whose rows-affected tells the handler whether
-- THIS request was the first to claim the jti — race-safe, with no read-then-
-- write window (a second concurrent redeem of the same assertion inserts zero
-- rows and is rejected). Rows are short-lived (ID-JAG TTL ~5 min); `expires_at`
-- mirrors the assertion's `exp` and the oauth sweeper reclaims rows once it
-- passes.
CREATE TABLE id_jag_jti (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

-- The sweeper deletes rows past `expires_at`; index keeps that delete cheap.
CREATE INDEX id_jag_jti_expires_at_idx ON id_jag_jti (expires_at);
