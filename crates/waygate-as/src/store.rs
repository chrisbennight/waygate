//! Postgres-backed stores for `/oauth/*` state.
//!
//! Three short-lived tables:
//! * `oauth_transactions` — in-flight authorize requests (TTL 15 min).
//! * `oauth_codes` — gateway-issued codes waiting to be swapped for tokens
//!   at `/oauth/token` (TTL 60 s).
//! * `oauth_refresh_tokens` — long-lived refresh tokens with rotation chain.
//!
//! The migrations live in `/migrations/0003_oauth_as.sql`; this module just
//! presents typed getters/setters.

use serde_json::Value as JsonValue;
use sqlx::postgres::PgPool;
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub txn_id: String,
    pub client_id: String,
    pub client_redirect_uri: String,
    pub client_state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub scopes: Vec<String>,
    pub resource: Option<String>,
    pub proxy_code_verifier: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct IssuedCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scopes: Vec<String>,
    pub sub: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub upstream_tokens_ciphertext: Option<Vec<u8>>,
    pub expires_at: OffsetDateTime,
    /// The principal's tenant id at the moment the code was minted.
    /// `token.rs::handle_auth_code` reads this back from `take_code`
    /// and threads it onto the successor refresh-token row + the
    /// gateway-minted access token's `tenant` claim, so a
    /// non-default tenant admin's subsequent `mcp:admin` API calls
    /// actually carry their tenant — without it, the gateway-issued
    /// access token would carry no `tenant` claim and
    /// `BearerValidator` would silently fall back to `default`.
    pub tenant_id: String,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub token: String,
    pub sub: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub client_id: String,
    pub rotated_from: Option<String>,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    /// Tenant carried forward from the IssuedCode that minted this
    /// token's initial chain (or copied from the parent on
    /// rotation). Read back by
    /// `token.rs::handle_refresh` to thread the same tenant
    /// onto the rotated successor + the freshly-minted access
    /// token's `tenant` claim. See `IssuedCode.tenant_id` for
    /// the originating rationale.
    pub tenant_id: String,
}

#[derive(Clone)]
pub struct OauthStore {
    pool: PgPool,
}

impl OauthStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert_transaction(&self, txn: &Transaction) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_transactions (
                txn_id, client_id, client_redirect_uri, client_state,
                code_challenge, code_challenge_method, scopes, resource,
                proxy_code_verifier, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&txn.txn_id)
        .bind(&txn.client_id)
        .bind(&txn.client_redirect_uri)
        .bind(&txn.client_state)
        .bind(&txn.code_challenge)
        .bind(&txn.code_challenge_method)
        .bind(JsonValue::from(
            txn.scopes
                .iter()
                .map(|s| JsonValue::from(s.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(&txn.resource)
        .bind(&txn.proxy_code_verifier)
        .bind(txn.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// One-shot take: delete the row and return it if it was live (not expired).
    pub async fn take_transaction(&self, txn_id: &str) -> Result<Option<Transaction>, StoreError> {
        let row = sqlx::query_as::<_, TransactionRow>(
            r#"
            DELETE FROM oauth_transactions
            WHERE txn_id = $1 AND expires_at > now()
            RETURNING txn_id, client_id, client_redirect_uri, client_state,
                      code_challenge, code_challenge_method, scopes, resource,
                      proxy_code_verifier, expires_at
            "#,
        )
        .bind(txn_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(Transaction::try_from).transpose()
    }

    pub async fn insert_code(&self, code: &IssuedCode) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_codes (
                code, client_id, redirect_uri, code_challenge, scopes,
                sub, email, groups, upstream_tokens_ciphertext, expires_at,
                tenant_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(&code.code)
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(&code.code_challenge)
        .bind(JsonValue::from(
            code.scopes
                .iter()
                .map(|s| JsonValue::from(s.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(&code.sub)
        .bind(&code.email)
        .bind(JsonValue::from(
            code.groups
                .iter()
                .map(|g| JsonValue::from(g.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(code.upstream_tokens_ciphertext.as_deref())
        .bind(code.expires_at)
        .bind(&code.tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn take_code(&self, code: &str) -> Result<Option<IssuedCode>, StoreError> {
        let row = sqlx::query_as::<_, IssuedCodeRow>(
            r#"
            DELETE FROM oauth_codes
            WHERE code = $1 AND expires_at > now()
            RETURNING code, client_id, redirect_uri, code_challenge, scopes,
                      sub, email, groups, upstream_tokens_ciphertext, expires_at,
                      tenant_id
            "#,
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await?;
        row.map(IssuedCode::try_from).transpose()
    }

    pub async fn insert_refresh(&self, rt: &RefreshToken) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_refresh_tokens (
                token, sub, email, groups, scopes, client_id, rotated_from, expires_at,
                tenant_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&rt.token)
        .bind(&rt.sub)
        .bind(&rt.email)
        .bind(JsonValue::from(
            rt.groups
                .iter()
                .map(|g| JsonValue::from(g.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(JsonValue::from(
            rt.scopes
                .iter()
                .map(|s| JsonValue::from(s.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(&rt.client_id)
        .bind(&rt.rotated_from)
        .bind(rt.expires_at)
        .bind(&rt.tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_refresh(&self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        let row = sqlx::query_as::<_, RefreshTokenRow>(
            r#"
            SELECT token, sub, email, groups, scopes, client_id, rotated_from,
                   issued_at, expires_at, revoked_at, tenant_id
            FROM oauth_refresh_tokens
            WHERE token = $1
            "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        row.map(RefreshToken::try_from).transpose()
    }

    /// Atomically revoke a refresh token. Returns `true` iff this call
    /// was the one that flipped `revoked_at` from NULL — the caller
    /// owns the rotation. Returns `false` when another concurrent
    /// rotation got there first (or the row was already revoked).
    ///
    /// `handle_refresh` relies on this bool to serialize concurrent
    /// `/oauth/token` refresh requests: only the winner may mint a
    /// successor refresh row, or RFC 6749 §10.4 single-use rotation
    /// degenerates into "whichever racing request finishes its insert
    /// last overwrites the chain".
    pub async fn revoke_refresh(&self, token: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE oauth_refresh_tokens
            SET revoked_at = now()
            WHERE token = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Revoke every live descendant of a token along the `rotated_from` chain.
    /// Triggered when a previously-rotated (revoked) token is replayed — a
    /// classic refresh-token theft indicator per RFC 6749 §10.4.
    pub async fn revoke_chain(&self, leaked_token: &str) -> Result<u64, StoreError> {
        let result = sqlx::query(
            r#"
            WITH RECURSIVE chain(token) AS (
                SELECT token FROM oauth_refresh_tokens WHERE token = $1
                UNION ALL
                SELECT r.token
                FROM oauth_refresh_tokens r
                JOIN chain c ON r.rotated_from = c.token
            )
            UPDATE oauth_refresh_tokens
            SET revoked_at = now()
            WHERE token IN (SELECT token FROM chain) AND revoked_at IS NULL
            "#,
        )
        .bind(leaked_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Group every live refresh token by `(client_id, sub, email)` and
    /// return one row per session for the admin dashboard.
    ///
    /// "Live" = not revoked AND not expired. Within a session we expose:
    /// * `chain_count` — how many live refresh-token rows the pair owns
    ///   right now. Each `/oauth/token refresh_token` rotation adds one
    ///   row before flipping the predecessor's `revoked_at`, so the live
    ///   set has size ≥1 even mid-rotation; a count >1 usually means the
    ///   user has multiple distinct logins (different browser sessions,
    ///   different machines).
    /// * `oldest_issued_at` / `newest_issued_at` — useful for telling a
    ///   long-lived session ("first login 12d ago") from a freshly-rotated
    ///   one ("first issue 4 minutes ago").
    pub async fn list_active_sessions(&self, limit: i64) -> Result<Vec<OauthSession>, StoreError> {
        // Naive `MAX(groups::TEXT)` / `MAX(scopes::TEXT)` picks one
        // chain's metadata lexicographically when a `(client_id, sub)`
        // pair owns multiple chains with *different* group or scope
        // sets — e.g. a user who logged in once asking for `[mcp:read]`
        // and again for `[mcp:invoke, mcp:read]`. The dashboard wants
        // the *union* so the row reflects what the session collectively
        // can do, not whichever JSON-text comparison happens to win.
        //
        // Correlated subqueries run once per output row (one per
        // `(client_id, sub)`); the same live filter scopes the inner
        // scan to the same rows the outer GROUP BY is already
        // consolidating. For homelab traffic (≤ thousands of live RTs)
        // this is cheap. If it ever isn't, the right answer is a
        // materialised session-summary table, not optimising this query.
        let rows = sqlx::query_as::<_, OauthSessionRow>(
            r#"
            SELECT t.client_id,
                   t.sub,
                   MAX(t.email)             AS email,
                   (SELECT jsonb_agg(DISTINCT g ORDER BY g)
                      FROM oauth_refresh_tokens r,
                           jsonb_array_elements_text(r.groups) AS g
                     WHERE r.client_id = t.client_id
                       AND r.sub = t.sub
                       AND r.revoked_at IS NULL
                       AND r.expires_at > now())::TEXT
                       AS groups_json,
                   (SELECT jsonb_agg(DISTINCT s ORDER BY s)
                      FROM oauth_refresh_tokens r,
                           jsonb_array_elements_text(r.scopes) AS s
                     WHERE r.client_id = t.client_id
                       AND r.sub = t.sub
                       AND r.revoked_at IS NULL
                       AND r.expires_at > now())::TEXT
                       AS scopes_json,
                   COUNT(*)::BIGINT         AS chain_count,
                   MIN(t.issued_at)         AS oldest_issued_at,
                   MAX(t.issued_at)         AS newest_issued_at
            FROM oauth_refresh_tokens t
            WHERE t.revoked_at IS NULL AND t.expires_at > now()
            GROUP BY t.client_id, t.sub
            ORDER BY MAX(t.issued_at) DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(OauthSession::try_from).collect()
    }

    /// Atomic refresh-token rotation: revoke `predecessor_token` if it's
    /// still live, then insert `successor`. Wrapped in a transaction that
    /// takes a Postgres advisory lock on the `(client_id, sub)` pair so
    /// a concurrent dashboard `revoke_by_client_sub` either sees the
    /// rotation before it starts (and we lose `won_rotation` → no
    /// successor inserted) or after it commits (and the revoke kills
    /// the just-inserted successor too).
    ///
    /// Returns `true` if this caller won the rotation race (predecessor
    /// was live and got flipped, successor was inserted) and `false` if
    /// another rotation got there first (predecessor already revoked at
    /// lock acquisition; no successor inserted).
    ///
    /// Without the lock there's a window where the admin revoke sees
    /// zero live rows (predecessor already revoked, successor not yet
    /// inserted) and the successor survives.
    pub async fn rotate_refresh(
        &self,
        predecessor_token: &str,
        successor: &RefreshToken,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        acquire_session_lock(&mut tx, &successor.client_id, &successor.sub).await?;

        let flipped = sqlx::query(
            r#"
            UPDATE oauth_refresh_tokens
            SET revoked_at = now()
            WHERE token = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(predecessor_token)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if flipped == 0 {
            // Predecessor already revoked (admin revoke beat us, or a
            // parallel refresh did). Commit so the lock releases cleanly;
            // no successor inserted, caller surfaces InvalidRefresh.
            tx.commit().await?;
            return Ok(false);
        }

        sqlx::query(
            r#"
            INSERT INTO oauth_refresh_tokens (
                token, sub, email, groups, scopes, client_id, rotated_from, expires_at,
                tenant_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&successor.token)
        .bind(&successor.sub)
        .bind(&successor.email)
        .bind(JsonValue::from(
            successor
                .groups
                .iter()
                .map(|g| JsonValue::from(g.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(JsonValue::from(
            successor
                .scopes
                .iter()
                .map(|s| JsonValue::from(s.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(&successor.client_id)
        .bind(&successor.rotated_from)
        .bind(successor.expires_at)
        // Bind tenant_id on rotation too. This INSERT is separate
        // from the regular `insert_refresh` path and needs its own
        // explicit bind — if it's dropped, the column defaults to
        // 'default' (migration 0010), every refresh after the first
        // re-hydrates `Principal.tenant = "default"`, and a
        // non-default tenant admin silently shifts to
        // default-tenant authority.
        .bind(&successor.tenant_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// Revoke every *live* refresh token belonging to a `(client_id, sub)`
    /// pair in one shot. "Live" matches `list_active_sessions`: not
    /// revoked AND not expired. Returns the number of rows flipped — `0`
    /// means the session was already gone (already revoked, expired,
    /// or never existed).
    ///
    /// Filtering on `expires_at > now()` keeps the count honest: revoking
    /// an already-expired-but-unswept row would inflate the audit log's
    /// "rows revoked" figure without affecting any live session, and the
    /// pair didn't show up in the dashboard listing in the first place.
    ///
    /// Used by the dashboard's "revoke session" button. Equivalent to the
    /// existing `revoke_chain` but keyed on the (client_id, sub) tuple
    /// rather than a single seed token: a session can span multiple
    /// rotation chains (e.g. two browser tabs), and the dashboard wants
    /// to kill them all together.
    pub async fn revoke_by_client_sub(
        &self,
        client_id: &str,
        sub: &str,
    ) -> Result<u64, StoreError> {
        // Same advisory lock `rotate_refresh` takes. Either:
        //  * Admin gets the lock first → revokes all live rows → commits.
        //    Concurrent refresh then acquires the lock, finds its
        //    predecessor already revoked, returns `won_rotation = false`,
        //    and inserts no successor.
        //  * Refresh gets the lock first → revokes + inserts successor
        //    → commits. Admin then acquires the lock and sees the newly
        //    inserted successor in its UPDATE … live filter, revokes it
        //    too.
        // Either ordering produces a session-revoke that actually kills
        // the session.
        let mut tx = self.pool.begin().await?;
        acquire_session_lock(&mut tx, client_id, sub).await?;
        let result = sqlx::query(
            r#"
            UPDATE oauth_refresh_tokens
            SET revoked_at = now()
            WHERE client_id = $1 AND sub = $2
              AND revoked_at IS NULL
              AND expires_at > now()
            "#,
        )
        .bind(client_id)
        .bind(sub)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }

    /// Claim an ID-JAG `jti` for one-time redemption (EMA Resource-AS replay
    /// defense). Returns `true` iff THIS call was the first to record the
    /// `jti` — the caller owns the redemption and may proceed. `false` ⇒ the
    /// `jti` was already recorded (replay) and the caller MUST reject.
    ///
    /// Race-safe: the conditional INSERT + `rows_affected` has no read-then-
    /// write window, so two concurrent redeems of the same assertion can't both
    /// see "unused" — exactly one inserts the row. `expires_at` mirrors the
    /// assertion's `exp` so the sweeper can reclaim the row afterwards.
    pub async fn claim_id_jag_jti(
        &self,
        jti: &str,
        expires_at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            INSERT INTO id_jag_jti (jti, expires_at)
            VALUES ($1, $2)
            ON CONFLICT (jti) DO NOTHING
            "#,
        )
        .bind(jti)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Sweep expired transactions, codes, and refresh tokens.
    ///
    /// We deliberately keep revoked-but-unexpired refresh rows around: replay
    /// detection in `token::handle_refresh` relies on `rt.revoked_at.is_some()`
    /// to chain-revoke a stolen token's descendants. Dropping them early
    /// would silently downgrade RFC 6749 §10.4 theft detection to "refresh
    /// token unknown" — indistinguishable from a typo.
    ///
    /// Indexes on `expires_at` keep all three deletes cheap.
    pub async fn sweep_expired(&self) -> Result<SweepCounts, StoreError> {
        let transactions = sqlx::query("DELETE FROM oauth_transactions WHERE expires_at < now()")
            .execute(&self.pool)
            .await?
            .rows_affected();
        let codes = sqlx::query("DELETE FROM oauth_codes WHERE expires_at < now()")
            .execute(&self.pool)
            .await?
            .rows_affected();
        let refresh_tokens =
            sqlx::query("DELETE FROM oauth_refresh_tokens WHERE expires_at < now()")
                .execute(&self.pool)
                .await?
                .rows_affected();
        // Drop expired oauth_consent_pending rows here so
        // abandoned consent screens don't retain their
        // encrypted upstream_tokens_ciphertext past the
        // pending TTL. Same shape as the other three
        // arms; the pending table sees one row per
        // gated /oauth/callback so the sweep stays
        // cheap.
        let consent_pending =
            sqlx::query("DELETE FROM oauth_consent_pending WHERE expires_at < now()")
                .execute(&self.pool)
                .await?
                .rows_affected();
        // Reclaim spent ID-JAG replay markers once the assertion they
        // guard has expired (a redeem of an expired assertion is rejected by
        // `verify_id_jag`'s exp check, so the marker is no longer needed).
        let id_jag_jti = sqlx::query("DELETE FROM id_jag_jti WHERE expires_at < now()")
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(SweepCounts {
            transactions,
            codes,
            refresh_tokens,
            consent_pending,
            id_jag_jti,
        })
    }
}

/// Take a Postgres advisory lock keyed on the `(client_id, sub)` session
/// identity. The two-arg `pg_advisory_xact_lock(int4, int4)` form
/// auto-releases at `COMMIT` / `ROLLBACK`. `hashtext(...)` already
/// returns `int4`; collisions across distinct sessions only cause
/// unrelated revoke/rotate flows to serialize, which is harmless.
async fn acquire_session_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    client_id: &str,
    sub: &str,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind(client_id)
        .bind(sub)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Loop that calls [`OauthStore::sweep_expired`] every `interval`, exits
/// when `shutdown` resolves. Caller owns the spawn — we stay agnostic to
/// whatever cancellation primitive the server uses.
///
/// Errors are logged and the loop continues; a transient DB hiccup must
/// not silently kill the sweeper.
pub async fn run_sweeper(
    store: OauthStore,
    interval: std::time::Duration,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let mut ticker = tokio::time::interval(interval);
    // Delay the first tick so a restart loop can't hammer the DB if the
    // sweeper itself crashes the process for some other reason.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // burn the immediate first tick
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::debug!("oauth sweeper exiting");
                return;
            }
            _ = ticker.tick() => {
                match store.sweep_expired().await {
                    Ok(counts)
                        if counts.transactions
                            + counts.codes
                            + counts.refresh_tokens
                            + counts.consent_pending
                            + counts.id_jag_jti
                            > 0 =>
                    {
                        tracing::info!(
                            transactions = counts.transactions,
                            codes = counts.codes,
                            refresh_tokens = counts.refresh_tokens,
                            consent_pending = counts.consent_pending,
                            id_jag_jti = counts.id_jag_jti,
                            "oauth sweeper removed expired rows",
                        );
                    }
                    Ok(_) => {
                        tracing::debug!("oauth sweeper: nothing to remove");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "oauth sweeper failed; retrying on next tick");
                    }
                }
            }
        }
    }
}

/// Row counts removed by [`OauthStore::sweep_expired`]. Logged by the
/// periodic sweeper so operators can see the sweeper is alive and working.
#[derive(Debug, Clone, Copy, Default)]
pub struct SweepCounts {
    pub transactions: u64,
    pub codes: u64,
    pub refresh_tokens: u64,
    /// Rows dropped from `oauth_consent_pending`. Carries encrypted
    /// upstream tokens, so a missed sweep is a real retention
    /// concern.
    pub consent_pending: u64,
    /// Expired ID-JAG replay markers reclaimed from `id_jag_jti`.
    pub id_jag_jti: u64,
}

/// Dashboard view: one row per live `(client_id, sub)` session. Aggregated
/// from `oauth_refresh_tokens` — the dashboard never sees individual
/// rotation rows.
#[derive(Debug, Clone)]
pub struct OauthSession {
    pub client_id: String,
    pub sub: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub chain_count: i64,
    pub oldest_issued_at: OffsetDateTime,
    pub newest_issued_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct OauthSessionRow {
    client_id: String,
    sub: String,
    email: Option<String>,
    /// JSONB collapsed to TEXT for the cross-row aggregate. Postgres can't
    /// `MAX(jsonb)` directly, so we cast to text in the query and parse
    /// here. Every row carries the same value for a given session (set at
    /// authorize time and never updated), so MAX is just picking one.
    groups_json: Option<String>,
    scopes_json: Option<String>,
    chain_count: i64,
    oldest_issued_at: OffsetDateTime,
    newest_issued_at: OffsetDateTime,
}

impl TryFrom<OauthSessionRow> for OauthSession {
    type Error = StoreError;
    fn try_from(r: OauthSessionRow) -> Result<Self, StoreError> {
        let groups = parse_str_array(r.groups_json.as_deref())?;
        let scopes = parse_str_array(r.scopes_json.as_deref())?;
        Ok(Self {
            client_id: r.client_id,
            sub: r.sub,
            email: r.email,
            groups,
            scopes,
            chain_count: r.chain_count,
            oldest_issued_at: r.oldest_issued_at,
            newest_issued_at: r.newest_issued_at,
        })
    }
}

fn parse_str_array(json: Option<&str>) -> Result<Vec<String>, StoreError> {
    match json {
        None => Ok(Vec::new()),
        Some(raw) => {
            let v: JsonValue = serde_json::from_str(raw)?;
            Ok(json_to_str_vec(v))
        }
    }
}

#[derive(sqlx::FromRow)]
struct TransactionRow {
    txn_id: String,
    client_id: String,
    client_redirect_uri: String,
    client_state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    scopes: JsonValue,
    resource: Option<String>,
    proxy_code_verifier: String,
    expires_at: OffsetDateTime,
}

impl TryFrom<TransactionRow> for Transaction {
    type Error = StoreError;
    fn try_from(r: TransactionRow) -> Result<Self, StoreError> {
        Ok(Self {
            txn_id: r.txn_id,
            client_id: r.client_id,
            client_redirect_uri: r.client_redirect_uri,
            client_state: r.client_state,
            code_challenge: r.code_challenge,
            code_challenge_method: r.code_challenge_method,
            scopes: json_to_str_vec(r.scopes),
            resource: r.resource,
            proxy_code_verifier: r.proxy_code_verifier,
            expires_at: r.expires_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct IssuedCodeRow {
    code: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scopes: JsonValue,
    sub: String,
    email: Option<String>,
    groups: JsonValue,
    upstream_tokens_ciphertext: Option<Vec<u8>>,
    expires_at: OffsetDateTime,
    tenant_id: String,
}

impl TryFrom<IssuedCodeRow> for IssuedCode {
    type Error = StoreError;
    fn try_from(r: IssuedCodeRow) -> Result<Self, StoreError> {
        Ok(Self {
            code: r.code,
            client_id: r.client_id,
            redirect_uri: r.redirect_uri,
            code_challenge: r.code_challenge,
            scopes: json_to_str_vec(r.scopes),
            sub: r.sub,
            email: r.email,
            groups: json_to_str_vec(r.groups),
            upstream_tokens_ciphertext: r.upstream_tokens_ciphertext,
            expires_at: r.expires_at,
            tenant_id: r.tenant_id,
        })
    }
}

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    token: String,
    sub: String,
    email: Option<String>,
    groups: JsonValue,
    scopes: JsonValue,
    client_id: String,
    rotated_from: Option<String>,
    #[allow(dead_code)]
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    tenant_id: String,
}

impl TryFrom<RefreshTokenRow> for RefreshToken {
    type Error = StoreError;
    fn try_from(r: RefreshTokenRow) -> Result<Self, StoreError> {
        Ok(Self {
            token: r.token,
            sub: r.sub,
            email: r.email,
            groups: json_to_str_vec(r.groups),
            scopes: json_to_str_vec(r.scopes),
            client_id: r.client_id,
            rotated_from: r.rotated_from,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            tenant_id: r.tenant_id,
        })
    }
}

fn json_to_str_vec(v: JsonValue) -> Vec<String> {
    match v {
        JsonValue::Array(items) => items
            .into_iter()
            .filter_map(|i| match i {
                JsonValue::String(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}
