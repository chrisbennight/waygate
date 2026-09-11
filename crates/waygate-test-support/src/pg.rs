//! The live-Postgres test preamble, extracted from ~40 per-file copies.
//!
//! Contract (unchanged from the copies): when `env_var` is unset the suite
//! **skips** — a DB-less `cargo test` passes as "not run", never as
//! "passed". CI provisions the prod-pinned Postgres and exports both URLs
//! (`AUDIT_DATABASE_URL`, `GATEWAY_AS_DATABASE_URL`), so the suites run
//! there; see AGENTS.md "Testing conventions".

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Connect to the live test database named by `env_var`, apply the
/// workspace migrations, and return the pool — or `None` (with a skip
/// notice on stderr) when the variable is unset.
///
/// Panics on a *set-but-unreachable* URL or a failed migration: those are
/// broken-environment states, not skip conditions, and passing silently
/// would report green for suites that exercised nothing.
pub async fn pool_or_skip(env_var: &str) -> Option<PgPool> {
    let Ok(url) = std::env::var(env_var) else {
        eprintln!("skipping: {env_var} not set (live-Postgres suite)");
        return None;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap_or_else(|e| panic!("connect to {env_var}: {e}"));
    // Embedded once here instead of once per test crate; the path is
    // relative to this crate's manifest and resolves to the workspace's
    // single `migrations/` set.
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    Some(pool)
}

/// [`pool_or_skip`] against `AUDIT_DATABASE_URL` — the variable most of
/// the workspace's `*_pg` suites key on.
pub async fn audit_pool_or_skip() -> Option<PgPool> {
    pool_or_skip("AUDIT_DATABASE_URL").await
}

/// Register a unique tenant for tests whose records follow tenant deletion.
pub async fn create_tenant(pool: &PgPool) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, display_name, status) VALUES ($1, 'Test tenant', 'active')",
    )
    .bind(&id)
    .execute(pool)
    .await
    .expect("create isolated test tenant");
    id
}
