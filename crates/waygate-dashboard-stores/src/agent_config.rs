//! Per-tenant agent configuration storage.
//!
//! Owns the `agent_configs` table (migration 0067) — the operator-authored
//! definitions of the in-app LLM agents: the interactive chat agent, the
//! policy-review task agent, and the classification-audit task agent. One
//! row per `(tenant, name)` agent.
//!
//! ## Why this crate
//!
//! Same shape as `inspection_rules` / `tasks`: a per-feature
//! crate owning its own trait + types + Pg impl, kept dependency-light so
//! the agent *runtime* (the bounded LLM ↔ tool loop) can hold the store by
//! handle to read a tenant's enabled agent config without pulling in
//! admin-only baggage.
//!
//! ## What this crate provides
//!
//! Storage + trait + Pg + in-memory impls. Nothing here *runs* an agent —
//! rows are config that the runtime loop and the chat handler read. The
//! admin dashboard "Gateway Agents" tab and approved governed-change
//! executors are the writers.
//!
//! ## Security-relevant fields
//!
//! - `allowed_tools` is the agent's tool allowlist. It is **empty by default**
//!   (`[]`): an agent can call no tool until an operator opts tools in. The
//!   runtime enforces it by narrowing the acting principal's
//!   `api_key_profile_restrictions` to this set, so the existing invocation
//!   pipeline denies any non-allowlisted call with no new gate logic.
//! - `enabled` defaults to **false**: a freshly-created agent is inert until an
//!   operator turns it on.
//! - `max_steps` / `max_tool_calls` / `token_budget` bound the loop so a
//!   runaway agent can't spin or burn budget without limit.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

/// The role of an agent. Closed enum so a typo at insert time fails fast;
/// mirrors the SQL CHECK constraint in `migrations/0067_agent_configs.sql`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// Interactive chat agent.
    Chat,
    /// Policy-review task agent.
    PolicyReview,
    /// Classification-audit task agent.
    Classification,
}

impl AgentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::PolicyReview => "policy_review",
            Self::Classification => "classification",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "chat" => Some(Self::Chat),
            "policy_review" => Some(Self::PolicyReview),
            "classification" => Some(Self::Classification),
            _ => None,
        }
    }

    /// Every kind, in declaration order — for rendering a `<select>`.
    pub fn all() -> &'static [AgentKind] {
        &[Self::Chat, Self::PolicyReview, Self::Classification]
    }
}

/// Full read-side view of an `agent_configs` row.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AgentConfig {
    pub id: Uuid,
    pub tenant_id: String,
    /// Operator-friendly label; unique within the tenant.
    pub name: String,
    pub kind: AgentKind,
    /// The `llm_models` alias this agent dispatches its reasoning to. A SOFT
    /// reference (not a DB FK): a discovered model can come and go, so the
    /// alias is validated at agent run time, not at config time.
    pub model_alias: String,
    /// Operator system-prompt addendum appended to the agent's base prompt.
    pub instructions: Option<String>,
    /// The agent's tool allowlist (fully-qualified tool ids, e.g.
    /// `gateway-observe.query_audit`, `<server>.<tool>`). Empty ⇒ the agent
    /// can call nothing.
    pub allowed_tools: Vec<String>,
    /// Max reasoning turns before the loop stops (bounds a runaway agent).
    pub max_steps: i32,
    /// Max tool calls before the loop stops.
    pub max_tool_calls: i32,
    /// Optional token budget per run; `None` ⇒ no per-run token cap (other
    /// budgets still apply).
    pub token_budget: Option<i32>,
    /// `false` ⇒ the agent is inert (not offered / not runnable).
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// The mutable field set for an insert or a full-replace update. `tenant_id`
/// and `id` are passed separately (tenant comes from the principal, never the
/// request body; id is the path for an update).
#[derive(Debug, Clone)]
pub struct AgentConfigFields<'a> {
    pub name: &'a str,
    pub kind: AgentKind,
    pub model_alias: &'a str,
    pub instructions: Option<&'a str>,
    pub allowed_tools: &'a [String],
    pub max_steps: i32,
    pub max_tool_calls: i32,
    pub token_budget: Option<i32>,
    pub enabled: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentConfigError {
    #[error("agent config store: {0}")]
    Database(#[source] sqlx::Error),
    #[error("an agent with the same (tenant, name) already exists")]
    DuplicateName,
}

/// Hard ceiling on `list` page size — mirrors the other admin stores.
pub use waygate_core::page::MAX_LIST_LIMIT;

#[async_trait]
pub trait AgentConfigStore: Send + Sync + 'static {
    /// Insert a new agent config. `AgentConfigError::DuplicateName` on the
    /// `(tenant, name)` UNIQUE collision.
    async fn insert(
        &self,
        tenant_id: &str,
        fields: AgentConfigFields<'_>,
    ) -> Result<AgentConfig, AgentConfigError>;

    /// Single fetch by id, tenant-scoped. `Ok(None)` collapses
    /// "no such id" and "exists but wrong tenant" (no cross-tenant existence
    /// disclosure), same posture as the other admin stores.
    async fn get(&self, tenant_id: &str, id: Uuid)
        -> Result<Option<AgentConfig>, AgentConfigError>;

    /// Paginated list for a tenant, ordered by `name`.
    async fn list(
        &self,
        tenant_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AgentConfig>, AgentConfigError>;

    /// Full-replace update of every mutable field. Returns `Ok(Some(_))` with
    /// the post-update row when the agent existed in the tenant; `Ok(None)`
    /// when it didn't. Full-replace (not partial) so nullable fields
    /// (`instructions`, `token_budget`) can be cleared by omitting them in the
    /// edit form.
    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        fields: AgentConfigFields<'_>,
    ) -> Result<Option<AgentConfig>, AgentConfigError>;

    /// Full-replace update only when the row still has the version captured by
    /// the caller. `Ok(None)` covers missing, cross-tenant, and stale rows so a
    /// reviewed stale replacement cannot overwrite a newer configuration.
    async fn update_if_updated_at_matches(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: OffsetDateTime,
        fields: AgentConfigFields<'_>,
    ) -> Result<Option<AgentConfig>, AgentConfigError>;

    /// Hard delete. `Ok(true)` when removed; `Ok(false)` on
    /// no-such-id-or-wrong-tenant.
    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, AgentConfigError>;

    /// Hard delete only when the row still has the captured version.
    /// `Ok(false)` covers missing, cross-tenant, and stale rows.
    async fn delete_if_updated_at_matches(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: OffsetDateTime,
    ) -> Result<bool, AgentConfigError>;
}

pub type SharedAgentConfigStore = Arc<dyn AgentConfigStore>;

// --- Postgres impl ----------------------------------------------------------

#[derive(Clone)]
pub struct PgAgentConfigStore {
    pool: PgPool,
}

impl PgAgentConfigStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn update_inner(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: Option<OffsetDateTime>,
        fields: AgentConfigFields<'_>,
    ) -> Result<Option<AgentConfig>, AgentConfigError> {
        let tools = tools_to_json(fields.allowed_tools);
        // One statement owns both direct and guarded updates. A NULL expected
        // version is the direct-admin path; a present version makes the write
        // conditional and closes the final validation-to-write race.
        let row = sqlx::query(
            r#"
            UPDATE agent_configs
               SET name           = $3,
                   kind           = $4,
                   model_alias    = $5,
                   instructions   = $6,
                   allowed_tools  = $7,
                   max_steps      = $8,
                   max_tool_calls = $9,
                   token_budget   = $10,
                   enabled        = $11
             WHERE tenant_id = $1 AND id = $2
               AND ($12::timestamptz IS NULL OR updated_at = $12)
            RETURNING id, tenant_id, name, kind, model_alias, instructions,
                      allowed_tools, max_steps, max_tool_calls, token_budget,
                      enabled, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(fields.name)
        .bind(fields.kind.as_str())
        .bind(fields.model_alias)
        .bind(fields.instructions)
        .bind(&tools)
        .bind(fields.max_steps)
        .bind(fields.max_tool_calls)
        .bind(fields.token_budget)
        .bind(fields.enabled)
        .bind(expected_updated_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_write_err)?;
        Ok(row.as_ref().map(row_to_config))
    }

    async fn delete_inner(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: Option<OffsetDateTime>,
    ) -> Result<bool, AgentConfigError> {
        let res = sqlx::query(
            r#"
            DELETE FROM agent_configs
             WHERE tenant_id = $1 AND id = $2
               AND ($3::timestamptz IS NULL OR updated_at = $3)
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .map_err(AgentConfigError::Database)?;
        Ok(res.rows_affected() > 0)
    }
}

#[async_trait]
impl AgentConfigStore for PgAgentConfigStore {
    async fn insert(
        &self,
        tenant_id: &str,
        fields: AgentConfigFields<'_>,
    ) -> Result<AgentConfig, AgentConfigError> {
        let tools = tools_to_json(fields.allowed_tools);
        let row = sqlx::query(
            r#"
            INSERT INTO agent_configs
                (tenant_id, name, kind, model_alias, instructions, allowed_tools,
                 max_steps, max_tool_calls, token_budget, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, tenant_id, name, kind, model_alias, instructions,
                      allowed_tools, max_steps, max_tool_calls, token_budget,
                      enabled, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(fields.name)
        .bind(fields.kind.as_str())
        .bind(fields.model_alias)
        .bind(fields.instructions)
        .bind(&tools)
        .bind(fields.max_steps)
        .bind(fields.max_tool_calls)
        .bind(fields.token_budget)
        .bind(fields.enabled)
        .fetch_one(&self.pool)
        .await
        .map_err(map_write_err)?;
        Ok(row_to_config(&row))
    }

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<AgentConfig>, AgentConfigError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, name, kind, model_alias, instructions,
                   allowed_tools, max_steps, max_tool_calls, token_budget,
                   enabled, created_at, updated_at
              FROM agent_configs
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(AgentConfigError::Database)?;
        Ok(row.as_ref().map(row_to_config))
    }

    async fn list(
        &self,
        tenant_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AgentConfig>, AgentConfigError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, name, kind, model_alias, instructions,
                   allowed_tools, max_steps, max_tool_calls, token_budget,
                   enabled, created_at, updated_at
              FROM agent_configs
             WHERE tenant_id = $1
             ORDER BY name
             LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(effective_limit)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(AgentConfigError::Database)?;
        Ok(rows.iter().map(row_to_config).collect())
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        fields: AgentConfigFields<'_>,
    ) -> Result<Option<AgentConfig>, AgentConfigError> {
        self.update_inner(tenant_id, id, None, fields).await
    }

    async fn update_if_updated_at_matches(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: OffsetDateTime,
        fields: AgentConfigFields<'_>,
    ) -> Result<Option<AgentConfig>, AgentConfigError> {
        self.update_inner(tenant_id, id, Some(expected_updated_at), fields)
            .await
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, AgentConfigError> {
        self.delete_inner(tenant_id, id, None).await
    }

    async fn delete_if_updated_at_matches(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: OffsetDateTime,
    ) -> Result<bool, AgentConfigError> {
        self.delete_inner(tenant_id, id, Some(expected_updated_at))
            .await
    }
}

/// Map a sqlx write error into `DuplicateName` (the operator-actionable UNIQUE
/// collision, Postgres `unique_violation` 23505) or generic `Database`.
fn map_write_err(e: sqlx::Error) -> AgentConfigError {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) {
            return AgentConfigError::DuplicateName;
        }
    }
    AgentConfigError::Database(e)
}

fn tools_to_json(tools: &[String]) -> serde_json::Value {
    serde_json::Value::Array(
        tools
            .iter()
            .map(|t| serde_json::Value::String(t.clone()))
            .collect(),
    )
}

fn json_to_tools(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn row_to_config(row: &PgRow) -> AgentConfig {
    let kind_str: String = row.get("kind");
    let kind = AgentKind::parse(&kind_str).unwrap_or(AgentKind::Chat);
    let tools_json: serde_json::Value = row.get("allowed_tools");
    AgentConfig {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        name: row.get("name"),
        kind,
        model_alias: row.get("model_alias"),
        instructions: row.get("instructions"),
        allowed_tools: json_to_tools(&tools_json),
        max_steps: row.get("max_steps"),
        max_tool_calls: row.get("max_tool_calls"),
        token_budget: row.get("token_budget"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

// --- In-memory impl ---------------------------------------------------------

/// In-memory [`AgentConfigStore`] for tests and dashboard render tests that
/// want to exercise the populated branch without a Postgres pool. Not used in
/// production (`waygate-server` wires the Pg impl when a pool exists).
#[derive(Default)]
pub struct InMemoryAgentConfigStore {
    rows: std::sync::Mutex<Vec<AgentConfig>>,
}

impl InMemoryAgentConfigStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn to_config(tenant_id: &str, id: Uuid, fields: &AgentConfigFields<'_>) -> AgentConfig {
        let now = OffsetDateTime::now_utc();
        AgentConfig {
            id,
            tenant_id: tenant_id.to_owned(),
            name: fields.name.to_owned(),
            kind: fields.kind,
            model_alias: fields.model_alias.to_owned(),
            instructions: fields.instructions.map(str::to_owned),
            allowed_tools: fields.allowed_tools.to_vec(),
            max_steps: fields.max_steps,
            max_tool_calls: fields.max_tool_calls,
            token_budget: fields.token_budget,
            enabled: fields.enabled,
            created_at: now,
            updated_at: now,
        }
    }

    fn update_inner(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: Option<OffsetDateTime>,
        fields: &AgentConfigFields<'_>,
    ) -> Result<Option<AgentConfig>, AgentConfigError> {
        let mut rows = self.rows.lock().unwrap();
        let Some(index) = rows.iter().position(|r| {
            r.tenant_id == tenant_id
                && r.id == id
                && expected_updated_at
                    .map(|expected| r.updated_at == expected)
                    .unwrap_or(true)
        }) else {
            return Ok(None);
        };
        if rows
            .iter()
            .any(|r| r.tenant_id == tenant_id && r.name == fields.name && r.id != id)
        {
            return Err(AgentConfigError::DuplicateName);
        }
        let existing = &mut rows[index];
        let created_at = existing.created_at;
        let previous_updated_at = existing.updated_at;
        let mut updated = Self::to_config(tenant_id, id, fields);
        updated.created_at = created_at;
        if updated.updated_at <= previous_updated_at {
            updated.updated_at = previous_updated_at + time::Duration::microseconds(1);
        }
        *existing = updated.clone();
        Ok(Some(updated))
    }

    fn delete_inner(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: Option<OffsetDateTime>,
    ) -> bool {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| {
            let target = r.tenant_id == tenant_id
                && r.id == id
                && expected_updated_at
                    .map(|expected| r.updated_at == expected)
                    .unwrap_or(true);
            !target
        });
        rows.len() != before
    }
}

#[async_trait]
impl AgentConfigStore for InMemoryAgentConfigStore {
    async fn insert(
        &self,
        tenant_id: &str,
        fields: AgentConfigFields<'_>,
    ) -> Result<AgentConfig, AgentConfigError> {
        let mut rows = self.rows.lock().unwrap();
        if rows
            .iter()
            .any(|r| r.tenant_id == tenant_id && r.name == fields.name)
        {
            return Err(AgentConfigError::DuplicateName);
        }
        let cfg = Self::to_config(tenant_id, Uuid::new_v4(), &fields);
        rows.push(cfg.clone());
        Ok(cfg)
    }

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<AgentConfig>, AgentConfigError> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.id == id)
            .cloned())
    }

    async fn list(
        &self,
        tenant_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AgentConfig>, AgentConfigError> {
        let rows = self.rows.lock().unwrap();
        let mut out: Vec<AgentConfig> = rows
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        let effective_limit = limit.min(MAX_LIST_LIMIT) as usize;
        Ok(out
            .into_iter()
            .skip(offset as usize)
            .take(effective_limit)
            .collect())
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        fields: AgentConfigFields<'_>,
    ) -> Result<Option<AgentConfig>, AgentConfigError> {
        self.update_inner(tenant_id, id, None, &fields)
    }

    async fn update_if_updated_at_matches(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: OffsetDateTime,
        fields: AgentConfigFields<'_>,
    ) -> Result<Option<AgentConfig>, AgentConfigError> {
        self.update_inner(tenant_id, id, Some(expected_updated_at), &fields)
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, AgentConfigError> {
        Ok(self.delete_inner(tenant_id, id, None))
    }

    async fn delete_if_updated_at_matches(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: OffsetDateTime,
    ) -> Result<bool, AgentConfigError> {
        Ok(self.delete_inner(tenant_id, id, Some(expected_updated_at)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields<'a>(name: &'a str, tools: &'a [String]) -> AgentConfigFields<'a> {
        AgentConfigFields {
            name,
            kind: AgentKind::Chat,
            model_alias: "gpt-x",
            instructions: None,
            allowed_tools: tools,
            max_steps: 8,
            max_tool_calls: 16,
            token_budget: None,
            enabled: false,
        }
    }

    #[test]
    fn agent_kind_roundtrips_through_as_str_parse() {
        for k in AgentKind::all() {
            assert_eq!(AgentKind::parse(k.as_str()), Some(*k));
        }
        assert_eq!(AgentKind::parse("nope"), None);
    }

    #[test]
    fn tools_json_roundtrip() {
        let tools = vec!["a.b".to_owned(), "gateway-observe.query_audit".to_owned()];
        let v = tools_to_json(&tools);
        assert_eq!(json_to_tools(&v), tools);
        // Non-array / garbage decodes to empty rather than panicking.
        assert!(json_to_tools(&serde_json::json!({"x": 1})).is_empty());
    }

    #[tokio::test]
    async fn in_memory_crud_and_tenant_isolation() {
        let store = InMemoryAgentConfigStore::new();
        let empty: Vec<String> = vec![];
        // Insert defaults: empty allowlist, disabled.
        let a = store.insert("t1", fields("chat", &empty)).await.unwrap();
        assert!(a.allowed_tools.is_empty());
        assert!(!a.enabled);

        // Duplicate name in the same tenant rejected; same name in another
        // tenant is fine.
        assert!(matches!(
            store.insert("t1", fields("chat", &empty)).await,
            Err(AgentConfigError::DuplicateName)
        ));
        store.insert("t2", fields("chat", &empty)).await.unwrap();

        // Tenant isolation on get.
        assert!(store.get("t2", a.id).await.unwrap().is_none());
        assert!(store.get("t1", a.id).await.unwrap().is_some());

        // Full-replace update flips fields + clears nothing it shouldn't.
        let tools = vec!["gateway-observe.query_audit".to_owned()];
        let updated = store
            .update(
                "t1",
                a.id,
                AgentConfigFields {
                    enabled: true,
                    allowed_tools: &tools,
                    ..fields("chat-renamed", &tools)
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(updated.enabled);
        assert_eq!(updated.name, "chat-renamed");
        assert_eq!(updated.allowed_tools, tools);
        assert_eq!(updated.created_at, a.created_at, "created_at preserved");

        // Update of a missing row → None (not an error).
        assert!(store
            .update("t1", Uuid::new_v4(), fields("x", &empty))
            .await
            .unwrap()
            .is_none());

        // Delete is tenant-scoped + idempotent-ish.
        assert!(!store.delete("t2", a.id).await.unwrap());
        assert!(store.delete("t1", a.id).await.unwrap());
        assert!(!store.delete("t1", a.id).await.unwrap());
    }

    #[tokio::test]
    async fn in_memory_guarded_writes_refuse_stale_versions() {
        let store = InMemoryAgentConfigStore::new();
        let empty = Vec::new();
        let original = store
            .insert("t1", fields("chat", &empty))
            .await
            .expect("insert");
        let stale = original.updated_at - time::Duration::seconds(1);

        assert!(store
            .update_if_updated_at_matches(
                "t1",
                original.id,
                stale,
                fields("stale-overwrite", &empty),
            )
            .await
            .expect("stale guarded update")
            .is_none());
        assert_eq!(
            store
                .get("t1", original.id)
                .await
                .expect("get")
                .expect("present")
                .name,
            "chat",
        );

        let future_version = OffsetDateTime::now_utc() + time::Duration::hours(1);
        store
            .rows
            .lock()
            .expect("lock rows")
            .iter_mut()
            .find(|row| row.id == original.id)
            .expect("inserted row")
            .updated_at = future_version;
        let updated = store
            .update_if_updated_at_matches(
                "t1",
                original.id,
                future_version,
                fields("reviewed-update", &empty),
            )
            .await
            .expect("guarded update")
            .expect("matching version updates");
        assert_eq!(updated.name, "reviewed-update");
        assert_eq!(
            updated.updated_at,
            future_version + time::Duration::microseconds(1),
            "the in-memory witness must advance even when the wall clock is behind",
        );

        assert!(!store
            .delete_if_updated_at_matches("t1", original.id, original.updated_at)
            .await
            .expect("stale guarded delete"));
        assert!(store
            .delete_if_updated_at_matches("t1", original.id, updated.updated_at)
            .await
            .expect("matching guarded delete"));
    }

    #[tokio::test]
    async fn in_memory_update_rejects_a_same_tenant_name_collision() {
        let store = InMemoryAgentConfigStore::new();
        let empty = Vec::new();
        let target = store
            .insert("t1", fields("target", &empty))
            .await
            .expect("insert target");
        store
            .insert("t1", fields("reserved", &empty))
            .await
            .expect("insert conflicting row");

        assert!(matches!(
            store
                .update("t1", target.id, fields("reserved", &empty))
                .await,
            Err(AgentConfigError::DuplicateName)
        ));
        assert_eq!(
            store
                .get("t1", target.id)
                .await
                .expect("get target")
                .expect("target remains")
                .name,
            "target",
        );
    }
}
