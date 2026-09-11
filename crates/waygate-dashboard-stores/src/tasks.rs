//! MCP Tasks primitive persistence.
//!
//! Holds the durable state of long-running tool calls
//! that the MCP Tasks spec lets a server return
//! immediately for. The wire shape (polling vs. event
//! stream, result envelope, resume protocol) isn't
//! settled yet, so this crate provides only the
//! persistence substrate: a `task_states` row per task,
//! lifecycle enum, admin read API for operators. Wiring
//! `InvocationService` write-through and adding the
//! client-facing Tasks endpoints are deferred until the
//! spec stabilizes.
//!
//! ## Why this crate, not a module in `waygate-storage`
//!
//! Same shape as `waygate-quota` / `waygate-tenants` /
//! `waygate-rbac`: per-feature crate owning its own
//! trait + types + Pg impl, kept dependency-light so the
//! invocation pipeline can hold the trait by handle
//! without pulling in admin-only baggage.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

/// Lifecycle of a task. Mirrors the SQL CHECK constraint
/// in `migrations/0031_tasks.sql`. Stored as snake-case
/// TEXT; the enum lives at the typed boundary the admin
/// handler + future client API consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Created but not yet picked up by a worker.
    Pending,
    /// A worker has it and is executing.
    Running,
    /// Finished successfully; `result_url` is populated.
    Succeeded,
    /// Finished with an error; `error_message` is
    /// populated.
    Failed,
    /// Operator or principal cancelled before
    /// completion.
    Cancelled,
    /// In a state where the client must echo
    /// `resume_token` to continue (long-poll
    /// reconnect, partial result, …). The wire
    /// semantics are TBD; the column exists so the
    /// future protocol slice doesn't need a schema
    /// rev.
    Resumable,
}

impl TaskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Resumable => "resumable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "running" => Some(Self::Running),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            "resumable" => Some(Self::Resumable),
            _ => None,
        }
    }

    /// Terminal statuses: `succeeded` / `failed` /
    /// `cancelled`. A task in any of these is done;
    /// callers should never see another state
    /// transition.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

/// Full read-side view of a `task_states` row.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Task {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_sub: String,
    pub tool_id: Uuid,
    pub arguments_hash: String,
    pub status: TaskStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
    pub result_url: Option<String>,
    pub resume_token: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug)]
pub struct NewTask<'a> {
    pub tenant_id: &'a str,
    pub principal_sub: &'a str,
    pub tool_id: Uuid,
    pub arguments_hash: &'a str,
    /// Initial status — typically `Pending`. Direct-
    /// completion paths (a tool that returned the
    /// result synchronously but the gateway is
    /// persisting it anyway for audit) could insert
    /// `Succeeded` straight away.
    pub status: TaskStatus,
}

#[derive(Debug)]
pub struct TaskStatusUpdate<'a> {
    pub status: TaskStatus,
    pub result_url: Option<&'a str>,
    pub resume_token: Option<&'a str>,
    pub error_message: Option<&'a str>,
    /// When `Some`, written to `completed_at`. The
    /// caller controls this so a worker can stamp the
    /// real completion time (vs. the trigger's `now()`
    /// on `updated_at`).
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    #[error("task store: {0}")]
    Database(#[source] sqlx::Error),
}

/// Hard ceiling on `TaskStore::list` page size; mirrors
/// the rest of the admin stores (`oauth_consent`,
/// `upstream_sessions`, `break_glass_tokens`).
pub use waygate_core::page::MAX_LIST_LIMIT;

#[async_trait]
pub trait TaskStore: Send + Sync + 'static {
    /// Insert a new task row. Returns the created row so
    /// the caller can read the surrogate id + the
    /// trigger-stamped `created_at` / `updated_at`.
    async fn insert(&self, task: NewTask<'_>) -> Result<Task, TaskError>;

    /// Single fetch by id, tenant-scoped — a task is
    /// visible to its tenant only. `Ok(None)` covers
    /// both "no such id" and "exists but wrong tenant"
    /// — the caller can't distinguish (which is
    /// deliberate; leaking existence across tenants
    /// would be an info-disclosure regression).
    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<Task>, TaskError>;

    /// Paginated list. Filters:
    /// - `principal_sub: Some(_)` scopes to one user.
    /// - `status: Some(_)` filters to that status.
    /// Both optional and ANDed. Ordered by
    /// `created_at DESC` so the newest tasks land
    /// first; stable for pagination.
    async fn list(
        &self,
        tenant_id: &str,
        filter: TaskListFilter<'_>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Task>, TaskError>;

    /// Update lifecycle + result fields on a task.
    /// Returns `Ok(Some(_))` with the post-update row
    /// when the task existed in the caller's tenant;
    /// `Ok(None)` when it didn't (same not-found vs.
    /// wrong-tenant collapsing as `get`).
    ///
    /// **The store does NOT enforce transitions** —
    /// "can `failed` go back to `pending`?" is a
    /// caller-policy concern. A future `transition_to`
    /// method may bake the matrix in; for now the
    /// persistence layer stays transition-agnostic.
    async fn update_status(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: TaskStatusUpdate<'_>,
    ) -> Result<Option<Task>, TaskError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TaskListFilter<'a> {
    pub principal_sub: Option<&'a str>,
    pub status: Option<TaskStatus>,
}

pub type SharedTaskStore = Arc<dyn TaskStore>;

#[derive(Clone)]
pub struct PgTaskStore {
    pool: PgPool,
}

impl PgTaskStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TaskStore for PgTaskStore {
    async fn insert(&self, task: NewTask<'_>) -> Result<Task, TaskError> {
        let row = sqlx::query(
            r#"
            INSERT INTO task_states
                (tenant_id, principal_sub, tool_id, arguments_hash, status)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, tenant_id, principal_sub, tool_id, arguments_hash,
                      status, created_at, updated_at, completed_at,
                      result_url, resume_token, error_message
            "#,
        )
        .bind(task.tenant_id)
        .bind(task.principal_sub)
        .bind(task.tool_id)
        .bind(task.arguments_hash)
        .bind(task.status.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(TaskError::Database)?;
        Ok(row_to_task(&row))
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<Task>, TaskError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, principal_sub, tool_id, arguments_hash,
                   status, created_at, updated_at, completed_at,
                   result_url, resume_token, error_message
              FROM task_states
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(TaskError::Database)?;
        Ok(row.as_ref().map(row_to_task))
    }

    async fn list(
        &self,
        tenant_id: &str,
        filter: TaskListFilter<'_>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Task>, TaskError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let offset_i = offset as i64;
        // Two optional filters — chain them in SQL with
        // `($N IS NULL OR <col> = $N)` guards so the
        // query plan stays stable (one prepared
        // statement instead of four variants). The
        // index `task_states_by_principal` covers the
        // common "show this user's tasks" path.
        let status_str = filter.status.map(|s| s.as_str().to_owned());
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, principal_sub, tool_id, arguments_hash,
                   status, created_at, updated_at, completed_at,
                   result_url, resume_token, error_message
              FROM task_states
             WHERE tenant_id = $1
               AND ($2::text IS NULL OR principal_sub = $2)
               AND ($3::text IS NULL OR status        = $3)
             ORDER BY created_at DESC, id
             LIMIT $4 OFFSET $5
            "#,
        )
        .bind(tenant_id)
        .bind(filter.principal_sub)
        .bind(status_str.as_deref())
        .bind(effective_limit)
        .bind(offset_i)
        .fetch_all(&self.pool)
        .await
        .map_err(TaskError::Database)?;
        Ok(rows.iter().map(row_to_task).collect())
    }

    async fn update_status(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: TaskStatusUpdate<'_>,
    ) -> Result<Option<Task>, TaskError> {
        // COALESCE keeps existing values on Option::None
        // (caller passes None to mean "leave alone").
        // `updated_at` is auto-bumped by the trigger so
        // it's deliberately NOT in the SET list.
        let row = sqlx::query(
            r#"
            UPDATE task_states
               SET status        = $3,
                   result_url    = COALESCE($4, result_url),
                   resume_token  = COALESCE($5, resume_token),
                   error_message = COALESCE($6, error_message),
                   completed_at  = COALESCE($7, completed_at)
             WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, principal_sub, tool_id, arguments_hash,
                      status, created_at, updated_at, completed_at,
                      result_url, resume_token, error_message
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(update.status.as_str())
        .bind(update.result_url)
        .bind(update.resume_token)
        .bind(update.error_message)
        .bind(update.completed_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(TaskError::Database)?;
        Ok(row.as_ref().map(row_to_task))
    }
}

fn row_to_task(row: &PgRow) -> Task {
    let status_str: String = row.get("status");
    // The DB CHECK constraint means status is always
    // one of the canonical values; falling back to
    // Pending on parse miss is purely defensive (an
    // operator who poked the row by hand bypassing
    // CHECK is the only path that'd hit this).
    let status = TaskStatus::parse(&status_str).unwrap_or(TaskStatus::Pending);
    Task {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        principal_sub: row.get("principal_sub"),
        tool_id: row.get("tool_id"),
        arguments_hash: row.get("arguments_hash"),
        status,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        completed_at: row.get("completed_at"),
        result_url: row.get("result_url"),
        resume_token: row.get("resume_token"),
        error_message: row.get("error_message"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_status_roundtrips_through_as_str_parse() {
        for s in [
            TaskStatus::Pending,
            TaskStatus::Running,
            TaskStatus::Succeeded,
            TaskStatus::Failed,
            TaskStatus::Cancelled,
            TaskStatus::Resumable,
        ] {
            assert_eq!(TaskStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(TaskStatus::parse("nope"), None);
    }

    #[test]
    fn task_status_is_terminal_matrix() {
        assert!(!TaskStatus::Pending.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());
        assert!(!TaskStatus::Resumable.is_terminal());
        assert!(TaskStatus::Succeeded.is_terminal());
        assert!(TaskStatus::Failed.is_terminal());
        assert!(TaskStatus::Cancelled.is_terminal());
    }
}
