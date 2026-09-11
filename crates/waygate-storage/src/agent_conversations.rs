//! Durable chat-agent conversation storage
//! (`migrations/0069_agent_conversations.sql`).
//!
//! Server-owned conversation history for the in-app chat agent — the list of
//! an operator's past conversations plus each one's message transcript. The
//! chat handler creates a conversation, appends messages as the loop
//! runs, and loads prior conversations for the history view.
//!
//! ## Owner scoping is a security boundary
//!
//! Every method takes `(tenant_id, user_sub)` and scopes to that owner: a user
//! can only ever read or mutate their OWN conversations. `get` / `messages` /
//! `append_message` / `set_title` / `delete` all collapse "no such id" and
//! "exists but not yours" so cross-user existence never leaks — the same
//! posture as `task_states` / `agent_configs`.
//!
//! ## Content-bearing (unlike audit)
//!
//! Conversations store prompts, replies, and tool observations — content, by
//! design (it's a chat). `content` is opaque JSONB (`Vec<ContentPart>`
//! serialized by the caller) so this layer stays decoupled from the canonical
//! LLM types.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

/// One conversation (the header row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub id: Uuid,
    pub tenant_id: String,
    /// Owning operator's OIDC subject — the security scope.
    pub user_sub: String,
    /// The agent config that drove this conversation.
    pub agent_name: String,
    pub title: String,
    /// The dashboard nav suffix the conversation was started from (e.g.
    /// `/policies`), set once at creation by the docked assistant; `None` for
    /// conversations created before this was recorded, or started outside a
    /// page context. Display-only — a sanitized slug, never free-form text.
    pub origin_page: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// One message in a conversation.
#[derive(Debug, Clone)]
pub struct ConversationMessage {
    /// Global monotonic order key (BIGSERIAL); messages read `ORDER BY seq`.
    pub seq: i64,
    pub id: Uuid,
    pub conversation_id: Uuid,
    /// `system` | `user` | `assistant` | `tool`.
    pub role: String,
    /// Serialized message content (`Vec<ContentPart>`), opaque to storage.
    pub content: Value,
    pub created_at: OffsetDateTime,
}

/// Insert payload for a new conversation. `tenant_id` + `user_sub` come from
/// the authenticated principal, never the request body.
#[derive(Debug, Clone)]
pub struct NewConversation<'a> {
    pub tenant_id: &'a str,
    pub user_sub: &'a str,
    pub agent_name: &'a str,
    pub title: &'a str,
    /// Originating dashboard page (sanitized nav suffix), or `None` when the
    /// conversation wasn't started from a page context. Persisted verbatim.
    pub origin_page: Option<&'a str>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    #[error("conversation store: {0}")]
    Database(#[source] sqlx::Error),
}

/// Hard ceiling on list/message page size — mirrors the other admin stores.
// Deliberate override of waygate_core::page::MAX_LIST_LIMIT (500):
// conversation rows carry full message bodies, so the cap stays tighter.
pub const MAX_LIST_LIMIT: u32 = 200;

#[async_trait]
pub trait ConversationStore: Send + Sync + 'static {
    /// Create a new (empty) conversation owned by `(tenant_id, user_sub)`.
    async fn create(&self, new: NewConversation<'_>) -> Result<Conversation, ConversationError>;

    /// The owner's conversations, newest activity first.
    async fn list(
        &self,
        tenant_id: &str,
        user_sub: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Conversation>, ConversationError>;

    /// One conversation, owner-scoped. `Ok(None)` ⇒ no such id for this owner.
    async fn get(
        &self,
        tenant_id: &str,
        user_sub: &str,
        id: Uuid,
    ) -> Result<Option<Conversation>, ConversationError>;

    /// Append a message to an owned conversation, bumping its activity time.
    /// `Ok(None)` ⇒ the conversation doesn't exist for this owner (nothing
    /// written) — never appends to someone else's conversation.
    async fn append_message(
        &self,
        tenant_id: &str,
        user_sub: &str,
        conversation_id: Uuid,
        role: &str,
        content: &Value,
    ) -> Result<Option<ConversationMessage>, ConversationError>;

    /// The transcript of an owned conversation, in order. Empty for a
    /// non-owned / missing conversation (no existence disclosure).
    async fn messages(
        &self,
        tenant_id: &str,
        user_sub: &str,
        conversation_id: Uuid,
        limit: u32,
    ) -> Result<Vec<ConversationMessage>, ConversationError>;

    /// Retitle an owned conversation. `Ok(false)` ⇒ not found for this owner.
    async fn set_title(
        &self,
        tenant_id: &str,
        user_sub: &str,
        id: Uuid,
        title: &str,
    ) -> Result<bool, ConversationError>;

    /// Delete an owned conversation (cascades its messages). `Ok(false)` ⇒ not
    /// found for this owner.
    async fn delete(
        &self,
        tenant_id: &str,
        user_sub: &str,
        id: Uuid,
    ) -> Result<bool, ConversationError>;
}

pub type SharedConversationStore = Arc<dyn ConversationStore>;

// --- Postgres impl ----------------------------------------------------------

#[derive(Clone)]
pub struct PgConversationStore {
    pool: PgPool,
}

impl PgConversationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ConversationStore for PgConversationStore {
    async fn create(&self, new: NewConversation<'_>) -> Result<Conversation, ConversationError> {
        let row = sqlx::query(
            r#"
            INSERT INTO agent_conversations (tenant_id, user_sub, agent_name, title, origin_page)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, tenant_id, user_sub, agent_name, title, origin_page, created_at, updated_at
            "#,
        )
        .bind(new.tenant_id)
        .bind(new.user_sub)
        .bind(new.agent_name)
        .bind(new.title)
        .bind(new.origin_page)
        .fetch_one(&self.pool)
        .await
        .map_err(ConversationError::Database)?;
        Ok(row_to_conversation(&row))
    }

    async fn list(
        &self,
        tenant_id: &str,
        user_sub: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Conversation>, ConversationError> {
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, user_sub, agent_name, title, origin_page, created_at, updated_at
              FROM agent_conversations
             WHERE tenant_id = $1 AND user_sub = $2
             ORDER BY updated_at DESC, id
             LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(user_sub)
        .bind(limit.min(MAX_LIST_LIMIT) as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(ConversationError::Database)?;
        Ok(rows.iter().map(row_to_conversation).collect())
    }

    async fn get(
        &self,
        tenant_id: &str,
        user_sub: &str,
        id: Uuid,
    ) -> Result<Option<Conversation>, ConversationError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, user_sub, agent_name, title, origin_page, created_at, updated_at
              FROM agent_conversations
             WHERE tenant_id = $1 AND user_sub = $2 AND id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_sub)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(ConversationError::Database)?;
        Ok(row.as_ref().map(row_to_conversation))
    }

    async fn append_message(
        &self,
        tenant_id: &str,
        user_sub: &str,
        conversation_id: Uuid,
        role: &str,
        content: &Value,
    ) -> Result<Option<ConversationMessage>, ConversationError> {
        // INSERT only if the conversation is owned by this (tenant, user) — the
        // WHERE EXISTS makes "append to someone else's conversation" a no-op
        // that returns no row rather than writing.
        let row = sqlx::query(
            r#"
            INSERT INTO agent_conversation_messages (conversation_id, role, content)
            SELECT $3, $4, $5
             WHERE EXISTS (
                SELECT 1 FROM agent_conversations
                 WHERE id = $3 AND tenant_id = $1 AND user_sub = $2
             )
            RETURNING seq, id, conversation_id, role, content, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(user_sub)
        .bind(conversation_id)
        .bind(role)
        .bind(content)
        .fetch_optional(&self.pool)
        .await
        .map_err(ConversationError::Database)?;
        // The conversation's `updated_at` is bumped atomically by the
        // `AFTER INSERT` trigger on agent_conversation_messages (migration
        // 0069), so the recent-list reorders without a second, fail-able write.
        Ok(row.as_ref().map(row_to_message))
    }

    async fn messages(
        &self,
        tenant_id: &str,
        user_sub: &str,
        conversation_id: Uuid,
        limit: u32,
    ) -> Result<Vec<ConversationMessage>, ConversationError> {
        let rows = sqlx::query(
            r#"
            SELECT m.seq, m.id, m.conversation_id, m.role, m.content, m.created_at
              FROM agent_conversation_messages m
              JOIN agent_conversations c ON c.id = m.conversation_id
             WHERE m.conversation_id = $3 AND c.tenant_id = $1 AND c.user_sub = $2
             ORDER BY m.seq ASC
             LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(user_sub)
        .bind(conversation_id)
        .bind(limit.clamp(1, MAX_LIST_LIMIT) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(ConversationError::Database)?;
        Ok(rows.iter().map(row_to_message).collect())
    }

    async fn set_title(
        &self,
        tenant_id: &str,
        user_sub: &str,
        id: Uuid,
        title: &str,
    ) -> Result<bool, ConversationError> {
        let res = sqlx::query(
            r#"
            UPDATE agent_conversations SET title = $4
             WHERE id = $3 AND tenant_id = $1 AND user_sub = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_sub)
        .bind(id)
        .bind(title)
        .execute(&self.pool)
        .await
        .map_err(ConversationError::Database)?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete(
        &self,
        tenant_id: &str,
        user_sub: &str,
        id: Uuid,
    ) -> Result<bool, ConversationError> {
        let res = sqlx::query(
            r#"
            DELETE FROM agent_conversations
             WHERE id = $3 AND tenant_id = $1 AND user_sub = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_sub)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(ConversationError::Database)?;
        Ok(res.rows_affected() > 0)
    }
}

fn row_to_conversation(row: &PgRow) -> Conversation {
    Conversation {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        user_sub: row.get("user_sub"),
        agent_name: row.get("agent_name"),
        title: row.get("title"),
        origin_page: row.get("origin_page"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn row_to_message(row: &PgRow) -> ConversationMessage {
    ConversationMessage {
        seq: row.get("seq"),
        id: row.get("id"),
        conversation_id: row.get("conversation_id"),
        role: row.get("role"),
        content: row.get("content"),
        created_at: row.get("created_at"),
    }
}

// --- In-memory impl ---------------------------------------------------------

/// In-memory [`ConversationStore`] for tests + dashboard render tests. Not used
/// in production (`waygate-server` wires the Pg impl when a pool exists).
#[derive(Default)]
pub struct InMemoryConversationStore {
    inner: std::sync::Mutex<InMemoryState>,
}

#[derive(Default)]
struct InMemoryState {
    conversations: Vec<Conversation>,
    messages: Vec<ConversationMessage>,
    next_seq: i64,
}

impl InMemoryConversationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ConversationStore for InMemoryConversationStore {
    async fn create(&self, new: NewConversation<'_>) -> Result<Conversation, ConversationError> {
        let now = OffsetDateTime::now_utc();
        let c = Conversation {
            id: Uuid::new_v4(),
            tenant_id: new.tenant_id.to_owned(),
            user_sub: new.user_sub.to_owned(),
            agent_name: new.agent_name.to_owned(),
            title: new.title.to_owned(),
            origin_page: new.origin_page.map(str::to_owned),
            created_at: now,
            updated_at: now,
        };
        self.inner.lock().unwrap().conversations.push(c.clone());
        Ok(c)
    }

    async fn list(
        &self,
        tenant_id: &str,
        user_sub: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Conversation>, ConversationError> {
        let st = self.inner.lock().unwrap();
        let mut out: Vec<Conversation> = st
            .conversations
            .iter()
            .filter(|c| c.tenant_id == tenant_id && c.user_sub == user_sub)
            .cloned()
            .collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.updated_at));
        Ok(out
            .into_iter()
            .skip(offset as usize)
            .take(limit.min(MAX_LIST_LIMIT) as usize)
            .collect())
    }

    async fn get(
        &self,
        tenant_id: &str,
        user_sub: &str,
        id: Uuid,
    ) -> Result<Option<Conversation>, ConversationError> {
        let st = self.inner.lock().unwrap();
        Ok(st
            .conversations
            .iter()
            .find(|c| c.id == id && c.tenant_id == tenant_id && c.user_sub == user_sub)
            .cloned())
    }

    async fn append_message(
        &self,
        tenant_id: &str,
        user_sub: &str,
        conversation_id: Uuid,
        role: &str,
        content: &Value,
    ) -> Result<Option<ConversationMessage>, ConversationError> {
        let mut st = self.inner.lock().unwrap();
        let owned = st
            .conversations
            .iter()
            .any(|c| c.id == conversation_id && c.tenant_id == tenant_id && c.user_sub == user_sub);
        if !owned {
            return Ok(None);
        }
        st.next_seq += 1;
        let msg = ConversationMessage {
            seq: st.next_seq,
            id: Uuid::new_v4(),
            conversation_id,
            role: role.to_owned(),
            content: content.clone(),
            created_at: OffsetDateTime::now_utc(),
        };
        st.messages.push(msg.clone());
        if let Some(c) = st
            .conversations
            .iter_mut()
            .find(|c| c.id == conversation_id)
        {
            c.updated_at = OffsetDateTime::now_utc();
        }
        Ok(Some(msg))
    }

    async fn messages(
        &self,
        tenant_id: &str,
        user_sub: &str,
        conversation_id: Uuid,
        limit: u32,
    ) -> Result<Vec<ConversationMessage>, ConversationError> {
        let st = self.inner.lock().unwrap();
        let owned = st
            .conversations
            .iter()
            .any(|c| c.id == conversation_id && c.tenant_id == tenant_id && c.user_sub == user_sub);
        if !owned {
            return Ok(Vec::new());
        }
        let mut out: Vec<ConversationMessage> = st
            .messages
            .iter()
            .filter(|m| m.conversation_id == conversation_id)
            .cloned()
            .collect();
        out.sort_by_key(|m| m.seq);
        out.truncate(limit.clamp(1, MAX_LIST_LIMIT) as usize);
        Ok(out)
    }

    async fn set_title(
        &self,
        tenant_id: &str,
        user_sub: &str,
        id: Uuid,
        title: &str,
    ) -> Result<bool, ConversationError> {
        let mut st = self.inner.lock().unwrap();
        if let Some(c) = st
            .conversations
            .iter_mut()
            .find(|c| c.id == id && c.tenant_id == tenant_id && c.user_sub == user_sub)
        {
            c.title = title.to_owned();
            c.updated_at = OffsetDateTime::now_utc();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn delete(
        &self,
        tenant_id: &str,
        user_sub: &str,
        id: Uuid,
    ) -> Result<bool, ConversationError> {
        let mut st = self.inner.lock().unwrap();
        let before = st.conversations.len();
        st.conversations
            .retain(|c| !(c.id == id && c.tenant_id == tenant_id && c.user_sub == user_sub));
        let removed = st.conversations.len() != before;
        if removed {
            st.messages.retain(|m| m.conversation_id != id);
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn newc(user: &str) -> NewConversation<'_> {
        NewConversation {
            tenant_id: "default",
            user_sub: user,
            agent_name: "ops-chat",
            title: "first",
            origin_page: None,
        }
    }

    #[tokio::test]
    async fn in_memory_crud_and_owner_isolation() {
        let store = InMemoryConversationStore::new();
        let c = store.create(newc("alice")).await.unwrap();

        // Append messages; ordered by seq.
        store
            .append_message(
                "default",
                "alice",
                c.id,
                "user",
                &serde_json::json!([{"type":"text","text":"hi"}]),
            )
            .await
            .unwrap()
            .expect("appended");
        store
            .append_message(
                "default",
                "alice",
                c.id,
                "assistant",
                &serde_json::json!([{"type":"text","text":"hello"}]),
            )
            .await
            .unwrap()
            .expect("appended");
        let msgs = store.messages("default", "alice", c.id, 100).await.unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[1].role, "assistant");
        assert!(msgs[0].seq < msgs[1].seq, "messages ordered by seq");

        // Owner isolation: bob can't see, append to, retitle, or delete alice's.
        assert!(store.get("default", "bob", c.id).await.unwrap().is_none());
        assert!(store
            .append_message("default", "bob", c.id, "user", &serde_json::json!([]))
            .await
            .unwrap()
            .is_none());
        assert!(store
            .messages("default", "bob", c.id, 100)
            .await
            .unwrap()
            .is_empty());
        assert!(!store
            .set_title("default", "bob", c.id, "hacked")
            .await
            .unwrap());
        assert!(!store.delete("default", "bob", c.id).await.unwrap());

        // Owner can list + retitle + delete (cascading messages).
        let list = store.list("default", "alice", 100, 0).await.unwrap();
        assert_eq!(list.len(), 1);
        assert!(store
            .set_title("default", "alice", c.id, "renamed")
            .await
            .unwrap());
        assert_eq!(
            store
                .get("default", "alice", c.id)
                .await
                .unwrap()
                .unwrap()
                .title,
            "renamed"
        );
        assert!(store.delete("default", "alice", c.id).await.unwrap());
        assert!(store
            .messages("default", "alice", c.id, 100)
            .await
            .unwrap()
            .is_empty());
        assert!(!store.delete("default", "alice", c.id).await.unwrap());
    }

    #[tokio::test]
    async fn origin_page_is_persisted_on_create_and_read_back() {
        let store = InMemoryConversationStore::new();
        // Started from a page → origin recorded and surfaced on get + list.
        let from_page = store
            .create(NewConversation {
                origin_page: Some("/policies"),
                ..newc("alice")
            })
            .await
            .unwrap();
        assert_eq!(from_page.origin_page.as_deref(), Some("/policies"));
        assert_eq!(
            store
                .get("default", "alice", from_page.id)
                .await
                .unwrap()
                .unwrap()
                .origin_page
                .as_deref(),
            Some("/policies"),
        );
        assert_eq!(
            store.list("default", "alice", 100, 0).await.unwrap()[0]
                .origin_page
                .as_deref(),
            Some("/policies"),
        );
        // No page context → NULL/None, the pre-existing behaviour.
        let no_page = store.create(newc("alice")).await.unwrap();
        assert_eq!(no_page.origin_page, None);
    }
}
