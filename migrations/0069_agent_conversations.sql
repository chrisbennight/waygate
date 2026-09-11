-- Gateway-Agents PR 1.1: durable chat-agent conversations.
--
-- Server-owned conversation history for the in-app chat agent: a list of the
-- operator's past conversations plus each conversation's message transcript.
-- The existing /chat tester keeps its transcript client-side only; the chat
-- *product* (PR 1.2+) persists here so an operator can revisit prior sessions
-- and so a turn's transcript survives the request.
--
-- ## Content boundary (deliberate)
--
-- Unlike `audit_log` (content-free by invariant I9), conversations are
-- inherently CONTENT-BEARING: they store the operator's prompts, the agent's
-- replies, and tool observations. That is the nature of a chat product. Rows
-- are scoped to their OWNER (`tenant_id` + `user_sub`) — a user only ever sees
-- their own conversations; the store enforces this on every read/write.
--
-- ## Shape
--
-- - `agent_conversations`: one row per conversation. `user_sub` is the owning
--   operator (the security scope, alongside `tenant_id`); `agent_name` records
--   which agent config drove it; `title` is an operator-facing label.
-- - `agent_conversation_messages`: one row per message. `seq` is a global
--   BIGSERIAL giving a stable total order (messages for a conversation are read
--   `ORDER BY seq`); `role` is system|user|assistant|tool; `content` is the
--   serialized message content (`Vec<ContentPart>`) as opaque JSONB so the
--   storage layer stays decoupled from the canonical LLM types.
-- - `tenant_id` is plain TEXT (no FK to `tenants`), matching the sibling
--   per-tenant stores `llm_models` (0047) and `agent_configs` (0067). Messages
--   FK their conversation `ON DELETE CASCADE` so deleting a conversation takes
--   its transcript with it.
--
-- ## Indexes
--
-- - `(tenant_id, user_sub, updated_at DESC)` for the owner's "recent
--   conversations" list.
-- - `(conversation_id, seq)` for loading one conversation's transcript in order.

CREATE TABLE agent_conversations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    user_sub    TEXT NOT NULL,
    agent_name  TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX agent_conversations_by_owner
    ON agent_conversations (tenant_id, user_sub, updated_at DESC);

CREATE TABLE agent_conversation_messages (
    seq             BIGSERIAL PRIMARY KEY,
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES agent_conversations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,
    content         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX agent_conversation_messages_by_conv
    ON agent_conversation_messages (conversation_id, seq);

-- updated_at auto-bump on conversation UPDATE (e.g. retitle); appends also bump
-- it from the store so the recent-list sorts by last activity.
CREATE OR REPLACE FUNCTION agent_conversations_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_conversations_touch_updated_at_trg
    BEFORE UPDATE ON agent_conversations
    FOR EACH ROW
    EXECUTE FUNCTION agent_conversations_touch_updated_at();

-- Appending a message bumps the parent conversation's activity time atomically
-- (so the store needs no second, fail-able UPDATE and the recent-list reorders
-- by last activity). The BEFORE-UPDATE touch trigger above then refreshes
-- updated_at on this UPDATE too — harmless and consistent.
CREATE OR REPLACE FUNCTION agent_conversations_bump_on_message() RETURNS TRIGGER AS $$
BEGIN
    UPDATE agent_conversations SET updated_at = now() WHERE id = NEW.conversation_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_conversation_messages_bump_parent_trg
    AFTER INSERT ON agent_conversation_messages
    FOR EACH ROW
    EXECUTE FUNCTION agent_conversations_bump_on_message();
