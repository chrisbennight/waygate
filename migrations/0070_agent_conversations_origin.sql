-- Contextual Assistant (PR 8): record the dashboard page a conversation began on.
--
-- The docked assistant panel is available on every admin page and sends the page
-- it's open on with each turn (the `page` field, sanitized server-side). When a
-- NEW conversation is created we now persist that originating page as a stable
-- nav suffix (e.g. `/policies`, `/servers`) so the recent-conversations list can
-- show where a thread began and a future "resume where I was" can deep-link back.
--
-- Additive + nullable by design:
--   - Existing rows (created before this column) keep NULL — there is no
--     originating page to backfill, and NULL reads as "unknown / not recorded".
--   - Only set on CREATE; a resumed conversation keeps its original origin.
--   - Stores the sanitized nav suffix only (the same `[A-Za-z0-9/_-]`,
--     length-capped slug the assistant grounds on), never free-form client text.
--   - No index: it is a display attribute on rows already fetched by the
--     owner-scoped list / get, never a query predicate.

ALTER TABLE agent_conversations ADD COLUMN origin_page TEXT;
