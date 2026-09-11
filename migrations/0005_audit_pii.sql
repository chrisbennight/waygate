-- Add the `pii` column to audit_log so every recorded tool-call event
-- carries the operator-declared PII flag at the time of the call.
--
-- Background: the manifest schema has always carried a `pii: bool` field
-- per tool (`ToolClassification.pii` in `crates/gateway-upstream/src/lib.rs`),
-- but the field was previously collected and dropped on the runtime
-- floor. Phase-0 slice 4 propagates `pii` end-to-end:
--   1. `ToolFacts` carries it from the pool's `tool_facts()` query;
--   2. the Cedar `Tool` entity stamps it as the `pii` attribute;
--   3. this column records it on every `audit_log` row for evidence;
--   4. a default policy refuses API-key callers on PII tools.
--
-- Column is nullable so older non-tool-call event categories (admin
-- mutations, OAuth lifecycle, etc.) — which slice 1a's EvidenceRecorder
-- refactor will introduce — don't need to invent a synthetic value.
-- For tool-call rows the value mirrors `ToolClassification.pii` at the
-- moment of the call.

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS pii BOOLEAN;

-- No index. Queries that filter by `pii = true` are operator-driven
-- (audit reports / compliance pulls); they're rare and benefit from a
-- bitmap index more than a BTree. If usage patterns shift toward
-- frequent `pii = true` filters we can revisit with a partial index.
