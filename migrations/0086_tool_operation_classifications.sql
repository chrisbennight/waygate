-- Per-operation classification for tools that carry many operations behind
-- one name.
--
-- A tool whose arguments select among many operations cannot be classified by
-- name alone: the gateway sees `infisical.read` whether the caller asked to
-- list projects or to reveal a secret. Classifying such a tool for the most
-- sensitive operation it can reach never under-classifies a request, but it
-- also makes the narrower grant inexpressible — a principal allowed to read at
-- all is allowed to reveal.
--
-- `discriminator` names the argument field whose value selects the operation.
-- NULL keeps the tool classified by name alone, which is every tool today, so
-- this is inert until an operator sets it.
--
-- Rows in `tool_operation_classifications` classify one tool for one
-- discriminator value. A value with no row is classified by the tool's own
-- row, so an unrecognized operation is never weaker than the tool it arrived
-- through. A row that is present carries the classification an operator
-- reviewed for that operation, which may be narrower than the tool's — that is
-- what lets an executor admit its harmless operations individually while its
-- tool-level row still covers everything unlisted.
--
-- The primary key's leading column already serves reads by tool_id, so no
-- separate index is defined.

ALTER TABLE tool_classifications
    ADD COLUMN discriminator TEXT
        CHECK (discriminator IS NULL OR length(discriminator) BETWEEN 1 AND 128);

CREATE TABLE tool_operation_classifications (
    -- References the tool-level classification, not the tool: an operation row
    -- only has meaning beside the row that classifies every value it does not
    -- name, and removing that fallback must remove the refinements with it.
    tool_id             UUID NOT NULL
                            REFERENCES tool_classifications(tool_id) ON DELETE CASCADE,
    operation           TEXT NOT NULL
                            CHECK (length(operation) BETWEEN 1 AND 256),
    risk                TEXT NOT NULL
                            CHECK (risk IN ('low','medium','high','critical')),
    side_effects        BOOLEAN NOT NULL,
    pii                 BOOLEAN NOT NULL,
    reviewed_at         TIMESTAMPTZ,
    reviewer            TEXT,
    PRIMARY KEY (tool_id, operation)
);

-- The ceiling is not enforced here.
--
-- The manifest loader refuses an operation more severe than its tool, but the
-- catalog takes writes that never pass through a manifest, so these columns can
-- still hold a row the loader would reject. A CHECK cannot see the parent row,
-- and a constraint trigger is the shape that would work.
--
-- It is deliberately not written yet. No code reads these rows, so nothing can
-- act on a bad one, and a trigger cannot be exercised without a live database.
-- It lands with the catalog read and write paths, where the same change can
-- test it and the resolver that depends on it.
