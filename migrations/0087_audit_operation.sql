-- The operation an audited call selected.
--
-- For a tool that carries many operations behind one name, `tool` no longer
-- says what ran: every call through an executor records the same tool name
-- whether the caller listed projects or revealed a secret. An investigator
-- reading this table needs the distinction, and so does anyone reconstructing
-- why a call was authorized the way it was — the risk and flags on the row
-- reflect the operation's classification, not the tool's.
--
-- Nullable, and null for every row written before this column existed as well
-- as every call to a tool classified by name alone. The chain encoding
-- contributes zero bytes when the operation is absent, so existing rows verify
-- unchanged.
--
-- Recorded whether or not an operator had classified the value: the audit trail
-- answers what was asked for, which is a different question from what policy
-- recognized.

-- Bounded to the length the catalog accepts for an operation name. The writer
-- already refuses anything longer, so this is the second line rather than the
-- first: a failing insert here would drop an audit row, which is worse than the
-- oversized value it would be rejecting.
ALTER TABLE audit_log
    ADD COLUMN operation TEXT
        CHECK (operation IS NULL OR length(operation) BETWEEN 1 AND 256);
