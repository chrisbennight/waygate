-- Preserve historical measurements without claiming that legacy provider
-- counts or partial cost subtotals follow the inclusive accounting contract.
-- Older writers omit this column and remain explicitly identifiable.
ALTER TABLE llm_usage
    ADD COLUMN accounting_version SMALLINT NOT NULL DEFAULT 1
    CHECK (accounting_version > 0);
