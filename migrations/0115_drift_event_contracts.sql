-- A drift event names the contract it replaced and the top-level contract
-- fields that differ. Events recorded before these columns existed keep NULL
-- previous_hash; NULL changed_fields means no comparison was available.
ALTER TABLE catalog_drift_events
    ADD COLUMN previous_hash text,
    ADD COLUMN changed_fields text[];

-- Each distinct contract a drift event refers to, stored once per tool so a
-- tool alternating between definitions adds no rows. Contracts too large for
-- review storage are not retained.
CREATE TABLE tool_contract_versions (
    tool_id uuid NOT NULL REFERENCES mcp_tools(id) ON DELETE CASCADE,
    contract_hash text NOT NULL,
    contract jsonb NOT NULL,
    PRIMARY KEY (tool_id, contract_hash),
    CHECK (jsonb_typeof(contract) = 'object'),
    CHECK (octet_length(contract::text) <= 262144)
);
