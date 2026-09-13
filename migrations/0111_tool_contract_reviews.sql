CREATE TABLE tool_contract_reviews (
    tool_id uuid PRIMARY KEY REFERENCES mcp_tools(id) ON DELETE CASCADE,
    approved_hash text NOT NULL,
    approved_contract jsonb NOT NULL,
    observed_hash text NOT NULL,
    observed_contract jsonb NOT NULL,
    generation bigint NOT NULL DEFAULT 1,
    quarantined boolean NOT NULL DEFAULT false,
    observed_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz,
    decided_by text,
    CHECK (octet_length(approved_contract::text) <= 262144),
    CHECK (octet_length(observed_contract::text) <= 262144)
);

CREATE TRIGGER tool_contract_reviews_discovery_insert
AFTER INSERT OR DELETE ON tool_contract_reviews
FOR EACH ROW EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER tool_contract_reviews_discovery_update
AFTER UPDATE ON tool_contract_reviews
FOR EACH ROW WHEN (OLD.quarantined IS DISTINCT FROM NEW.quarantined
    OR OLD.observed_hash IS DISTINCT FROM NEW.observed_hash)
EXECUTE FUNCTION advance_catalog_discovery_generation();
