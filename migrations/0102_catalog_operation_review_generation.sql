-- Operation classifications participate in the served contract only after
-- review. Activating or withdrawing that review must invalidate discovery in
-- the same transaction as the catalog change.

DROP TRIGGER IF EXISTS tool_operation_classifications_discovery_generation_update
ON tool_operation_classifications;

CREATE TRIGGER tool_operation_classifications_discovery_generation_update
AFTER UPDATE OF operation, risk, side_effects, pii, reviewed_at
ON tool_operation_classifications
FOR EACH ROW
WHEN (
    OLD.operation IS DISTINCT FROM NEW.operation OR
    OLD.risk IS DISTINCT FROM NEW.risk OR
    OLD.side_effects IS DISTINCT FROM NEW.side_effects OR
    OLD.pii IS DISTINCT FROM NEW.pii OR
    (OLD.reviewed_at IS NULL) IS DISTINCT FROM (NEW.reviewed_at IS NULL)
)
EXECUTE FUNCTION advance_catalog_discovery_generation();
