-- Complete the discovery invalidation trigger with every mcp_tool_versions
-- field that contributes to the served tool contract, including schema
-- identity and annotation-native security metadata.

DROP TRIGGER IF EXISTS mcp_tool_versions_discovery_generation_update
ON mcp_tool_versions;

CREATE TRIGGER mcp_tool_versions_discovery_generation_update
AFTER UPDATE OF schema_hash, description, input_schema, output_schema,
                tool_annotations, action_metadata, approved_at, approved_by
ON mcp_tool_versions
FOR EACH ROW
WHEN (
    OLD.schema_hash IS DISTINCT FROM NEW.schema_hash OR
    OLD.description IS DISTINCT FROM NEW.description OR
    OLD.input_schema IS DISTINCT FROM NEW.input_schema OR
    OLD.output_schema IS DISTINCT FROM NEW.output_schema OR
    OLD.tool_annotations IS DISTINCT FROM NEW.tool_annotations OR
    OLD.action_metadata IS DISTINCT FROM NEW.action_metadata OR
    OLD.approved_at IS DISTINCT FROM NEW.approved_at OR
    OLD.approved_by IS DISTINCT FROM NEW.approved_by
)
EXECUTE FUNCTION advance_catalog_discovery_generation();
