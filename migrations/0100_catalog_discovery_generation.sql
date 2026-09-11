-- Fleet-wide generation and doorbell for discovery-affecting server changes.
--
-- The row is durable authority.  LISTEN/NOTIFY is only the prompt wake-up:
-- readers compare the generation before and after a discovery projection, and
-- listeners re-read it after every notification or reconnect.  Keeping the
-- notification in the trigger's transaction means aborted catalog changes
-- neither advance the generation nor wake downstream sessions.

CREATE TABLE catalog_discovery_generation (
    singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0)
);

INSERT INTO catalog_discovery_generation (singleton, generation)
VALUES (TRUE, 0);

CREATE FUNCTION advance_catalog_discovery_generation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE catalog_discovery_generation
       SET generation = generation + 1
     WHERE singleton = TRUE;

    -- An empty, stable payload lets PostgreSQL coalesce multiple row changes
    -- in one transaction.  The durable generation carries the information.
    PERFORM pg_notify('mcp_catalog_reload', '');
    RETURN NULL;
END;
$$;

CREATE TRIGGER mcp_servers_discovery_generation_insert
AFTER INSERT ON mcp_servers
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER mcp_servers_discovery_generation_delete
AFTER DELETE ON mcp_servers
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER mcp_servers_discovery_generation_update
AFTER UPDATE OF tenant_id, name, status, visibility, classification_mode ON mcp_servers
FOR EACH ROW
WHEN (
    OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
    OLD.name IS DISTINCT FROM NEW.name OR
    OLD.status IS DISTINCT FROM NEW.status OR
    OLD.visibility IS DISTINCT FROM NEW.visibility OR
    OLD.classification_mode IS DISTINCT FROM NEW.classification_mode
)
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER mcp_tools_discovery_generation_insert
AFTER INSERT ON mcp_tools
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER mcp_tools_discovery_generation_delete
AFTER DELETE ON mcp_tools
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER mcp_tools_discovery_generation_update
AFTER UPDATE OF server_id, name ON mcp_tools
FOR EACH ROW
WHEN (
    OLD.server_id IS DISTINCT FROM NEW.server_id OR
    OLD.name IS DISTINCT FROM NEW.name
)
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER mcp_tool_versions_discovery_generation_insert
AFTER INSERT ON mcp_tool_versions
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER mcp_tool_versions_discovery_generation_delete
AFTER DELETE ON mcp_tool_versions
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER mcp_tool_versions_discovery_generation_update
AFTER UPDATE OF description, input_schema, output_schema, approved_at, approved_by
ON mcp_tool_versions
FOR EACH ROW
WHEN (
    OLD.description IS DISTINCT FROM NEW.description OR
    OLD.input_schema IS DISTINCT FROM NEW.input_schema OR
    OLD.output_schema IS DISTINCT FROM NEW.output_schema OR
    OLD.approved_at IS DISTINCT FROM NEW.approved_at OR
    OLD.approved_by IS DISTINCT FROM NEW.approved_by
)
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER tool_classifications_discovery_generation_insert
AFTER INSERT ON tool_classifications
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER tool_classifications_discovery_generation_delete
AFTER DELETE ON tool_classifications
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER tool_classifications_discovery_generation_update
AFTER UPDATE OF risk, side_effects, pii, data_classification, cost_class,
                requires_approval, discriminator
ON tool_classifications
FOR EACH ROW
WHEN (
    OLD.risk IS DISTINCT FROM NEW.risk OR
    OLD.side_effects IS DISTINCT FROM NEW.side_effects OR
    OLD.pii IS DISTINCT FROM NEW.pii OR
    OLD.data_classification IS DISTINCT FROM NEW.data_classification OR
    OLD.cost_class IS DISTINCT FROM NEW.cost_class OR
    OLD.requires_approval IS DISTINCT FROM NEW.requires_approval OR
    OLD.discriminator IS DISTINCT FROM NEW.discriminator
)
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER tool_operation_classifications_discovery_generation_insert
AFTER INSERT ON tool_operation_classifications
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER tool_operation_classifications_discovery_generation_delete
AFTER DELETE ON tool_operation_classifications
FOR EACH ROW
EXECUTE FUNCTION advance_catalog_discovery_generation();

CREATE TRIGGER tool_operation_classifications_discovery_generation_update
AFTER UPDATE OF operation, risk, side_effects, pii
ON tool_operation_classifications
FOR EACH ROW
WHEN (
    OLD.operation IS DISTINCT FROM NEW.operation OR
    OLD.risk IS DISTINCT FROM NEW.risk OR
    OLD.side_effects IS DISTINCT FROM NEW.side_effects OR
    OLD.pii IS DISTINCT FROM NEW.pii
)
EXECUTE FUNCTION advance_catalog_discovery_generation();
