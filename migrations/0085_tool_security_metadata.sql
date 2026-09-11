-- Keep deployment policy separate from upstream MCP behavior claims while
-- preserving both for review. Existing servers remain on legacy manifest
-- classification until an operator explicitly activates annotation mode.

ALTER TABLE mcp_servers
    ADD COLUMN classification_mode TEXT NOT NULL DEFAULT 'manifest'
        CHECK (classification_mode IN ('manifest', 'mcp_annotations'));

ALTER TABLE mcp_tool_versions
    ADD COLUMN tool_annotations JSONB,
    ADD COLUMN action_metadata JSONB;
