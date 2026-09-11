"""A minimal MCP server on the stateless generation, for the build smoke.

The legacy fixture next door proves the gateway can still dial a peer that
predates discovery. This one proves the opposite half: that the bridge does
not *downgrade* a peer that can discover. Nothing in CI exercised the
stateless generation before this — it was live on exactly one first-party
upstream and on no test.

Deliberately the same SDK family as the legacy fixture and deliberately not
rmcp, so the pair differ only in the generation they speak. An rmcp server
would answer discovery natively and prove only that rmcp talks to itself.
"""

from mcp.server.mcpserver import MCPServer

# Distinct from the legacy fixture's token so a mixed-up assertion cannot pass
# by dialling the wrong upstream.
PING_TOKEN = "modern-smoke-ok"

mcp = MCPServer(name="modern-smoke-upstream")


@mcp.tool()
def ping() -> str:
    """Return a fixed token proving the tool call round-tripped."""
    return PING_TOKEN


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="0.0.0.0", port=9000)
