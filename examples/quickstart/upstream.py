"""A deterministic demonstration server; neither tool changes external state."""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer(name="gateway-demo")


@mcp.tool()
def greet(name: str) -> str:
    """Greet someone to demonstrate a complete gateway tool call."""
    return f"Hello, {name}! Your request passed through the gateway."


@mcp.tool()
def restricted() -> str:
    """A harmless tool deliberately forbidden by the demonstration policy."""
    return "The demonstration policy should prevent this response."


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="0.0.0.0", port=9000)
