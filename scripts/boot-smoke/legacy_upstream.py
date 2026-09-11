"""A minimal MCP server for the build's boot smoke, deliberately built on a
different SDK than the gateway.

The gateway is an rmcp client. An rmcp *server* would answer `server/discover`
natively, so a smoke built on one would only ever prove that rmcp can talk to
itself — and would stay green through exactly the kind of client-side change
that leaves the gateway unable to dial the servers it actually fronts. This is
a Python-SDK server, pinned to a release that predates the stateless
generation, so the smoke exercises the real cross-implementation handshake the
fleet runs on.
"""

from mcp.server.fastmcp import FastMCP

# A tool must exist for the upstream to advertise one and for the manifest's
# classification to match something real. The smoke does NOT call it: the
# gateway runs with auth enforced against a stub issuer, so there is no way to
# make an authenticated tool call, and the assertions stop at the handshake.
PING_TOKEN = "legacy-smoke-ok"

mcp = FastMCP("legacy-smoke-upstream", host="0.0.0.0", port=9000)


@mcp.tool()
def ping() -> str:
    """Return a fixed token proving the tool call round-tripped."""
    return PING_TOKEN


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
