# Inspect upstream compatibility

Open **Servers**, expand a server's configuration, and select **Show
compatibility evidence**. The same read-only report is available at
`GET /api/v1/servers/{name}/compatibility`. It requires `mcp:admin` in the
default tenant, which owns the gateway-wide upstream configuration. Other
tenants and peer assertions cannot read it. The dashboard checks both the
authenticated tenant and the selected tenant.

The report distinguishes:

- **Configured:** transport, protocol selection, resource ownership, and
  gateway-run task configuration.
- **Advertised:** implementation name/version and selected capability flags
  retained by the MCP library, separately for each retained connection. These are
  upstream declarations, not independently verified facts.
- **Observed:** the protocol that connection negotiated and the age of its
  successful catalog observation, plus pre-admission schema warnings and runtime availability.
- **Explicitly tested:** `not_recorded`. Opening a report runs no tool,
  resource, elicitation, file-transfer, or conformance probe. Use a separately
  selected harmless qualification workflow to test those contracts.

Peer declarations carry their connection observation time. A catalog refresh
that replaces the connection gets new declarations; reading a report does not
refresh them. Old observations remain visibly old rather than acquiring the
report's timestamp. Catalog age is separate from the declaration timestamp.
Neither an old declaration nor a healthy connection proves current conformance.
Known-closed SDK connections and open breakers mark retained declarations
stale, with their original timestamps. Current and stale lanes are distinct,
including a mixed report during recovery. Eviction makes their declarations
unavailable. Current means the SDK has not observed closure and the breaker is
not open; it is not an independent liveness or conformance test. The last
successful connection time is availability history only. A busy lane returns
`busy` within a bounded wait instead of guessing or
holding the operator page behind a long call.

Input-schema warning counts describe tools in the retained upstream catalog
before quarantine, durable review decisions, caller authorization, and client
presentation. They do not count currently client-visible tools. In particular,
approval on another replica can change durable admission while this replica's
local quarantine cache remains unchanged. The report does not reproduce that
admission decision or claim an effective catalog for any caller. Output-schema
refusals remain evidence of invalid output contracts omitted during publication.

Reports cover one explicitly selected upstream. At most 32 retained lanes are
returned, with an explicit truncation signal; peer-controlled display labels
are bounded. No endpoint URLs, headers, credential values, arbitrary extension
settings, or tool payloads are included. No new history or worker is created.

Explanations identify the gateway's task-delivery limitation, conditional
elicitation, unknown draft file compatibility, resource-ownership requirement,
client schema projection, and legacy HTTP+SSE dependency. A declaration is
never permission to invoke a capability. MCP Apps negotiation remains deferred.
