# Client compatibility report

The dashboard's **Identities → Clients** tab and
`GET /api/v1/admin/client_compatibility` report MCP client declarations observed
with an authenticated principal. Both require `mcp:admin`, reject peer
assertions, and restrict results to the authenticated tenant. A dashboard URL
selecting another tenant is refused; the selector is not authorization.
Responses use `Cache-Control: no-store`.

Each row joins trusted tenant, issuer, subject, authentication method and
credential-profile identifier with the observed client name/version and
protocol generation/version. A context fingerprint distinguishes scope or
profile-confinement changes. It hashes ordinary scope/profile metadata, never
a token or key. It is not a policy decision, token identifier, or complete
authorization snapshot. Raw credentials, email, groups, request arguments,
results and session identifiers are not stored.

Client metadata is self-reported. Missing fields remain unknown. A client
using a generic SDK label cannot be identified as a particular product or
installation from that label. Shared credentials and matching declarations
coalesce into one observation row; this report does not count devices. The
same credentials with changed declarations produce separate rows. Metadata
is bounded and marked when truncated; authenticated identity fields are never
truncated into a different identity.

## Coverage and retention

The report is a bounded, in-memory reporting store for the **current process**.
It retains rows last observed within 24 hours, up to 4096 distinct combinations.
Expired rows are excluded from reports; memory cleanup happens on subsequent
admission or report reads, so an idle process can retain expired metadata until
its next access or termination.
It has no database write, worker, replay, or cross-replica aggregation. A restart
clears it; another replica has its own observations. Request admission never
waits for report reads: lock contention, capacity exhaustion, and oversized
identity fields drop observations. The report exposes a process-wide drop
count so incomplete evidence cannot silently look complete.

Each row shows first/last observed Unix timestamps and its retained lifetime
request count. The selected window filters on last seen; the count is not a
count within that window. Rows older than five minutes are marked stale in the
dashboard. Report time, process observation start, retention, window and
freshness threshold are returned in JSON. Missing or stale rows are never
proof that a client, version or compatibility dependency is absent. Collect
coverage from all relevant replicas and a representative operating window
before retiring a compatibility path.

The MCP handler observes authenticated served requests, including legacy
initialization and subsequent session requests, and stateless inline metadata.
Initialization may have no negotiated version yet; that observation remains
unknown until a later request supplies the negotiated version. SDK-owned
methods that do not reach gateway handlers, inference requests, and rejected
authentication are not client-use observations. Compatibility data never
changes authorization or client selection, and introduces no identity or
arbitrary version labels into Prometheus.

## Filters and pagination

The API accepts exact `subject`, `issuer`, and `client` filters,
`window_seconds` from 1 to 86400 (default 3600), `limit` from 1 to 100 (default
50), and `offset` up to 4096. The response includes `next_offset` when another
page exists. The dashboard preserves filters and its tenant prefix on the next
page. Pagination is a live view: new observations can change page membership.
There is no historical snapshot or durable audit completeness promise.

See [client schema qualification](client-schema-compatibility.md)
for synthetic current-client results. Those observations show why a declared
SDK name/version and an independently known CLI version must remain separate.
