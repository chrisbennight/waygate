# Migrate legacy MCP HTTP+SSE upstreams

Waygate serves Streamable HTTP to clients. An upstream configured with
`transport: sse` uses the older HTTP+SSE transport: responses arrive on a
long-lived connection and requests post to an endpoint announced on that
connection. Migrate that upstream transport independently of downstream client
sessions or the upstream's negotiated protocol revision.

[SEP-2596 is Final](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2596-spec-feature-lifecycle-and-deprecation.md).
Its transition rule makes HTTP+SSE eligible for specification removal three
months after Final. The
[deprecated-feature registry](https://modelcontextprotocol.io/specification/2026-07-28/deprecated)
describes eligibility; a Core Maintainer decision and release changes establish
actual specification removal. Neither event silently changes Waygate's support
policy. The [gateway policy](guides/mcp.md#protocol-support-policy) keeps
configured dependencies working until a reviewed migration and announced
gateway removal are ready.

SSE framing is also used by Streamable HTTP subscriptions and inference
responses. Retiring the legacy transport does not mean deleting those SSE
parsers, disabling subscriptions, or retiring the 2025-11-25 protocol generation.

## Inventory configuration and actual use

Keep the operational inventory in the operator's deployment records. Public
reports should contain synthetic examples and general compatibility findings,
without endpoints, identities, credentials, or deployment manifests.

1. Inspect the served upstream manifests, including configuration managed
   through the dashboard or manifest ledger. Repository tutorial fixtures are
   not evidence of the live set. Find every `transport: sse` declaration.
2. Compare that set with the dashboard's Servers view or authenticated
   `GET /api/v1/servers` inventory. Retain only the identifiers, transport,
   connection/health state, and negotiated protocol needed for this review.
   Do not copy full configuration or credential-bearing URLs into reports.
3. Check per-upstream audit, request, and connection evidence over an operator
   chosen observation period, including scheduled and infrequent workflows.
   Distinguish configured, connected, recently used, and unknown. A failed or
   unloaded server is not proof that its capability can be removed.
4. Record the capability owner and a migration or explicit defer decision for
   each dependency. Absence of observed traffic alone does not establish that
   a recovery or occasional workflow is unused.

Downstream protocol counters cannot identify an upstream's transport. A legacy
initialization session can run over Streamable HTTP, while one gateway request
can reach an upstream using a different protocol generation.

## Choose a migration

| Choice | Required evidence |
| --- | --- |
| Upgrade the upstream's native transport | Verify the exact deployed release supports Streamable HTTP and preserves the required operations. A hosted service, WebSocket endpoint, or path named `/mcp` is not sufficient evidence. |
| Deploy a maintained external adapter | Review its provenance, lifetime, request and response limits, cancellation, authentication, identity isolation, and resource/file behavior. Keep it visible in deployment ownership and monitoring; do not hide a permanent legacy proxy inside Waygate. |
| Replace or defer the upstream | Confirm which capability replaces it, or record why the dependency remains and who owns the next decision. Do not remove support while a required workflow has no working migration. |

For a native migration, use `transport: http` and the upstream's documented
Streamable HTTP endpoint. Choose `protocol: auto`, an explicit modern revision,
or `protocol: legacy` according to the release actually deployed. Streamable
HTTP does not require an upstream to implement the newer stateless revision.
Use the ordinary reviewed manifest publication/reload workflow and verify a
fresh connection; do not simply rename the transport while retaining an
unverified endpoint.

Preserve the manifest's destination, trust, credential-reference, identity,
resource-prefix, tool admission, and review constraints. A transport change
does not authorize a broader origin, weaker TLS, a privileged shared session,
or an automatic reset of reviewed tool definitions. See
[upstream configuration](agents/upstreams.md).

## Check the capability before switching

Use disposable fixtures or explicitly harmless operations. Compare the old
and candidate connection under the same policy and record unknown or untested
behavior separately from passes.

- Compare visible tool names, schemas, descriptions, result metadata, and
  capabilities. Test a permitted read and a known policy refusal; no destructive
  operation is needed to prove the route.
- Check authentication failures and credential isolation. With separate test
  identities, verify that one caller cannot inherit another's permissions or
  session context. Do not print credential values or request bodies in evidence.
- Cancel a harmless in-flight request and check that the provider work stops or
  reaches its documented cancellation state. Verify reconnect and deadline
  behavior without automatically resubmitting an uncertain operation.
- Check advertised resources, resource refusals, and required governed file
  upload/download behavior. Preserve owner binding, URI boundaries, limits, and
  negotiated file capabilities; an adapter must not turn a refusal into a
  fallback read.
- For long-running work, retain the returned task or execution handle, follow
  status and cancellation, and verify the supported disconnect behavior. Use
  notifications only where the released SDK and negotiated capabilities support
  them. Do not introduce hidden background polling to make a transport appear
  compatible.

Roll out through the operator's existing deployment process, verify real
readiness and a harmless permitted call, and retain a tested recovery path.
Keep actual deployment findings and sensitive evidence outside the public
project.

## Gate gateway removal

Removing the legacy transport is a separate change after migration:

- Inventory and ownership decisions are current, and required configured or
  active dependencies have a verified migration.
- Release notes announce the gateway's support change and explain the supported
  configuration, regardless of the specification's earliest eligibility.
- Startup, import, dashboard, and reload paths reject retired configuration with
  actionable migration guidance; no configured server is silently dropped.
- The removal covers gateway-owned transport code, obsolete configuration and
  dependencies, while retaining Streamable HTTP SSE framing and supported
  legacy protocol sessions.
- Required source checks and applicable interoperability regressions pass.

If a dependency still requires HTTP+SSE, keep the removal gated and record the
mitigation or defer decision. This guide changes no live manifest and restarts
no service.
