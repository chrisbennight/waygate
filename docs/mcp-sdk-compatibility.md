# MCP SDK compatibility

Waygate uses the official Rust MCP SDK, rmcp 3.9.0. This assessment covers the
released changes since the previously locked 3.5.1 and the relevant current
TypeScript SDK and FastMCP behavior. Library versions describe the assessment;
they do not identify a connected client's implementation or prove its support.

## Rust SDK

The [official release history](https://github.com/modelcontextprotocol/rust-sdk/releases)
and the locked registry packages are the source for this upgrade.

| Change | Waygate disposition |
| --- | --- |
| Abandoned-call cancellation, EOF cancellation, session shutdown, and protocol-error delivery | Adopt the released SDK fixes through the existing invocation and connection lifetime. Keep the gateway's cancellation and deadline tests for both supported protocol generations. |
| Malformed JSON-RPC rejection, request-header validation, HTTP media types, and Accept quality values | Adopt SDK parsing and transport fixes. Keep bounded response materialization and gateway admission checks around the SDK. |
| Body-free HTTP status errors | Preserve the typed status in dial diagnostics, including a refused discovery probe followed by a legacy handshake. Do not record upstream bodies or raw retry-header text. |
| Same-origin redirects in the SDK's default HTTP client | Preserve the stricter gateway policy. Production connections supply their own client through `with_client`; its redirect refusal and destination checks still apply. |
| Graceful child shutdown and bounded stdio lines | Adopt SDK behavior through the existing child-process transport. No second process supervisor is introduced. |
| Skills discovery and manifest checks | Adopt library support while retaining Waygate's governed Skills delivery. Its dynamic Git resources do not advertise directory reads or verified static manifests. |
| Result-shape and output-schema fixes | Adopt SDK fixes. Keep custom file authorization decoding tied to the originating method so unrelated typed result shapes cannot consume extension fields. |
| SDK OAuth discovery and refresh improvements | Not an adoption of SDK-managed OAuth: the gateway does not enable that SDK feature. Its existing credential, identity, exchange, and destination boundaries remain authoritative. |
| Task-status subscription delivery | Still unavailable in this release. `SubscriptionFilter` lacks `taskIds`, and the SDK subscription sink rejects `notifications/tasks`. Keep explicit polling; do not duplicate the transport to bypass this gap. |

The relevant gateway boundaries are
[`http_policy.rs`](../crates/waygate-upstream/src/http_policy.rs),
[`bounded_http_client.rs`](../crates/waygate-upstream/src/bounded_http_client.rs),
[`transport.rs`](../crates/waygate-upstream/src/transport.rs), and
[upstream-owned Tasks](agents/tasks.md#upstream-owned-tasks).

The SDK now derives tool output schemas from serialization. Nullable fields
that the gateway actually serializes are declared as required, instead of
being advertised as omittable. The built-in tool capture and its context budget
include those field names. The budget change reflects more accurate output
contracts; it adds no tools, input fields, descriptions, or runtime operations.

## Other libraries

These libraries inform interoperability and regression coverage. They are not
production framework dependencies of Waygate.

| Library change | Waygate disposition |
| --- | --- |
| TypeScript SDK 2.4.0 Skills schemas require modern cache hints | Adopted in governed `skills/list` and `skills/get`; the official `SkillsClient` check and dynamic-resource limits are recorded in [Skills client verification](skills-client-verification.md). |
| TypeScript schema fidelity, referenced object outputs, and stricter URI validation | Preserve upstream schemas and structured results through the normal protocol adapters. Keep schema presentation opt-in and enforce the authoritative schema on calls; see [client schema compatibility](client-schema-compatibility.md). A client-specific workaround is not evidence that the original schema is invalid. |
| TypeScript notification metadata and per-request revision binding | Keep the existing negotiated revision and subscription boundary. Task notifications remain gated by the Rust SDK's released support. |
| FastMCP authorization after transformation | Already a gateway constraint: presentation adaptation grants no authority; invocation resolves the admitted operation and applies its ordinary authorization. Do not introduce a second authorization path. |
| FastMCP denied-resource/template fallback | No local template fallback is added. The gateway authorizes the resolved resource owner and URI before dispatch; an upstream's internal template authorization remains that upstream's responsibility. |
| FastMCP issuer-bound OAuth credential reuse | Preserve the configured exchange-client/cache pairing and fixed token endpoint. Do not pool credentials across issuers. The FastMCP OAuth provider options are not gateway configuration options. |
| FastMCP stateless file ownership | Preserve authenticated principal and tenant ownership through the governed file handlers. An MCP session ID or untrusted client name is not an authorization identity. |
| FastMCP framework, inspector UI, callback server, and deployment-directory changes | Not applicable to the Rust gateway runtime. No framework or callback-server dependency is added. |

Sources: [TypeScript SDK 2.4.0](https://github.com/modelcontextprotocol/typescript-sdk/releases/tag/v2.4.0)
and [FastMCP 4.1.2](https://github.com/PrefectHQ/fastmcp/releases/tag/v4.1.2).

## Verification boundary

The official `@modelcontextprotocol/client` 2.4.0 was exercised against the
production handler's loopback Skills fixture on both 2025-11-25 and 2026-07-28.
Listing, metadata, root and supporting-file reads, cache-hint shaping, and
unknown-resource refusals passed. Directory reads were correctly unavailable.
This exposed the SDK's new typed Skills dispatch boundary; the typed handlers
now delegate to the same governed implementation, with an HTTP regression.
Cancellation coverage comes from the gateway's existing HTTP suites; this
manual client run did not exercise cancellation or FastMCP as a live peer.

The deprecated-capability audit found no gateway Roots or Sampling relay or
advertisement to remove. The dormant per-request MCP log-level parser was
removed; Logging remains unadvertised and refused. Existing capability-mirror
and MRTR refusal tests retain Roots and Sampling boundaries, while an HTTP
regression checks Logging advertisement and refusal. Ordinary logs, trace
sampling, files, resources, and model inference remain independent capabilities.
See [deprecated features](guides/mcp.md#deprecated-features).

Use the contributor checks plus the existing Streamable HTTP, cancellation,
resource-read, file-ownership, and result-shaping suites. These test synthetic
providers and identities. Database suites require isolated database settings;
an early return without those settings is not a pass of database behavior.

The official conformance-suite integration is separate ongoing work. An SDK
upgrade and local regression suites do not establish conformance for every
client, every upstream, or every transport combination. Record independent
client runs with their exact version and negotiated protocol; retain untested
combinations as unknown.
