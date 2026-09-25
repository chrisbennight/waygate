# Out-of-context file transfer

## Status and purpose

The gateway handles files in both directions. A client can stream a local file
into gateway storage with `files/authorizeUpload`, or use
`gateway-files.prepare_upload` and a small helper script. A later tool call may
put the returned gateway URI in an `x-mcp-file` input. Only then does the
gateway ask the selected upstream where to send the file, stream it there, and
replace the gateway URI with the upstream's private URI before dispatch.

An uploaded file may also be consumed by the gateway itself rather than
forwarded: a control-plane change request can carry its authored document — a
manifest set, a Cedar statement, an agent instruction — as a file reference
instead of inline text, which the submission layer reads and substitutes before
the proposal is stored. The admission rules are the file plane's own
(owner-scoped lookup, credential-profile restrictions); see
`docs/agents/hitl-control-plane.md` § "Uploading a document instead of inlining
it" for why the reference never survives into the stored proposal.

For downloads, the gateway saves an upstream file as it arrives, checks its
declared size, SHA-256 digest, and media type, and replaces the upstream URI
with a gateway URI before returning the tool result. A file-aware MCP host can
use `files/authorizeDownload`; other clients can use
`gateway-files.prepare_download` and a small helper script.

Files are currently marked `uninspectable` because no scanner is connected.
A missing scanner does not block a valid download or claim
that the file was checked.

The product requirement is simple: a host or ordinary helper must be able to
move a real file without placing its bytes in MCP JSON-RPC or model context.
There is no fixed gateway-wide byte limit and no base64 fallback. File size,
retention, and quota policy will be set by the production authority and storage
provider, not by buffering the body in this protocol adapter.

## Retained connector responses

A connector may return a compact HTTP-result envelope whose
`payload.resource_uri` identifies a retained MCP resource. The gateway reads that
resource on the originating upstream session before the session is released.
This adapter buffers the upstream text or blob inside the gateway; it does not
require native file-transfer support from the connector.
Buffered recovery admits at most 16 MiB of decoded body, independently of the
larger disk-file quota. The encoded resource response is also bounded before
JSON decoding. Larger retained bodies receive an explicit capacity error;
the adapter does not attempt multi-gigabyte in-memory recovery.
Transports without bounded resource reads return `bounded_resource_read_unsupported`.

Direct clients receive an owner-scoped gateway file, a resource link, and the
file descriptor under
`CallToolResult._meta["io.cacahuate.mcp-gateway/retained-delivery"].file`.
Use the descriptor's `uri` with `gateway-files.prepare_download` and the existing
helper. Code Mode materializes supported bodies within its runtime allowance;
larger or binary bodies use the same file route, exposed as
`_gateway_delivery.file` in the connector value. Neither path places the whole
body in model context automatically.

This applies to reads and mutations alike. Operation success and attachment
delivery are separate outcomes. An unavailable attachment after a confirmed
mutation reports `operation_status: "succeeded"`,
`delivery_status: "unavailable"`, an error code, and `retry_operation: false`.
An attachment failure does not authorize or trigger redispatch of the operation.

Retained bodies pass through response controls before file publication. If
inspection replaces the data, only the replacement is stored. The adapter reuses
the inspected body's schema validation before constructing its gateway delivery
envelope. That envelope describes a file instead of repeating the upstream
`data` and is governed by the gateway delivery contract. Published upstream
output schemas accept either the upstream response or a structured
`_gateway_delivery` envelope containing the file descriptor or delivery error.
The gateway validates the inspected body against the original upstream schema
and the final delivery envelope against its own schema. Its byte count describes
the stored replacement. The adapter reuses
file ownership, storage budgets, retention, SHA-256 calculation, publication,
download authorization, and cleanup. File scanner coverage remains reported as
`uninspectable` until an actual file scanner is installed; response inspection
does not claim scanner coverage. Unsupported transports, missing resources,
denied reads, disabled storage, and delivery failures remain explicit.

## Standards grounding

The compatibility target is the current draft of
[SEP-2631](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2631),
which builds on the `x-mcp-file` annotation proposed by SEP-2356. The draft is
not merged, so its spellings are isolated in `waygate_mcp::files`.

The native method reads the current protocol's per-request capability metadata
from `_meta["io.modelcontextprotocol/clientCapabilities"].files`. The SEP
draft's examples also show `capabilities.files` in the initialization-era
handshake: that shape belongs to negotiated legacy sessions only, is never
consulted for a stateless request, and is not readable through the pinned MCP
library today — the negotiation matrix below states which mixed-version
shapes work now and which await the tracked library gap.

Only a client that explicitly declares the direction and `https` transport is
treated as capable of the native method. A client without that declaration can
still use `gateway-files.prepare_download` and a helper. Unknown future
transport names remain parseable but are not executed. A request without the
declaration gets an explicit unsupported-capability error; this does not assume
permanent behavior from Codex, Claude, OpenCode, or any other client.

## Wire profiles

The gateway serves three file-transfer compatibility surfaces. Each is an
explicit wire profile, classified once at the MCP edge
(`waygate_mcp::files::classify_downstream_caller`) rather than inferred from
where a field happened to appear:

- **`stateless-native`** — an MCP `2026-07-28` self-contained request whose
  `_meta["io.modelcontextprotocol/clientCapabilities"].files` declares the
  direction and `https` transport. The declaration is request-local and
  authoritative: it is never merged with remembered session state, so any
  replica can serve any request.
- **`legacy-draft`** — a connection that negotiated a legacy `initialize`
  session. The SEP draft's examples put `files` in the initialization
  capability exchange; the pinned Rust MCP library drops that unknown member
  from its typed capability object, so a literal draft client's
  initialization-time file capability currently arrives unobservable. The
  classification carries the negotiated capability when the library can expose
  it; until then a legacy caller receives a precise error telling it to
  redeclare file capabilities in request `_meta`, which a dual-version client
  can do on the same session.
- **`tool-fallback`** — no native negotiation at all. The caller discovers
  `gateway-files.prepare_upload` / `prepare_download` through ordinary
  `tools/list` and completes transfers with a helper. This is a first-class
  product surface, not scaffolding, because SEP-2631 is a draft that ordinary
  hosts cannot be assumed to implement.

A profile selects a wire adapter only. All three converge on the same
canonical file identity, transfer authority, storage, integrity, retention,
and audit lifecycle — there is exactly one transfer implementation.

Toward upstreams the gateway is itself a file-transfer client and always emits
the stateless-native declaration, built in one place
(`waygate_mcp::files::stateless_client_capability_meta`) so both delivery
directions and any future draft revision share a single wire shape.

That emission travels as an explicit per-request metadata override, not only in
the request params. On a leg the upstream negotiated at `2026-07-28` the MCP
library stamps its own client capability object onto every outgoing request,
built from the capabilities the connection was dialed with, and that stamp
replaces the same metadata key in the params rather than merging into it. The
typed capability struct cannot carry the draft's `files` member (the same
library gap as the initialize-time rows below), so a declaration written only
into the params reaches such an upstream as an empty capability object. The
library applies an explicit override after its own stamping, which is why the
declaration is composed onto the dialed capabilities there.

### Version negotiation matrix

The gateway sits on both sides of MCP, and each side may be stateless
(`2026-07-28`) or a negotiated legacy session. Capability interpretation is
version-correct on both boundaries, and no session-derived capability state
ever applies to a stateless request — any replica must be able to serve any
self-contained request from its own contents.

| Caller / upstream shape | Native file transfer | How |
| --- | --- | --- |
| Stateless caller with request `_meta` declaration | works | request-local capability is authoritative |
| Legacy-session caller redeclaring in request `_meta` | works | dual-version client path; request-local wins, session state never merged |
| Legacy-session caller relying only on initialize-time `capabilities.files` | refused with a precise error | the pinned MCP library drops the draft member from its typed initialize capabilities; the refusal names the redeclare-in-`_meta` path |
| Stateless upstream | works | the gateway emits the request-local declaration on each `files/authorize*`, as a per-request override composed onto the dialed capabilities so the library's own capability stamp cannot replace it |
| Legacy-session upstream reading per-request `_meta` | works | the same emission travels on the session; the gateway's own downstream edge applies this exact rule, so gateway-to-gateway hops negotiate cleanly |
| Legacy-session upstream requiring initialize-time client `files` | native route unavailable | the typed client capabilities cannot carry the draft member; the connection-layer seam (`connect_with_capabilities`) is ready for it |
| Tool-fallback caller | works regardless of the caller's generation | `gateway-files.*` tools replace only the downstream native negotiation; the upstream leg of a later delivery still follows the upstream rows above |

Legacy capability state, once the library can expose it, is retained only for
its own negotiated session and admitted through the same classification
(`DownstreamNegotiation::LegacySession`) — never remembered across stateless
requests.

## Discovery

How a client learns that file transfer exists differs by profile, and the
fallback's discoverability never depends on the native surface:

- **Fallback (portable)**: the presence of `gateway-files.prepare_upload` and
  `gateway-files.prepare_download` in `tools/list` is the portable
  declaration that governed file transfer exists. Any client that can list
  tools can find it, on either protocol generation.
- **Native (interim)**: the draft has not yet reconciled a server-side file
  capability with the stateless `server/discover` shape, so the gateway
  advertises nothing and does not invent an experimental capability — an
  invented shape would be adopted as if it were the standard and would then
  have to be carried beside the finalized one. A client that knows the draft
  calls `files/authorize*` directly; an unsupported or disabled method
  answers with the machine-readable categories above
  (`unsupported_capability`, `not_enabled`), so trial invocation is cheap
  and routable rather than a prose-parsing exercise.
- **The projection seam**: the server-capability object is built in exactly
  one place, from which both the legacy initialize result and the stateless
  `server/discover` response derive. When the standard (or its extension
  registration) settles a server-side shape, native file support is
  advertised by populating that one point; nothing else changes.
- **Upstream direction**: the gateway likewise learns an upstream's native
  support from the authorization methods' answers. An upstream that answers
  method-not-found surfaces as `not_enabled` ("does not support native file
  transfer"), distinct from a failed attempt (`transfer_failed`); only the
  bounded code informs that distinction, never the upstream's message.
  Reading a settled server capability from the upstream's discovery response
  belongs to the same future shape.

## How files move

MCP carries the file reference and download instructions. HTTPS carries the
file itself:

```text
MCP client/host -- files/authorize* --> gateway
MCP client/host <-- FileValue + HTTPS instructions -- gateway
host/helper     ===== streamed file =====> gateway or client storage
model           <-- stable FileValue only -- host

later tool call -- gateway file URI (string, or extension object) --> gateway
gateway         -- files/authorizeUpload --> selected upstream
gateway         ===== streamed file =====> upstream-private endpoint
upstream tool   <-- admitted arguments with the private file reference -- gateway
```

`FileValue` is a stable reference with optional metadata:

```json
{
  "uri": "mcp-file://gateway/opaque-file-id",
  "name": "report.pdf",
  "mimeType": "application/pdf",
  "size": 734003200,
  "digest": { "algorithm": "sha-256", "value": "base64url-no-padding" }
}
```

Only `uri` is required. A caller may authorize an upload before it knows the
length or digest, and the streaming executor reports both after consuming the
body once. When size or digest is supplied, it becomes an integrity constraint.
The URI identifies a file; it is not an access credential.

Every evaluated `x-mcp-file` location obeys the same admission rules however
it was reached — direct properties, arrays, references, and composed or
conditional branches. `transferModes` names which trust and data path the tool
admitted, and a value using a disallowed mode is rejected rather than
forwarded: an upload-only field refuses inline `data:` values (bytes must not
re-enter JSON-RPC around the governed upload path), and an inline-only field
refuses gateway file references (the upstream could not resolve them). An
admitted inline `data:` value is checked against the declared `maxSize` using
its decoded byte count and against `accept` using its declared media type,
then left in place — the inline payload is itself the admitted value. The
gateway validates exactly the header components its own policy consumes: the
media-type essence (percent escapes decoded, then two restricted tokens) for
`accept` matching, the base64 marker, and the payload encoding for the size
measurement. Semicolon parameters such as `charset` are consumed by no
gateway policy and pass through for the upstream's own parser. Base64
payloads accept the widely produced unpadded form (as browsers do), while
inconsistent padding, embedded whitespace, invalid symbols, impossible
symbol counts, and non-canonical set pad bits are rejected as malformed —
deliberately stricter than the fully forgiving browser decode, because the
gateway forwards the value verbatim and a strict upstream decoder must not
receive a payload the gateway measured differently. The
`accept` list mixes MIME patterns with dot-prefixed filename extension hints,
mirroring the HTML picker attribute: a file passes on either a media-type
match or a (case-insensitive) name-extension match, an extension hint is
never compared against a media type, and a hints-only list cannot deny a file
whose name is unknown.

### Object-valued file inputs are a gateway compatibility extension

SEP-2631 is deliberately narrow about input representation: a file-valued
tool or elicitation field is a URI *string* annotated with `x-mcp-file`,
whose value is an inline `data:` URI or a negotiated file URI. The draft's
`FileValue` object appears in outputs and authorization results, never as
the normative input shape.

The gateway additionally accepts an object-valued input when — and only
when — the upstream tool's own admitted schema defines that object. This is
a gateway compatibility extension beyond the draft, kept because real vendor
contracts already model an attachment as a structured object. Its boundary:

- The strict URI-string form is the interoperable SEP contract. A server
  author who publishes an object schema must not expect a plain SEP-2631
  client to understand it; only gateway-fronted callers receive the
  translation.
- The extension introduces no public keyword. Admission is driven entirely
  by the upstream schema plus the same `x-mcp-file` annotation the strict
  form uses.
- Caller-supplied file identity and integrity metadata are never
  authoritative: the URI, size, digest, and media type delivered upstream
  come from the gateway's stored file state and the authorization exchange,
  and the complete rewritten object is validated against the admitted
  schema before bytes move. The display *name* is the one deliberate
  exception — it is a presentation hint the caller may choose (it also
  feeds picker-style extension-hint matching), and it never carries
  integrity or authority.
- Translation is isolated from the strict path: a URI-string value is
  replaced by a plain string and never widens into the object shape, so a
  draft revision to the SEP input contract cannot silently alter the
  extension, nor the reverse.

An authorization result contains a required transfer descriptor for the
requested direction. HTTPS `GET`, raw `PUT`, raw `POST`, and streaming
`multipart/form-data` upload are represented. A descriptor URL must use HTTPS —
with one narrow exception for an upstream the gateway already dials in
cleartext, described under the address-pinning rules below — and must never
contain userinfo. Its URL scheme must also be the transport it declared, so a
descriptor cannot claim one protection level and run at another. Expiry is
parsed but the endpoint remains the authority because client clocks can differ.

The reference host follows bounded download redirects. It drops descriptor and
helper-provided headers before a cross-origin redirect. It never replays an
upload after a redirect because replay would require buffering or reopening the
source; the caller must obtain a fresh descriptor instead.

## Streaming and local publication

The reference client uses real MCP custom requests and real loopback HTTPS. An
unknown-length upload begins reaching the server before the producer supplies
its final chunk, proving that the client does not pre-buffer the body. Uploads
are single-pass and calculate SHA-256 and byte count while streaming.

Production uploads and downloads follow the same rule. The client upload
endpoint writes each request chunk to a temporary file while counting bytes
and calculating SHA-256. The file becomes usable only after the complete body
matches any declared size and digest. The transfer request and stored file are
then completed and published in one database transaction. An interrupted,
mismatched, or uncommitted upload never becomes a ready file.

A client upload must deliver at least 64 KiB or finish within each 30-second
progress window. Empty chunks and smaller accumulated amounts do not extend
the window. Each 64 KiB of progress starts a new window; a large burst does not
bank time for a later stall. The window begins before storage setup and also
bounds final storage writes after the body ends. An upload can run for as long
as it keeps making progress within its authorized byte limit. Once byte staging
finishes, admission is released before durable authority publication, which
retains its existing completion and uncertainty rules. A stalled upload releases its
transfer slot when the progress deadline expires. Other staging failures also
release their slot before cleanup. The gateway then allows up to five seconds
to record failure and remove the partial file before returning HTTP 408 with
`upload_progress_timeout` for a stall, or HTTP 400 with `invalid_upload` for
other staging failures. If finalization is blocked or fails,
incomplete content remains unavailable: deletion state is retained when it was
recorded, while abandoned pending files and requests follow their existing
five-minute inactivity recovery. The sweeper retries cleanup when storage is
available. Cancellation also leaves incomplete content unavailable until cleanup.
Obtain fresh upload authorization before retrying a failed attempt.

That transaction is the durable boundary: the file, request, and grant are
either all pending or all completed. If the database loses the commit
acknowledgement, the gateway checks the joined state before answering. If that
check also loses its connection, it returns `completion_unknown` rather than
claiming success or claiming that cleanup removed a file which may have
committed. This is the unavoidable last-acknowledgement case; another receipt
transaction would only move the same race.

For downloads, the gateway writes each response
chunk to a temporary file as it arrives while counting bytes and calculating
SHA-256. It rejects a declared size or digest mismatch. If the MCP `FileValue`
and the HTTP response both name a media type, they must agree. The temporary
file authorization may fill missing size, digest, or media-type checks, but it
cannot add a filename or other display text to the already-inspected tool
result. The temporary file becomes available only after the complete tool
result passes its output schema check. A failed transfer, check, or schema
validation removes it.

Public HTTPS file links may point at object storage or another delivery host.
The gateway resolves and pins those addresses before connecting, rejects local
or private addresses, and refuses headers that could change the destination.
A private address is allowed only when it has the same hostname as the MCP
server that returned it, or when the MCP server is a local process. For a
network upstream, the file client reuses the address set pinned when that MCP
connection was opened instead of resolving the name again. This keeps ordinary
signed object-store links working without giving an upstream a way to probe
unrelated private services. The HTTPS file service may use a different port on
that same host; control and file endpoints are often separate. The upstream
already supplies the request headers and the gateway adds no caller or gateway
credential to that request.

Transfer descriptors must use HTTPS, with one narrow exception: an upstream the
gateway already dials in cleartext may return a plaintext descriptor for its own
pinned host. Both conditions are required. The destination must classify as
pinned — the descriptor names the same host as the MCP endpoint, so the transfer
reuses the address set pinned when that connection was opened — and the
upstream's live MCP connection must itself be wholly cleartext.

Streamable HTTP qualifies when its manifest URL is cleartext HTTP. Legacy SSE
qualifies only after its endpoint handshake has shown that both the receive URL
and the server-issued message endpoint are cleartext HTTP on the same host.
Mixed-scheme or cross-host SSE connections do not qualify. Stdio never
qualifies, even if a permissive manifest carries a URL which its local-process
dial path ignores.

The reasoning is that TLS on that leg would protect nothing. The gateway has
already sent that upstream its tool arguments, any inline `data:` payload, and
the file reference authorizing the transfer, in the clear, across the same
segment to the same host. Encrypting only the bytes is a rule with no
corresponding property. What it did have was a cost: an upstream reachable only
on a private network with no proxy in front of it — a sidecar on a
gateway-owned segment, say — could not use the file plane at all without
standing up a TLS terminator, or a certificate authority, or a public hostname
that gives away the isolation which made the arrangement safe in the first
place.

On that qualifying leg, the gateway includes `http` alongside `https` in the
per-request file capability sent to the upstream. Protected control-plane and
local-process legs continue to advertise HTTPS only. This keeps descriptor
negotiation aligned with the observed connection property that governs whether
the gateway will execute it.

The exception cannot widen. A public destination is a host the gateway never
agreed to reach in cleartext and still requires HTTPS. An upstream whose MCP
endpoint is `https` still requires HTTPS on its file leg, so this can never be
used to downgrade a protected connection. A local process keeps the requirement,
because the argument is about a pinned network segment and stdio has none. There
is no setting: the condition is a property of the connection, and an operator
toggle would let cleartext be enabled where the reasoning does not hold.

Retention starts when the complete tool result is published. While another
member of a multi-file result is being authorized or streamed, the gateway
renews the whole pending batch so an earlier completed member cannot expire.
The sweeper removes a pending file only after those renewals stop, such as
after a process crash. Completed files expire and are removed by the same
sweeper. The storage path must be shared by all gateway replicas that can serve
a later download, and those replicas must use the same storage identity. Newly
created storage directories use mode `0700` and new files use `0600`; an
existing operator-provisioned directory keeps its chosen permissions.

After a client upload or download starts, it renews its authority row once a
minute. Grant expiry blocks new transfers but does not stop a live stream. If a
process exits and those renewals stop, the sweeper fails the abandoned request
after five minutes and removes its expired rows. Deleting a tenant marks its
stored files for removal but keeps each storage key until the file and any
partial write have actually been deleted, so cleanup can be retried after a
failure.

These are transfer mechanics, not product limits. The native reference client
has no total timeout; callers may configure one or cancel the operation. The
generic `mcp-files` helper uses an explicit bounded transfer deadline so a
stalled direct process does not wait forever. Resumable or range transfers are
deliberately deferred until the provider contract is known, so this draft does
not create a gateway-specific chunk protocol.

One shared limit covers both files arriving from MCP servers and files leaving
for clients. If every slot is busy, a new transfer fails immediately so the
caller can retry; it is not held in an unbounded queue. The limit controls open
streams, not file size.

## Native and generic clients

A file-aware MCP host calls `files/authorizeUpload`, keeps the returned HTTPS
instructions private, streams the local file, and gives only the returned
stable `FileValue` to the model. The upload authorization does not name a tool:
the file can be retained and used later. When a tool with an annotated file
input is called, the normal invocation gates choose and authorize that tool;
the gateway then obtains a fresh, upstream-private upload descriptor and
streams the stored file before dispatching the tool call.

The same host calls `files/authorizeDownload` for a gateway-owned file, keeps
the returned HTTPS instructions private, downloads the file, and gives only
the stable `FileValue` to the model. Native upload and download bearer
credentials are short-lived and can start one transfer for one file. They are
not the client's broad MCP credential.
The draft does not define a proof-of-possession field for this native path, so
the standard response uses that narrow bearer credential. Each native method is
available only when the client declares that transfer direction over HTTPS.
Neither is offered for a plain HTTP public URL.

A general-purpose client that lacks SEP support can run a helper in any
language. For upload, the helper creates a temporary signing key, calls
`gateway-files.prepare_upload` with the key thumbprint and any known name,
media type, size, or SHA-256 digest, exchanges the returned opaque handle over
the fixed credential endpoint, and streams the local file with `PUT`. The tool
result spells out every field and header. After a successful upload the client
keeps only `file.uri` and its safe metadata; it never puts the file bytes,
local path, transfer credential, or upload URL in a tool argument.

The `mcp-files` reference helper reads the first complete JSON value by default,
so a process host can write either compact or formatted JSON without signalling
EOF. Explicit EOF-delimited (`--input-framing eof`) and compact
newline-delimited (`--input-framing jsonl`) modes remain available for hosts
that require fixed framing. Every mode is size-bounded, and the modes that can
run with an open stdin reject a partial frame after a bounded wait. The
canonical input is the prepare call's `structuredContent`.
A whole call result is also accepted. If a client adapter drops
`structuredContent`, compatibility is limited to exactly one text content block
whose entire text is the JSON prepare result; explanatory prose and multiple
blocks are rejected rather than heuristically scraped.

Credential exchange and byte transfer use separate explicit deadlines. Once an
upload request begins, a transport timeout or the gateway's
`completion_unknown` response is reported as an ambiguous outcome rather than
as a safe retry. The error preserves the safe file URI. The caller reconciles
it with the read-only `gateway-files.upload_status` tool before preparing
another upload: `ready` proves atomic publication, `prepared` and `in_progress`
do not authorize a duplicate, and `failed` or `expired` permit a fresh prepare.
The status lookup is owner- and credential-profile-scoped, consumes no grant,
and exposes no handle, credential, key material, or private endpoint.

The gateway upload is intentionally separate from the later upstream upload.
This matches `files/authorizeUpload`, which has no target-tool field, and lets
the same ready file be used in a later authorized call. The gateway never
fetches a caller-supplied URL. It rewrites only gateway-owned URIs found at
input fields marked `x-mcp-file` with upload enabled. When a credential profile
restricts source tools, the consuming credential must also permit the tool or
built-in operation that produced the stored file.

For download, the helper needs:

1. the gateway file URI from the earlier tool result;
2. a temporary key it creates for this transfer; and
3. a destination path on the local machine.

The Rust reference host models the second input as a
`TransferCredentialProvider`. It does not assume access to the MCP client's
OAuth or CIMD cache. The gateway supports that separation as follows:

1. The helper creates a temporary asymmetric key. The client calls
   `gateway-files.prepare_download` with the gateway file URI and the key's
   RFC 7638 SHA-256 thumbprint.
2. The tool returns file metadata, an opaque grant handle, and fixed exchange
   and download URLs. It returns no file bytes or bearer credential. The handle
   cannot be redeemed without the temporary private key.
3. The helper sends an RFC 9449 DPoP proof directly to
   `POST /file-transfers/credentials` and puts the grant handle in the JSON
   body as `grant_handle`. No MCP bearer is sent, and the opaque handle is not
   placed in request URLs or routine HTTP traces.
4. The gateway returns a short-lived `DPoP` transfer credential bound to that
   key. The helper sends a fresh proof when it starts the download. The
   credential stays in headers and out of URLs and model-visible objects.

Each grant records who owns the file, which invocation produced it, the file
URI, direction, source, destination, expiry, request count, media type, size,
and digest. API-key server and tool restrictions are checked again when the
download is prepared. The database stores hashes of grant handles and transfer
credentials, not their usable values. DPoP proof IDs are claimed atomically so
two gateway replicas cannot accept the same proof.

Preparing either a native or helper download creates short-lived grant state,
so both paths consume the same configured call and side-effect rate limits and
share the file-transfer concurrency limit. The helper tool is not advertised
as read-only. Invalid or unowned file requests are rejected before they consume
a quota token.

Grant and credential expiry prevent a new download from starting;
they do not terminate a request that was already authorized. Each start gets a
durable authorization identifier, so a large stream can finish without an
implicit total timeout while stale credentials still cannot begin new work.
Each allowed request finishes separately. A size or digest mismatch is written
to the audit log before the request is marked failed. If a required audit write
fails while issuing authority, the gateway withholds the new credential or
authorization and tries to revoke it.

A file downloaded from an upstream keeps the invocation identifier of the tool
call that produced it. For an uploaded client file used later, required
delivery evidence links the upload preparation to the consuming tool call
before dispatch continues. Separate audit entries record byte arrival and
declared size, digest, and media-type checks. This gives operators an end-to-end
trace without recording file bytes or usable credentials.

The result names every HTTP method, URL, header, request field, and response
field needed by a helper. Python-style download pseudocode is intentionally
ordinary:

```python
key = create_temporary_signing_key()
prepared = call_prepare_download(
    file_uri,
    helper_jkt=rfc7638_thumbprint(key.public_key()),
)
exchange = prepared["credential_exchange"]
exchange_proof = sign_dpop(key, method="POST", url=exchange["url"])
credential = http.post(
    exchange["url"],
    headers={"DPoP": exchange_proof},
    json={exchange["grantHandleField"]: prepared["grant_handle"]},
).json()[exchange["accessTokenField"]]

download = prepared["download"]
download_proof = sign_dpop(
    key,
    method="GET",
    url=download["url"],
    access_token=credential,  # adds the RFC 9449 `ath` claim
)
with http.stream(
    "GET",
    download["url"],
    headers={"Authorization": f"DPoP {credential}", "DPoP": download_proof},
    follow_redirects=False,
    timeout=None,
) as response:
    response.raise_for_status()
    stream_to_temporary_file(response.iter_bytes())
```

For a download, stream response chunks to a sibling temporary file, enforce a
declared size while reading, compare the complete SHA-256 digest, then rename
the verified file into place. On a cross-origin redirect, discard all supplied
headers and use only authority carried by the new URL or a newly scoped
credential. Libraries differ in their streaming and redirect defaults, so a
helper must set those behaviors explicitly.

## Machine-readable errors

A message string is unstable machine input, so every file-transfer refusal
and failure carries a bounded recovery category. On the MCP surfaces —
native `files/authorize*` methods and the `gateway-files.*` fallback tools
alike — the category travels as `error` inside the JSON-RPC `error.data`,
the same bounded field name the gateway's other machine-readable envelopes
use; wherever a `reason` field appears it is human prose. The file
vocabulary is: `unsupported_capability`, `authentication_required`,
`invalid_file_input`, `invalid_tool_contract`, `file_unavailable`,
`not_enabled`, `quota_exhausted`, `temporarily_unavailable`,
`policy_violation`, `integrity_mismatch`, `transfer_failed`, and
`completion_unknown`. Upstream file-authorization failures reach the caller
as a bounded `transfer_failed`; the upstream's own message is deliberately
retained nowhere — the gateway log records only the bounded error code,
because an upstream-controlled message could carry a signed URL or
credential. Two adjacent
surfaces contribute their own bounded values on the same field:
authorization denials use the governed-tool envelope shared by every
built-in (`forbidden`, and the step-up shape), and a quota refusal uses
`rate_limited` with its retry metadata. The HTTPS transfer endpoints keep
their existing `error` body field, which uses the same words where the
concept exists there (`file_unavailable`, `temporarily_unavailable`,
`completion_unknown`) plus credential-exchange values from the OAuth
vocabulary. Surfaces may encode detail differently; the bounded category
sets and their meanings are the stable contract.

Two boundaries are deliberate: a file that exists but is not owned is
indistinguishable from one that does not exist (`file_unavailable`), and no
category or message exposes storage keys, provider detail, signed URLs, or
credentials — audit evidence carries the richer operator-facing record.

## Threat-model rationale

A malicious model that can select files, invoke tools, or run code already has
easier ways to substitute an upload or request an unwanted transfer. A helper
proof or narrow token does not attest that the model is benign. Its useful job
is narrower: keep the broad MCP credential in the MCP client, keep transfer
authority out of URLs and model context, and limit the credential used for the
file download. Destination policy remains an authorization and client-policy
decision.

A tool schema may admit inline `data:` values under `transferModes`. These are
upstream input values: the gateway enforces the declared mode and content
constraints and forwards them without creating gateway file-transfer authority.

## Gateway settings

`GATEWAY_FILE_STORAGE_DIR` enables production uploads, upstream delivery, and
downloads, and requires `GATEWAY_DATABASE_URL`.
The published container runs as uid/gid `65532`; its conventional
`/var/lib/mcp-gateway/files` path is pre-created with that ownership so a fresh
Docker named volume mounted there is writable. An existing volume keeps its
old ownership across image upgrades, and custom paths or bind/shared mounts
must likewise be made writable by `65532` by the operator. `/readyz` does not
write-probe this directory, so include a real upload in post-deploy validation;
explicitly repair or replace/migrate an older root-owned volume.
`GATEWAY_FILE_RETENTION_SECONDS` controls how long a saved file remains
available and defaults to 24 hours. An upstream that stages secret material can
mark it by returning `"sensitivity": "secret"` in its `files/authorizeDownload`
result; the gateway then stores that file under the shorter
`GATEWAY_FILE_SECRET_RETENTION_SECONDS` window (default 5 minutes) instead of
the general retention. The secret window is clamped to the general one when
the general retention is configured shorter: the hint can only shorten a
file's life, never extend it. The member is an extension the gateway reads leniently:
an absent or unrecognized value simply selects the general retention, so
upstreams that never send it are unaffected. The class is recorded on the
stored file, so batch keepalive and publication preserve it per file:
retention still starts at publication, but each file's clock runs for its own
class window, so a secret-marked file can never be moved onto the general
window by a sibling's renewal or by publication. When file storage is enabled, production
deployments must set an HTTPS `GATEWAY_PUBLIC_URL`. Plain HTTP is accepted only
for a loopback address used by local development, and only the generic helper
path is available there.

One tool call is capped at 1 GiB of staged bytes unless
`GATEWAY_FILE_MAX_BYTES` sets a different ceiling. The budget is counted across
every file a single result carries, not per file: a result may reference many
files, so a per-file check alone would leave the call itself unbounded. The cap used to be absent by default, which left a
deployment that never set the variable with no bound at all: an upstream
declaring a file with no `size` could stream into the storage directory until
the volume filled, and the concurrency limit below bounds simultaneous streams
rather than bytes, so a single call was enough. Raise the value if the
deployment genuinely moves larger files; there is deliberately no setting for
"unlimited". `GATEWAY_FILE_TRANSFER_CONCURRENCY` limits simultaneous inbound and
outbound file streams separately from normal MCP calls and defaults to 8. These
limits apply within each gateway process. One owner, identified by tenant,
issuer, and subject, can use at most half the configured slots rounded up.
With the default, one owner can use four slots, leaving capacity for other
owners. A configured global limit of one still permits one transfer. Admission
fails immediately when either limit is full; there is no waiting queue.
Owner exhaustion returns HTTP 503 with `owner_transfer_capacity_exhausted` on
the byte endpoint. That authorized attempt is failed, so obtain fresh transfer
authorization before retrying after capacity becomes available. Outbound MCP
transfers report temporary unavailability through the existing transfer error.
None of these settings buffer a complete file or set a total transfer timeout.

## Elicited files across MRTR retries

An upstream that discovers mid-call that it needs a file can pause with an
`input_required` elicitation; the caller answers and retries the original
request with `inputResponses` and the echoed `requestState`.

`requestState` crosses an untrusted client, so MCP requires a server whose
state influences authorization or business logic to integrity-protect it,
reject what fails verification, and bind the authenticated principal, an
expiry, and the originating request inside that protection. The gateway is a
server at its own hop, so when it relays a pause it seals its own AEAD
envelope — principal, tenant, selected server and tool, and a 30-minute
expiry — around whatever the upstream minted. On the retry it verifies and
unwraps that envelope and hands the upstream exactly its own opaque state,
or none when the upstream minted none. Conformant clients echo the value
unmodified without inspecting it, so the wrapping is invisible to them, and
nothing is persisted: every fact needed to serve a retry travels in the
retry, so any replica still answers any retry.

On the retry, elicited files follow the same governed path as ordinary file
arguments. The caller uploads through either the native method or the
fallback tools as usual and places the returned gateway file URI in its
response. Before the retry dispatches, the gateway walks the caller-authored
`inputResponses` for the self-describing `mcp-file://gateway/` namespace —
nothing else is ever treated as a file there — and for each reference checks
ownership, credential-profile restrictions, and the consuming invocation
binding, obtains a fresh upstream upload authorization, streams the bytes,
and replaces the gateway URI with the upstream-private URI. A gateway
reference never reaches the upstream unresolved, and the delivery leaves the
same audit evidence as an argument delivery.

That envelope is what makes an elicited file safe to deliver: files are
delivered only for a retry whose continuation state verifies as one this
gateway sealed. What it binds is the principal, the selected server and
tool, and a digest of the caller-authored arguments — taken before file
rewriting, so the pausing leg and its retry identify the same call. An
envelope minted for one call therefore cannot be presented on another,
even by the same caller to the same tool.

It also seals the response keys that pause issued, so a retry may answer
only what its own pause asked, and separately the subset of those asked by
an elicitation. Only those may carry a file: a sampling or roots request is
answered by the client itself rather than by a human choosing a file, so it
authorizes no upload. A fabricated, transplanted, cross-call, expired, or
invented-key continuation is refused before quota and before any authority
is taken, so a caller cannot steer the gateway into uploading an owned file
to a tool that never elicited one. A tool with no declared file input can
still elicit a file, because provenance — not the destination's schema — is
what authorizes the delivery; a gateway file reference that would not be
delivered under these rules is refused rather than forwarded unresolved.

Within an elicitation, delivery is bounded by the issued key rather than by
which field asked for a file. The pinned MCP library parses elicitation
schemas into typed structures and discards unknown keywords, so the
upstream's own `x-mcp-file` marker does not survive the pause relay and
cannot be sealed; an elicitation key is the finest grain available. What
remains is that a caller may answer one of its own pause's non-file
elicitation keys with a file reference, which the gateway delivers and the
eliciting upstream then rejects as an unexpected value.

The seal key comes from `GATEWAY_MRTR_STATE_KEY` (32 bytes, base64url or
64-char hex) and must be identical across every replica of a deployment,
since any replica may serve any retry. Without it the gateway relays pauses
exactly as before and refuses elicited files rather than delivering them
without provenance; a malformed key fails boot.

Two further boundaries are deliberate. First, elicitation responses carry no
gateway-trusted schema: the elicitation schema is authored by the upstream
and answered back to that same upstream, so declared constraints such as
`accept` or `maxSize` on elicited fields are the asking upstream's to
enforce on receipt — the gateway must not trust a client-echoed copy of the
schema, and it does not persist pause state to obtain one, which would break
replica independence. Second, approval-gated calls remain single-round: a
continuation on an approval-gated call is refused before quota and the
one-time grant claim, so elicited files never interact with approval
consumption. On a gateway without file storage, a continuation carrying a
gateway file reference is refused deterministically before quota with the
same not-enabled category as ordinary file inputs.

## Result surfaces

The draft proposes several places a generated file can appear: a `FileValue`
in `structuredContent`, a `type: "file"` content block, and optionally
file-backed resource contents. Those are projections of one logical file, and
the gateway treats them that way: there is exactly one publication path — the
output processor stages every upstream file in a private batch, validates the
complete tool result, then publishes the batch atomically — and every result
surface is a view over that one published file. A file therefore has one
gateway identity, one retention clock, one authorization scope, and one audit
chain no matter how many surfaces project it; a projection must never grow
its own download or storage logic.

Which projections exist today:

- **`structuredContent`** carries `FileValue` objects now. It is the broadly
  usable projection: tool-only and older clients read it without any SEP
  support, so it remains produced even after richer projections are added.
- **The `type: "file"` content block** cannot be represented by the pinned
  Rust MCP library; adding it depends on the library exposing that shape.
  When it lands it is fed from the same published file, and the gateway does
  not emit a hand-built raw-JSON approximation ahead of the library — a
  second wire stack would drift from validation, schema, and error behavior.
- **File-backed resource contents** use a request-local, negotiated bridge.
  When a downstream `resources/read` request advertises HTTPS download support,
  file storage is enabled, and the gateway's public URL can serve native HTTPS,
  the gateway forwards that capability to the selected upstream. A loopback
  HTTP deployment keeps the inline path because it cannot hand the client a
  usable native download descriptor. The upstream may then place a draft `FileValue` in
  `_meta["io.modelcontextprotocol/fileResourceContents"]` on an otherwise
  typed text or blob resource content. The pinned Rust MCP library does not yet
  model the draft's top-level resource `content` variant, so this namespaced
  metadata is the narrow compatibility representation rather than a second
  hand-written protocol stack. The gateway pulls, validates, stages, and
  atomically publishes the file through the same lifecycle as tool output,
  then replaces the nested value with its governed gateway `mcp-file:` URI.
  Without that per-request capability the gateway strips any file signal and
  the upstream must return ordinary inline contents. File URIs and resource
  URIs remain distinct: a file URI resolves through file-transfer
  authorization, never through `resources/read`.

  The MCP response that carries a file descriptor is itself bounded by
  `GATEWAY_RESOURCE_RESPONSE_MAX_BYTES` (4 MiB by default), before rmcp decodes
  it. That is intentionally separate from `GATEWAY_FILE_MAX_BYTES` (1 GiB by
  default): the first protects gateway memory while materializing the resource
  envelope, while the second governs streamed file bytes. Text resource
  contents also pass through the normal response-inspector chain before any
  file is staged or published; binary resource contents are not interpreted as
  text.
