# Host a client identity document

`mcp-test-client login` uses a Client ID Metadata Document (CIMD): the
client ID is the HTTPS URL of a JSON document that describes the client.
Choose and host that identity explicitly. The client has no built-in document
URL and does not contact a maintainer's server by default.

Bearer-token and unauthenticated client modes do not require a CIMD URL.
An interactive OAuth login does; without one it fails locally before discovery.
Set `--cimd-url` or `MCP_TEST_CLIENT_CIMD_URL` to the hosted document URL.

## Publish a document

1. Copy [the client template](../../../cimd/mcp-test-client.json).
2. Replace its example `client_id` with the exact HTTPS URL where you will
   serve the document. Use a non-root path without credentials, a query, or a
   fragment. Keep the redirect URIs appropriate to this CLI's loopback callback.
3. Serve the JSON from an operator-controlled public HTTPS origin. The gateway
   must be able to fetch it without authentication or redirects. Metadata is
   public; never put a credential in the document.
4. Log in using your gateway and the matching document URL:

```sh
mcp-test-client --gateway https://gateway.example.com \
  --cimd-url https://clients.example.com/mcp-test-client.json login
```

The hostnames above are placeholders. A private Git web interface that requires
login or resolves to a private address is not a suitable public document host.
The gateway's fetcher checks destination addresses, pins DNS results, refuses
redirects, and bounds response size and duration.

The optional [Git publisher](../../../scripts/publish-cimd.sh) renders the
same template. It requires both `CIMD_WELL_KNOWN_REPO` (authenticated Git
access through your existing client) and `CIMD_CLIENT_ID_URL` (the served URL).
Keep those deployment choices in your own configuration. Run
`scripts/publish-cimd.sh --dry-run` first: it validates and prints the rendered
public document without contacting Git. Running without `--dry-run` commits
and pushes `mcp-test-client.json` at the destination repository root. Configure
that repository's hosting separately and verify the served URL after publication.

## Host development documents on the gateway

An operator can enable a small, disk-backed registry by setting
`GATEWAY_AS_CIMD_DEV_DOC_DIR` with the built-in authorization server enabled.
Mount a directory of client JSON documents read-only into the container:

```yaml
environment:
  GATEWAY_AS_ENABLED: "true"
  GATEWAY_AS_CIMD_DEV_DOC_DIR: /etc/gateway/cimd-dev
volumes:
  - ./cimd-dev:/etc/gateway/cimd-dev:ro
```

A file named `mcp-test-client.json` is served at
`https://gateway.example.com/cimd/dev-clients/mcp-test-client.json`; set its
`client_id` and the CLI's `--cimd-url` to that same URL. Use the gateway's actual
configured public origin, including its port when applicable. Unsetting the
directory disables this feature. Permission to write this directory is
permission to define these client identities; it is not a public registration API.

For a URL on the authorization server's own origin and within this exact
registry route, the gateway reads the configured local file directly and
validates its metadata. This supports split-horizon DNS without relaxing the
remote-fetch destination checks. It is a local registry lookup, not the draft's
loopback network exception. See the [fetcher](../../waygate-as/src/cimd.rs)
and [document host](../../waygate-as/src/cimd_dev_host.rs).

## Upgrade existing clients

Keep using the same hosted identity when refreshing an existing session.
The token cache records the original client ID and uses it for refresh.
For an older cache that lacks that field, explicitly supply the original URL
or log in again with your chosen identity. Changing a URL does not migrate a
refresh token to a different OAuth client.

## Standards and implementation scope

The [IETF CIMD draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
is work in progress. Revision
[02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02),
published July 6, 2026, describes document services in its non-normative
Appendix A and SSRF considerations in section 8.6. The gateway implements
public-client CIMD login with PKCE and `token_endpoint_auth_method: none`;
`private_key_jwt` is not implemented. This is a description of the implemented
subset, not a claim of complete conformance to every revision of the draft.
