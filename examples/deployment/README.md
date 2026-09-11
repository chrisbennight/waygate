# Authenticated single-host deployment

Use this after the [local tutorial](../quickstart/README.md), with an actual
identity provider and your own upstreams and policies. The Compose file
publishes only a loopback gateway port; configure a TLS reverse proxy for the
public URL. It does not provision DNS, certificates, identity clients, or backups.

1. Copy this directory into your deployment repository. Copy the source
   [environment template](../../.env.example) into its ignored `.env`, or have
   your secret provider materialize that file with restricted permissions.
   Never commit the populated file.
2. Follow the [configuration guide](../../docs/configuration.md) to register the
   separate dashboard and built-in authorization-server clients. Replace every
   placeholder, supply cryptographically generated keys, and set the public URL.
   This example follows the template with the built-in authorization server enabled.
3. Add `GATEWAY_IMAGE` as a published image with an immutable `@sha256:` digest,
   `POSTGRES_IMAGE` as your reviewed PostgreSQL image, `POSTGRES_PASSWORD`, and
   `GATEWAY_IDENTITY_SIGNING_KEY_FILE` as an absolute host file path. Set
   `GATEWAY_DATABASE_URL` to the same database credentials at hostname `postgres`;
   URL-encode password characters when constructing the connection URL.
   The container's signing-key path stays `/run/secrets/gateway-identity.pem`.
4. Create `servers/` and `policies/` with your reviewed manifests and Cedar
   policies. The gateway's uid 65532 needs directory traversal and read access;
   dashboard publication also needs write access. The signing key needs read
   access by that uid and no broader access than necessary. Missing bind paths
   fail instead of silently creating empty configuration.
5. From the copied deployment directory, validate without printing resolved
   secrets, then start:

   ```sh
   docker compose --env-file .env config --quiet
   docker compose --env-file .env up -d --wait
   docker compose --env-file .env ps
   ```

The environment file configures the gateway; the Compose file overrides its
listener to `0.0.0.0:8080` inside the container and enforces the production
profile and bearer authorization. It does not enable host-wide network access.
Postgres has no published host port. The file volume is present, but file storage
is enabled only if you set `GATEWAY_FILE_STORAGE_DIR=/var/lib/mcp-gateway/files`.

Verify interactive dashboard login, authenticated MCP discovery, one harmless
permitted call, and one expected refusal. Confirm a durable audit record and
healthy configuration before admitting real traffic. The tutorial issuer is
never a substitute for this login check. See the [operator runbook](../../docs/operations.md)
for acceptance, upgrades, and recovery.

The database directory layout here matches PostgreSQL 17, the major version
exercised in source CI. A newer major image may change its data-directory
contract; review that image and PostgreSQL's upgrade procedure before changing
the database version. This single-host example does not establish high
availability. Multiple gateway replicas need the shared configuration and
storage contracts described in the runbook.
