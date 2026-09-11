# Configuration

Start with the [runnable tutorial](../README.md#quick-start-local) for local
evaluation. For an authenticated installation, use
[`.env.example`](../.env.example) as a checklist and follow
[deployment guidance](deployment.md). The example contains deliberately invalid
placeholders; replace them through your deployment's configuration and secret
management before starting the gateway.

## Loading settings

The gateway reads the process environment at startup. It does not automatically
load `.env`. A native launcher or service manager must export the settings;
a container deployment must explicitly pass them with its environment or
`env_file` configuration. Paths are interpreted inside the gateway process's
filesystem, so a host secret file needs a corresponding container mount.

The repository's Compose file is a fixed, disposable tutorial. It interpolates
`POSTGRES_PASSWORD` and the optional `GATEWAY_IMAGE` image name. It does not
forward arbitrary settings from `.env` into the gateway. Its local issuer,
policies, and read-only mounts demonstrate a first call. Put authenticated
deployment wiring in your own overlay instead of repurposing the tutorial.

Leave unused optional variables absent. An empty string is not consistently
equivalent to absence: an empty signing-key path attempts to read an empty
filename, for example. Partial credential groups can fail startup. Change
environment settings by restarting the process; SIGHUP reloads manifests and
policies, not the environment. See
[runtime configuration ownership](server-config-source-of-truth.md) for
publication, recovery, and multi-replica coordination.

## Required deployment settings

These defaults describe the binary, which may differ from the tutorial's
explicit values. Ordinary URLs, client identifiers, key identifiers, and file
paths are configuration metadata. Password-bearing database URLs, client
secrets, encryption keys, and private signing-key contents are credentials.
Keep credential values out of Git and diagnostic output.

| Setting | Default or requirement |
| --- | --- |
| `GATEWAY_LISTEN_ADDR` | `0.0.0.0:8080`. Use `127.0.0.1:8080` for a native local listener. Inside a container, bind its interface and restrict host publication or ingress separately. |
| `GATEWAY_PUBLIC_URL` | Derived from the listener unless set. Set the public HTTPS origin used by clients; it determines the gateway issuer and default callback URLs. |
| `GATEWAY_AUDIENCE` | Defaults to the public URL. External access tokens must name the configured audience. |
| `GATEWAY_AUTH_MODE` | `enforce`; requires `AUTHENTIK_ISSUER`. `disabled` is accepted only by debug builds and disables both bearer authentication and Cedar enforcement. |
| `GATEWAY_DEPLOYMENT_PROFILE` | `dev`. Set `prod` for deployment safety checks; this is independent of the Cargo build profile. |
| `AUTHENTIK_ISSUER` | Required in enforce mode and with the built-in authorization server. The issuer must expose OIDC discovery and JWKS. |
| `GATEWAY_DATABASE_URL` | Unset uses a warning-producing null audit sink in development. Required by the production profile, built-in authorization server, and persistent file/Code Mode features. Contains a database credential. |
| `GATEWAY_SERVERS_DIR` | `/etc/mcp-gateway/servers`; deployment-owned upstream manifests. |
| `GATEWAY_POLICIES_DIR` | `/etc/mcp-gateway/policies`; deployment-owned Cedar policies. |
| `GATEWAY_POLICY_EDITING` | On by default; `false` disables policy mutation. Publication also requires a writable persistent policy directory. |

The production profile additionally requires dashboard authentication and rejects
stdio upstreams and deprecated upstream-token passthrough. The profile does not
provision TLS, register OAuth clients, or make example policies appropriate for
your organization. Supply those deployment decisions explicitly.

## Dashboard and authorization server

Dashboard login and the built-in OAuth authorization server have separate
credential groups and callback routes. Configure each OAuth client at the
identity provider before enabling it.

| Group | Required together | Purpose and format |
| --- | --- | --- |
| Dashboard | `GATEWAY_DASHBOARD_CLIENT_ID`, `GATEWAY_DASHBOARD_CLIENT_SECRET`, `GATEWAY_DASHBOARD_SESSION_KEY` | Client identifier, client secret, and a distinct random 32-byte session key encoded as base64 or 64 hexadecimal characters. Callback defaults to `<public URL>/admin/auth/callback`. All absent leaves dashboard login disabled in development; a partial group fails startup. |
| Built-in authorization server | `GATEWAY_AS_ENABLED=true`, `GATEWAY_AS_UPSTREAM_CLIENT_ID`, `GATEWAY_AS_UPSTREAM_CLIENT_SECRET`, `GATEWAY_UPSTREAM_TOKEN_KEY` | Client identifier, client secret, and random 32-byte key in standard base64 for stored upstream-token encryption. Also requires the issuer, database, and signing key. Callback defaults to `<public URL>/oauth/callback`. |
| Signing key | Exactly one of `GATEWAY_IDENTITY_SIGNING_KEY_PATH` or `GATEWAY_IDENTITY_SIGNING_KEY_PEM` | Ed25519 PKCS8 PEM. Prefer a read-only secret mount and the path setting. `GATEWAY_IDENTITY_KID` labels the public verification key; its default is `gateway-v1`. |
| Signing-key rotation | `GATEWAY_IDENTITY_JWT_KEYS` and `GATEWAY_IDENTITY_JWT_ACTIVE` | Comma-separated `kid:path` entries and the active signing identifier. This pair takes precedence over the single-key settings. Preserve verification keys while tokens issued under them remain valid. |

The session key and token-encryption key must be independently generated and
stored securely. They are not OAuth client secrets or signing keys. The
[identity guide](agents/identity.md) explains registration and key rotation,
including the versioned `GATEWAY_UPSTREAM_TOKEN_KEY_<id>` family. Do not combine
that family with the legacy single-key `GATEWAY_UPSTREAM_TOKEN_KEY` setting.

For a resource-server-only deployment, leave `GATEWAY_AS_ENABLED` absent or
false and omit its credential group. The gateway validates external tokens
against the issuer and audience; clients need an authorization flow compatible
with that provider. The tutorial's disposable issuer is not such a login
service. Changing to resource-server-only mode does not remove the production
database or dashboard requirements.

## Optional capabilities

Enable only the services you intend to operate. Each setting below is read at
startup; runtime catalogs and policies have their own governed update paths.

| Capability | Starting settings and dependencies |
| --- | --- |
| File transfer | `GATEWAY_FILE_STORAGE_DIR` plus the database. Use storage accessible to every serving replica. The directory enables uploads and downloads; leaving it absent disables those production paths. See [file transfer](file-transfer.md). |
| Durable Code Mode results | `GATEWAY_CODEMODE_RESULT_STORAGE=allow` plus the database. Default is `disabled`; persistence is an explicit operator choice. See [Code Mode execution behavior](guides/code-mode.md). |
| Code Mode execution budget | `GATEWAY_CODEMODE_EXECUTION_LIMIT_SECONDS`: default 300 seconds (5 minutes), configurable up to 86,400 seconds (24 hours). It bounds program execution, including deliberate waits. Client and upstream operation timers still apply independently. |
| Skills from Git | `GATEWAY_SKILLS_GIT_API_URL`, `GATEWAY_SKILLS_GIT_REPOSITORY`, and `GATEWAY_SKILLS_GIT_ROOTS` are required together. Set `GATEWAY_SKILLS_SOURCE_ID` explicitly. `GATEWAY_SKILLS_GIT_TOKEN_ENV` names a credential variable; it is not the token itself. See [skills from Git](skills-git-source.md). |
| Inference | Model/provider configuration and credentials are opt-in. See [inference configuration](inference-plane.md) for `GATEWAY_LLM_MODELS`, dynamic discovery, and credential labels. These settings can enable provider-network access. |
| Tracing | `OTEL_EXPORTER_OTLP_ENDPOINT` selects the collector; omit it when no collector is available. `OTEL_SERVICE_NAME` identifies this service. See [telemetry](agents/telemetry.md). |

The [runtime setting reference](configuration-reference.md) covers additional
operator controls. The implementation reference is
[`Config::from_env`](../crates/waygate-server/src/config.rs), with subsystem
readers next to the features they configure. The example is intentionally a
deployment starting point, not an exhaustive list of every environment reader.

## Diagnose startup failures

| Symptom | Action |
| --- | --- |
| Enforce mode requires an issuer | Set `AUTHENTIK_ISSUER` to the configured provider's issuer, not its authorization endpoint. |
| Dashboard or token exchange partially configured | Supply the entire named group, or remove all of it when the feature is optional. |
| Signing-key path cannot be read | Check the path inside the container and its read permissions; remove an unused empty setting. |
| Session or upstream key has the wrong length | Supply a newly generated 32-byte key in the required encoding through the secret provider. |
| Production profile refuses startup | Read the named missing requirement; configure it rather than lowering the deployment profile. |
| Database migration failure | Check database reachability and release compatibility. Never edit an already applied migration. |

Use `gateway-server --healthcheck` for the process's `/readyz` probe. A healthy
process does not prove upstream tool calls or an OAuth login work; validate
those with a real client and the intended identity. Avoid dumping the complete
process environment or container configuration when collecting diagnostics.

## Build prerequisites and generated clients

[`rust-toolchain.toml`](../rust-toolchain.toml) selects stable Rust with rustfmt
and clippy. [`Cargo.toml`](../Cargo.toml) declares Rust 1.88 as its minimum, but
CI tests the selected stable toolchain, not a separate 1.88 compatibility job.
Use the selected toolchain for source builds. The container builder pins its
own Rust image in [`Dockerfile`](../Dockerfile).

[`scripts/gen-clients.sh`](../scripts/gen-clients.sh) generates local TypeScript,
Python, and Rust admin clients from the current OpenAPI schema. Generated output
is ignored by Git. The repository does not currently contain a workflow that
publishes these clients to package registries. The generator requires its CLI
and Java; follow the [official installation instructions](https://openapi-generator.tech/docs/installation/).
Record the selected generator version when distributing your generated client.
