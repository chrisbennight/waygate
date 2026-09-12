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

## Configure an authenticated deployment

Use the [runtime setting reference](configuration-reference.md) for exact
names, defaults, formats, and required credential groups. Keep credential
values out of Git and diagnostic output.

1. Choose the public HTTPS origin and token audience, then configure the OIDC
   issuer and register the dashboard client with that provider.
2. Provision Postgres and persistent manifest and policy directories. Start
   from the [authenticated deployment example](../examples/deployment/README.md).
3. Select the production deployment profile and mount signing and encryption
   keys through your secret provider. Supply the dashboard credential group
   together; do not reuse its session key as an OAuth client secret.
4. Decide whether to run the built-in authorization server. If enabled,
   register its separate upstream OAuth client and callback and supply the
   complete authorization-server credential group. See
   [identity setup](agents/identity.md).
5. Configure upstream manifests and Cedar policies for your organization,
   then verify an allowed call and an expected refusal before exposing ingress.

The production profile validates settings; it does not provision TLS, register
OAuth clients, or select appropriate access policies for your organization.

## Enable optional capabilities

Choose the services you intend to operate, then use the setting reference for
their configuration. Runtime catalogs and policies have separate update paths.

- [File transfer](file-transfer.md) requires persistent storage visible to
  serving replicas and a database.
- [Durable Code Mode](guides/code-mode.md) requires an explicit decision to
  persist execution data and a database.
- [Git skills](skills-git-source.md) require a source identity, repository
  access, and distribution approval.
- [Model routing](guides/inference.md) requires provider credentials and an
  authorized model catalog.
- [Observability](guides/observability.md) describes telemetry destinations and
  the evidence available for operational diagnosis.

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
