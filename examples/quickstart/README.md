# Your first gateway tool call

This tutorial runs a gateway, Postgres, a small MCP server, and a disposable
test issuer. It demonstrates discovery, a successful tool call, and Cedar
policy enforcement. The upstream
uses the same locked Python MCP SDK environment as the repository's modern
protocol smoke test. Neither demonstration tool changes external state.

## Start

Install Docker with Compose and Python 3. Run these commands from the repository
root. Docker builds the Rust gateway, so a host Rust installation is not needed.
The first build downloads dependencies and can take several minutes.

```sh
POSTGRES_PASSWORD=dev docker compose up --build --wait
python3 examples/quickstart/check.py
```

`dev` is a disposable example database password, not a production credential.
The test issuer gives anyone a short-lived token for a fixed demo identity.
The gateway validates its signature and evaluates Cedar policies, but this is
not a production login system. Both host ports publish only on `127.0.0.1`;
do not expose them through a proxy or use this stack for real data. The issuer
keeps its generated signing key only in memory and replaces it on restart.
Dashboard login is disabled in this development stack, so the dashboard is
also accessible to anyone who can reach the loopback listener.

Expected output:

```text
PASS: discovery exposes the permitted demo tool
Hello, world! Your request passed through the gateway.
PASS: Cedar refuses the restricted tool for the demo identity
```

The check speaks stateless MCP directly, using ordinary `tools/list` and
`tools/call`. It obtains a demo token in memory and never prints it. It needs no
SDK or model-provider account. The gateway endpoint is
`http://127.0.0.1:8080/mcp`; requests require that demo bearer token. The issuer
is a test fixture, not an interactive OAuth server for ordinary client login.
See [the host discovery contract](../../docs/host-tool-discovery.md) for how
client-side deferred loading works with the standard tool catalog.

## Explore

Open [the dashboard](http://127.0.0.1:8080/admin/) to inspect the demonstration.
Real dashboard login requires an interactive identity provider; use the
authenticated deployment guide for that separate workflow.

The [manifest](servers/demo.yaml) names both tools and their risk facts. The
[policy](policies/demo.cedar) permits the demo group's actions but
explicitly forbids `demo.restricted`. Cedar forbids override permits. The
forbidden tool is absent from discovery and a direct call is still refused.

Configuration is mounted read-only in this tutorial. Dashboard publication
requires writable persistent configuration in an authenticated deployment;
see [deployment guidance](../../docs/deployment.md). To experiment locally,
edit the demo files on the host and restart the gateway. These policies are
learning examples, not a production authorization policy.

## Troubleshoot and clean up

If port 8080 or 9090 is occupied, change the corresponding host port in Compose
and pass the new URL to `check.py --gateway` or `--issuer`.

If startup is unhealthy, inspect the demo services:

```sh
POSTGRES_PASSWORD=dev docker compose ps
POSTGRES_PASSWORD=dev docker compose logs gateway demo-upstream demo-issuer
```

The gateway healthcheck calls the binary's `/readyz` probe. The tutorial check
additionally proves that a real tool is callable and that policy denies the
restricted tool. A healthy process alone is not that proof.

If you restart the issuer, restart the gateway too so it immediately loads the
new public key instead of waiting for its cached key set to refresh.

Stop the stack and delete its disposable database when finished:

```sh
POSTGRES_PASSWORD=dev docker compose down --volumes
```

To practice backup and restore with a separate disposable project, run
`python3 examples/quickstart/verify-recovery.py` after building the image.
It uses random loopback ports, repeats the same permit/refusal check after
restoring into a new database, and cleans up its own containers and volumes.
See the [recovery exercise](../../docs/operations.md#practice-recovery-on-disposable-data).
