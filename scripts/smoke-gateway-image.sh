#!/usr/bin/env bash
# Prove a freshly built gateway image boots under production hardening and can
# complete MCP handshakes with both supported upstream protocol generations.
#
# Required environment:
#   GATEWAY_IMAGE_PINNED  exact local image tag produced by build-docker.sh
#   PG_IMAGE             Postgres image used for the migration/boot exercise

set -euo pipefail
IMG="${GATEWAY_IMAGE_PINNED:?build step did not export GATEWAY_IMAGE_PINNED}"
NET=gw-smoke-net
ATTEMPTS=3
READY_TIMEOUT=60
mkdir -p /tmp/gw-smoke-empty-servers
# Policies are no longer baked into the PUBLISHED image (#492); prod
# supplies them via a runtime NFS volume. A `-v /host/path:...` bind
# mount does NOT work for this in the DinD runner: `docker run` resolves
# the mount SOURCE on the docker DAEMON's filesystem — a separate
# container from where these run-steps execute — so a job-staged dir
# arrives EMPTY in the gateway and it fails closed ("loaded ZERO
# policies"; the #492/#493 builds hit exactly this). `docker build`, by
# contrast, sends its context from the JOB side, so build a SMOKE-ONLY
# image that bakes the repo policies on top of the freshly built image
# and run THAT. The published image ($IMG) stays de-baked; the
# runtime-volume path is verified in prod at deploy, not here.
#
# Count the source first with an errexit-safe for-loop (no pipeline;
# `[ -e ]` is a loop condition, exempt from errexit; an unmatched glob
# stays literal in bash and is skipped) so a missing/empty policies/
# fails LOUD here instead of as an opaque downstream "not ready" timeout.
SRC_COUNT=0
for f in crates/waygate-authz/tests/fixtures/policies/*.cedar; do
  [ -e "$f" ] || continue
  SRC_COUNT=$((SRC_COUNT + 1))
done
echo "boot-smoke: found ${SRC_COUNT} policies/*.cedar at cwd=$(pwd)"
if [ "${SRC_COUNT}" -lt 1 ]; then
  echo "BOOT SMOKE SETUP FAILED: no policies/*.cedar to bake from cwd=$(pwd)."
  ls -la crates/waygate-authz/tests/fixtures/policies/ 2>&1 | head -20 || true
  exit 1
fi
SMOKE_IMG="gw-smoke-policies:local"
rm -rf /tmp/gw-smoke-ctx && mkdir -p /tmp/gw-smoke-ctx/policies
cp crates/waygate-authz/tests/fixtures/policies/*.cedar /tmp/gw-smoke-ctx/policies/
printf 'FROM %s\nCOPY --chown=nonroot:nonroot policies/ /etc/mcp-gateway/policies/\n' "$IMG" > /tmp/gw-smoke-ctx/Dockerfile
sudo docker build -t "$SMOKE_IMG" /tmp/gw-smoke-ctx >/dev/null
echo "boot-smoke: built ${SMOKE_IMG} (de-baked image + ${SRC_COUNT} baked-for-smoke policies)"

# The reachability variant: the same smoke image plus ONE upstream
# manifest, baked for the same daemon-vs-job filesystem reason the
# policies are. The attempts above boot with zero upstreams on
# purpose, which means they prove the binary STARTS and can never
# prove it can DIAL anything — the gap that let an image whose every
# upstream handshake failed pass this gate and go straight to the
# fleet.
UPSTREAM_IMG="gw-smoke-upstream-cfg:local"
rm -rf /tmp/gw-smoke-up-ctx && mkdir -p /tmp/gw-smoke-up-ctx/servers
# BOTH manifests, so one gateway boot fronts a legacy peer and a
# stateless-generation peer at once — the shape the fleet actually
# runs, and one boot instead of two.
cp scripts/boot-smoke/upstream.yaml /tmp/gw-smoke-up-ctx/servers/legacy.yaml
cp scripts/boot-smoke-2026/upstream.yaml /tmp/gw-smoke-up-ctx/servers/modern.yaml
printf 'FROM %s\nCOPY --chown=nonroot:nonroot servers/ /etc/mcp-gateway/servers/\n' "$SMOKE_IMG" > /tmp/gw-smoke-up-ctx/Dockerfile
sudo docker build -t "$UPSTREAM_IMG" /tmp/gw-smoke-up-ctx >/dev/null
sudo docker build -t gw-smoke-upstream:local scripts/boot-smoke >/dev/null
sudo docker build -t gw-smoke-upstream-2026:local scripts/boot-smoke-2026 >/dev/null
echo "boot-smoke: built ${UPSTREAM_IMG} + the legacy and stateless Python-SDK upstreams"

cleanup() {
  sudo docker rm -f -v gw-smoke gw-smoke-db gw-smoke-upstream gw-smoke-upstream-2026 gw-smoke-reach >/dev/null 2>&1 || true
  sudo docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
sudo docker network create "$NET" >/dev/null
PEM="$(openssl genpkey -algorithm ed25519)"

# One throwaway Postgres for all attempts (exercises connect + migrations).
sudo docker run -d --name gw-smoke-db --network "$NET" \
  -e POSTGRES_USER=gateway -e POSTGRES_PASSWORD=smoke -e POSTGRES_DB=gateway \
  "$PG_IMAGE" >/dev/null
for i in $(seq 1 30); do
  sudo docker exec gw-smoke-db pg_isready -U gateway -d gateway >/dev/null 2>&1 && break
  sleep 1
done

for attempt in $(seq 1 "$ATTEMPTS"); do
  echo "--- hardened boot attempt $attempt/$ATTEMPTS ---"
  sudo docker rm -f -v gw-smoke >/dev/null 2>&1 || true
  # enforce + an unreachable issuer (JWKS prime is lazy/non-fatal) + AS
  # disabled keeps this hermetic; an empty servers dir = zero upstreams so
  # /readyz isn't gated on dialing real upstreams; the ed25519 key exercises
  # the identity keyring (jsonwebtoken key construction) under hardening.
  sudo docker run -d --name gw-smoke --network "$NET" \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt=no-new-privileges --user 65532:65532 \
    -v /tmp/gw-smoke-empty-servers:/etc/mcp-gateway/servers:ro \
    -e GATEWAY_AUTH_MODE=enforce \
    -e AUTHENTIK_ISSUER=https://stub.smoke.invalid \
    -e GATEWAY_AUDIENCE=https://stub.smoke.invalid/mcp \
    -e GATEWAY_DEPLOYMENT_PROFILE=dev \
    -e GATEWAY_DATABASE_URL=postgres://gateway:smoke@gw-smoke-db:5432/gateway \
    -e GATEWAY_IDENTITY_SIGNING_KEY_PEM="$PEM" \
    -e GATEWAY_IDENTITY_KID=smoke-kid \
    "$SMOKE_IMG" >/dev/null
  ok=0
  for i in $(seq 1 "$READY_TIMEOUT"); do
    if sudo docker exec gw-smoke /usr/local/bin/gateway-server --healthcheck >/dev/null 2>&1; then
      ok=1; break
    fi
    st="$(sudo docker inspect gw-smoke --format '{{.State.Status}}' 2>/dev/null || echo gone)"
    if [ "$st" != "running" ]; then echo "container left running state early (status=$st)"; break; fi
    sleep 1
  done
  if [ "$ok" != "1" ]; then
    echo "BOOT SMOKE FAILED (attempt $attempt): /readyz not healthy within ${READY_TIMEOUT}s under prod hardening — not publishing."
    # Surface the likely-relevant lines FIRST (policy load / authz gate /
    # fail-closed / panic), then a broader tail, then the host-side mount
    # state — so the cause is legible even without the full run log.
    echo "--- container status ---"
    sudo docker inspect gw-smoke --format 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} err={{.State.Error}}' 2>&1 || true
    echo "--- policy / authz / fail-closed lines ---"
    sudo docker logs gw-smoke 2>&1 | grep -iE 'polic|authz|cedar|deny-all|fail|panic|error|refus' | tail -30 || true
    echo "--- full tail ---"
    sudo docker logs --tail 80 gw-smoke 2>&1 | grep -ivE 'tantivy|managed_directory' | tail -50 || true
    echo "--- policies baked into the smoke image (${SMOKE_IMG}) ---"
    sudo docker image inspect "$SMOKE_IMG" --format '{{json .RootFS.Layers}}' 2>&1 | tail -c 200 || true
    echo "(smoke image was built from ${SRC_COUNT} policies/*.cedar; see 'boot-smoke: built …' above)"
    exit 1
  fi
  echo "attempt $attempt: /readyz green under hardening"
done
echo "Boot smoke passed: ${ATTEMPTS}/${ATTEMPTS} hardened boots reached /readyz."

# --- Reachability: can this image actually DIAL a real upstream? ---
#
# The upstream is a Python-SDK server pinned to a release that
# predates the stateless generation, deliberately NOT rmcp: an rmcp
# server answers `server/discover` natively, so a smoke built on one
# proves only that rmcp talks to itself and stays green through the
# client-side changes that break dialing everything else.
echo "--- reachability: dialing real legacy and stateless upstreams ---"
sudo docker rm -f -v gw-smoke gw-smoke-upstream gw-smoke-reach >/dev/null 2>&1 || true
# The gate's assertion runs INSIDE the fixture container, not from a
# pulled utility image: it decides whether the image is published, so
# it has to be content-addressed with this commit rather than a
# mutable third-party tag that could change under it. The gateway's
# own runtime is distroless with no shell or HTTP client, and its
# binary self-probe returns only an exit code, so it cannot host it.
sudo docker run -d --name gw-smoke-upstream --network "$NET" gw-smoke-upstream:local >/dev/null
sudo docker run -d --name gw-smoke-upstream-2026 --network "$NET" gw-smoke-upstream-2026:local >/dev/null
for fixture in gw-smoke-upstream gw-smoke-upstream-2026; do
  up=0
  for i in $(seq 1 60); do
    if [ "$(sudo docker inspect -f '{{.State.Health.Status}}' "$fixture" 2>/dev/null)" = "healthy" ]; then
      up=1; break
    fi
    sleep 1
  done
  if [ "$up" != "1" ]; then
    echo "REACHABILITY SMOKE FAILED: upstream fixture $fixture never started listening — not publishing."
    sudo docker logs --tail 30 "$fixture" 2>&1 || true
    exit 1
  fi
done

# Give this phase its OWN database. The hardened attempts boot a
# zero-upstream manifest set and this phase boots a one-upstream
# set; against a shared database that difference advances the
# manifest turnstile pointer, and waygate-server refuses to activate
# a snapshot while the pointer is younger than RECONCILE_GRACE (15s,
# waygate-manifest-store) — reporting exactly the "retry boot" error
# that made this gate flaky on main. Retrying cannot help with that:
# a boot failure is detected in under a second, so three attempts
# finish well inside a 15s window. The fix is to stop creating the
# conflict, not to out-wait it.
REACH_DB=gateway_reach
sudo docker exec gw-smoke-db createdb -U gateway "$REACH_DB"

# The retry below remains for boot races that are genuinely
# transient. It sleeps past RECONCILE_GRACE between attempts,
# because a retry that returns inside the settle window asks a
# question whose answer cannot have changed.
RECONCILE_GRACE_S=16
ok=0
rc=1
for boot in $(seq 1 "$ATTEMPTS"); do
  sudo docker rm -f -v gw-smoke-reach >/dev/null 2>&1 || true
  sudo docker run -d --name gw-smoke-reach --network "$NET" \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt=no-new-privileges --user 65532:65532 \
    -e GATEWAY_AUTH_MODE=enforce \
    -e AUTHENTIK_ISSUER=https://stub.smoke.invalid \
    -e GATEWAY_AUDIENCE=https://stub.smoke.invalid/mcp \
    -e GATEWAY_DEPLOYMENT_PROFILE=dev \
    -e GATEWAY_DATABASE_URL=postgres://gateway:smoke@gw-smoke-db:5432/${REACH_DB} \
    -e GATEWAY_IDENTITY_SIGNING_KEY_PEM="$PEM" \
    -e GATEWAY_IDENTITY_KID=smoke-kid \
    "$UPSTREAM_IMG" >/dev/null

# A bare "is /readyz 200?" poll is NOT a reachability assertion. The
# upstream check reports `skipped` (and therefore READY) while no
# upstream is registered yet, so the first 200 routinely lands in the
# startup window before any dial is attempted — a green that says
# nothing about whether dialing works. Require the readiness body to
# show a CONNECTED upstream instead: `skipped` carries no `connected`
# key, and a failed dial reports `connected:0`.
# The whole gate is one assertion, made against the readiness body
# rather than the protocol-generation gauge. The gauge collapses
# every version outside its closed label set into `other`, so
# "not exactly 2026-07-28" there would also accept some future
# generation and quietly stop proving the bridge is exercised. The
# readiness body carries the negotiated version strings verbatim,
# which makes the pre-2026 check exact.
  # Did the gateway stay up for this attempt? Only a boot failure
  # is worth another boot; a live gateway that could not dial has
  # already answered the question, and re-running it would spend
  # ATTEMPTS full timeouts to reach the same verdict.
  stayed_up=1
  for i in $(seq 1 "$READY_TIMEOUT"); do
    # A dead gateway cannot be distinguished from an unreachable
    # upstream by probing alone — the container name stops resolving
    # and every probe reports DNS failure. Check the container
    # first so a boot failure is reported as one, immediately,
    # instead of costing the full timeout and blaming the dial.
    if [ "$(sudo docker inspect -f '{{.State.Status}}' gw-smoke-reach 2>/dev/null)" != "running" ]; then
      stayed_up=0
      rc=1
      break
    fi
    # Both peers, each on the generation it is supposed to speak.
    # Asserting only "connected" would pass while the gateway
    # downgraded the discovery-capable one — the exact failure the
    # bridge must not have.
    set +e
    sudo docker exec gw-smoke-upstream python -I -S /app/assert_reachable.py \
      http://gw-smoke-reach:8080/readyz legacy-smoke legacy
    rc=$?
    if [ "$rc" -eq 0 ]; then
      sudo docker exec gw-smoke-upstream python -I -S /app/assert_reachable.py \
        http://gw-smoke-reach:8080/readyz modern-smoke stateless
      rc=$?
    fi
    set -e
    if [ "$rc" -eq 0 ]; then ok=1; break; fi
    # 3 = connected, but the peer is no longer a legacy one. Retrying
    # cannot change that, so fail now with the actionable remedy.
    if [ "$rc" -eq 3 ]; then break; fi
    sleep 1
  done

  # A fixture that stopped being legacy is a verdict, not a flake.
  if [ "$ok" = "1" ] || [ "$rc" -eq 3 ]; then break; fi

  # Re-check before classifying. `stayed_up` is only as fresh as the
  # last iteration that looked, so a gateway that exits during the
  # final assertion or the sleep after it would otherwise be judged
  # on a stale reading and recorded as a live dial failure — the one
  # verdict that skips the retry this phase exists to perform.
  if [ "$(sudo docker inspect -f '{{.State.Status}}' gw-smoke-reach 2>/dev/null)" != "running" ]; then
    stayed_up=0
  fi
  # A gateway that came up and still could not dial is a verdict too.
  if [ "$stayed_up" = "1" ]; then break; fi
  echo "--- reachability boot attempt $boot/$ATTEMPTS: the gateway did not stay up ---"
  sudo docker inspect gw-smoke-reach --format 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} err={{.State.Error}}' 2>&1 || true
  sudo docker logs --tail 30 gw-smoke-reach 2>&1 | grep -ivE 'tantivy|managed_directory' | tail -20 || true
  # Settle past RECONCILE_GRACE before re-booting. A boot failure is
  # detected in under a second, so an immediate retry re-asks inside
  # the window that refused the first one and gets the same answer.
  if [ "$boot" -lt "$ATTEMPTS" ]; then
    echo "settling ${RECONCILE_GRACE_S}s before the next boot"
    sleep "$RECONCILE_GRACE_S"
  fi
done

if [ "$rc" -eq 3 ]; then
  echo "REACHABILITY SMOKE FAILED: an upstream connected on the wrong protocol generation."
  echo "Either an SDK pin drifted across the 2026-07-28 boundary (scripts/boot-smoke/ must stay below it,"
  echo "scripts/boot-smoke-2026/ must stay at or above it), or the dial downgraded a discovery-capable peer."
  exit 1
fi
if [ "$ok" != "1" ]; then
  # `$boot` holds the attempt the loop stopped on, which is 1 on the
  # deliberately single-boot live-dial path and ATTEMPTS only when
  # the gateway kept failing to stay up. Reporting the constant here
  # told an operator the gate had tried three times when it had not.
  echo "REACHABILITY SMOKE FAILED: no upstream reached connected state after ${boot} boot(s) — not publishing."
  sudo docker inspect gw-smoke-reach --format 'status={{.State.Status}} exit={{.State.ExitCode}}' 2>&1 || true
  sudo docker logs --tail 60 gw-smoke-reach 2>&1 | grep -ivE 'tantivy|managed_directory' | tail -40 || true
  echo "--- upstream logs ---"
  sudo docker logs --tail 20 gw-smoke-upstream 2>&1 || true
  sudo docker logs --tail 20 gw-smoke-upstream-2026 2>&1 || true
  exit 1
fi
echo "Reachability smoke passed: legacy upstream bridged, stateless upstream not downgraded."
