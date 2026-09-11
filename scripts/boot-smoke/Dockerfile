# Pinned deliberately: this fixture's job is to be an upstream that predates
# the stateless generation, so it must NOT float forward onto an SDK release
# that learns `server/discover`. Bumping the `mcp` pin in pyproject.toml is a
# decision to change what the smoke proves, and the gate fails loudly rather
# than vacuously if it is made carelessly.
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

# uv, digest-pinned like every other external image here. The fixture's whole
# dependency closure is resolved from the checked-in uv.lock, not from
# whatever the index happens to serve on the day of a build: the handshake
# this fixture produces is what authorizes an image publish, so it has to be
# reproducible from the commit. `--frozen` fails the build if the lock and
# pyproject.toml ever disagree, so the pin cannot drift silently.
COPY --from=ghcr.io/astral-sh/uv:0.12.0@sha256:606e70c71c852d03f611b1e56a195d08648507018a7057fab82c4974c4eae105 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY legacy_upstream.py /app/legacy_upstream.py
# The gate's assertion runs from in here rather than from a pulled utility
# image, so the code that authorizes a publish is content-addressed with the
# commit that relies on it. It is invoked on the base interpreter under
# `-I -S`, never the project venv, so the fixture's dependencies cannot reach
# the deciding path even though they are now locked.
COPY assert_reachable.py /app/assert_reachable.py

EXPOSE 9000

# "Listening" is the only readiness this fixture has. An HTTP probe is the
# wrong question: MCP's streamable transport answers a bare GET with 406 or
# 400 depending on the Accept header, so a fetch-based check can never
# succeed and degrades into a fixed sleep. A socket connect asks what the
# caller actually needs to know.
HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=30 \
  CMD python -I -S -c "import socket; socket.create_connection(('127.0.0.1', 9000), timeout=3).close()"

# The server runs on the locked venv; the assertion deliberately does not.
CMD ["/app/.venv/bin/python", "legacy_upstream.py"]
