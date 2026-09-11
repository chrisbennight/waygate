# Pinned deliberately, in the opposite direction to the legacy fixture: this
# one's job is to speak the stateless generation, so it must track an SDK
# release that does. If the pin ever slips back below 2026-07-28 the gate
# fails loudly rather than quietly proving nothing.
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

COPY modern_upstream.py /app/modern_upstream.py
# No assertion script here: the gate's probes run from the legacy fixture
# container, which already carries it. One copy, one place to audit.


EXPOSE 9000

# "Listening" is the only readiness this fixture has. An HTTP probe is the
# wrong question: MCP's streamable transport answers a bare GET with 406 or
# 400 depending on the Accept header, so a fetch-based check can never
# succeed and degrades into a fixed sleep. A socket connect asks what the
# caller actually needs to know.
HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=30 \
  CMD python -I -S -c "import socket; socket.create_connection(('127.0.0.1', 9000), timeout=3).close()"

# The server runs on the locked venv; the assertion deliberately does not.
CMD ["/app/.venv/bin/python", "modern_upstream.py"]
