"""Decide whether the built image proved it can dial a real upstream, on the
generation that upstream is supposed to speak.

Takes the expected generation because both directions are contracts. A legacy
peer must be reached through the bridge, and a discovery-capable peer must NOT
be downgraded through it -- an assertion that only checked "connected" would
pass in both cases while the gateway silently did the wrong thing to one.

Exit codes are the smoke's contract:
  0  the upstream is connected on the expected generation -- the gate passes
  1  not (yet) satisfied; the caller retries until its timeout
  3  connected, but on the WRONG generation. No amount of retrying fixes a
     fixture whose SDK pin has drifted across the boundary, or a gateway that
     downgrades a capable peer, so the caller fails immediately.

Reads `/readyz`, not the protocol-generation gauge. The gauge collapses every
version outside its closed label set into `other`, so "not exactly 2026-07-28"
there would also accept some future generation and quietly stop proving the
bridge is exercised. The readiness body carries the negotiated version strings
verbatim, which makes the generation check exact. Spec revisions are ISO
dates, so a lexicographic compare is a chronological one.

Runs stdlib-only and is invoked with `-I -S`, so the interpreter that decides
a publish does not import site-packages -- the fixture's own dependency
closure cannot reach this path.
"""

import json
import sys
import urllib.request

STATELESS_GENERATION = "2026-07-28"

EXPECTATIONS = ("legacy", "stateless")

if len(sys.argv) != 4 or sys.argv[3] not in EXPECTATIONS:
    print(
        "usage: assert_reachable.py <readyz-url> <upstream-name> <legacy|stateless>",
        file=sys.stderr,
    )
    raise SystemExit(2)

url, wanted, expected = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    with urllib.request.urlopen(url, timeout=5) as response:
        body = json.loads(response.read().decode("utf-8", "replace"))
except Exception as exc:  # noqa: BLE001 - anything here means "not ready yet"
    print(f"readyz unavailable: {exc}", file=sys.stderr)
    raise SystemExit(1)

if body.get("status") != "ready":
    print(f"not ready: {json.dumps(body.get('checks', {}))[:400]}", file=sys.stderr)
    raise SystemExit(1)

upstreams = body.get("checks", {}).get("upstreams", {})
detail = next((u for u in upstreams.get("detail", []) if u.get("name") == wanted), None)
if detail is None:
    # `skipped` reports READY while no upstream is registered yet, which is
    # exactly the startup window a bare status-code poll mistakes for success.
    print(f"upstream {wanted!r} not registered yet: {json.dumps(upstreams)[:400]}", file=sys.stderr)
    raise SystemExit(1)

if not detail.get("connected"):
    print(f"upstream {wanted!r} not connected: {json.dumps(detail)[:400]}", file=sys.stderr)
    raise SystemExit(1)

versions = detail.get("protocol_versions") or []
if not versions:
    print(f"upstream {wanted!r} reports no negotiated generation", file=sys.stderr)
    raise SystemExit(1)

if expected == "legacy":
    wrong = [v for v in versions if v >= STATELESS_GENERATION]
    complaint = "should predate the stateless generation"
else:
    wrong = [v for v in versions if v < STATELESS_GENERATION]
    complaint = "should have negotiated the stateless generation, not been downgraded"
if wrong:
    print(f"upstream {wanted!r} negotiated {wrong}, which {complaint}", file=sys.stderr)
    raise SystemExit(3)

print(f"{wanted} connected on {versions} ({expected})")
