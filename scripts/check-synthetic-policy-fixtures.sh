#!/usr/bin/env bash
# Keep identity-bearing authorization examples in obvious public namespaces.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

POLICY_DIR = Path("crates/waygate-authz/tests/fixtures/policies")
GOLDEN_DIR = Path("crates/waygate-authz/tests/golden")
TOOL_CAPTURE = Path("scripts/fixtures/tool-context/standard-tools-list.json")
TOOL_PRODUCER = Path("crates/waygate-mcp/examples/tool_context_projection.rs")

RUST_SERVER_FIXTURES = (
    Path("crates/waygate-authz/src/cedar.rs"),
    Path("crates/waygate-authz/tests/authz_e2e.rs"),
    Path("crates/waygate-authz/tests/operation_attribute.rs"),
)
PER_UPSTREAM_FIXTURE = Path("crates/waygate-authz/tests/per_upstream_policies.rs")

EXAMPLE_SERVER = re.compile(r"example-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
DEMO_SERVER = re.compile(r"demo-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
EXAMPLE_POLICY = re.compile(r"20-example-[a-z0-9]+(?:-[a-z0-9]+)*\.cedar\Z")
CEDAR_SERVER = re.compile(r'''resource\.server\s*(?:==|!=)\s*"([^"]+)"''')
CEDAR_RESOURCE_URI = re.compile(r'''resource\.uri\s*(?:==|!=)\s*"([^"]+)"''')
RUST_SERVER = re.compile(r'''server:\s*"([^"]+)"''')
RUST_TOOL_CALL = re.compile(r'''tool(?:_se)?\(\s*"([^"]+)"''')
RUST_CATALOG_SERVER = re.compile(r'''\(\s*"([^"]+)"\.to_owned\(\),\s*vec!\[''')

failures: list[str] = []


def fail(path: Path, detail: str) -> None:
    failures.append(f"{path}: {detail}")


def require_server(path: Path, value: object, context: str) -> None:
    if isinstance(value, str) and not EXAMPLE_SERVER.fullmatch(value):
        fail(path, f"{context} must use example-*, found {value!r}")


def reserved_email(value: str) -> bool:
    if "@" not in value:
        return False
    domain = value.rsplit("@", 1)[1].lower()
    return domain in {"example.com", "example.net", "example.org"} or domain.endswith(
        (".example", ".test", ".invalid", ".localhost")
    )


def reserved_resource_uri(value: str) -> bool:
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"}:
        host = (parsed.hostname or "").lower()
        return host in {"example.com", "example.net", "example.org", "localhost"} or host.endswith(
            (".example", ".test", ".invalid", ".localhost")
        )
    authority = parsed.netloc.lower()
    return parsed.scheme.startswith("example-") and (
        not authority or EXAMPLE_SERVER.fullmatch(authority) is not None
    )


for path in sorted(POLICY_DIR.glob("20-*.cedar")):
    if not EXAMPLE_POLICY.fullmatch(path.name):
        fail(path, "service policy filename must match 20-example-*.cedar")

for path in sorted(POLICY_DIR.glob("*.cedar")):
    text = path.read_text(encoding="utf-8")
    for match in CEDAR_SERVER.finditer(text):
        require_server(path, match.group(1), "resource.server literal")
    for uri in CEDAR_RESOURCE_URI.findall(text):
        if not reserved_resource_uri(uri):
            fail(path, f"resource URI must use a reserved example namespace, found {uri!r}")

for path in sorted(GOLDEN_DIR.glob("*.json")):
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        fail(path, "golden case root must be an object")
        continue
    principal = document.get("principal")
    if isinstance(principal, dict):
        email = principal.get("email")
        if isinstance(email, str) and not reserved_email(email):
            fail(path, f"principal email must use a reserved domain, found {email!r}")
        scim = principal.get("scim")
        if isinstance(scim, dict):
            external_id = scim.get("external_id")
            if isinstance(external_id, str) and "@" in external_id and not reserved_email(external_id):
                fail(path, f"SCIM external_id email must use a reserved domain, found {external_id!r}")
    action = document.get("action")
    if isinstance(action, dict):
        if isinstance(action.get("name"), str):
            server, separator, _ = action["name"].partition(".")
            if separator:
                require_server(path, server, "action server prefix")
        uri = action.get("uri")
        if isinstance(uri, str) and not reserved_resource_uri(uri):
            fail(path, f"action URI must use a reserved example namespace, found {uri!r}")
    resource = document.get("resource")
    if isinstance(resource, dict):
        require_server(path, resource.get("server"), "resource.server")
        if resource.get("kind") == "Server":
            require_server(path, resource.get("name"), "Server resource.name")
        uri = resource.get("uri")
        if isinstance(uri, str) and not reserved_resource_uri(uri):
            fail(path, f"resource URI must use a reserved example namespace, found {uri!r}")

for path in RUST_SERVER_FIXTURES:
    text = path.read_text(encoding="utf-8")
    for server in RUST_SERVER.findall(text):
        if server != "gateway-control":
            require_server(path, server, "Rust fixture server")

text = PER_UPSTREAM_FIXTURE.read_text(encoding="utf-8")
for server in RUST_TOOL_CALL.findall(text):
    if server not in {"synthetic_no_policy", "unrelated"}:
        require_server(PER_UPSTREAM_FIXTURE, server, "policy-test server")

capture = json.loads(TOOL_CAPTURE.read_text(encoding="utf-8"))
for tool in capture.get("result", {}).get("tools", []):
    name = tool.get("name", "")
    server, separator, _ = name.partition(".")
    if not separator or not DEMO_SERVER.fullmatch(server):
        fail(TOOL_CAPTURE, f"tool name must use a demo-* server prefix, found {name!r}")

producer_servers = RUST_CATALOG_SERVER.findall(TOOL_PRODUCER.read_text(encoding="utf-8"))
if not producer_servers:
    fail(TOOL_PRODUCER, "could not find representative catalog server literals")
for server in producer_servers:
    if not DEMO_SERVER.fullmatch(server):
        fail(TOOL_PRODUCER, f"catalog server must use demo-*, found {server!r}")

if failures:
    for failure in failures:
        print(f"check-synthetic-policy-fixtures: FAIL — {failure}")
    raise SystemExit(1)

print("check-synthetic-policy-fixtures: OK")
PY
