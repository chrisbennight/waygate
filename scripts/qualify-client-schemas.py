#!/usr/bin/env python3
"""Qualify one isolated client against synthetic MCP and model endpoints."""

import argparse
import http.server
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading


REPO = Path(__file__).resolve().parents[1]
CASES = json.loads((REPO / "crates/waygate-mcp/tests/fixtures/client-schema-cases.json").read_text())
BY_NAME = {case["tool"]: case for case in CASES}
PREFIX = "mcp__schema_fixture__"


def functions(tools, client):
    result = []
    for tool in tools:
        if client == "claude":
            name = tool.get("name", "")
            if name.startswith(PREFIX) and name[len(PREFIX):] in BY_NAME:
                result.append((name[len(PREFIX):], name, None, tool.get("input_schema")))
        elif tool.get("type") == "namespace" and tool.get("name", "").rstrip("_") == "mcp__schema_fixture":
            for child in tool.get("tools", []):
                if child.get("name") in BY_NAME:
                    result.append((child["name"], child["name"], tool["name"], child.get("parameters")))
        elif tool.get("name", "").startswith(PREFIX):
            name = tool["name"][len(PREFIX):]
            if name in BY_NAME:
                result.append((name, tool["name"], None, tool.get("parameters")))
    return result


def anthropic_events(calls, sequence):
    message = {"id": "msg_fixture_" + str(sequence), "type": "message", "role": "assistant", "model": "fixture",
               "content": [], "stop_reason": None, "stop_sequence": None,
               "usage": {"input_tokens": 1, "output_tokens": 1}}
    events = [("message_start", {"type": "message_start", "message": message})]
    for index, call in enumerate(calls or [None]):
        block = ({"type": "tool_use", "id": call["id"], "name": call["name"], "input": {}}
                 if call else {"type": "text", "text": ""})
        events.append(("content_block_start", {"type": "content_block_start", "index": index, "content_block": block}))
        delta = ({"type": "input_json_delta", "partial_json": json.dumps(call["arguments"])}
                 if call else {"type": "text_delta", "text": "done"})
        events.append(("content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}))
        events.append(("content_block_stop", {"type": "content_block_stop", "index": index}))
    events.extend([
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use" if calls else "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    ])
    return events


def responses_events(calls, sequence):
    items = []
    for call in calls:
        item = {"id": "fc_" + call["id"], "type": "function_call", "call_id": call["id"],
                "name": call["name"], "arguments": json.dumps(call["arguments"]), "status": "completed"}
        if call["namespace"]:
            item["namespace"] = call["namespace"]
        items.append(item)
    if not items:
        items = [{"id": "msg_fixture_" + str(sequence), "type": "message", "role": "assistant", "status": "completed",
                  "content": [{"type": "output_text", "text": "done", "annotations": []}]}]
    response = {"id": "resp_fixture_" + str(sequence), "object": "response", "created_at": 1, "status": "completed",
                "model": "fixture", "output": items, "usage": {"input_tokens": 1, "output_tokens": 1,
                "total_tokens": 2, "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}}
    events = [{"type": "response.created", "response": {**response, "status": "in_progress", "output": []}}]
    for index, item in enumerate(items):
        initial = {**item, "status": "in_progress"}
        initial["arguments" if calls else "content"] = "" if calls else []
        events.append({"type": "response.output_item.added", "output_index": index, "item": initial})
        if calls:
            events.append({"type": "response.function_call_arguments.delta", "item_id": item["id"], "output_index": index, "delta": item["arguments"]})
            events.append({"type": "response.function_call_arguments.done", "item_id": item["id"], "output_index": index, "arguments": item["arguments"]})
        else:
            part = {"type": "output_text", "text": "", "annotations": []}
            events.extend([
                {"type": "response.content_part.added", "item_id": item["id"], "output_index": index, "content_index": 0, "part": part},
                {"type": "response.output_text.delta", "item_id": item["id"], "output_index": index, "content_index": 0, "delta": "done"},
                {"type": "response.output_text.done", "item_id": item["id"], "output_index": index, "content_index": 0, "text": "done"},
            ])
        events.append({"type": "response.output_item.done", "output_index": index, "item": item})
    events.append({"type": "response.completed", "response": response})
    return [(event["type"], event) for event in events]


def provider(client, exercise, records):
    lock = threading.Lock()
    issued = False

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": [{"id": "fixture", "object": "model", "owned_by": "fixture"}]}).encode())

        def do_POST(self):
            nonlocal issued
            length = int(self.headers.get("content-length", "0"))
            if not 0 < length <= 2 * 1024 * 1024:
                self.send_error(413)
                return
            body = json.loads(self.rfile.read(length))
            if self.path.endswith("count_tokens"):
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"input_tokens":1}')
                return
            available = functions(body.get("tools", []), client)
            calls = []
            with lock:
                records.append({"tools": [{"tool": name, "schema": schema} for name, _, _, schema in available]})
                sequence = len(records)
                if exercise and available and not issued:
                    issued = True
                    for name, wire_name, namespace, _ in available:
                        for kind in ("valid", "invalid"):
                            calls.append({"id": name + "_" + kind, "name": wire_name, "namespace": namespace,
                                          "arguments": BY_NAME[name][kind]})
            events = anthropic_events(calls, sequence) if client == "claude" else responses_events(calls, sequence)
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for event, value in events:
                self.wfile.write(("event: " + event + "\ndata: " + json.dumps(value) + "\n\n").encode())

    return http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def client_command(args, root, mcp_url, provider_url, env):
    if args.client == "claude":
        config = root / "mcp.json"
        config.write_text(json.dumps({"mcpServers": {"schema_fixture": {"type": "http", "url": mcp_url}}}))
        env.update({"CLAUDE_CONFIG_DIR": str(root / "client"), "ANTHROPIC_BASE_URL": provider_url,
                    "ANTHROPIC_API_KEY": "synthetic-no-provider-access", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                    "DISABLE_AUTOUPDATER": "1", "ENABLE_TOOL_SEARCH": "false"})
        return [str(args.client_binary), "--bare", "--disable-slash-commands", "--setting-sources", "",
                "--strict-mcp-config", "--mcp-config", str(config), "--tools", "", "--allowedTools", PREFIX + "*",
                "--max-turns", "2", "--output-format", "stream-json", "--verbose", "-p", "Report ready."]
    config = root / "client"
    config.mkdir()
    # This sets the subprocess's documented configuration directory. It never
    # modifies the caller's Codex configuration or authentication material.
    env.update({"CODEX_HOME": str(config), "WAYGATE_FIXTURE_API_KEY": "synthetic-no-provider-access", "OTEL_SDK_DISABLED": "true"})
    (config / "config.toml").write_text(
        'model="fixture"\nmodel_provider="fixture"\napproval_policy="never"\nsandbox_mode="read-only"\n'
        '[mcp_servers.schema_fixture]\nurl=' + json.dumps(mcp_url) + '\n'
        '[model_providers.fixture]\nname="Fixture"\nbase_url=' + json.dumps(provider_url + "/v1") + '\n'
        'wire_api="responses"\nenv_key="WAYGATE_FIXTURE_API_KEY"\nrequires_openai_auth=false\nrequest_max_retries=0\nstream_max_retries=0\n')
    return [str(args.client_binary), "--no-daemon", "exec", "--ephemeral", "--ignore-rules", "--skip-git-repo-check", "--json", "Report ready."]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", choices=("claude", "codex"), required=True)
    parser.add_argument("--client-binary", type=Path, required=True)
    parser.add_argument("--fixture-binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--adapt", action="store_true")
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--exercise-calls", action="store_true")
    args = parser.parse_args()
    args.client_binary = args.client_binary.resolve(strict=True)
    args.fixture_binary = args.fixture_binary.resolve(strict=True)
    records = []
    with tempfile.TemporaryDirectory(prefix="waygate-client-schema-") as directory:
        root = Path(directory)
        with (root / "fixture.log").open("w") as log:
            command = [str(args.fixture_binary), "--http"]
            if args.adapt:
                command.append("--adapt")
            if args.legacy:
                command.append("--legacy")
            fixture = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True)
            backend = None
            try:
                startup = queue.Queue(maxsize=1)
                threading.Thread(target=lambda: startup.put(fixture.stdout.readline()), daemon=True).start()
                mcp_url = json.loads(startup.get(timeout=15))["url"]
                backend = provider(args.client, args.exercise_calls, records)
                threading.Thread(target=backend.serve_forever, daemon=True).start()
                env = {key: value for key, value in os.environ.items() if key in {"PATH", "TMPDIR", "LANG", "LC_ALL", "TERM", "SYSTEMROOT"}}
                command = client_command(args, root, mcp_url, "http://127.0.0.1:" + str(backend.server_port), env)
                version = subprocess.run([str(args.client_binary), "--version"], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True).stdout.strip()
                result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=90)
            finally:
                fixture.terminate()
                fixture.wait(timeout=10)
                if backend:
                    backend.shutdown()
                    backend.server_close()
        observations = []
        for line in (root / "fixture.log").read_text().splitlines():
            try:
                fields = json.loads(line).get("fields", {})
            except json.JSONDecodeError:
                continue
            if fields.get("message") == "synthetic client observation":
                observations.append({key: fields[key] for key in ("method", "protocol", "client_name", "client_version", "tool", "accepted") if key in fields})
        report = {"client": args.client, "cli_version": version, "client_exit": result.returncode,
                  "adaptation": args.adapt, "legacy_fixture": args.legacy, "exercise_calls": args.exercise_calls,
                  "remote_configuration": "not fetched; fresh isolated client configuration",
                  "real_provider_api_acceptance": "not tested; loopback model stub only",
                  "provider_requests": records, "mcp_observations": observations}
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"report": str(args.report), "client_exit": result.returncode,
                          "presented_tools": sorted({tool["tool"] for record in records for tool in record["tools"]}),
                          "mcp_calls": sum(row.get("method") == "tools/call" for row in observations)}))
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
