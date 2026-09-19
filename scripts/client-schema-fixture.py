#!/usr/bin/env python3
"""Disposable stdio MCP fixture for client registration checks; no dependencies."""
import argparse
import json
import logging
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, default=Path(__file__).resolve().parents[1]
                        / "crates/waygate-mcp/tests/fixtures/client-schema-tools.json")
    args = parser.parse_args()
    tools = json.loads(args.tools.read_text())
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request.get("method")
        params = request.get("params", {})
        version = params.get("_meta", {}).get("io.modelcontextprotocol/protocolVersion")
        if method == "initialize":
            requested = params.get("protocolVersion")
            logging.info("initialize protocolVersion=%s", requested)
            version = requested if requested in ("2025-06-18", "2025-11-25") else "2025-11-25"
            result = {"protocolVersion": version, "capabilities": {"tools": {}},
                      "serverInfo": {"name": "schema-fixture", "version": "1.0.0"}}
        elif method == "tools/list":
            logging.info("tools/list request protocolVersion=%s", version)
            result = {"tools": tools}
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            known = any(tool["name"] == name for tool in tools)
            rejected = not known
            if name == "conditional_dropped":
                mode, size = arguments.get("mode"), arguments.get("size")
                cap = 2000000000 if mode == "large" else 16000000
                rejected = (not isinstance(mode, str) or
                            (size is not None and (type(size) is not int or size > cap)))
            result = {"content": [{"type": "text", "text": "rejected" if rejected else "ok"}],
                      "isError": rejected}
            logging.info("tools/call tool=%s rejected=%s", name, rejected)
        elif method == "ping":
            result = {}
        else:
            response = {"jsonrpc": "2.0", "id": request["id"],
                        "error": {"code": -32601, "message": "Method not found"}}
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            continue
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
