"""Exercise the local tutorial using only Python's standard library."""

import argparse
import json
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def call(base_url, method, params, token):
    params = dict(params)
    params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "quickstart", "version": "1"},
    }
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "MCP-Method": method,
    }
    if "name" in params:
        headers["MCP-Name"] = params["name"]
    request = urllib.request.Request(
        base_url.rstrip("/") + "/mcp",
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers=headers,
    )
    try:
        response = urllib.request.urlopen(request, timeout=30)
    except urllib.error.HTTPError as error:
        # A routing-header policy refusal can precede JSON-RPC dispatch.
        response = error
    with response:
        if response.headers.get_content_type() == "text/event-stream":
            for line in response:
                if line.startswith(b"data:"):
                    message = json.loads(line[5:])
                    if "result" in message or "error" in message:
                        return message
            raise RuntimeError("MCP stream ended without a response")
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="http://127.0.0.1:8080")
    parser.add_argument("--issuer", default="http://127.0.0.1:9090")
    args = parser.parse_args()

    with urllib.request.urlopen(args.issuer.rstrip("/") + "/demo-token", timeout=10) as response:
        token = json.load(response)["access_token"]

    names = set()
    params = {}
    while True:
        page = call(args.gateway, "tools/list", params, token)["result"]
        names.update(tool["name"] for tool in page["tools"])
        cursor = page.get("nextCursor")
        if not cursor:
            break
        params = {"cursor": cursor}
    require("demo.greet" in names, "The demo upstream is not discoverable")
    require("demo.restricted" not in names, "The forbidden tool was exposed")
    print("PASS: discovery exposes the permitted demo tool")

    result = call(args.gateway, "tools/call", {
        "name": "demo.greet", "arguments": {"name": "world"},
    }, token)["result"]
    require(not result.get("isError"), "The permitted tool returned an error")
    expected = "Hello, world! Your request passed through the gateway."
    require(any(item.get("text") == expected for item in result["content"]),
            "The permitted tool did not return the expected greeting")
    print(expected)

    refused = call(args.gateway, "tools/call", {
        "name": "demo.restricted", "arguments": {},
    }, token)
    error = refused["error"]
    require(error["data"]["error"] == "forbidden", "Expected an authorization refusal")
    require(error["data"]["policy_ids"], "The refusal must identify a Cedar policy")
    print("PASS: Cedar refuses the restricted tool for the demo identity")


if __name__ == "__main__":
    main()
