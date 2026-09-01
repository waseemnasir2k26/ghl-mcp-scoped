"""A fake GoHighLevel MCP server.

Newline-delimited JSON-RPC over stdio, the same shape as a real MCP stdio
server, with a handful of plausible GHL tool names. It talks to nothing: no
network, no credentials, no GoHighLevel account. Every id below is invented.

Extra non-protocol methods used by the tests:
  debug/emit-noise  - writes a line of non-JSON before its reply, to prove the
                      relay passes frames it does not understand straight through
  debug/echo        - returns its params verbatim
"""

from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "contacts_get-contacts",
        "description": "List contacts in a location.",
        "inputSchema": {"type": "object", "properties": {"locationId": {"type": "string"}}},
    },
    {
        "name": "contacts_get-contact",
        "description": "Fetch one contact by id.",
        "inputSchema": {"type": "object", "properties": {"contactId": {"type": "string"}}},
    },
    {
        "name": "contacts_upsert-contact",
        "description": "Create or update a contact.",
        "inputSchema": {"type": "object", "properties": {"locationId": {"type": "string"}}},
    },
    {
        "name": "contacts_add-tags",
        "description": "Add tags to a contact.",
        "inputSchema": {"type": "object", "properties": {"tags": {"type": "array"}}},
    },
    {
        "name": "conversations_send-a-new-message",
        "description": "Send an SMS or email to a contact.",
        "inputSchema": {"type": "object", "properties": {"contactId": {"type": "string"}}},
    },
    {
        "name": "conversations_search-conversation",
        "description": "Search conversations.",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
    },
    {
        "name": "opportunities_update-opportunity",
        "description": "Move an opportunity between pipeline stages.",
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
    },
    {
        "name": "payments_list-transactions",
        "description": "List payment transactions.",
        "inputSchema": {"type": "object", "properties": {"locationId": {"type": "string"}}},
    },
    {
        "name": "blogs_create-blog-post",
        "description": "Publish a blog post.",
        "inputSchema": {"type": "object", "properties": {"locationId": {"type": "string"}}},
    },
    {
        "name": "blogs_get-blogs",
        "description": "List blogs in a location.",
        "inputSchema": {"type": "object", "properties": {"locationId": {"type": "string"}}},
    },
    {
        "name": "social-media-posting_create-post",
        "description": "Schedule a social post.",
        "inputSchema": {"type": "object", "properties": {"locationId": {"type": "string"}}},
    },
    {
        "name": "locations_get-location",
        "description": "Fetch location metadata.",
        "inputSchema": {"type": "object", "properties": {"locationId": {"type": "string"}}},
    },
]


def write(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def handle(message: dict) -> dict | None:
    method = message.get("method")
    request_id = message.get("id")

    if request_id is None:
        return None  # a notification

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "fake-ghl-mcp", "version": "0.0.0-test"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments", {})
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": "fake-ghl executed %s" % name}],
                "isError": False,
                "_echo": {"name": name, "arguments": arguments},
            },
        }

    if method == "debug/echo":
        return {"jsonrpc": "2.0", "id": request_id, "result": message.get("params")}

    if method == "debug/emit-noise":
        sys.stdout.write("this line is not JSON\n")
        sys.stdout.flush()
        return {"jsonrpc": "2.0", "id": request_id, "result": {"ok": True}}

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": "Method not found: %s" % method},
    }


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            write(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
            )
            continue
        response = handle(message)
        if response is not None:
            write(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
