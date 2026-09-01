"""Drive a wrapped session and print the exchange, for the README transcript.

    python examples/demo_session.py

Runs the real wrapper in front of the bundled fake GHL MCP server
(tests/fake_ghl_server.py). No network, no credentials.
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "policies" / "content-only.yaml"
SERVER = ROOT / "tests" / "fake_ghl_server.py"
LOCATION = "loc_EXAMPLE_CLIENT_A"

SCRIPT = [
    ("tools/list", None),
    (
        "tools/call",
        {"name": "blogs_create-blog-post", "arguments": {"locationId": LOCATION, "title": "5 signs your furnace is done"}},
    ),
    (
        "tools/call",
        {"name": "contacts_upsert-contact", "arguments": {"locationId": LOCATION, "email": "lead@example.test"}},
    ),
    (
        "tools/call",
        {"name": "social-media-posting_create-post", "arguments": {"locationId": "loc_SOMEONE_ELSES", "summary": "..."}},
    ),
]


def main() -> int:
    argv = [
        sys.executable,
        "-m",
        "ghl_mcp_scoped",
        "run",
        "--policy",
        str(POLICY),
        "--",
        sys.executable,
        str(SERVER),
    ]
    proc = subprocess.Popen(
        argv, cwd=str(ROOT), stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0
    )
    inbox: "queue.Queue[bytes]" = queue.Queue()

    def reader() -> None:
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            inbox.put(raw)

    threading.Thread(target=reader, daemon=True).start()

    print("$ ghl-mcp-scoped run --policy policies/content-only.yaml -- <your ghl mcp server>")
    print()
    for i, (method, params) in enumerate(SCRIPT, start=1):
        request = {"jsonrpc": "2.0", "id": i, "method": method}
        if params:
            request["params"] = params
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
        proc.stdin.flush()
        label = params["name"] if params else method
        print("agent  --> %s %s" % (method, json.dumps(params) if params else ""))
        response = json.loads(inbox.get(timeout=20).decode("utf-8"))
        if "error" in response:
            print("wrapper <-- REFUSED  %s" % response["error"]["message"])
            print("           rule: %s" % response["error"]["data"]["rule"])
        elif method == "tools/list":
            names = [t["name"] for t in response["result"]["tools"]]
            print("wrapper <-- %d tools visible: %s" % (len(names), ", ".join(names)))
        else:
            print("wrapper <-- OK  %s" % response["result"]["content"][0]["text"])
        print()

    assert proc.stdin is not None
    proc.stdin.close()
    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
