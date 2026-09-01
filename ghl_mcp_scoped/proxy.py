"""The stdio JSON-RPC relay.

Shape: the wrapper is launched by the MCP client in place of the real GoHighLevel
MCP server. It spawns that server as a child process and relays newline-delimited
JSON-RPC frames in both directions, byte-faithfully, with two exceptions:

* ``tools/call`` requests are checked against the policy. A refused call is
  never forwarded; the wrapper answers it itself with a JSON-RPC error.
* ``tools/list`` responses are filtered so the agent cannot see tools it is not
  allowed to call.

Everything else - initialize, resources, prompts, notifications, progress,
anything a future revision of the protocol adds - passes through untouched.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, BinaryIO, Callable

from .audit import AuditLog
from .policy import CONFIRM_MESSAGE, Policy

# Implementation-defined JSON-RPC server error codes (-32000..-32099).
ERROR_POLICY_DENIED = -32003
ERROR_POLICY_CONFIRM = -32004
ERROR_MALFORMED_CALL = -32005


def _dump(obj: Any) -> bytes:
    return (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")


def build_refusal(
    request_id: Any,
    tool: str,
    decision: str,
    rule: str,
    reason: str,
    policy_path: str = "",
) -> dict[str, Any]:
    """A well-formed JSON-RPC error naming the rule that blocked the call."""
    if decision == "confirm":
        code = ERROR_POLICY_CONFIRM
        message = (
            "ghl-mcp-scoped: '%s' requires human confirmation (rule '%s'). %s"
            % (tool, rule, CONFIRM_MESSAGE)
        )
    else:
        code = ERROR_POLICY_DENIED
        message = "ghl-mcp-scoped: '%s' was blocked by policy rule '%s'. %s" % (
            tool,
            rule,
            reason,
        )
    data: dict[str, Any] = {
        "blockedBy": "ghl-mcp-scoped",
        "tool": tool,
        "decision": decision,
        "rule": rule,
        "reason": reason,
    }
    if policy_path:
        data["policy"] = policy_path
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message, "data": data},
    }


class ScopedProxy:
    """Policy-enforcing relay between one MCP client and one MCP server."""

    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        *,
        client_in: BinaryIO,
        client_out: BinaryIO,
        server_in: BinaryIO,
        server_out: BinaryIO,
        on_stderr: Callable[[str], None] | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.client_in = client_in
        self.client_out = client_out
        self.server_in = server_in
        self.server_out = server_out
        self._out_lock = threading.Lock()
        self._in_lock = threading.Lock()
        self._pending_list_ids: set[str] = set()
        self._pending_lock = threading.Lock()
        self._log = on_stderr or (lambda message: None)

    # -- io helpers ------------------------------------------------------
    def _to_client(self, payload: dict[str, Any]) -> None:
        with self._out_lock:
            self.client_out.write(_dump(payload))
            self.client_out.flush()

    def _raw_to_client(self, raw: bytes) -> None:
        with self._out_lock:
            self.client_out.write(raw)
            self.client_out.flush()

    def _raw_to_server(self, raw: bytes) -> None:
        with self._in_lock:
            self.server_in.write(raw)
            self.server_in.flush()

    @staticmethod
    def _id_key(request_id: Any) -> str:
        return "%s:%r" % (type(request_id).__name__, request_id)

    # -- direction: client -> server -------------------------------------
    def handle_client_frame(self, raw: bytes) -> None:
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            self._raw_to_server(raw)
            return
        try:
            message = json.loads(text)
        except json.JSONDecodeError:
            # Not our business to understand it. Relay it unchanged.
            self._raw_to_server(raw)
            return
        if not isinstance(message, dict):
            self._raw_to_server(raw)
            return

        method = message.get("method")

        if method == "tools/list":
            if "id" in message:
                with self._pending_lock:
                    self._pending_list_ids.add(self._id_key(message["id"]))
            self._raw_to_server(raw)
            return

        if method != "tools/call":
            self._raw_to_server(raw)
            return

        params = message.get("params")
        params = params if isinstance(params, dict) else {}
        tool = params.get("name")
        arguments = params.get("arguments", {})
        request_id = message.get("id")

        if not isinstance(tool, str) or not tool:
            self.audit.record(
                event="tools/call",
                tool="<missing>",
                decision="deny",
                rule="malformed",
                reason="tools/call had no params.name",
            )
            if request_id is not None:
                self._to_client(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": ERROR_MALFORMED_CALL,
                            "message": (
                                "ghl-mcp-scoped: refusing a tools/call with no "
                                "params.name; it cannot be checked against the policy"
                            ),
                            "data": {"blockedBy": "ghl-mcp-scoped"},
                        },
                    }
                )
            return

        decision = self.policy.decide(tool, arguments)
        self.audit.record(
            event="tools/call",
            tool=tool,
            decision=decision.decision,
            rule=decision.rule,
            reason=decision.reason,
            arguments=arguments if arguments is not None else {},
            extra={"forwarded": decision.allowed},
        )

        if decision.allowed:
            self._raw_to_server(raw)
            return

        self._log(
            "blocked %s (%s by rule '%s')" % (tool, decision.decision, decision.rule)
        )
        if request_id is None:
            # A notification: there is nobody to answer. Dropping it is the
            # only option, and it cannot hang the client.
            return
        self._to_client(
            build_refusal(
                request_id,
                tool,
                decision.decision,
                decision.rule,
                decision.reason,
                policy_path=self.policy.source_path,
            )
        )

    # -- direction: server -> client -------------------------------------
    def handle_server_frame(self, raw: bytes) -> None:
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            self._raw_to_client(raw)
            return
        try:
            message = json.loads(text)
        except json.JSONDecodeError:
            self._raw_to_client(raw)
            return
        if not isinstance(message, dict) or "id" not in message:
            self._raw_to_client(raw)
            return

        key = self._id_key(message["id"])
        with self._pending_lock:
            is_list = key in self._pending_list_ids
            if is_list:
                self._pending_list_ids.discard(key)

        if not is_list:
            self._raw_to_client(raw)
            return

        result = message.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            self._raw_to_client(raw)
            return

        kept: list[Any] = []
        hidden: list[str] = []
        for entry in result["tools"]:
            name = entry.get("name") if isinstance(entry, dict) else None
            if not isinstance(name, str):
                kept.append(entry)
                continue
            if self.policy.is_visible(name):
                kept.append(entry)
            else:
                hidden.append(name)

        result["tools"] = kept
        self.audit.record(
            event="tools/list",
            decision="filtered",
            rule="visibility",
            reason="%d tool(s) visible, %d hidden" % (len(kept), len(hidden)),
            extra={
                "visible": [t.get("name") for t in kept if isinstance(t, dict)],
                "hidden": hidden,
            },
        )
        self._to_client(message)

    # -- pumps -----------------------------------------------------------
    def pump_server_to_client(self) -> None:
        for raw in iter(self.server_out.readline, b""):
            try:
                self.handle_server_frame(raw)
            except Exception as exc:  # never drop a frame on our own bug
                self._log("relay error (server->client): %r" % exc)
                self._raw_to_client(raw)

    def pump_client_to_server(self) -> None:
        for raw in iter(self.client_in.readline, b""):
            try:
                self.handle_client_frame(raw)
            except Exception as exc:
                self._log("relay error (client->server): %r" % exc)
                self._raw_to_server(raw)


def run(
    policy: Policy,
    audit: AuditLog,
    command: list[str],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    verbose: bool = False,
) -> int:
    """Spawn the wrapped MCP server and relay until either side closes."""

    def log(message: str) -> None:
        if verbose:
            print("[ghl-mcp-scoped] " + message, file=sys.stderr, flush=True)

    child = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,  # the wrapped server's own logging goes straight through
        cwd=str(cwd) if cwd else None,
        env=env,
        bufsize=0,
    )
    audit.record(
        event="session_start",
        extra={
            "command": command,
            "policy": policy.source_path,
            "mode": policy.mode,
            "read_only": policy.read_only,
            "rules": len(policy.rules),
        },
    )
    log("wrapping: %s" % " ".join(command))

    assert child.stdin is not None and child.stdout is not None
    proxy = ScopedProxy(
        policy,
        audit,
        client_in=sys.stdin.buffer,
        client_out=sys.stdout.buffer,
        server_in=child.stdin,
        server_out=child.stdout,
        on_stderr=log,
    )

    downstream = threading.Thread(target=proxy.pump_server_to_client, daemon=True)
    downstream.start()
    try:
        proxy.pump_client_to_server()
    finally:
        try:
            child.stdin.close()
        except OSError:
            pass
        code = child.wait()
        downstream.join(timeout=5)
        audit.record(event="session_end", extra={"exit_code": code})
        audit.close()
    return code
