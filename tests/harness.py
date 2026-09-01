"""Test harness: drive a real ghl-mcp-scoped process over stdio.

The tests below are end-to-end. They spawn the wrapper as its own process,
which spawns fake_ghl_server.py as ITS own process, and speak JSON-RPC down a
pipe. No mocks of the relay, no network, no credentials.
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
FAKE_SERVER = Path(__file__).resolve().parent / "fake_ghl_server.py"
TIMEOUT = 20.0


class WrappedServer:
    """A running wrapper + fake server pair."""

    def __init__(self, policy_path: str | Path, verbose: bool = False) -> None:
        argv = [
            sys.executable,
            "-m",
            "ghl_mcp_scoped",
            "run",
            "--policy",
            str(policy_path),
            "--",
            sys.executable,
            str(FAKE_SERVER),
        ]
        if verbose:
            argv.insert(argv.index("--policy"), "--verbose")
        self.proc = subprocess.Popen(
            argv,
            cwd=str(REPO_ROOT),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.lines: "queue.Queue[bytes]" = queue.Queue()
        self.raw_lines: list[str] = []
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        self._next_id = 0

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for raw in iter(self.proc.stdout.readline, b""):
            self.lines.put(raw)

    def send_raw(self, payload: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        self.send_raw(payload)
        return self.await_id(request_id)

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def await_id(self, request_id: Any) -> dict[str, Any]:
        while True:
            try:
                raw = self.lines.get(timeout=TIMEOUT)
            except queue.Empty as exc:  # pragma: no cover - only on a hang
                raise AssertionError(
                    "no response for id %r within %ss; frames seen: %r"
                    % (request_id, TIMEOUT, self.raw_lines)
                ) from exc
            text = raw.decode("utf-8").rstrip("\r\n")
            self.raw_lines.append(text)
            try:
                message = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and message.get("id") == request_id:
                return message

    def close(self) -> int:
        if self.proc.stdin is not None:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            self.proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:  # pragma: no cover
            self.proc.kill()
            self.proc.wait()
        self._reader.join(timeout=5)
        return self.proc.returncode

    def stderr_text(self) -> str:
        assert self.proc.stderr is not None
        return self.proc.stderr.read().decode("utf-8", errors="replace")

    def __enter__(self) -> "WrappedServer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def write_policy(tmp_path: Path, body: str, name: str = "policy.yaml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def audit_entries(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
