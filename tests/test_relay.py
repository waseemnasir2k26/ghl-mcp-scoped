"""End-to-end tests: a real wrapper process in front of a real fake server."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from harness import REPO_ROOT, WrappedServer, audit_entries, write_policy

LOC_A = "loc_EXAMPLE_CLIENT_A"
LOC_B = "loc_EXAMPLE_CLIENT_B"


def _policy(tmp_path: Path, body: str) -> Path:
    audit = (tmp_path / "audit.jsonl").as_posix()
    return write_policy(tmp_path, body.replace("__AUDIT__", audit))


# ---------------------------------------------------------------------------
# allowlist / denylist
# ---------------------------------------------------------------------------


def test_allowlist_denies_everything_not_listed(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - match: "contacts_get-*"
    action: allow
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        ok = server.call_tool("contacts_get-contacts", {"locationId": LOC_A})
        assert "result" in ok
        assert ok["result"]["_echo"]["name"] == "contacts_get-contacts"

        blocked = server.call_tool("payments_list-transactions", {"locationId": LOC_A})
        assert "result" not in blocked
        assert blocked["error"]["code"] == -32003
        assert blocked["error"]["data"]["rule"] == "default:allowlist"
        assert "payments_list-transactions" in blocked["error"]["message"]


def test_denylist_allows_unlisted_and_blocks_named(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: denylist
tools:
  - id: no-payments
    match: "payments_*"
    action: deny
    reason: financial records are out of scope
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        assert "result" in server.call_tool("contacts_upsert-contact", {"locationId": LOC_A})
        blocked = server.call_tool("payments_list-transactions", {})
        assert blocked["error"]["data"]["rule"] == "no-payments"
        assert "financial records are out of scope" in blocked["error"]["message"]


# ---------------------------------------------------------------------------
# read_only
# ---------------------------------------------------------------------------


def test_read_only_caps_writes_even_when_a_rule_allows_them(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
read_only: true
read_verbs: [get, list, search, fetch]
tools:
  - match: "*"
    action: allow
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        assert "result" in server.call_tool("contacts_get-contact", {"contactId": "c_1"})
        assert "result" in server.call_tool("conversations_search-conversation", {"query": "x"})

        blocked = server.call_tool("contacts_upsert-contact", {"locationId": LOC_A})
        assert blocked["error"]["data"]["rule"] == "read_only"
        assert blocked["error"]["data"]["decision"] == "deny"


def test_read_verbs_are_configurable(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
read_only: true
read_verbs: [get]
tools:
  - match: "*"
    action: allow
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        assert "result" in server.call_tool("contacts_get-contact", {})
        blocked = server.call_tool("payments_list-transactions", {})
        assert blocked["error"]["data"]["rule"] == "read_only"


# ---------------------------------------------------------------------------
# argument constraints
# ---------------------------------------------------------------------------


def test_argument_constraints_gate_one_location(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - id: upsert-scoped
    match: "contacts_upsert-contact"
    action: allow
    when:
      - arg: locationId
        in: ["%s"]
      - arg: dndSettings
        forbidden: true
audit:
  path: __AUDIT__
"""
        % LOC_A,
    )
    with WrappedServer(policy) as server:
        good = server.call_tool("contacts_upsert-contact", {"locationId": LOC_A})
        assert "result" in good

        wrong_location = server.call_tool("contacts_upsert-contact", {"locationId": LOC_B})
        assert wrong_location["error"]["data"]["rule"] == "upsert-scoped"
        assert "not in the permitted set" in wrong_location["error"]["message"]

        forbidden_arg = server.call_tool(
            "contacts_upsert-contact",
            {"locationId": LOC_A, "dndSettings": {"SMS": {"status": "inactive"}}},
        )
        assert forbidden_arg["error"]["data"]["decision"] == "deny"
        assert "dndSettings" in forbidden_arg["error"]["message"]

        missing = server.call_tool("contacts_upsert-contact", {})
        assert "is missing" in missing["error"]["message"]


def test_nested_and_regex_constraints(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - id: namespaced-tags
    match: "contacts_add-tags"
    action: allow
    when:
      - arg: tags.0
        matches: "^agent:"
      - arg: contact.locationId
        equals: "%s"
audit:
  path: __AUDIT__
"""
        % LOC_A,
    )
    with WrappedServer(policy) as server:
        good = server.call_tool(
            "contacts_add-tags",
            {"tags": ["agent:nurture"], "contact": {"locationId": LOC_A}},
        )
        assert "result" in good

        bad_tag = server.call_tool(
            "contacts_add-tags", {"tags": ["vip"], "contact": {"locationId": LOC_A}}
        )
        assert bad_tag["error"]["data"]["rule"] == "namespaced-tags"

        bad_nested = server.call_tool(
            "contacts_add-tags",
            {"tags": ["agent:nurture"], "contact": {"locationId": LOC_B}},
        )
        assert "contact.locationId" in bad_nested["error"]["message"]


def test_otherwise_confirm_downgrades_instead_of_denying(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - id: scoped-or-ask
    match: "contacts_upsert-contact"
    action: allow
    otherwise: confirm
    when:
      - arg: locationId
        in: ["%s"]
audit:
  path: __AUDIT__
"""
        % LOC_A,
    )
    with WrappedServer(policy) as server:
        blocked = server.call_tool("contacts_upsert-contact", {"locationId": LOC_B})
        assert blocked["error"]["code"] == -32004
        assert blocked["error"]["data"]["decision"] == "confirm"


# ---------------------------------------------------------------------------
# tools/list filtering
# ---------------------------------------------------------------------------


def test_tools_list_hides_what_cannot_be_called(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - match: "contacts_get-*"
    action: allow
  - id: send-needs-human
    match: "conversations_send-a-new-message"
    action: confirm
  - id: upsert-scoped
    match: "contacts_upsert-contact"
    action: allow
    when:
      - arg: locationId
        in: ["%s"]
audit:
  path: __AUDIT__
"""
        % LOC_A,
    )
    with WrappedServer(policy) as server:
        listed = server.request("tools/list")
        names = [t["name"] for t in listed["result"]["tools"]]
        assert names == [
            "contacts_get-contacts",
            "contacts_get-contact",
            "contacts_upsert-contact",
        ]
        assert "payments_list-transactions" not in names
        # confirm tools are hidden by default
        assert "conversations_send-a-new-message" not in names
        # every surviving entry keeps its schema untouched
        assert listed["result"]["tools"][0]["inputSchema"]["type"] == "object"


def test_confirm_tools_can_be_kept_visible(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
visibility:
  hide_confirm: false
tools:
  - id: send-needs-human
    match: "conversations_send-a-new-message"
    action: confirm
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        names = [t["name"] for t in server.request("tools/list")["result"]["tools"]]
        assert names == ["conversations_send-a-new-message"]

        blocked = server.call_tool("conversations_send-a-new-message", {"contactId": "c_1"})
        assert blocked["error"]["code"] == -32004
        assert "human" in blocked["error"]["message"].lower()


# ---------------------------------------------------------------------------
# audit log
# ---------------------------------------------------------------------------


def test_audit_records_decisions_and_redacts_sensitive_keys(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - match: "contacts_get-*"
    action: allow
audit:
  path: __AUDIT__
  redact_keys: "token|secret|key|password|phone|email"
""",
    )
    secret = "FAKE-TOKEN-MUST-NEVER-BE-LOGGED"
    with WrappedServer(policy) as server:
        server.call_tool(
            "contacts_get-contact",
            {
                "contactId": "c_1",
                "apiKey": secret,
                "email": "someone@example.test",
                "nested": {"accessToken": secret, "note": "safe"},
                "phone": "+10000000000",
            },
        )
        server.call_tool("payments_list-transactions", {"locationId": LOC_A})

    entries = audit_entries(tmp_path / "audit.jsonl")
    calls = [e for e in entries if e["event"] == "tools/call"]
    assert [e["decision"] for e in calls] == ["allow", "deny"]
    assert calls[0]["forwarded"] is True and calls[1]["forwarded"] is False
    assert calls[1]["rule"] == "default:allowlist"

    args = calls[0]["arguments"]
    assert args["apiKey"] == "[REDACTED]"
    assert args["email"] == "[REDACTED]"
    assert args["phone"] == "[REDACTED]"
    assert args["nested"]["accessToken"] == "[REDACTED]"
    assert args["nested"]["note"] == "safe"
    assert args["contactId"] == "c_1"

    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert secret not in raw
    assert "someone@example.test" not in raw

    events = [e["event"] for e in entries]
    assert events[0] == "session_start" and events[-1] == "session_end"


def test_audit_can_drop_arguments_entirely(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - match: "contacts_get-*"
    action: allow
audit:
  path: __AUDIT__
  log_arguments: false
""",
    )
    with WrappedServer(policy) as server:
        server.call_tool("contacts_get-contact", {"contactId": "c_1", "note": "sensitive"})

    calls = [e for e in audit_entries(tmp_path / "audit.jsonl") if e["event"] == "tools/call"]
    assert calls[0]["arguments"] == "[REDACTED]"


def test_audit_records_the_tools_list_filter(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - match: "locations_get-*"
    action: allow
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        server.request("tools/list")

    listings = [e for e in audit_entries(tmp_path / "audit.jsonl") if e["event"] == "tools/list"]
    assert listings[0]["visible"] == ["locations_get-location"]
    assert "payments_list-transactions" in listings[0]["hidden"]


# ---------------------------------------------------------------------------
# refusal frames and faithful passthrough
# ---------------------------------------------------------------------------


def test_refusal_is_a_well_formed_jsonrpc_error(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - id: no-payments
    match: "payments_*"
    action: deny
    reason: financial records are out of scope
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        blocked = server.call_tool("payments_list-transactions", {})
    assert blocked["jsonrpc"] == "2.0"
    assert blocked["id"] == 1
    assert "result" not in blocked
    error = blocked["error"]
    assert isinstance(error["code"], int) and -32099 <= error["code"] <= -32000
    assert isinstance(error["message"], str) and error["message"]
    assert error["data"]["blockedBy"] == "ghl-mcp-scoped"
    assert error["data"]["tool"] == "payments_list-transactions"
    assert error["data"]["rule"] == "no-payments"
    assert error["data"]["policy"].endswith("policy.yaml")


def test_malformed_tools_call_is_refused_not_forwarded(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: denylist
tools:
  - match: "payments_*"
    action: deny
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        server.send_raw({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {}})
        reply = server.await_id(99)
    assert reply["error"]["code"] == -32005


def test_denied_notification_does_not_stall_the_stream(tmp_path):
    """A tools/call with no id cannot be answered. Dropping it must not wedge
    the next real request."""
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - match: "contacts_get-*"
    action: allow
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        server.send_raw(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "payments_list-transactions", "arguments": {}},
            }
        )
        assert "result" in server.call_tool("contacts_get-contact", {"contactId": "c_1"})


def test_everything_that_is_not_a_tool_call_passes_through_untouched(tmp_path):
    policy = _policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - match: "contacts_get-*"
    action: allow
audit:
  path: __AUDIT__
""",
    )
    with WrappedServer(policy) as server:
        init = server.request(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}},
        )
        assert init["result"]["serverInfo"] == {"name": "fake-ghl-mcp", "version": "0.0.0-test"}

        server.send_raw({"jsonrpc": "2.0", "method": "notifications/initialized"})

        echoed = server.request("debug/echo", {"deep": {"list": [1, 2, {"x": None}]}})
        assert echoed["result"] == {"deep": {"list": [1, 2, {"x": None}]}}

        unknown = server.request("resources/list")
        assert unknown["error"]["code"] == -32601

        noise = server.request("debug/emit-noise")
        assert noise["result"] == {"ok": True}
        assert "this line is not JSON" in server.raw_lines

        # allowed calls reach the server with their arguments byte-identical
        payload = {"contactId": "c_1", "unicode": "café — ü", "n": 3.5}
        result = server.call_tool("contacts_get-contact", payload)
        assert result["result"]["_echo"]["arguments"] == payload


# ---------------------------------------------------------------------------
# the shipped policies
# ---------------------------------------------------------------------------


def _validate(policy_name: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "ghl_mcp_scoped", "validate", "policies/" + policy_name],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )


def test_shipped_policies_validate():
    for name in ("read-only.yaml", "content-only.yaml", "full-with-audit.yaml"):
        proc = _validate(name)
        assert proc.returncode == 0, proc.stderr
        assert "OK  policy is valid." in proc.stdout


def test_validate_prints_effective_permissions(tmp_path):
    tools = tmp_path / "tools.json"
    tools.write_text(
        json.dumps(
            {
                "result": {
                    "tools": [
                        {"name": "contacts_get-contacts"},
                        {"name": "contacts_upsert-contact"},
                        {"name": "payments_list-transactions"},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ghl_mcp_scoped",
            "validate",
            "policies/read-only.yaml",
            "--tools",
            str(tools),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "contacts_get-contacts" in proc.stdout
    # read-only.yaml allows the two read tools and denies the write
    assert "2 allowed, 0 needing a human, 1 denied" in proc.stdout
    assert "contacts_upsert-contact" in proc.stdout


def test_validate_rejects_a_broken_policy(tmp_path):
    bad = write_policy(
        tmp_path,
        """
version: 1
mode: allowlist
tools:
  - match: "contacts_*"
    action: allow
    when:
      - arg: locationId
        in: []
""",
        name="bad.yaml",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "ghl_mcp_scoped", "validate", str(bad)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "INVALID" in proc.stderr
    assert "non-empty list" in proc.stderr
