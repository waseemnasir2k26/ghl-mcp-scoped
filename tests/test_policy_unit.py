"""Unit tests for the matchers, the policy loader and audit redaction."""

from __future__ import annotations

import re

import pytest

from ghl_mcp_scoped.audit import redact
from ghl_mcp_scoped.matchers import Constraint, resolve_path, is_missing
from ghl_mcp_scoped.policy import PolicyError, load_policy, load_policy_dict


# -- matchers ---------------------------------------------------------------


def test_resolve_path_walks_dicts_and_lists():
    args = {"contact": {"tags": ["a", "b"]}}
    assert resolve_path(args, "contact.tags.1") == "b"
    assert is_missing(resolve_path(args, "contact.tags.9"))
    assert is_missing(resolve_path(args, "contact.missing"))
    assert is_missing(resolve_path(args, "contact.tags.notanindex"))


@pytest.mark.parametrize(
    "constraint,args,expected",
    [
        (Constraint("a", "equals", 1), {"a": 1}, True),
        (Constraint("a", "equals", 1), {"a": 2}, False),
        (Constraint("a", "equals", 1), {}, False),
        (Constraint("a", "in", ["x", "y"]), {"a": "y"}, True),
        (Constraint("a", "in", ["x", "y"]), {"a": "z"}, False),
        (Constraint("a", "matches", "^agent:"), {"a": "agent:x"}, True),
        (Constraint("a", "matches", "^agent:"), {"a": "vip"}, False),
        (Constraint("a", "required", True), {"a": 0}, True),
        (Constraint("a", "required", True), {"a": None}, False),
        (Constraint("a", "required", True), {}, False),
        (Constraint("a", "forbidden", True), {}, True),
        (Constraint("a", "forbidden", True), {"a": None}, True),
        (Constraint("a", "forbidden", True), {"a": "x"}, False),
        (Constraint("a", "equals", 1, optional=True), {}, True),
        (Constraint("a", "equals", 1, optional=True), {"a": 2}, False),
        (Constraint("a", "required", True, optional=True), {}, False),
    ],
)
def test_constraint_truth_table(constraint, args, expected):
    ok, why = constraint.check(args)
    assert ok is expected
    assert why


# -- policy semantics -------------------------------------------------------


def _p(**kwargs):
    base = {"version": 1, "mode": "allowlist", "tools": []}
    base.update(kwargs)
    return load_policy_dict(base)


def test_first_matching_rule_wins():
    policy = _p(
        tools=[
            {"id": "first", "match": "contacts_*", "action": "deny"},
            {"id": "second", "match": "contacts_get-contact", "action": "allow"},
        ]
    )
    assert policy.decide("contacts_get-contact").rule == "first"


def test_read_verb_tokenisation():
    policy = _p(read_only=True, tools=[{"match": "*", "action": "allow"}])
    assert policy.is_read_tool("contacts_get-contacts")
    assert policy.is_read_tool("mcp__ghl__payments_list-transactions")
    assert not policy.is_read_tool("contacts_upsert-contact")
    # "forget" contains "get" but not as a token, so it is not a read tool
    assert not policy.is_read_tool("contacts_forget-contact")


def test_visibility_keeps_conditionally_allowed_tools():
    policy = _p(
        tools=[
            {
                "id": "scoped",
                "match": "contacts_upsert-contact",
                "action": "allow",
                "when": [{"arg": "locationId", "in": ["loc_EXAMPLE_CLIENT_A"]}],
            }
        ]
    )
    assert policy.is_visible("contacts_upsert-contact")
    assert not policy.is_visible("payments_list-transactions")
    assert policy.decide("contacts_upsert-contact", {"locationId": "other"}).decision == "deny"


# -- loader rejections ------------------------------------------------------


@pytest.mark.parametrize(
    "data,fragment",
    [
        ({"version": 2}, "unsupported version"),
        ({"mode": "whatever"}, "'mode' must be one of"),
        ({"read_only": "yes"}, "must be true or false"),
        ({"read_verbs": []}, "non-empty list"),
        ({"mode": "denylist", "tools": []}, "allows every tool"),
        ({"tools": [{"action": "allow"}]}, "'match'"),
        ({"tools": [{"match": "a", "action": "maybe"}]}, "'action' must be one of"),
        ({"tools": [{"match": "a", "action": "deny", "when": [{"arg": "x", "required": True}]}],},
         "only meaningful on an 'allow' rule"),
        ({"tools": [{"match": "a", "when": [{"arg": "x"}]}]}, "exactly one matcher"),
        (
            {"tools": [{"match": "a", "when": [{"arg": "x", "equals": 1, "in": [1]}]}]},
            "exactly one matcher",
        ),
        ({"tools": [{"match": "a", "when": [{"arg": "x", "matches": "["}]}]}, "invalid regex"),
        ({"tools": [{"match": "a", "when": [{"arg": "x", "required": "yes"}]}]}, "literal value true"),
        ({"tools": [{"match": "a", "action": "allow"}, {"match": "a", "action": "deny"}]},
         "can never fire"),
        ({"audit": {"redact_keys": "("}}, "invalid regex"),
        ({"audit": {"max_string_length": 0}}, "positive integer"),
        ({"nonsense": 1}, "unknown top level key"),
        ({"tools": [{"match": "a", "otherwise": "allow"}]}, "'otherwise' must be"),
    ],
)
def test_loader_rejects_bad_policies(data, fragment):
    payload = {"version": 1, "mode": "allowlist", "tools": []}
    payload.update(data)
    with pytest.raises(PolicyError) as exc:
        load_policy_dict(payload)
    assert fragment in str(exc.value)


def test_missing_file_is_a_policy_error(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nope.yaml")


def test_empty_file_is_a_policy_error(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


# -- redaction --------------------------------------------------------------


def test_redaction_is_by_key_and_recursive():
    pattern = re.compile("token|secret|key|password|phone|email", re.IGNORECASE)
    out = redact(
        {
            "apiKey": "fake-not-a-real-key",
            "Email": "a@b.test",
            "items": [{"accessToken": "t", "label": "keep"}],
            "note": "y" * 20,
        },
        pattern,
        "[REDACTED]",
        10,
    )
    assert out["apiKey"] == "[REDACTED]"
    assert out["Email"] == "[REDACTED]"
    assert out["items"][0]["accessToken"] == "[REDACTED]"
    assert out["items"][0]["label"] == "keep"
    assert out["note"] == "y" * 10 + "...[truncated]"
