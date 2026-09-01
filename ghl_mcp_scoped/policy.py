"""Policy loading, validation and the decision engine."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .matchers import MATCHER_KEYS, Constraint, ConstraintSet

DEFAULT_READ_VERBS = ["get", "list", "search", "fetch"]
DEFAULT_REDACT_KEYS = r"token|secret|key|password|phone|email"
DEFAULT_AUDIT_PATH = "ghl-mcp-audit.jsonl"

ACTIONS = ("allow", "deny", "confirm")
MODES = ("allowlist", "denylist")

_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+")

CONFIRM_MESSAGE = (
    "This tool is marked 'confirm' in the active policy. It is not callable by an "
    "agent. A human must run it directly against the GoHighLevel MCP server, or the "
    "policy must be changed to 'allow'."
)


class PolicyError(Exception):
    """Raised when a policy file is malformed."""


@dataclass
class Decision:
    decision: str  # allow | deny | confirm
    rule: str  # human readable id of the rule that decided
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


@dataclass
class AuditConfig:
    enabled: bool = True
    path: str = DEFAULT_AUDIT_PATH
    log_arguments: bool = True
    redact_keys: str = DEFAULT_REDACT_KEYS
    redact_placeholder: str = "[REDACTED]"
    max_string_length: int = 200


@dataclass
class VisibilityConfig:
    hide_denied: bool = True
    hide_confirm: bool = True


@dataclass
class Rule:
    match: str
    action: str
    when: ConstraintSet = field(default_factory=ConstraintSet)
    otherwise: str = "deny"
    reason: str = ""
    id: str = ""

    def matches_name(self, tool: str) -> bool:
        return self.match == tool or fnmatch.fnmatchcase(tool, self.match)


@dataclass
class Policy:
    mode: str = "allowlist"
    read_only: bool = False
    read_verbs: list[str] = field(default_factory=lambda: list(DEFAULT_READ_VERBS))
    rules: list[Rule] = field(default_factory=list)
    audit: AuditConfig = field(default_factory=AuditConfig)
    visibility: VisibilityConfig = field(default_factory=VisibilityConfig)
    name: str = ""
    description: str = ""
    source_path: str = ""

    # -- helpers ---------------------------------------------------------
    def is_read_tool(self, tool: str) -> bool:
        tokens = {t.lower() for t in _TOKEN_SPLIT.split(tool) if t}
        return any(v.lower() in tokens for v in self.read_verbs)

    def find_rule(self, tool: str) -> Rule | None:
        for rule in self.rules:
            if rule.matches_name(tool):
                return rule
        return None

    # -- decisions -------------------------------------------------------
    def decide(
        self, tool: str, arguments: Any = None, evaluate_arguments: bool = True
    ) -> Decision:
        """Decide one tools/call.

        Precedence: the read_only cap, then the first matching rule in file
        order, then the mode default. With ``evaluate_arguments=False`` the
        ``when:`` block is skipped (used for name-only tools/list filtering).
        """
        if arguments is None:
            arguments = {}

        if self.read_only and not self.is_read_tool(tool):
            return Decision(
                "deny",
                "read_only",
                "policy sets read_only: true and '%s' contains none of the read verbs (%s)"
                % (tool, ", ".join(self.read_verbs)),
            )

        rule = self.find_rule(tool)
        if rule is None:
            if self.mode == "allowlist":
                return Decision(
                    "deny",
                    "default:allowlist",
                    "no rule in the policy allows '%s' and mode is allowlist "
                    "(deny by default)" % tool,
                )
            return Decision(
                "allow",
                "default:denylist",
                "no rule in the policy denies '%s' and mode is denylist" % tool,
            )

        if rule.action == "deny":
            return Decision(
                "deny", rule.id, rule.reason or "rule '%s' denies this tool" % rule.id
            )
        if rule.action == "confirm":
            return Decision(
                "confirm",
                rule.id,
                rule.reason or "rule '%s' requires a human to run this tool" % rule.id,
            )

        if rule.when and evaluate_arguments:
            ok, why = rule.when.check(arguments)
            if not ok:
                return Decision(
                    rule.otherwise,
                    rule.id,
                    "rule '%s' allows this tool only when its argument constraints "
                    "hold; %s" % (rule.id, why),
                )
        return Decision("allow", rule.id, rule.reason or "rule '%s' allows this tool" % rule.id)

    def decide_visibility(self, tool: str) -> Decision:
        """Name-only decision, used to filter tools/list.

        Argument constraints cannot be evaluated here (there are no arguments
        yet), so a conditionally allowed tool stays visible and is judged at
        call time.
        """
        return self.decide(tool, arguments={}, evaluate_arguments=False)

    def is_visible(self, tool: str) -> bool:
        decision = self.decide_visibility(tool)
        if decision.decision == "allow":
            return True
        if decision.decision == "confirm":
            return not self.visibility.hide_confirm
        return not self.visibility.hide_denied


# ---------------------------------------------------------------------------
# loading and validation
# ---------------------------------------------------------------------------

_ALLOWED_TOP = {
    "version",
    "name",
    "description",
    "mode",
    "read_only",
    "read_verbs",
    "tools",
    "audit",
    "visibility",
}
_ALLOWED_RULE = {"match", "tool", "action", "when", "otherwise", "reason", "id"}
_ALLOWED_CONSTRAINT = {"arg", "optional", *MATCHER_KEYS}
_ALLOWED_AUDIT = {
    "enabled",
    "path",
    "log_arguments",
    "redact_keys",
    "redact_placeholder",
    "max_string_length",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def _parse_constraint(raw: Any, where: str) -> Constraint:
    _require(isinstance(raw, dict), "%s: each 'when' entry must be a mapping" % where)
    unknown = set(raw) - _ALLOWED_CONSTRAINT
    _require(
        not unknown,
        "%s: unknown constraint key(s) %s; allowed: arg, optional, %s"
        % (where, sorted(unknown), ", ".join(MATCHER_KEYS)),
    )
    arg = raw.get("arg")
    _require(isinstance(arg, str) and arg, "%s: 'arg' must be a non-empty string" % where)
    kinds = [k for k in MATCHER_KEYS if k in raw]
    _require(
        len(kinds) == 1,
        "%s: exactly one matcher of %s is required, got %s"
        % (where, list(MATCHER_KEYS), kinds),
    )
    kind = kinds[0]
    value = raw[kind]
    if kind == "in":
        _require(
            isinstance(value, list) and len(value) > 0,
            "%s: 'in' must be a non-empty list" % where,
        )
    if kind == "matches":
        _require(isinstance(value, str), "%s: 'matches' must be a regex string" % where)
        try:
            re.compile(value)
        except re.error as exc:
            raise PolicyError("%s: invalid regex for 'matches': %s" % (where, exc)) from exc
    if kind in ("required", "forbidden"):
        _require(
            value is True,
            "%s: '%s' takes the literal value true" % (where, kind),
        )
    return Constraint(
        arg=arg, kind=kind, value=value, optional=bool(raw.get("optional", False))
    )


def _parse_rule(raw: Any, index: int) -> Rule:
    where = "tools[%d]" % index
    _require(isinstance(raw, dict), "%s: each tool rule must be a mapping" % where)
    unknown = set(raw) - _ALLOWED_RULE
    _require(not unknown, "%s: unknown key(s) %s" % (where, sorted(unknown)))
    match = raw.get("match", raw.get("tool"))
    _require(
        isinstance(match, str) and match,
        "%s: 'match' (or its alias 'tool') must be a non-empty string" % where,
    )
    action = raw.get("action", "allow")
    _require(
        action in ACTIONS,
        "%s: 'action' must be one of %s, got %r" % (where, list(ACTIONS), action),
    )
    otherwise = raw.get("otherwise", "deny")
    _require(
        otherwise in ("deny", "confirm"),
        "%s: 'otherwise' must be 'deny' or 'confirm', got %r" % (where, otherwise),
    )
    when_raw = raw.get("when", []) or []
    _require(isinstance(when_raw, list), "%s: 'when' must be a list of constraints" % where)
    if when_raw:
        _require(
            action == "allow",
            "%s: 'when' is only meaningful on an 'allow' rule (this rule is '%s')"
            % (where, action),
        )
    constraints = [
        _parse_constraint(entry, "%s.when[%d]" % (where, i)) for i, entry in enumerate(when_raw)
    ]
    reason = raw.get("reason", "")
    _require(isinstance(reason, str), "%s: 'reason' must be a string" % where)
    rule_id = raw.get("id") or "%s:%s:%s" % (where, match, action)
    return Rule(
        match=match,
        action=action,
        when=ConstraintSet(constraints),
        otherwise=otherwise,
        reason=reason,
        id=str(rule_id),
    )


def _parse_audit(raw: Any) -> AuditConfig:
    if raw is None:
        return AuditConfig()
    _require(isinstance(raw, dict), "audit: must be a mapping")
    unknown = set(raw) - _ALLOWED_AUDIT
    _require(not unknown, "audit: unknown key(s) %s" % sorted(unknown))
    redact = raw.get("redact_keys", DEFAULT_REDACT_KEYS)
    _require(isinstance(redact, str), "audit.redact_keys must be a regex string")
    try:
        re.compile(redact)
    except re.error as exc:
        raise PolicyError("audit.redact_keys: invalid regex: %s" % exc) from exc
    max_len = raw.get("max_string_length", 200)
    _require(
        isinstance(max_len, int) and not isinstance(max_len, bool) and max_len > 0,
        "audit.max_string_length must be a positive integer",
    )
    return AuditConfig(
        enabled=bool(raw.get("enabled", True)),
        path=str(raw.get("path", DEFAULT_AUDIT_PATH)),
        log_arguments=bool(raw.get("log_arguments", True)),
        redact_keys=redact,
        redact_placeholder=str(raw.get("redact_placeholder", "[REDACTED]")),
        max_string_length=max_len,
    )


def _parse_visibility(raw: Any) -> VisibilityConfig:
    if raw is None:
        return VisibilityConfig()
    _require(isinstance(raw, dict), "visibility: must be a mapping")
    unknown = set(raw) - {"hide_denied", "hide_confirm"}
    _require(not unknown, "visibility: unknown key(s) %s" % sorted(unknown))
    return VisibilityConfig(
        hide_denied=bool(raw.get("hide_denied", True)),
        hide_confirm=bool(raw.get("hide_confirm", True)),
    )


def load_policy_dict(data: Any, source_path: str = "") -> Policy:
    _require(isinstance(data, dict), "policy: the top level must be a mapping")
    unknown = set(data) - _ALLOWED_TOP
    _require(not unknown, "policy: unknown top level key(s) %s" % sorted(unknown))

    version = data.get("version", 1)
    _require(
        version == 1, "policy: unsupported version %r (this build understands 1)" % version
    )

    mode = data.get("mode", "allowlist")
    _require(mode in MODES, "policy: 'mode' must be one of %s, got %r" % (list(MODES), mode))

    read_only = data.get("read_only", False)
    _require(isinstance(read_only, bool), "policy: 'read_only' must be true or false")

    read_verbs = data.get("read_verbs", DEFAULT_READ_VERBS)
    _require(
        isinstance(read_verbs, list)
        and len(read_verbs) > 0
        and all(isinstance(v, str) and v for v in read_verbs),
        "policy: 'read_verbs' must be a non-empty list of non-empty strings",
    )

    tools_raw = data.get("tools", []) or []
    _require(isinstance(tools_raw, list), "policy: 'tools' must be a list of rules")
    rules = [_parse_rule(entry, i) for i, entry in enumerate(tools_raw)]

    first_seen: dict[str, int] = {}
    for i, rule in enumerate(rules):
        earlier = first_seen.get(rule.match)
        if earlier is not None and not rules[earlier].when:
            raise PolicyError(
                "tools[%d]: pattern %r is already handled unconditionally by tools[%d]; "
                "the later rule can never fire" % (i, rule.match, earlier)
            )
        first_seen.setdefault(rule.match, i)

    if mode == "denylist" and not rules:
        raise PolicyError(
            "policy: mode 'denylist' with no rules allows every tool; add at least one "
            "deny rule or switch to allowlist"
        )

    return Policy(
        mode=mode,
        read_only=read_only,
        read_verbs=[str(v) for v in read_verbs],
        rules=rules,
        audit=_parse_audit(data.get("audit")),
        visibility=_parse_visibility(data.get("visibility")),
        name=str(data.get("name", "") or ""),
        description=str(data.get("description", "") or ""),
        source_path=source_path,
    )


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    if not p.is_file():
        raise PolicyError("policy file not found: %s" % p)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError("%s: could not parse YAML: %s" % (p, exc)) from exc
    if data is None:
        raise PolicyError("%s: policy file is empty" % p)
    return load_policy_dict(data, source_path=str(p))
