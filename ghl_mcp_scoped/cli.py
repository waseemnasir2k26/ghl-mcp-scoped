"""Command line interface: `ghl-mcp-scoped run` and `ghl-mcp-scoped validate`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .audit import AuditLog
from .policy import Policy, PolicyError, load_policy
from .proxy import run as run_proxy

EXIT_OK = 0
EXIT_POLICY_ERROR = 2
EXIT_USAGE = 64


def _fmt_conditions(rule: Any) -> str:
    if not rule.when:
        return "-"
    return "; ".join(c.describe() for c in rule.when.constraints)


def _load_tool_names(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("result", data).get("tools", [])
        names = []
        for entry in data:
            if isinstance(entry, str):
                names.append(entry)
            elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
                names.append(entry["name"])
        return names
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    out = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    out.append("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        out.append("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))).rstrip())
    return "\n".join(out)


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print("INVALID  %s" % exc, file=sys.stderr)
        return EXIT_POLICY_ERROR

    print("ghl-mcp-scoped %s  policy: %s" % (__version__, policy.source_path))
    if policy.name:
        print("name:        %s" % policy.name)
    if policy.description:
        print("description: %s" % policy.description)
    print("mode:        %s" % policy.mode)
    print(
        "read_only:   %s%s"
        % (
            "true" if policy.read_only else "false",
            "  (read verbs: %s)" % ", ".join(policy.read_verbs) if policy.read_only else "",
        )
    )
    print(
        "audit:       %s"
        % (
            "%s  (arguments: %s, redact keys matching /%s/)"
            % (
                policy.audit.path,
                "logged" if policy.audit.log_arguments else "not logged",
                policy.audit.redact_keys,
            )
            if policy.audit.enabled
            else "DISABLED"
        )
    )
    print(
        "visibility:  denied tools %s, confirm tools %s in tools/list"
        % (
            "hidden" if policy.visibility.hide_denied else "shown",
            "hidden" if policy.visibility.hide_confirm else "shown",
        )
    )
    print()

    rows = []
    for rule in policy.rules:
        rows.append(
            [
                rule.match,
                rule.action,
                _fmt_conditions(rule),
                rule.otherwise if rule.when else "-",
                rule.id,
            ]
        )
    if rows:
        print("RULES (first match wins)")
        print(_table(rows, ["PATTERN", "ACTION", "WHEN", "ELSE", "RULE ID"]))
    else:
        print("RULES: none")
    default = "deny" if policy.mode == "allowlist" else "allow"
    print()
    print("Anything not matched above: %s (mode: %s)" % (default.upper(), policy.mode))
    if policy.read_only:
        print("read_only cap: any tool without a read verb is DENIED before rules are consulted.")

    if args.tools:
        names = _load_tool_names(Path(args.tools))
        print()
        print("EFFECTIVE PERMISSIONS for %d tool(s) from %s" % (len(names), args.tools))
        rows = []
        for name in sorted(names):
            decision = policy.decide_visibility(name)
            rows.append(
                [
                    name,
                    decision.decision.upper(),
                    "yes" if policy.is_visible(name) else "no",
                    decision.rule,
                ]
            )
        print(_table(rows, ["TOOL", "DECISION", "LISTED", "RULE"]))
        allowed = sum(1 for r in rows if r[1] == "ALLOW")
        print()
        print(
            "%d allowed, %d needing a human, %d denied"
            % (
                allowed,
                sum(1 for r in rows if r[1] == "CONFIRM"),
                sum(1 for r in rows if r[1] == "DENY"),
            )
        )

    warnings = _warnings(policy)
    if warnings:
        print()
        for warning in warnings:
            print("WARNING  %s" % warning)

    print()
    print("OK  policy is valid.")
    return EXIT_OK


def _warnings(policy: Policy) -> list[str]:
    out = []
    if not policy.audit.enabled:
        out.append("audit logging is disabled; refusals will not be recorded anywhere.")
    if policy.mode == "allowlist" and not any(r.action == "allow" for r in policy.rules):
        out.append("mode is allowlist and no rule allows anything; every tool call will be denied.")
    if policy.read_only:
        for rule in policy.rules:
            if rule.action == "allow" and "*" not in rule.match and not policy.is_read_tool(rule.match):
                out.append(
                    "rule '%s' allows '%s', but read_only: true denies it anyway "
                    "(no read verb in the name)." % (rule.id, rule.match)
                )
    if policy.mode == "denylist":
        out.append(
            "mode is denylist: any tool the wrapped server adds in a future release is "
            "allowed automatically. allowlist is the safer default."
        )
    return out


def cmd_run(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print("ghl-mcp-scoped: INVALID POLICY: %s" % exc, file=sys.stderr)
        return EXIT_POLICY_ERROR

    if not args.command:
        print(
            "ghl-mcp-scoped: no wrapped server command given.\n"
            "usage: ghl-mcp-scoped run --policy POLICY -- <server command...>",
            file=sys.stderr,
        )
        return EXIT_USAGE

    if args.audit_log:
        policy.audit.path = args.audit_log
        policy.audit.enabled = True

    audit = AuditLog(policy.audit, base_dir=Path(policy.source_path).parent if policy.source_path else None)
    return run_proxy(policy, audit, list(args.command), verbose=args.verbose)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghl-mcp-scoped",
        description=(
            "Least-privilege policy wrapper for a GoHighLevel MCP server. "
            "Declare which tools an agent may call; everything else is refused and logged."
        ),
    )
    parser.add_argument("--version", action="version", version="ghl-mcp-scoped " + __version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="run the wrapped MCP server behind a policy")
    run_p.add_argument("--policy", "-p", required=True, help="path to the policy YAML")
    run_p.add_argument("--audit-log", help="override audit.path from the policy")
    run_p.add_argument(
        "--verbose", "-v", action="store_true", help="log relay activity to stderr"
    )
    run_p.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="the wrapped server command, after a bare --",
    )
    run_p.set_defaults(func=cmd_run)

    val_p = sub.add_parser("validate", help="lint a policy and print the permission table")
    val_p.add_argument("policy", help="path to the policy YAML")
    val_p.add_argument(
        "--tools",
        help=(
            "optional file of tool names to evaluate against: .txt (one per line) "
            "or .json (a tools/list dump, or a plain list of names)"
        ),
    )
    val_p.set_defaults(func=cmd_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
