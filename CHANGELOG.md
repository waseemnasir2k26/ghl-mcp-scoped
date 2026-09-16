# Changelog

All notable changes to this project are documented in this file.

## [2026.09] - 2026-09-16

- Maintenance review of ghl-mcp-scoped — a Python least-privilege policy wrapper that sits in front of any GoHighLevel MCP server, enforcing a declarative allow/deny policy over tool calls and logging every decision.
- Status: public, MIT-licensed, v1 shipped 2026-09-01. Package `ghl_mcp_scoped` (cli, policy, matchers, proxy, audit), three example policies (read-only, content-only, full-with-audit), a runnable demo in `examples/demo_session.py`, and a test suite with a fake GHL server under `tests/`. Python 3.11+, PyYAML the only runtime dependency.
- Reviewed September 2026: docs refreshed, `## Status` line added to README, changelog started, versioned as v2026.09. Code and policy files untouched.
- Known gaps, as the README's own Limitations section states: policy layer only (no authentication, no credentials), bypassable by anything that reaches the wrapped server directly, structural argument matching only, stdio JSON-RPC transport only, and no rate limiting, spend caps or time windows in v1.
- Not re-verified this month: the README's "59 passing" test badge and the demo output were taken as-is; no test run was performed in this maintenance pass.
