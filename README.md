# ghl-mcp-scoped

A least-privilege policy wrapper that sits in front of any GoHighLevel MCP server: you declare which tools an AI agent may call and under what conditions, and the wrapper enforces it, logs every call, and refuses the rest.

```text
$ ghl-mcp-scoped run --policy policies/content-only.yaml -- <your ghl mcp server>

agent  --> tools/list
wrapper <-- 4 tools visible: blogs_create-blog-post, blogs_get-blogs, social-media-posting_create-post, locations_get-location

agent  --> tools/call {"name": "blogs_create-blog-post", "arguments": {"locationId": "loc_EXAMPLE_CLIENT_A", "title": "5 signs your furnace is done"}}
wrapper <-- OK  fake-ghl executed blogs_create-blog-post

agent  --> tools/call {"name": "contacts_upsert-contact", "arguments": {"locationId": "loc_EXAMPLE_CLIENT_A", "email": "lead@example.test"}}
wrapper <-- REFUSED  ghl-mcp-scoped: 'contacts_upsert-contact' was blocked by policy rule 'no-crm'. a content agent has no business reading or writing the CRM
           rule: no-crm

agent  --> tools/call {"name": "social-media-posting_create-post", "arguments": {"locationId": "loc_SOMEONE_ELSES", "summary": "..."}}
wrapper <-- REFUSED  ghl-mcp-scoped: 'social-media-posting_create-post' was blocked by policy rule 'social-create-one-location'. rule 'social-create-one-location' allows this tool only when its argument constraints hold; 'locationId'='loc_SOMEONE_ELSES' is not in the permitted set
           rule: social-create-one-location
```

That is real output. Reproduce it with `python examples/demo_session.py`, which runs the wrapper in front of the fake MCP server bundled in `tests/`.

![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![dependencies](https://img.shields.io/badge/dependencies-PyYAML%20only-lightgrey)
![tests](https://img.shields.io/badge/tests-59%20passing-brightgreen)

## Quick start

1. Install it next to whatever MCP client you use:

   ```bash
   pip install ghl-mcp-scoped     # or: pip install -e .  from a clone
   ```

2. Copy a policy and edit the location ids in it:

   ```bash
   cp policies/read-only.yaml my-policy.yaml
   ```

3. Check it, and see exactly what your agent will be able to do:

   ```bash
   ghl-mcp-scoped validate my-policy.yaml
   ```

4. Put the wrapper in front of your existing server in `.mcp.json`. Before:

   ```json
   {
     "mcpServers": {
       "ghl": {
         "command": "npx",
         "args": ["-y", "some-ghl-mcp-server"],
         "env": { "GHL_API_KEY": "..." }
       }
     }
   }
   ```

   After:

   ```json
   {
     "mcpServers": {
       "ghl": {
         "command": "ghl-mcp-scoped",
         "args": [
           "run",
           "--policy",
           "my-policy.yaml",
           "--",
           "npx",
           "-y",
           "some-ghl-mcp-server"
         ],
         "env": { "GHL_API_KEY": "..." }
       }
     }
   }
   ```

   The wrapped server still gets the same environment, the same stdio, the same everything. The only change is that `tools/call` now has to get past your policy first.

5. Restart the client and read the audit log at the path your policy names.

## The problem

MCP servers for GoHighLevel exist in numbers, and the working assumption across them is all-or-nothing: you hand the server an API key or a private integration token for a location, and every tool it implements becomes callable by whatever model is driving. Several state plainly that they give the agent full access to the location. That is a reasonable default for a developer poking at their own sandbox. It is not a reasonable default for an agency running an agent against a client's CRM, where the same credential reaches contacts, conversations, opportunities, calendars and payments.

The gap is not authentication - that part works. The gap is that there is no way to say "this agent may draft blog posts for this one location and nothing else" without forking the server. So the choice on offer is: give the agent everything, or don't use it. This wrapper is the third option, and it works with a server you did not write and cannot modify.

Note the ordinary failure modes, not just the dramatic ones. An agent that is merely confused deletes tags, moves an opportunity to Won, or messages a real contact at 3am. A scope is cheaper than an incident review.

## Policy reference

A policy is one YAML file. Everything below is the whole language; there is no expression syntax and nothing in a policy is ever executed.

### Top level

| Key           | Type                      | Default                      | Meaning                                                                                                                                                    |
| ------------- | ------------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`     | int                       | `1`                          | Policy schema version. Only `1` exists.                                                                                                                    |
| `name`        | string                    | -                            | Free text, shown by `validate`.                                                                                                                            |
| `description` | string                    | -                            | Free text, shown by `validate`.                                                                                                                            |
| `mode`        | `allowlist` \| `denylist` | `allowlist`                  | What happens to a tool no rule matches. `allowlist` denies it (deny by default); `denylist` allows it.                                                     |
| `read_only`   | bool                      | `false`                      | A hard cap: a tool whose name carries no read verb is denied before any rule is consulted, even a rule that allows it.                                     |
| `read_verbs`  | list of strings           | `[get, list, search, fetch]` | The verbs that make a tool name count as a read. Matched against name _tokens_, so `contacts_get-contacts` is a read and `contacts_forget-contact` is not. |
| `tools`       | list of rules             | `[]`                         | The rules, evaluated in file order.                                                                                                                        |
| `audit`       | mapping                   | see below                    | Audit log settings.                                                                                                                                        |
| `visibility`  | mapping                   | see below                    | What `tools/list` hides.                                                                                                                                   |

### A rule

| Key                    | Type                           | Default  | Meaning                                                                                                          |
| ---------------------- | ------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------- |
| `match` (alias `tool`) | string                         | required | Tool name, or a glob: `contacts_*`, `*get*`, `*`. Case sensitive.                                                |
| `action`               | `allow` \| `deny` \| `confirm` | `allow`  | What to do when the name matches.                                                                                |
| `when`                 | list of constraints            | `[]`     | Argument-level conditions. Only valid on an `allow` rule. Every constraint must pass.                            |
| `otherwise`            | `deny` \| `confirm`            | `deny`   | What happens when `when` does not hold.                                                                          |
| `reason`               | string                         | -        | Text shown to the agent in the refusal and written to the audit log. Write these; they are what the agent reads. |
| `id`                   | string                         | auto     | Short name for the rule, used in refusals and audit lines.                                                       |

The **first** rule whose `match` fits the tool name decides. A later rule for the same name never fires, and `validate` rejects the policy if an earlier rule already handles that exact pattern unconditionally.

`confirm` refuses the call and tells the caller a human has to run it. It does not prompt: stdio is occupied by the protocol, and there is nowhere to ask.

```yaml
- id: human-sends-messages
  match: "conversations_send-a-new-message"
  action: confirm
  reason: an outbound SMS reaches a real person and cannot be recalled
```

### Argument constraints (`when`)

Each entry names an argument path and exactly one matcher.

| Matcher     | Example                                     | Passes when                                                      |
| ----------- | ------------------------------------------- | ---------------------------------------------------------------- |
| `equals`    | `{arg: type, equals: "lead"}`               | The value equals the literal (types included: `1` is not `"1"`). |
| `in`        | `{arg: locationId, in: ["loc_A", "loc_B"]}` | The value is one of the listed items.                            |
| `matches`   | `{arg: tags.0, matches: "^agent:"}`         | `re.search` of the pattern against the value as text.            |
| `required`  | `{arg: title, required: true}`              | The path exists and is not null.                                 |
| `forbidden` | `{arg: dndSettings, forbidden: true}`       | The path is absent or null.                                      |

Extra key: `optional: true` makes an absent path pass for `equals` / `in` / `matches` (it means "if it is there it must look like this"). Without it, an absent path fails those three.

Paths are dotted and walk both objects and arrays: `locationId`, `contact.locationId`, `tags.0`. An unresolvable path is treated as absent, never as an error.

```yaml
- id: upsert-scoped
  match: "contacts_upsert-contact"
  action: allow
  when:
    - arg: locationId
      in: ["loc_EXAMPLE_CLIENT_A", "loc_EXAMPLE_CLIENT_B"]
    - arg: dndSettings
      forbidden: true
  otherwise: deny
  reason: upserts are fine inside this engagement's own locations
```

### `visibility`

| Key            | Default | Meaning                                                                                                                   |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------- |
| `hide_denied`  | `true`  | Denied tools are stripped from `tools/list`.                                                                              |
| `hide_confirm` | `true`  | So are `confirm` tools. Set `false` if you want the agent to be able to tell the operator what it would like run by hand. |

A tool that is allowed _conditionally_ stays listed: the arguments do not exist yet at list time, so the wrapper cannot know, and hiding it would be a lie in the other direction. It is judged at call time.

### `audit`

| Key                  | Default                                      | Meaning                                                                                                    |
| -------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `enabled`            | `true`                                       | Turn logging off. `validate` warns when you do.                                                            |
| `path`               | `ghl-mcp-audit.jsonl`                        | Log file. A relative path resolves against the policy file's directory. Directories are created as needed. |
| `log_arguments`      | `true`                                       | When false, arguments are replaced wholesale by the placeholder.                                           |
| `redact_keys`        | `token\|secret\|key\|password\|phone\|email` | Regex, case-insensitive, matched against **key names**.                                                    |
| `redact_placeholder` | `[REDACTED]`                                 | What a redacted value becomes.                                                                             |
| `max_string_length`  | `200`                                        | Longer strings are truncated with `...[truncated]`.                                                        |

### CLI

```text
ghl-mcp-scoped run --policy POLICY [--audit-log PATH] [--verbose] -- <server command...>
ghl-mcp-scoped validate POLICY [--tools tools.json|tools.txt]
```

`validate` prints the rule table, the mode default, any warnings, and - with `--tools`, given a `tools/list` dump or a plain list of names - the effective decision for every tool your server actually exposes. It exits `2` on an invalid policy, so it belongs in CI.

## The three shipped policies

| Policy                          | Use it when                                                                                                                             | Shape                                                                                                                                                                |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `policies/read-only.yaml`       | The agent answers questions and writes nothing: reporting, lookups, drafting copy from real data. The safest thing to hand a new agent. | `allowlist` + `read_only: true`. Writes are denied by name, including tools that do not exist yet.                                                                   |
| `policies/content-only.yaml`    | A content agent publishes blogs and schedules social posts for one location and must not touch the CRM.                                 | `allowlist`. Blog and social tools allowed, each write pinned to one `locationId`; contacts, conversations and payments denied by name so the refusal reads clearly. |
| `policies/full-with-audit.yaml` | An operator is driving the agent live and wants the full toolset with a paper trail and a few hard stops. Not for an unattended loop.   | `denylist`. Payments denied, outbound messaging and pipeline moves set to `confirm`, contact writes scoped to two locations and to an `agent:` tag namespace.        |

Every id in them (`loc_EXAMPLE_CLIENT_A`, and so on) is a placeholder. Replace them before use.

## Audit log

One JSON object per line, appended, flushed on every write. Real lines from the transcript above:

```json
{"ts": "2026-09-01T10:07:05.464Z", "event": "tools/list", "pid": 10644, "decision": "filtered", "rule": "visibility", "reason": "4 tool(s) visible, 8 hidden", "visible": ["blogs_create-blog-post", "blogs_get-blogs", "social-media-posting_create-post", "locations_get-location"], "hidden": ["contacts_get-contacts", "contacts_get-contact", "contacts_upsert-contact", "contacts_add-tags", "conversations_send-a-new-message", "conversations_search-conversation", "opportunities_update-opportunity", "payments_list-transactions"]}
{"ts": "2026-09-01T10:07:05.464Z", "event": "tools/call", "pid": 10644, "tool": "contacts_upsert-contact", "decision": "deny", "rule": "no-crm", "reason": "a content agent has no business reading or writing the CRM", "arguments": {"locationId": "loc_EXAMPLE_CLIENT_A", "email": "[REDACTED]"}, "forwarded": false}
```

Fields: `ts` (UTC, ISO 8601), `event` (`session_start`, `tools/call`, `tools/list`, `session_end`), `pid`, `tool`, `decision` (`allow` / `deny` / `confirm` / `filtered`), `rule`, `reason`, `arguments`, `forwarded`.

Redaction is **structural, by key name**. Any key matching the redaction regex has its whole value replaced, at any depth, whatever its type; values are never inspected or guessed at. That is why `email` is redacted above while `locationId` is not. Credentials passed as arguments are removed by the same mechanism, and the wrapper never reads or logs the environment variables your GHL server authenticates with.

The log is still sensitive: it holds the arguments your agent used. It is gitignored here, and it should be treated like any other client record. Turn `log_arguments: false` off if you only need the decision trail.

## Limitations

Read these before you rely on it.

- **It is a policy layer, not authentication.** It does not verify who is calling, and it holds no credentials of its own.
- **Anyone who can edit the policy file can rewrite the rules.** Put it under the same access control as your other production config, and check it into version control so changes are reviewable.
- **Anyone who can reach the wrapped server directly bypasses the wrapper entirely.** It only constrains traffic that goes through it. If the same API key is also in another `.mcp.json` entry, or in a shell script, or in an n8n node, none of that is scoped.
- **Argument matching is structural, not semantic.** `locationId in [...]` proves a string matched a list. It does not know whether the body of a message is abusive, whether a blog post is defamatory, or whether a "test" contact is a real person. A policy constrains reach, not judgment.
- **A wildcard `allow` in `denylist` mode inherits future tools.** If the wrapped server adds a tool in its next release, `denylist` mode allows it silently. `validate` warns about this; `allowlist` does not have the problem.
- **Newline-delimited JSON-RPC over stdio only.** That is what MCP stdio servers speak. HTTP and SSE transports are not wrapped.
- **Tool _names_ are the unit of control.** If a server hides several operations behind one generic tool, the policy can only allow or deny the whole thing, plus whatever the arguments let you pin down.
- **No rate limiting, no spend caps, no time windows.** Out of scope for v1.

## Contributing

Issues and pull requests welcome, particularly: policies for real-world agency setups, matcher gaps found in practice, and compatibility reports against specific GHL MCP servers (name the server and the tool names, never a key or a location id).

Run the suite before you open a PR:

```bash
python -m pytest tests -q
```

The tests spawn a real wrapper process in front of a fake MCP server (`tests/fake_ghl_server.py`) and speak JSON-RPC to it over a pipe. There is no network access and no GoHighLevel credential anywhere in this repo, and there must not be one in a contribution either.

---

Built by SkynetLabs (Waseem Nasir) - we wire GoHighLevel and AI agents for agencies. https://skynetjoe.com · https://calendly.com/skynetlabs/schedule-a-free-consultation

GoHighLevel is a trademark of its respective owner. This is an independent, unaffiliated tool and is not endorsed by, sponsored by, or connected with GoHighLevel.

## License

MIT. See [LICENSE](LICENSE).
