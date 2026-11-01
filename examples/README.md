# Executable examples

Run from the repository root after [installing dependencies](../docs/getting-started.md). Every `demo` invocation is independent: it starts a fresh daemon and removes its own temporary state. `--json` is available on each scenario. No external API, model, database server or MCP service is required.

| Scenario | Command | Expected result | Demonstrated boundary |
|---|---|---|---|
| Safe command + replay | `.venv/bin/python -IS bin/kechaa demo --scenario allow` | ALLOW, then BLOCK | Real grant preparation and diagnostic single-use consumption; echo does not execute |
| Destructive request | `.venv/bin/python -IS bin/kechaa demo --scenario destructive` | BLOCK | Explicit deny rule for rm; temporary sentinel remains; no destructive process runs |
| Human approval | `.venv/bin/python -IS bin/kechaa demo --scenario approval` | PENDING_APPROVAL, then ALLOW | Disposable operator inspects/approves digests, then simulates; production agent cannot approve itself |
| Outside filesystem request | `.venv/bin/python -IS bin/kechaa demo --scenario filesystem` | BLOCK | Sensitive-path command rejected at authorization; not an OS read-denial experiment |
| MCP declarations | `.venv/bin/python -IS bin/kechaa demo --scenario mcp` | Offline ALLOW, external BLOCK | Actual tool_request API; no server invocation or proxy |
| SQL command contract | `.venv/bin/python -IS bin/kechaa demo --scenario sql` | ALLOW with executed=false | Python/SQLite script included in grant input identity; no query runs |
| Agent tool integration | `.venv/bin/python -IS bin/kechaa demo --scenario agent` | ALLOW with executed=false | Function-call mapping and separate supervised process-tree grant simulation; no model launches |

## Local SQL workload

```bash
.venv/bin/python examples/sqlite_task.py
```

Actual output:

```json
{"rows": [[1, "review policy"]], "boundary": "standalone local workload; no KECHAA containment"}
```

This runs a real in-memory SQLite query locally. It creates no persistent database. To evaluate confinement of a SQL **process**, put a reviewed copy in a dedicated Linux workspace and submit its interpreter/script through KECHAA. This is not SQL statement filtering, remote database authorization or evidence of Linux containment on macOS.

## Your existing agent

[agent_tool.py](agent_tool.py) calls the real Python client against an already confirmed run. Inspect its options:

```bash
.venv/bin/python examples/agent_tool.py --help
```

Prepared Linux environment template (replace identifiers/paths; not a self-contained host command):

```bash
.venv/bin/python examples/agent_tool.py --socket /run/kechaa/agent.sock --run RUN_ID --session SESSION --cwd /work/project -- /usr/bin/echo hello
```

Use `--simulate` only against your explicitly chosen diagnostic daemon. The adapter exits 2 for pending approval, 3 for a blocked/failed request, or the executed command's exit code. It never runs a command directly as a fallback. [Adapter development](../docs/adapter-development.md).

## Real protected execution

The existing `kechaa exec` and `kechaa agent launch` paths are for a prepared root-owned Linux daemon and separate action UID. Start with [Linux requirements](../docs/linux-requirements.md), then the [operator workflow](../docs/integrations.md#generic-command-wrapper). Exact executable/loader paths depend on the VM; generate and review the policy rather than copying `/bin` paths that may be symlinks.

The YAML and contract JSON in this directory are authoring examples, not portable pre-authorized policies. Historical protected shell/package/network scenarios live in [completion.md](../docs/completion.md). They are separate from the current simulated demos and current Linux acceptance gaps.
