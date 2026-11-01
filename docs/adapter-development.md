# Build an agent adapter

Start with the generic Python client or Local API. Avoid duplicating the policy engine in framework hooks. The client intentionally has no administrative endpoint, automatic approval, retry-on-disconnect or direct subprocess fallback.

## Runnable integration

```bash
.venv/bin/python -IS bin/kechaa demo --scenario agent
.venv/bin/python examples/agent_tool.py --help
```

The first command translates a function-call message, prepares and simulates an exact-action grant, and separately simulates a supervised process-tree grant through a real diagnostic Unix daemon. No model, network service or command runs. The second describes the standalone CLI adapter for an already confirmed run.

## Python interface

`AgentClient(socket, run, session, daemon_uid=0)` pins the expected daemon UID. Use the actual current UID only for explicitly chosen diagnostic environments. The client runs under the agent OS account; supplying a UID is not impersonation because the daemon reads peer credentials.

| Method | Behavior |
|---|---|
| `prepare(argv, cwd, inputs=None, supervised=False)` | Returns issued or pending grant; policy failures raise `KechaaError` |
| `execute(prepared)` | Uses exact returned action; requires issued Linux profile and root daemon; no retry |
| `simulate(prepared)` | Consumes a diagnostic grant, returns `executed:false` |
| `check_tool(tool, effects)` | Checks declarations only; no tool execution |
| `prepare_tool_call(tool_call)` | Maps one `run_command` function-call JSON message to `prepare` |
| `close()` | Ends the run and requests termination of its active action |

After `PENDING_APPROVAL`, expose the grant ID and let an operator inspect it. Do not repeatedly prepare the same pending request or automatically approve. After approval, inspect the existing grant status or use the exact CLI invocation supplied by your operator. Low-level `grant_status` returns the action/state; `execute` must include the original supervised marker too.

## Function-call message mapping

The supported input shape is:

```json
{"id":"call-1","type":"function","function":{"name":"run_command","arguments":"{\"argv\":[\"/usr/bin/echo\",\"hello\"],\"cwd\":\"/work/project\"}"}}
```

Use an application-defined `run_command` function with `argv` as an array of strings, absolute `cwd`, and optional explicit `inputs`. The adapter parses the JSON with KECHAA's strict decoder and accepts only that function. It does not accept arbitrary tool names, approval flags or administrator operations. Return the result using the original `tool_call_id` in your orchestration layer.

This is compatibility with the function-call **message shape**, not a verified integration with a particular hosted model, streaming API or framework release. No OpenAI SDK, API key or service is needed to run the demonstration. LangChain, LangGraph, CrewAI and AutoGen can call this boundary through their own tool functions; no framework-specific interception is shipped or claimed.

## MCP and SQL boundaries

MCP declarations use `kind=mcp_effect_contract`, read/write arrays and `network=offline`. An ALLOW result is permission for those declarations, not proof of what an arbitrary MCP server will do. There is no MCP proxy or authenticated remote producer transport. Keep direct/remote server invocation outside KECHAA's claimed coverage until it is explicitly mediated.

SQL can be a command workload (for example, a local SQLite script) inside a properly provisioned Linux run. KECHAA constrains that process's filesystem/network/resource effects. It does not understand SELECT versus DELETE, database rows, SQL credentials or remote transaction permissions. Use database roles and query controls for those concerns. The [SQLite example](../examples/sqlite_task.py) is a harmless local workload, not a SQL security product.

## Integration checklist

Bind run/session to the authenticated OS account; persist identifiers across client restarts. Preserve exact argv/cwd/inputs and supervised mode. Surface pending approvals and structured failures separately. Treat disconnects as an unknown consumed-grant outcome; inspect state rather than replaying. Bound output handling and cancellation. Do not expose the admin socket to the model or silently fall back to unrestricted execution.

For a mandatory boundary, place the workload inside the supported Linux launcher and verify every tool path, child process, cancellation and restart with your exact agent version. A hook or Python wrapper can be bypassed by code that still has another host execution path. The existing [Claude hook](integrations.md#claude-code-adapter) remains an unverified external-harness integration.
