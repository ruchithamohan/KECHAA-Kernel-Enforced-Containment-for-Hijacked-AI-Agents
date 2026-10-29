# Local API and adapters

One security engine serves every integration. A harness adapter reports an action;
it cannot grant itself authority. Ordinary OS UID checks are authoritative.
Run/session strings are binding context, not independent authenticated identities
between hostile processes sharing the same UID.

## Local API v1

Use a Unix-domain stream socket. Send one UTF-8 JSON line and close the request
direction. A request is at most 256 KiB, with no duplicate keys, floats, excessive
nesting or unknown envelope fields:

```json
{"v":1,"operation":"prepare","data":{"run":"RUN","session":"SESSION","action":{"argv":["/usr/bin/echo","hello"],"cwd":"/work/project","inputs":[]}}}
```

Success is `{"v":1,"ok":true,"request_id":"…","result":{…}}`; failure has
`ok:false` and `error:{code,message,category}`. The server reads Linux SO_PEERCRED
or macOS getpeereid. Neither UID nor an approval flag is accepted from an agent
request. A root-owned `admin.sock` is separate from the group-accessible
`agent.sock`. A same-user diagnostic daemon is explicitly **not** a trust boundary
against that user. Protected mode rejects same-user/unprivileged daemon operation.

| Agent operations | Administrative operations |
|---|---|
| health, policy_get | run_open with confirmed contract and target UID |
| run_get, run_close | grant_get, grant_approve, grant_revoke |
| prepare, grant_status | policy_import, policy_history, policy_rollback, checkpoint |
| execute; simulate only in diagnostic mode | audit_verify, audit_export, audit_checkpoint |
| event, which can only tighten | |

`grant_status` takes grant/run/session and only returns the bound request to its
owning UID and run. `grant_approve` requires both digests from the inspected grant.
`execute` and `simulate` require grant/run/session plus the exact action. They
recompute artifact identities before atomic consumption. A request disconnect
does not restore a consumed grant. Calls are bounded, and the experimental
backend permits one active action at a time.

The operator-only `diagnostic` console accepts the same request objects on stdin.
`--admin` explicitly enables diagnostic administrative operations. It never opens
the execution backend and makes no peer-authentication claim. Use it for policy
review and grant-state inspection, not to protect a harness.

## Generic command wrapper

An administrator first inspects a contract JSON containing project roots,
expected executable paths (including ELF loaders), a `write` boolean and an
optional `lifetime_seconds` (default 3600), then confirms it:

```bash
kechaa --admin-socket /run/kechaa/admin.sock run open \
  --uid 1001 --session chosen-session --contract contract.json --confirm
```

The wrapper uses the returned run ID:

```bash
kechaa prepare --run RUN --session chosen-session --cwd /work/project -- /usr/bin/echo hello
kechaa --admin-socket /run/kechaa/admin.sock grant show --grant GRANT
kechaa --admin-socket /run/kechaa/admin.sock grant approve \
  --grant GRANT --action-digest DISPLAYED_ACTION_HASH --effects-digest DISPLAYED_EFFECT_HASH
kechaa exec --run RUN --session chosen-session --grant GRANT --cwd /work/project -- /usr/bin/echo hello
```

The administrative commands must run under the separate administrator OS identity.
A tty, a transcript message, an environment flag or an agent's claim to be human
cannot authorize them. For diagnostic use, replace the final execute API call
with `simulate`; no command runs.

## Claude Code adapter

The public [hook reference](https://code.claude.com/docs/en/hooks), inspected on
2026-10-29, documents `PreToolUse`, `hookSpecificOutput.permissionDecision`, and
`updatedInput`. KECHAA implements that contract. No Claude Code binary was
installed in the development environment, so **no exact Claude version is
certified and no real Claude session was exercised**.

The hook invocation is:

```bash
kechaa --socket /run/kechaa/agent.sock hook claude \
  --run RUN --session ACTUAL_CLAUDE_SESSION_ID \
  --wrapper /opt/kechaa/bin/kechaa --shell /usr/bin/bash
```

Install this invocation only in administrator-controlled managed settings after
reviewing it. This project does not edit user or managed settings automatically.
The session must already have an administrator-confirmed contract. Configure
SessionStart, PreToolUse and SessionEnd only. PreToolUse must cover every tool
whose bypass would violate the deployment boundary, not just Bash.

Bash requests are bound to `shell -c` with the original command as one exact
argument. A policy `allow` rewrites the command to the authenticated execution
wrapper. An `ask` returns a deny with the pending grant and exact wrapper;
an administrator must inspect and approve it, and the agent may retry that wrapper.
This is intentionally independent of the harness's auto-approval setting.
Recognized wrappers must match every expected token and are re-quoted before use.
An altered wrapper cannot authorize another action.

Web/MCP requests tighten the run and are denied because this adapter cannot
confine their non-shell effects. Other tool types and background Bash requests
are denied with compatibility explanations. SessionEnd closes the run. No
post-execution hook output is treated as kernel evidence.

Hook failure or disablement in the harness is outside this adapter's guarantee.
Whole-agent containment and managed-settings integrity are deployment prerequisites
for claiming mandatory interception; KECHAA does not currently supply that baseline.

## Compatibility matrix

| Integration | Translation code | Real operation verified | Scope |
|---|---|---|---|
| Generic CLI and diagnostic console, Python 3.14.8/macOS Darwin 27 | Implemented | Installation, policies, grants and audit console | No execution |
| Local Unix API, Debian ARM64 | Implemented | Real sockets, UID roles, execution, restart and cancellation exercised | Root daemon; UID 1001 actions in disposable VM |
| Local Unix API, macOS | Implemented | BLOCKED: socket bind denied by host sandbox | macOS peer credentials remain unverified |
| Claude hook API | Implemented against inspected public docs | UNVERIFIED; no installed version | Bash rewriting and explicit administrator approval |
| Codex CLI | Generic wrapper path only | UNVERIFIED | No native hook adapter or settings changes |
| Gemini CLI | Generic wrapper path only | UNVERIFIED | No native hook adapter |
| MCP/non-shell tool effects | Not implemented | Unsupported | Adapter denies these operations |

Additional adapters should translate to Local API v1, document cancellation,
resume, input rewriting and interception guarantees for their exact version,
and share this engine. Do not create a second policy evaluator in an adapter.
Disabling an adapter consists of removing the reviewed settings entry; the
project does not modify the harness installation.

## Lifecycle and failure contract

Capability discovery uses `health`: protocol/policy/state versions, active
profile, execution availability, lifecycle-only observation, and explicit absent
leases/whole-agent coverage. Production readiness is always false in this alpha.
Protected requests require a prepared dedicated workspace filesystem and separate
OS roles. The generic CLI was actually operated under the guest action account;
a real Claude, Codex CLI or Gemini model session has not been certified.

A client disconnect never refunds authorization. The action remains bounded by
its grant and session deadline. Use `run_close` to cancel the session and terminate
its active action; an administrator can revoke authority or terminate the daemon.
An unavailable service never triggers direct local command execution. A daemon
crash invalidates unconsumed grants on restart and reconciles action cgroups.
A lost response means the caller must inspect state, not replay the grant.

Persist the run/session identifiers across harness restarts. `run_get` returns the
stored mode and contract; do not create a fresh session automatically to evade
posture. Only the administrative socket can confirm a new contract or relax mode.
Legacy unbounded sessions close on upgrade. Remote MCP effects and hook disablement
remain outside the product's OS boundary.

Protected `execute` and hook requests also require a root server peer. A same-user
diagnostic or impersonating service cannot assert a protected profile to the hook.
The diagnostic console and explicit `simulate` remain non-executing operator tools.
