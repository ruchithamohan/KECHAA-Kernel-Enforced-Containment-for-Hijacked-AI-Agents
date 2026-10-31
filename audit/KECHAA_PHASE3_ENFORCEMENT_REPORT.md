# KECHAA Phase 3 Enforcement Report

Date: 2026-10-31  
Branch: `kechaa/mission-critical-remediation`  
Scope: Phase 3 mandatory whole-agent containment, MCP/non-shell enforcement, multi-agent isolation, Linux certification readiness, and attack/defense demonstration.

## 1. Executive Summary

Phase 3 added a supported whole-agent launch path and additional verification evidence, but KECHAA still must not be described as production-ready or fully Linux-certified from this macOS environment.

Implemented in this phase:

- `kechaa agent prepare|launch|simulate` CLI surface for supervised whole-agent launches.
- Supervised grants bound to `supervised=True`, preventing ordinary action grants from being upgraded and supervised grants from being consumed through ordinary execution.
- Persistent `supervised_agent_prepared` history records containing the intended process-tree boundary and Linux mechanisms.
- Concurrent active action support after serialized mandatory startup handoff, allowing separate per-grant cgroups to run concurrently on Linux.
- Expanded Linux certification scenario inventory through LC-013 and an executable procedure output.
- Controlled `tools/demo_attack_defense.py` showing an authorized agent action, malicious external tool request, history-aware posture tightening, and subsequent approval-required behavior.
- Additional adversarial unit tests; local test suite increased from 12 to 15 passing tests.

Final answer: **PARTIALLY**. KECHAA can now explicitly constrain the supported `kechaa agent launch` path through the existing Linux worker design, and the control plane prevents grant/identity/session bypasses. It has not been certified on a disposable Linux VM in this run, and unsupported direct/unwrapped agent execution remains outside KECHAA's claimed supported boundary.

## 2. Architecture Changes

### Supervised Agent Launch Boundary

New supported lifecycle:

1. Administrator opens a run with a confirmed task contract.
2. Client requests `kechaa agent prepare --run ... --session ... --cwd ... -- <agent argv>`.
3. `Engine.prepare(..., supervised=True)` evaluates policy, history, authorization lease, contract scope, action identity, and bounded effects.
4. The grant body records `supervised_agent=true` and a `boundary` document.
5. `kechaa agent launch` consumes only a supervised grant with `supervised=True`.
6. On Linux execution mode, the daemon launches the agent through the existing worker path with cgroup, namespace, Landlock, seccomp, credential-drop, stdin/stdout/stderr, lease, and grant controls.
7. Child processes inherit kernel restrictions from the launched process tree.
8. Quarantine, lease expiry, policy updates, or trusted posture events request independent worker termination through cgroup/process cleanup.

### Files Changed

- `kechaa/engine.py`: supervised grant marker, boundary metadata, `supervised_agent_prepared` history, supervised consume binding.
- `kechaa/cli.py`: `agent prepare|launch|simulate` commands.
- `kechaa/daemon.py`: active action concurrency no longer globally limited after startup handoff; startup remains serialized by `execution_reserved`.
- `tests/test_security_control_plane.py`: supervised grant and boundary tests.
- `tools/certify_linux.py`: expanded LC scenario inventory, `procedure`, and fail-closed `run` command.
- `tools/demo_attack_defense.py`: controlled attack-and-defense demonstration.

## 3. Whole-Agent Containment Implementation

The new whole-agent mechanism is a mandatory supported entry path, not a claim that KECHAA can control arbitrary host processes. A supervised grant is cryptographically signed like existing grants and records:

- `kind`: `whole-agent-process-tree`.
- `mandatory`: `true` only outside diagnostic mode.
- `run` and `session` binding.
- Intended mechanisms: single-use grant, lease-bound run, cgroup v2, PID namespace, mount namespace, network namespace, Landlock, seccomp, credential drop.
- Coverage: entry process and descendants launched by the KECHAA Linux worker.
- Unsupported: processes started outside the KECHAA launcher.

Security improvement:

- Supervised grants cannot be consumed as ordinary actions.
- Ordinary grants cannot be upgraded into supervised agent launches.
- Supervised launch preparation is recorded in trusted history.
- Existing run/session/UID binding applies to agent launch grants.

Remaining limitation:

- Linux kernel enforcement could not be executed on this macOS host.
- KECHAA still cannot prevent a user from starting an unwrapped process outside KECHAA unless deployment policy makes `kechaa agent launch` the only supported/available path for the agent runtime.

## 4. MCP and Non-Shell Enforcement Coverage

Current implementation:

- `Engine.tool_request()` remains the trusted gateway for non-shell effects.
- Web/MCP/external network effects fail closed in the offline profile.
- In-scope offline file reads can be allowed.
- Writes in guarded posture require approval instead of silent execution.
- Claude harness MCP/web requests route through `tool_request`.

Phase 3 improvement:

- The supervised agent launch path makes direct network/process execution unavailable inside the supported Linux offline boundary when Linux controls are active.
- This reduces bypass risk for agents that attempt to evade tool-gateway denials by spawning subprocesses or using direct sockets.

Remaining limitation:

- There is still no full MCP protocol proxy with effect contracts, asynchronous invocation tracking, argument schemas, response provenance, and per-tool allowlists.
- Supported claim should remain: unsupported MCP/web/external network effects fail closed under the offline profile; complete MCP integration is not yet implemented.

## 5. Multi-Agent Isolation

Current implementation:

- Runs are bound to UID and session.
- History reads require matching run/session/UID.
- Tool requests require matching run/session/UID.
- Quarantine state and policy posture are per run.
- Audit records are signed and include run-level events.
- Linux worker cgroups are per grant/action.
- Daemon now permits multiple active workers after startup handoff, allowing separate active process boundaries rather than a single global active action.

Remaining limitation:

- Multi-agent Linux process/workspace isolation was not executed on a Linux VM in this phase.
- Cross-agent filesystem and process attacks still need LC-012 certification on a disposable Linux host with separate workspaces.

## 6. Linux Certification Results

Actual result in this run: **BLOCKED**.

Executed on macOS:

```text
tools/certify_linux.py preflight
ready=false
failure=Linux is required for kernel containment certification.
exit=3
```

Executed certification run command on macOS:

```text
tools/certify_linux.py run
certified=false
required_scenarios=LC-001..LC-013
exit=4
```

Prepared but not executed:

- `tools/certify_linux.py plan` lists 13 certification scenarios.
- `tools/certify_linux.py procedure` prints an executable disposable-VM procedure.

Certification status: **not certified**. Passing macOS tests proves control-plane behavior only, not kernel containment.

## 7. Attack-and-Defense Demonstration

Script: `tools/demo_attack_defense.py`.

Executed locally in diagnostic mode with safe temporary fixtures.

Scenario:

1. Open a task-scoped run.
2. Prepare and consume a supervised agent grant for a permitted file read.
3. Simulate malicious external content/tool pressure through a `WebFetch` effect.
4. Trusted tool gateway denies external network access and tightens posture to guarded.
5. A subsequent otherwise-permitted action is not silently executed; it becomes `ask`/`pending`.
6. Trusted history records the sequence.

Observed evidence:

- `gateway_decision.decision = deny`.
- `gateway_decision.mode = guarded`.
- `gateway_decision.terminate_active = true`.
- `post_injection_action.decision = ask`.
- History kinds include `contract_confirmed`, `grant_prepared`, `supervised_agent_prepared`, `grant_consumed`, and `tool_request`.

Limitation:

- This is a control-plane demonstration, not Linux kernel certification.

## 8. Test Evidence

Executed commands:

| Check | Result |
|---|---|
| `python -m compileall -q kechaa tools tests` | PASS |
| `python -m unittest discover -v` | 15 PASS, 0 FAIL |
| `python -m kechaa policy validate examples/linux-offline.yaml` | PASS |
| `python -m kechaa agent prepare --help` | PASS |
| `tools/demo_attack_defense.py` | PASS |
| `tools/certify_linux.py plan` | PASS |
| `tools/certify_linux.py procedure` | PASS |
| `tools/certify_linux.py preflight` on macOS | BLOCKED as expected, exit 3 |
| `tools/certify_linux.py run` on macOS | BLOCKED as expected, exit 4 |

New tests added:

- Supervised agent grant records process-tree boundary metadata.
- Supervised grant cannot be consumed as an ordinary action.
- Ordinary grant cannot be upgraded into supervised launch.

Existing tests still pass:

- History recording.
- Sensitive path denial.
- Repeated-denial history lockdown.
- Quarantine/recovery.
- Lease expiry.
- Trusted compromise event quarantine.
- Audit anchor persistence.
- Tool gateway denial/allow/ask behavior.
- Cross-agent control-plane binding.
- History persistence across engine restart.

## 9. Updated GitHub Issue Status

| Issue | Phase 3 Status | Evidence | Remaining Gap |
|---|---|---|---|
| #1 Whole-agent containment | Partially advanced | `agent` launcher, supervised grant binding, boundary history, Linux worker design | Needs real Linux VM LC-011 proving process-tree containment and bypass denial |
| #2 Linux certification | Procedure advanced, not certified | LC-001..LC-013 plan, `procedure`, macOS fail-closed run | Disposable Linux VM execution still required |
| #3 MCP/non-shell enforcement | Partially advanced | `tool_request` fail-closed external effects plus supervised offline boundary | Full MCP proxy/effect-contract implementation missing |
| #7 Multi-agent isolation | Partially advanced | run/session binding tests, per-grant cgroup design, concurrent active workers after startup | Linux LC-012 cross-agent process/filesystem certification required |
| #9 Attack/demo | Partially advanced | `tools/demo_attack_defense.py` passed locally | Needs full Linux demo showing actual kernel-enforced denial/quarantine |

## 10. Remaining Security Gaps

P0/P1 blockers remaining before strong security claims:

1. Linux certification has not been executed in a disposable VM.
2. Whole-agent containment is only claimed for the supported `kechaa agent launch` path.
3. Direct/unwrapped host execution is outside current enforcement unless deployment removes that route.
4. Complete MCP protocol proxy and per-tool effect contracts are not implemented.
5. Multi-agent isolation needs real Linux cross-workspace/process attack tests.
6. The demo proves history-aware control-plane behavior, not kernel-level denial.

## 11. Production-Readiness Assessment

Updated assessment: **DEVELOPMENT STAGE — IMPORTANT SECURITY WORK REMAINS**.

The Phase 3 implementation improves architectural credibility by making whole-agent launch an explicit supported boundary and preventing grant confusion between ordinary actions and supervised agent launches. However, production readiness requires executed Linux certification and a deployment model that makes the launcher mandatory for supported agents.

## 12. Final Answer

Can KECHAA now independently constrain a compromised long-running AI agent across every execution path it claims to support?

**PARTIALLY.**

Evidence for partial yes:

- Supported `kechaa agent launch` grants are bound to run, session, UID, exact action, lease, history, and supervised launch intent.
- Supervised launch grants cannot be consumed through ordinary execution and ordinary grants cannot be upgraded.
- The intended Linux worker boundary covers the launched process tree and descendants using cgroups, namespaces, Landlock, seccomp, credential drop, and network isolation.
- Tool gateway denies unsupported external MCP/web/network effects fail-closed in the offline profile.
- History-aware posture changes influence subsequent authorization.

Evidence preventing full yes:

- No Linux VM kernel enforcement test was executed in this environment.
- Full MCP/effect-contract gateway is incomplete.
- Direct host processes outside `kechaa agent launch` remain outside the claimed supported boundary.
- Multi-agent kernel isolation and full attack-defense demo still require Linux certification.
