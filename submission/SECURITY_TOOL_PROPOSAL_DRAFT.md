# KECHAA Security Tool Proposal Draft

## Tool Name

KECHAA — Kernel-Enforced Containment for Hijacked AI Agents

## Short Description

KECHAA is an experimental defensive security tool for constraining AI-agent actions with explicit, signed, policy-bound effect envelopes. It focuses on fail-closed authorization, persistent execution history, supervised launch, and reproducible evidence for Linux kernel-enforced containment.

## Security Problem

Autonomous AI agents can be manipulated by prompt injection, hostile tool output, malicious documents, compromised integrations, or gradual goal drift. Once manipulated, an agent may use legitimate tools and credentials in unauthorized ways. KECHAA addresses the practical question: can an independently defined runtime boundary keep enforcing limits after the agent itself becomes untrustworthy?

## Technical Approach

KECHAA separates agent reasoning from authorization and enforcement:

- Administrators define YAML policies and task-scoped contracts.
- KECHAA issues single-use signed grants bound to argv, cwd, UID, session, policy version, effect envelope, file identities, and expiry.
- A supervised launch path binds supported agent execution to a run/session and records trusted history.
- History-aware policy decisions can tighten future authorization after suspicious or denied actions.
- Unsupported MCP/web/external-network effects fail closed unless explicitly represented by an offline effect contract.
- The Linux execution design uses cgroups, namespaces, Landlock, seccomp, read-only mounts, credential dropping, and bounded output for supported offline execution paths.

## Demonstrated Evidence To Date

Current local evidence:

- 22 automated unit/integration/adversarial tests pass.
- Grant replay, forged grants, identity confusion, history-reset attempts, MCP uncontracted calls, and external-network effects are rejected in control-plane tests.
- Certification harness refuses to certify outside Linux and reports blocked status instead of false success.
- Safe control-plane attack/defense demo shows an external tool request tightening posture and preventing silent follow-up execution.

Linux whole-agent certification is still pending. LC-001 through LC-013 must be executed in a disposable Linux VM before making OS-enforcement claims.

## Novelty

KECHAA combines several defensive ideas into an agent-focused runtime:

- Approval-bound effect envelopes instead of broad shell permission.
- Persistent trusted history influencing later authorization.
- Supervised agent launch with explicit run/session/UID binding.
- Fail-closed MCP effect-contract authorization.
- Signed audit records and certification scenarios designed to distinguish policy decisions from actual OS enforcement.

## Supported Environment

Current target:

- Linux `aarch64` or `x86_64` with cgroup v2 and Landlock ABI `>= 6`.
- Dedicated ext4/tmpfs workspaces without bind aliases or nested mounts.
- Root-owned daemon and distinct unprivileged agent account.
- Offline profile only.

Current non-supported or limited environments:

- macOS diagnostic/control-plane mode only; no native protected execution.
- Complete MCP protocol proxying is not implemented.
- Direct host execution outside `kechaa agent launch` is outside supported containment claims.

## Demo Plan

A safe demo should use a disposable Linux VM and synthetic data only:

1. Start KECHAA with a policy for `/work/agent-a`.
2. Open a task contract and launch a synthetic agent through `kechaa agent launch`.
3. Show a permitted action succeeding inside the workspace.
4. Deliver a controlled malicious instruction causing an external tool/network attempt.
5. Show KECHAA denying the effect, tightening posture, and recording audit evidence.
6. Attempt direct file/network/process bypass from the supervised process tree.
7. Show the OS boundary preventing prohibited action.
8. Show audit export/checkpoint and cleanup.

Fallback demo when Linux certification is unavailable:

- Run the control-plane demo and explicitly label it as non-certified, non-OS-enforced evidence.
- Show `tools/certify_linux.py run` failing closed with `certified=false`.

## Safety Precautions

- Use disposable VM only.
- Use synthetic workspaces and synthetic secrets only.
- Do not mount host home directories, SSH agents, cloud credentials, Docker sockets, or personal files.
- Disable real outbound network unless a local synthetic denial test requires observation.
- Retain audit logs and signed checkpoints, not private keys.

## Known Limitations

- Linux LC-001 through LC-013 are not yet executed in the current environment.
- No production-readiness claim.
- No complete MCP protocol mediation.
- No claim to detect semantic goal drift or guarantee agent alignment.
- Whole-agent containment applies only to supported supervised launch paths after Linux certification.

## Attendee / Evaluator Takeaways

- How to separate agent authorization from agent reasoning.
- How to design fail-closed containment evidence for AI-agent tools.
- Why policy decisions are not the same as OS enforcement.
- How history-aware authorization can reduce long-running agent risk.
- How to reproduce or falsify containment claims using synthetic adversarial scenarios.

## Presenter Template

Presenter: `[name]`  
Role: `[security researcher / engineer / maintainer]`  
Repository: `https://github.com/ruchithamohan/KECHAA-Kernel-Enforced-Containment-for-Hijacked-AI-Agents`  
License: MIT  
Version / branch for demo: `[commit hash]`  
Certification status for demo environment: `[PASS/FAIL/BLOCKED with evidence path]`
