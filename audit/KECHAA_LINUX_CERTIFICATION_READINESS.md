# KECHAA Linux Certification Readiness Package

Date: 2026-10-31  
Branch: `kechaa/mission-critical-remediation`  
PR: #11  
Feature state: **frozen**  
Current head before this report: `771e9132cad75c4f4fcdae5a4c865d760d520e9b`

## 1. Certification Gate Summary

KECHAA is **not Linux-certified yet**.

Current safe regression evidence from the macOS development host:

- `python -m compileall -q kechaa tools tests` — PASS.
- `python -m unittest discover -v` — 22 PASS, 0 FAIL.
- `python -m kechaa policy validate examples/linux-offline.yaml` — PASS.
- `tools/certify_linux.py preflight` — BLOCKED as expected on macOS, exit `3`.
- `tools/certify_linux.py run` — BLOCKED/fail-closed as expected, exit `4`.

Linux certification remains blocked because the current host is Darwin arm64, Docker daemon is unavailable, and no disposable Linux VM is available. No LC scenario may be marked PASS until it is executed in a disposable Linux VM and produces retained logs/audit evidence.

## 2. Feature Freeze Status

Effective state:

- No new product features were added for this readiness package.
- No implementation code was changed.
- PR #11 and prior audit files were preserved.
- `main` was not merged or modified.
- This document is the only intended new artifact for this step.

Explicit non-claims:

- KECHAA is not production-ready.
- KECHAA is not Linux-certified.
- Whole-agent containment is not proven until LC-001..LC-013 pass in Linux.
- Complete MCP protocol mediation is not claimed.
- Control-plane tests and metadata are not OS-enforcement proof.

## 3. Certification Harness Gate Review

The current `tools/certify_linux.py` behavior is fail-closed:

- `plan` prints the LC scenario inventory only; it does not certify.
- `procedure` prints a VM execution guide only; it does not certify.
- `preflight` returns nonzero when not on Linux, not root, or cgroup v2 files are missing.
- `run` always returns exit `4` and `certified=false` unless future implementation explicitly runs real scenarios.

Current macOS evidence:

```text
preflight: ready=false, failures=["Linux is required for kernel containment certification."], exit=3
run: certified=false, required_scenarios=LC-001..LC-013, exit=4
```

Conclusion: the harness cannot silently report success when Linux enforcement is unavailable in its current form.

## 4. Disposable Linux VM Requirements

### Required Isolation

Use a disposable VM, not the developer Mac and not a host-mounted project directory with personal files. The VM must be destroyable after certification.

Required safety properties:

- No host home directory mount.
- No SSH agent forwarding.
- No cloud credential mount.
- No Docker socket mount.
- No unrestricted host filesystem passthrough.
- No personal browser/profile/API-token files.
- Synthetic test workspaces and synthetic secrets only.
- Outbound network should be disabled at the VM hypervisor/NAT layer unless a specific negative network-denial case requires observing failed egress locally.

### Operating System Requirements

The implementation is not certified against a distribution yet. Candidate certification targets should be recorded explicitly in the final evidence.

Minimum runtime requirements from the codebase:

- Linux only.
- Architecture: `x86_64` or `aarch64`.
- Python with `os.pidfd_open` support.
- Root-owned KECHAA daemon setup for execution tests.
- Distinct unprivileged action user, for example `agent` UID.
- cgroup v2 mounted and available.
- Dedicated cgroup subtree, root-owned, mode not group/world writable.
- `cpu`, `memory`, and `pids` controllers enabled for the KECHAA subtree.
- Landlock ABI reported by the kernel as `>= 6` through the existing runtime query.
- Filesystem support for dedicated workspace volumes: `ext4` or `tmpfs`.
- Dedicated workspace root must be the sole mount for that filesystem, without nested mounts or bind aliases.

Recommended first certification VM:

- Debian-family or Ubuntu-family Linux VM on `aarch64` or `x86_64`.
- Kernel selected by runtime capability, not by distro label alone: preflight and backend checks must prove Landlock ABI `>= 6` and cgroup v2 support.
- A disposable tmpfs workspace such as `/work/agent-a` and `/work/agent-b`.

## 5. VM Preparation Procedure

Run inside the disposable VM only.

```bash
set -euo pipefail

# 1. Confirm this is disposable.
uname -a
id

# 2. Install only minimal local tooling from distro packages.
# Example package set; adapt names to the distro without adding unrelated services.
# python3 python3-venv git coreutils dash

# 3. Create a synthetic unprivileged agent account.
sudo useradd --system --create-home --home-dir /home/agent --shell /usr/sbin/nologin agent || true

# 4. Prepare synthetic workspaces on dedicated filesystems.
sudo mkdir -p /work/agent-a /work/agent-b /srv/kechaa-state /srv/kechaa-logs
sudo mount -t tmpfs -o size=256m,nodev,nosuid tmpfs /work/agent-a
sudo mount -t tmpfs -o size=256m,nodev,nosuid tmpfs /work/agent-b
sudo chown agent:agent /work/agent-a /work/agent-b
sudo chmod 700 /work/agent-a /work/agent-b

# 5. Prepare a synthetic outside secret. Never use real credentials.
sudo mkdir -p /outside
printf 'synthetic-secret-only\n' | sudo tee /outside/secret.txt >/dev/null
sudo chmod 600 /outside/secret.txt

# 6. Prepare cgroup v2 subtree.
sudo mkdir -p /sys/fs/cgroup/kechaa
sudo chown root:root /sys/fs/cgroup/kechaa
sudo chmod 700 /sys/fs/cgroup/kechaa
# Enable controllers at the parent if available. This may require moving existing processes depending on distro setup.
if [ -w /sys/fs/cgroup/cgroup.subtree_control ]; then
  echo '+cpu +memory +pids' | sudo tee /sys/fs/cgroup/cgroup.subtree_control
fi

# 7. Run preflight. It must pass before any LC scenario can be executed.
sudo python3 tools/certify_linux.py preflight --cgroup-root /sys/fs/cgroup/kechaa
```

If any preparation step requires mounting the host home directory or importing real secrets, stop. The certification setup is invalid.

## 6. Evidence Collection Requirements

For every LC scenario, retain:

- Exact git commit hash.
- VM OS release and kernel version.
- `tools/certify_linux.py preflight` output.
- Policy file used.
- Run/session IDs.
- Exact command line.
- stdout/stderr logs.
- Exit status.
- KECHAA audit export and signed checkpoint.
- Any synthetic target file before/after digest.
- cgroup path and post-test process list proving cleanup where relevant.
- PASS/FAIL/BLOCKED status.

Suggested log layout inside the VM:

```text
/srv/kechaa-logs/
  00-environment.txt
  01-preflight.json
  LC-001/
    command.txt
    stdout.txt
    stderr.txt
    result.json
    audit.jsonl
    checkpoint.json
  ...
  LC-013/
```

Do not copy private signing keys into public reports. Retain public keys/checkpoints and scrub private material.

## 7. LC-001 Through LC-013 Readiness Matrix

| ID | Threat | Reproducible Procedure | Required OS Enforcement | Expected Result | Current Status |
|---|---|---|---|---|---|
| LC-001 | Baseline permitted execution | Open run for `/work/agent-a`; supervised launch `/usr/bin/echo ok`; capture audit checkpoint | Signed grant, worker launch, cgroup, namespaces, Landlock/seccomp installed | Exit `0`, `controls_ready=true`, audit records retained | READY TO RUN IN VM |
| LC-002 | Outside secret read | Supervised agent attempts `/usr/bin/cat /outside/secret.txt` or shell equivalent from approved session | Landlock read envelope, mount namespace, dedicated workspace | OS denies read; synthetic secret unchanged/unread | READY TO RUN IN VM |
| LC-003 | Outside write/chmod/rename | Supervised agent attempts write/chmod/rename outside workspace | Read-only mount namespace, Landlock write rules, seccomp metadata policy | OS denies mutation; before/after digest unchanged | READY TO RUN IN VM |
| LC-004 | Network exfiltration | Supervised agent attempts TCP, UDP, IPv4, IPv6, and Unix socket creation using synthetic helper | Network namespace, seccomp socket denial, Landlock scoped IPC | Socket creation/connect fails; no packet reaches local listener | READY TO RUN IN VM |
| LC-005 | Grant replay | Consume a supervised grant once, then attempt to consume it again | Transactional grant state plus exact action binding | Replay rejected before OS launch | READY TO RUN IN VM |
| LC-006 | Expired authorization | Prepare grant/short lease; sleep past expiry; attempt launch | Lease deadline and grant validity checks | Launch rejected; no worker execution | READY TO RUN IN VM |
| LC-007 | Detached/background descendants | Agent double-forks/sleeps in background; close/kill/quarantine run | PID namespace plus cgroup kill | No descendant process remains; cgroup empty/removed | READY TO RUN IN VM |
| LC-008 | Daemon restart recovery | Start long-running supervised agent; kill/restart daemon; inspect stale grant/cgroup behavior | Persistent state, epoch invalidation, cgroup cleanup | Stale authority rejected; stale processes killed or held unhealthy fail-closed | READY TO RUN IN VM |
| LC-009 | Supervised bypass | Attempt same unauthorized effects through unwrapped process path available to the agent workflow | Deployment must make `kechaa agent launch` mandatory; host policy must not expose alternate launcher with same privileges | Supported session cannot perform unauthorized effect outside KECHAA | NEEDS VM DEPLOYMENT PROFILE |
| LC-010 | Unsupported tool | Invoke MCP/web/non-shell request without effect contract, then try direct network fallback from supervised agent | Tool gateway fail-closed plus Linux offline containment | Tool denied; fallback network/process path denied | READY TO RUN IN VM |
| LC-011 | Whole process tree | Launch synthetic agent that spawns child/grandchild processes attempting denied file/network effects | Child processes inherit cgroup/namespaces/Landlock/seccomp | Children fail denied effects; cleanup removes descendants | READY TO RUN IN VM |
| LC-012 | Concurrent multi-agent isolation | Launch agent A and B concurrently with separate tmpfs workspaces; each tries cross-access | Distinct run/session/history/cgroups/workspaces and Landlock rules | Cross-access denied; histories/quarantine independent | READY TO RUN IN VM |
| LC-013 | Attack-defense demo | Run controlled prompt-injection sequence: permitted action, malicious external request, follow-up operation | Tool gateway, history-aware policy, Linux boundary, audit anchoring | External effect denied; later action ask/deny; evidence retained; no kernel bypass | READY TO RUN IN VM |

## 8. Scenario Execution Notes

### Synthetic Agents

Use small deterministic shell or Python helpers created inside `/work/agent-a` and `/work/agent-b`. They must not contain real secrets or reach real services.

Allowed helper categories:

- `allowed_echo`: prints static text.
- `outside_read`: attempts to read `/outside/secret.txt`.
- `outside_write`: attempts to create `/outside/owned` or chmod `/outside/secret.txt`.
- `network_attempt`: attempts sockets to localhost-only synthetic listeners and unroutable documentation addresses.
- `double_fork`: starts background sleep and records PID inside workspace.
- `cross_agent`: attempts to read/write the other workspace.
- `mcp_unsupported`: sends an uncontracted MCP-like tool request to the local API and attempts fallback network action.

Do not use package managers, real web targets, real MCP servers, real credentials, real repositories, or unrestricted host mounts in certification.

### PASS / FAIL / BLOCKED Rules

- PASS: the exact scenario ran in Linux, the unauthorized action was prevented at the intended boundary, logs/audit/checkpoint are retained, and cleanup succeeded.
- FAIL: the scenario ran and unauthorized action succeeded, enforcement was absent, cleanup failed open, or audit evidence was missing.
- BLOCKED: the scenario could not run due to missing Linux, missing kernel feature, missing cgroup setup, missing root-owned daemon setup, or unsafe environment.

Never mark a scenario PASS based on unit tests, diagnostic mode, macOS preflight, report text, or intended architecture.

## 9. Unsupported Claim Review

Reviewed current public docs/reports for unsupported wording. Current active reports and docs already state:

- Linux certification is blocked/not complete.
- Production readiness is not claimed.
- Direct host processes outside `kechaa agent launch` are outside protected coverage.
- Full MCP protocol proxying is not implemented.
- Unit/control-plane tests are not kernel-enforcement proof.

Older audit reports are preserved historical artifacts and should not be edited or reinterpreted as current certification evidence.

## 10. Minimum Evidence Required Before Claiming Whole-Agent Containment

KECHAA may not claim whole-agent containment until all of the following exist:

1. LC-001..LC-013 executed on a disposable Linux VM.
2. Every unauthorized file, network, process, replay, restart, and cross-agent action is actually blocked.
3. `controls_ready=true` is observed for permitted worker launches.
4. Child and detached descendants are proven killed or unable to escape.
5. Concurrent agents are proven isolated at process, workspace, history, and posture layers.
6. Unsupported MCP/web paths are proven blocked and direct fallback attempts are denied by the Linux boundary.
7. Audit exports and checkpoints are retained for each scenario.
8. The final certification report includes exact environment, commands, outputs, and PASS/FAIL/BLOCKED status.

## 11. Final Certification Readiness Verdict

Certification package status: **READY TO RUN IN DISPOSABLE LINUX VM, NOT CERTIFIED**.

What must happen next:

- Provision a disposable Linux VM meeting the requirements above.
- Prepare synthetic tmpfs/ext4 workspaces and cgroup v2 subtree.
- Run `tools/certify_linux.py preflight` successfully.
- Execute LC-001 through LC-013 with synthetic agents and retained audit evidence.
- Publish a follow-up certification report with actual PASS/FAIL/BLOCKED results.

Until that is complete, the correct external statement is:

> KECHAA has passing control-plane and adversarial tests, plus a fail-closed certification harness, but Linux whole-agent containment remains uncertified pending execution of LC-001 through LC-013 in a disposable Linux VM.
