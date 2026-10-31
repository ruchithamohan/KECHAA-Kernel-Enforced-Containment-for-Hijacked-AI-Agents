# KECHAA Linux Containment Certification Report

Date: 2026-10-31  
Branch: `kechaa/linux-containment-certification`  
Base commit inspected: `19c1d30d53b4db4bea3b760f386f0376060c4036`  
Certification evidence directory: `audit/certification-evidence/20261031-lc001-lc013-blocked/`

## 1. Executive Summary

Certification verdict: **CERTIFICATION BLOCKED — ENVIRONMENT OR PREREQUISITES MISSING**.

LC-001 through LC-013 were inspected but not executed against Linux kernel enforcement. The current host is macOS/Darwin arm64, Docker daemon is unavailable, and no disposable Linux VM/runtime is available. Running the certification scenarios on this host would not prove Linux containment and would violate the certification rules.

Important finding: `tools/certify_linux.py` currently provides scenario inventory, procedure text, preflight, and a fail-closed `run` command. It does **not** yet implement automated execution of LC-001 through LC-013. This is appropriate for avoiding false certification, but it means certification cannot pass until a Linux VM is provided and either manual scenario procedures or a real scenario runner executes and retains evidence.

No OS-level containment PASS result is claimed in this report.

## 2. Repository and Branch State

Initial repository inspection:

- Working branch before certification branch: `kechaa/mission-critical-remediation`.
- Dedicated certification branch created: `kechaa/linux-containment-certification`.
- HEAD inspected: `19c1d30d53b4db4bea3b760f386f0376060c4036`.
- Existing untracked audit files were preserved.
- No source code was modified for certification.
- No merge into `main` was attempted.

Preserved untracked files observed:

- `audit/01-baseline.md`
- `audit/02-assessment.md`
- `audit/KECHAA_INDEPENDENT_PRODUCTION_AUDIT_20261031.md`
- `audit/KECHAA_MISSION_CRITICAL_REMEDIATION_PLAN_20261031.md`

## 3. Test Environment and Kernel Configuration

Actual environment:

```text
OS: Darwin / macOS
Architecture: arm64
Docker client: present
Docker daemon: unavailable
Linux VM tooling found: none among docker daemon, podman, lima, limactl, colima, multipass, qemu-system-aarch64, qemu-system-x86_64, vagrant, tart
```

Evidence files:

- `audit/certification-evidence/20261031-lc001-lc013-blocked/environment.txt`
- `audit/certification-evidence/20261031-lc001-lc013-blocked/preflight.json`
- `audit/certification-evidence/20261031-lc001-lc013-blocked/preflight.exit`
- `audit/certification-evidence/20261031-lc001-lc013-blocked/run.json`
- `audit/certification-evidence/20261031-lc001-lc013-blocked/run.exit`

Preflight result:

```text
ready=false
failure=Linux is required for kernel containment certification.
exit=3
```

Certification run result:

```text
certified=false
required_scenarios=LC-001..LC-013
exit=4
```

## 4. Existing Implementation Reviewed

Reviewed implementation surfaces:

- `tools/certify_linux.py`: LC inventory, procedure, preflight and fail-closed run behavior.
- `kechaa/backends/linux.py`: cgroup, namespace, Landlock, seccomp, mount restriction and worker setup implementation.
- `kechaa/worker.py`: private Linux worker entry point.
- `kechaa/daemon.py`: worker launch, active action lifecycle, cgroup cleanup and stop-required paths.
- `kechaa/engine.py`: grants, leases, history-aware policy, MCP tool request authorization, quarantine/recovery and supervised launch metadata.
- `kechaa/cli.py`: `agent` launch flow and `mcp-check` effect-contract authorization path.
- `tests/test_security_control_plane.py` and `tests/test_adversarial_control_plane.py`: control-plane and adversarial test coverage.
- `audit/KECHAA_LINUX_CERTIFICATION_READINESS.md`: certification prerequisites and LC readiness matrix.

Conclusion: the codebase has a plausible Linux enforcement design, but the current environment and harness do not provide OS-level execution evidence.

## 5. LC-001 Through LC-013 Results

| Scenario | Test Objective | Expected Result | Actual Result | Status | Evidence |
|---|---|---|---|---|---|
| LC-001 | Approved echo exits 0 inside workspace | Permitted supervised execution succeeds with `controls_ready=true` | Not executed; no Linux VM | BLOCKED | `lc-plan.json`, `preflight.json`, `run.json` |
| LC-002 | Outside synthetic secret read fails at OS level | Kernel denies outside read | Not executed; no Linux VM | BLOCKED | Same |
| LC-003 | Outside write/chmod/rename fail and target remains unchanged | Kernel denies outside mutation | Not executed; no Linux VM | BLOCKED | Same |
| LC-004 | TCP/UDP/IPv4/IPv6/Unix socket creation fail | Kernel/network policy denies sockets | Not executed; no Linux VM | BLOCKED | Same |
| LC-005 | Consumed grant cannot authorize another execution | Replay denied before launch | Unit equivalent passed; Linux launch replay not executed | BLOCKED | `unittest.log`, `run.json` |
| LC-006 | Expired grant or lease blocks execution | Expired authorization denied | Unit equivalent passed; Linux launch expiry not executed | BLOCKED | `unittest.log`, `run.json` |
| LC-007 | Background and double-fork descendants are killed | Process tree cleaned up | Not executed; no Linux VM | BLOCKED | `run.json` |
| LC-008 | Restart kills stale action cgroups and rejects stale grants | Fail-closed restart recovery | Control-plane history persistence tested; cgroup restart not executed | BLOCKED | `unittest.log`, `run.json` |
| LC-009 | Direct unwrapped execution path unavailable in supported session | Supervised boundary cannot be bypassed in deployment | Not executed; requires Linux deployment profile | BLOCKED | `run.json` |
| LC-010 | MCP/web/non-shell tool without effect contract fails closed | Tool denied and fallback direct effect blocked | Unit equivalent passed; Linux fallback not executed | BLOCKED | `unittest.log`, `run.json` |
| LC-011 | Agent launch enters cgroup/namespaces/Landlock/seccomp and descendants inherit restrictions | Process tree contained | Not executed; no Linux VM | BLOCKED | `run.json` |
| LC-012 | Concurrent agents have distinct cgroups/histories/workspaces and cannot cross-access | Cross-agent interference denied | Control-plane equivalent passed; Linux concurrency not executed | BLOCKED | `unittest.log`, `run.json` |
| LC-013 | Malicious external instruction tightens posture and later action requires approval/denial with evidence | End-to-end attack-defense demo with OS boundary | Control-plane demo passed; Linux kernel denial not executed | BLOCKED | `demo-attack-defense.json`, `run.json` |

Machine-readable result summary: `audit/certification-evidence/20261031-lc001-lc013-blocked/results.json`.

## 6. Evidence References

Evidence directory contents:

- `environment.txt`: host, branch, commit, virtualization tooling and Docker status.
- `lc-plan.json`: scenario inventory from `tools/certify_linux.py plan`.
- `procedure.sh`: procedure text from `tools/certify_linux.py procedure`.
- `preflight.json` and `preflight.exit`: current host preflight result.
- `run.json` and `run.exit`: current host certification run result.
- `compileall.log`: compile check evidence.
- `unittest.log`: 22-test local suite evidence.
- `policy-validate.log`: example policy validation evidence.
- `demo-attack-defense.json`: control-plane attack/defense demo output.
- `package-smoke.log`: package smoke evidence.
- `results.json`: machine-readable LC scenario status summary.

## 7. Failures and Root-Cause Analysis

### Blocker 1: No Linux certification environment

Root cause: current host is macOS/Darwin arm64 and has no usable disposable Linux VM. Docker client exists but Docker daemon is unavailable. Other checked VM/container tools are unavailable.

Impact: LC-001 through LC-013 cannot be executed as OS-level Linux enforcement tests.

Resolution required: provision a disposable Linux VM meeting the requirements in `audit/KECHAA_LINUX_CERTIFICATION_READINESS.md`.

### Blocker 2: Certification harness is not a full scenario runner

Root cause: `tools/certify_linux.py run` intentionally returns `certified=false` and exit `4`. It does not execute LC scenario commands even if preflight were to pass.

Impact: certification still requires manual execution using the procedure/readiness docs or implementation of a real Linux-only runner. This is safe and fail-closed, but incomplete.

Resolution required: either execute documented LC procedures manually in the VM and retain evidence, or implement a Linux-only scenario runner that performs every LC test with synthetic fixtures and fail-closed result handling. That runner itself must be validated in the VM.

### Blocker 3: No OS-level evidence for key claims

Root cause: process, filesystem, network, cgroup and namespace behavior cannot be observed from macOS diagnostic mode.

Impact: KECHAA must not claim certified whole-agent containment, filesystem isolation, network isolation, process-tree cleanup or concurrent-agent OS isolation.

Resolution required: run LC-001 through LC-013 in Linux and preserve logs/audit/cgroup/process evidence.

## 8. Fixes Implemented

No implementation fixes were made in this milestone.

Reason: no Linux scenario executed, so no genuine OS-enforcement failure was observed. Implementing unverified changes would risk producing speculative code rather than certified security improvements.

Generated package artifacts from the package smoke test were removed/restored so the repository was not left with unintended build outputs.

## 9. Regression Test Results

Safe local regression results captured in evidence directory:

| Check | Result | Evidence |
|---|---|---|
| `python -m compileall -q kechaa tools tests` | PASS | `compileall.log` |
| `python -m unittest discover -v` | 22 PASS, 0 FAIL | `unittest.log` |
| `python -m kechaa policy validate examples/linux-offline.yaml` | PASS | `policy-validate.log` |
| `python tools/demo_attack_defense.py` | PASS as control-plane demo | `demo-attack-defense.json` |
| `python tools/certify_linux.py preflight` | BLOCKED/fail-closed, exit 3 | `preflight.json`, `preflight.exit` |
| `python tools/certify_linux.py run` | BLOCKED/fail-closed, exit 4 | `run.json`, `run.exit` |
| `python tools/package.py` | PASS; generated artifacts cleaned | `package-smoke.log` |

## 10. Remaining Vulnerabilities and Limitations

- Linux whole-agent containment is not certified.
- Process-tree containment and descendant cleanup are not certified.
- Filesystem and network restrictions are not certified.
- Quarantine/recovery process termination is not certified.
- Concurrent-agent Linux isolation is not certified.
- Supervised-launch bypass prevention is not certified in a real deployment profile.
- MCP effect-contract authorization is tested at control plane, but full MCP protocol mediation is not implemented.
- The certification harness lacks an automated Linux scenario executor.
- Performance and reliability under real Linux long-running agent workloads remain unmeasured.

## 11. Reproduction Instructions

To complete certification, use a disposable Linux VM only.

Minimum steps:

1. Provision Linux `x86_64` or `aarch64` VM.
2. Confirm cgroup v2, Landlock ABI `>= 6`, `os.pidfd_open`, root-owned daemon setup and distinct unprivileged `agent` account.
3. Prepare synthetic `tmpfs` or `ext4` workspaces under `/work/agent-a` and `/work/agent-b`.
4. Do not mount host home directories, SSH agents, cloud credentials, Docker socket or unrestricted host filesystems.
5. Run:

```bash
python3 tools/certify_linux.py preflight --cgroup-root /sys/fs/cgroup/kechaa
python3 tools/certify_linux.py plan
python3 tools/certify_linux.py procedure
```

6. Execute LC-001 through LC-013 with synthetic agents and data only.
7. Preserve raw commands, stdout/stderr, exit codes, KECHAA audit exports, signed checkpoints, cgroup evidence, process evidence and before/after file digests.
8. Mark every scenario PASS, FAIL or BLOCKED using the readiness rules.
9. Do not publish PASS unless the prohibited action was actually blocked by the intended enforcement boundary.

## 12. Final Certification Verdict

**CERTIFICATION BLOCKED — ENVIRONMENT OR PREREQUISITES MISSING**

This verdict is not a security pass and not a security fail. It means the current host cannot execute genuine Linux containment certification and the current certification harness intentionally refuses to report success.

Updated KECHAA readiness remains:

**FUNCTIONAL SECURITY PROTOTYPE — NOT PRODUCTION READY**

The exact next action is to provide or authorize a disposable Linux VM that satisfies the documented cgroup, Landlock, namespace, root-daemon and unprivileged-agent requirements, then execute LC-001 through LC-013 with retained evidence.
