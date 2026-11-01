# Linux requirements and verification status

Protected execution is experimental and belongs in a disposable VM with synthetic data. Diagnostics need no privileged setup. Windows is unsupported; macOS has no native protected execution backend.

| Requirement | Reason / admission behavior |
|---|---|
| Linux x86_64 or aarch64 | Implemented native syscall tables; other architectures refused |
| Landlock ABI 6+ | Required filesystem, signal and abstract Unix-socket scope |
| seccomp, PID/network/mount/IPC/UTS/user/cgroup namespace support | Mandatory worker setup; unsupported setup fails closed |
| cgroup v2 subtree with CPU, memory and pids controllers; cgroup.kill | Resource accounting, limits and descendant cleanup |
| mount_setattr and pidfd support | Private read-only mount restrictions and parent-death checks |
| Root-owned daemon, source, interpreter, direct pinned dependency installation | Trusted supervisor and startup checks |
| Separate unprivileged action UID and agent socket group | OS identity is the boundary; session strings are not tenants |
| Dedicated bounded ext4 or tmpfs volume per contract root | Refuse shared directories, bind aliases, shared-device mounts and nested mounts |
| State/sockets outside writable roots | Agent cannot edit authority or signing keys |

A nominal kernel version alone is insufficient: distribution configuration, available namespaces and mount/cgroup setup must satisfy `doctor` and per-launch checks. Landlock ABI is authoritative. Historical observations used Debian 13 / Linux 6.12.113 on ARM64 and x86_64; this is not a supported-distribution guarantee.

## Current evidence

- macOS diagnostic Unix API, signed state, concurrency/restart and S1–S4 regression paths have been exercised.
- Linux kernel controls are implemented; earlier VM command/read/network/cleanup observations are retained in [completion.md](completion.md).
- The current S3 filesystem acceptance and Linux lifecycle verification were not rerun in the remediation pass. The corresponding tests skip on macOS. New CI probes may also skip when runner kernel prerequisites are absent.
- No real Claude/Codex/Gemini/framework session or full MCP mediation is certified.

[The S1–S4 report](../audit/KECHAA_S1_S4_REMEDIATION_REPORT.md) states each finding's status. [Operator preparation](operations.md#experimental-linux-preparation) explains the manual VM setup. There is no one-command privileged host bootstrap.

## Evaluation sequence

First run the diagnostic walkthrough and inspect the policy/contract. Then provision a disposable VM and dedicated volumes through your normal administrator process. Run `doctor`; start the explicit experimental daemon; exercise permitted access plus denied parent/sibling/symlink, mount alias, replay, expiry and descendant cleanup cases. Record observed file/process/errno outcomes and signed audit evidence separately.

`tools/certify_linux.py plan` is an inventory. Its `run` command does not execute all privileged scenarios and cannot confer certification. Preflight, a successful launch, a nonzero process exit or a skipped test alone does not establish a Linux security property.
