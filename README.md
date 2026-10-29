# KECHAA

KECHAA binds an agent command's approval to an explicit effect envelope. A
root-owned Python daemon issues single-use signed grants, then starts the action
under Linux filesystem, syscall, namespace and process-lifetime restrictions.
Thin adapters share the same YAML policy engine and local API.

**KECHAA 0.2.0a1 is an experimental Linux containment alpha, not production-ready.** Actual ARM64 and x86_64 Linux VM
operation now demonstrates offline command and package workflows, filesystem and
network denials, approval binding, descendant cleanup and daemon-loss handling.
The [operational report](docs/completion.md) records failures found and corrected,
measurements, and remaining blockers. No readiness percentage is claimed.

| Platform | Available | Execution boundary |
|---|---|---|
| Linux ARM64 | CLI, daemon, policies, grants, audit and experimental launcher | Exercised on Debian 13 / Linux 6.12.113; dedicated workspace filesystem required |
| Linux x86_64 | CLI, daemon and experimental launcher | Basic Debian 13 / Linux 6.12.113 scenarios operated; broader coverage unverified |
| macOS | CLI, policies, diagnostic grant/state/audit operations | Native protected execution disabled; Linux VM operation is not native macOS containment |

The Linux profile is **offline only**. It requires Landlock ABI 6+, seccomp,
private namespaces, read-only mount restrictions, a prepared cgroup v2 subtree,
a root-owned installation, and a separate unprivileged action account. Each
confirmed project root must occupy a dedicated ext4 or tmpfs filesystem with no
alternate or nested mounts. Ordinary shared host directories are refused because
pre-existing hardlinks can cross apparent path boundaries.

## Install and inspect

Use a reviewed Python 3.11+ environment with the pinned dependencies in
`requirements.txt`. The installer itself never downloads dependencies or starts
services, edits shell profiles, changes PATH, or prepares kernel controls.

```bash
python -IS tools/install.py install --prefix ./installation --python /absolute/path/to/python
./installation/bin/kechaa version
python -IS tools/install.py verify --prefix ./installation
./installation/bin/kechaa doctor
```

`doctor` exits 3 when required execution prerequisites are unavailable. It is a
read-only probe, not certification of a protected deployment.

```bash
kechaa policy init --root /absolute/dedicated/project --output policy.yaml
kechaa policy validate policy.yaml
kechaa policy explain policy.yaml --cwd /absolute/dedicated/project -- /usr/bin/echo hello
kechaa diagnostic --state ./diagnostic-state --policy policy.yaml --admin --duration 300
```

The explicitly non-executing console accepts Local API JSON lines such as
`{"v":1,"operation":"health","data":{}}`. EOF ends it. To execute in a prepared
Linux VM, follow [installation and operations](docs/operations.md), then the
[contract, approval and execution workflow](docs/integrations.md).

## Implemented capabilities

- Strict YAML profiles, deterministic allow/ask/deny precedence, explanations,
  schema export, policy history, atomic import, scoped expiry and reviewed rollback.
- Ed25519 grants bound to argv, cwd identity, UID/session, policy, effects,
  executable/input digests and expiry; atomic adoption and restart invalidation.
- Linux Landlock, seccomp, private read-only mounts, namespaces, privilege dropping,
  cgroup limits, bounded output, expiry and descendant termination.
- Persistent contracts, one live session per OS UID, expiry and label-driven monotonic tightening.
- Signed audit records and checkpoints, verification/export, authenticated offline
  backup and restoration into a new state directory; checkpoint-bound public evidence bundles.
- Generic execution CLI and Local API v1; a Claude hook adapter whose real-harness
  compatibility remains unverified.

A wrapper covers only actions submitted through it. Whole-agent interception,
immutable writable builds and arbitrary transitive inputs, positive network permissions, renewable leases,
complete kernel effect observation and native macOS enforcement are not shipped.
Read-only work can opt into `immutable-workspace` contracts on administrator-prepared
read-only volumes. Startup disables Python site hooks and checks root ownership
of application and dependency files. Aggregate CPU budgets cover descendants.
See the [audit follow-up](docs/completion.md#audit-handoff-hardening) for actual use and remaining gaps.
Labels can tighten policy; they do not establish observed-effect drift or intent.

## Guides and release artifacts

- [Installation, upgrade, backup, recovery and uninstall](docs/operations.md)
- [YAML policy reference](docs/policy.md)
- [Adapters and protocol](docs/integrations.md)
- [Threat model and trust boundaries](docs/security.md)
- [Actual validation and performance](docs/completion.md)
- [Release blockers](docs/release.md)
- [Documentation-only comparison](docs/comparison.md)
- [Dependency/license provenance](docs/provenance.md) and [security reporting](SECURITY.md)

`python tools/package.py` produces a deterministic source archive, file manifest,
limited-scope CycloneDX SBOM and SHA-256 checksum. It excludes the architecture
PDF, `.local`, keys, state and lab data. Checksums are not release signatures.
Original source is MIT licensed. See [release notes and publication procedure](docs/release.md)
for the alpha's scope, verification steps and remaining production release gates.
