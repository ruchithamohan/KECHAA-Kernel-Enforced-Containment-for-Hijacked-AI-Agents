# Documentation-only comparison

Reviewed 2026-10-29. No competitor executable was installed or benchmarked. Only
public documentation and repository metadata were consulted; no competitor
implementation file was used as a code template. Documented capabilities are
vendor/project statements, not independently demonstrated results.

## Evidence sources

| Project | Document inspected / source snapshot |
|---|---|
| NVIDIA OpenShell | [README](https://github.com/NVIDIA/OpenShell/blob/def7da876cb5665d1d9b1acde5fc31eda79bf93f/README.md) |
| Anthropic Sandbox Runtime | [README](https://github.com/anthropic-experimental/sandbox-runtime/blob/98a4016d27609ed34dd1fb43d23ed6efb6eeeb77/README.md), selected capability/limitation sections |
| nono | [README](https://github.com/nolabs-ai/nono/blob/081a4090c588da4f51df004401b2c9ce372e5e94/README.md) |
| Sondera coding-agent hooks | [README](https://github.com/sondera-ai/sondera-coding-agent-hooks/blob/c9642340b3d00cbc5b665c93853f339e7e3132f4/README.md) |
| KEIP | [README](https://github.com/Otsmane-Ahmed/KEIP/blob/d5465ddf5bec01fb0a1d7070d0a5f41548410a46/README.md), selected capability/requirement sections |
| Microsoft Agent Governance Toolkit | [README](https://github.com/microsoft/agent-governance-toolkit/blob/1b6805366554cc0ed8d8b8453ed745fff98fd755/README.md), selected scope sections |
| Kubernetes Agent Sandbox | [README](https://github.com/kubernetes-sigs/agent-sandbox/blob/6a7ad5aa3999a8f9f14c2e771980e2f6ab8c4496/README.md) |
| GolemHalt | No matching public repository found in the searches performed; identity/capabilities UNVERIFIED. Do not assume equivalence with Sondera. |

The architecture PDF's approval-laundering research citations and priority/novelty
claims were not independently validated. They are not used as evidence that
KECHAA is first or superior.

## Documented capabilities

| Project | Platforms/integration | Policy/enforcement | Operations and limitations evident in inspected docs |
|---|---|---|---|
| OpenShell | Linux, Apple Silicon macOS, experimental WSL2; CLI/gateway/SDKs; container or host virtualization | Declared file/syscall/network policy; isolated agent runtime; endpoint-bound credential injection; policy-change verification | Gateway and sandbox lifecycle, policy review and Kubernetes path documented. Precise per-action grant/replay and drift semantics were not established by the inspected README. |
| Sandbox Runtime | Linux bubblewrap, macOS Seatbelt, documented Windows backend; CLI/library and MCP wrapping | Filesystem rules, domain-filtering HTTP/SOCKS proxies, Unix socket controls; process-tree restrictions documented | Network updates via control FD; filesystem policy not generally mutable live. Explicit weaker-isolation/Apple Events caveats. Research preview. No inference that approval-binding features are absent. |
| nono | Linux, macOS, WSL2; agent profiles and per-tool sandboxes | Composable JSON capabilities, environment/credential controls, HTTP method/path network policies, supply-chain attestation | Cryptographic audit, optional signing, verified snapshots/rollback and profile inheritance documented. Exact grant replay/lifetime/drift semantics require deeper verification. |
| Sondera hooks | Linux x86-64 and Apple Silicon archives; Claude, Cursor, Copilot, Gemini and more adapters | Normalized hooks → local service; Cedar allow/deny/escalate and deterministic signature scanning | Adapter-specific blocking capabilities and fail-closed hooks documented; optional probabilistic classifiers. OS process-tree containment and signed OS-effect grants not established by this source. |
| KEIP | Linux; pip install monitoring | eBPF LSM socket-connect enforcement and behavioral port/IP/transfer thresholds; process-group termination described | Dedicated privileged-capability Python setup and post-install .pth auditing documented. Process-group claims are not assumed equivalent to complete cgroup containment. No independent validation of README efficacy/performance claims. |
| Microsoft AGT | Python/other SDKs and framework integrations; first-party developer adapters | YAML policy, identity/trust, audit and application-level intervention | README explicitly identifies application middleware rather than OS kernel enforcement and shared process boundary. Runtime layers and Merkle audit described; public preview. Exact OS controls must be assessed in deployed integrations. |
| Kubernetes Agent Sandbox | Kubernetes CRDs/controller, Go/Python SDKs | Declarative sandbox lifecycle; delegates isolation to runtime classes such as gVisor/Kata | Stable identity/storage, scheduled deletion, pause/resume, claims/templates/warm pools. A sandbox orchestrator, not itself the underlying kernel-isolation implementation. |
| KECHAA 0.2.0a1 | Portable Python control plane; generic CLI and unverified Claude adapter | Strict YAML, exact-context Ed25519 grants and state machine; experimental offline Linux worker | Diagnostic operations on macOS and offline Linux ARM64 filesystem/network/lifecycle/package scenarios operated; native macOS disabled and real AI-harness integration unverified. See completion.md. |

## Approval, history and evidence gaps

For each competitor, single-use approval-to-OS-effect binding, cross-session
replay behavior, executable/input race guarantees, lease tightening, run-level
drift rules, event-loss handling and audit immutability require dedicated protocol
or implementation-independent operational evaluation. **Not established here**
does not mean absent. None was deliberately configured weakly or evaluated
against KECHAA's own chosen success criteria.

The strongest documented candidates differ by capability: OpenShell for managed
runtime/policy-change administration; Sandbox Runtime and nono for cross-platform
tool isolation; nono for supply-chain attestation and rollback; Sondera for hook
coverage and Cedar policy; AGT for framework governance; Kubernetes Agent Sandbox
for stateful sandbox orchestration; KEIP for focused pip-install monitoring.
These are directions for evaluation, not measured rankings.

KECHAA's intended differentiator is explicit approval-to-envelope binding with
durable tightening and independently verifiable evidence. Its current verified
advantage is **not established**: it has substantial functionality and validation
gaps compared with those documented systems.

## Fair evaluation plan

Use identical disposable machine images, project copies, resource budgets and
local fixtures. Follow each project's supported installation and strongest
appropriate documented configuration. Include unmodified real development
workflows and the same local-only credential/read/write/descendant/network/replay
scenarios. Record native feature support separately from wrapper customization.

Report unauthorized effects, compatibility blocks, policy mistakes, additional
approvals, actual wall/CPU/RSS costs, installation steps, restart behavior and
audit evidence independently. Use endpoint/file observations, not only logs.
Document unavailable features and installation constraints; do not assign a
fabricated composite score or claim universal superiority. None of this
comparative operational evaluation has yet been performed.
