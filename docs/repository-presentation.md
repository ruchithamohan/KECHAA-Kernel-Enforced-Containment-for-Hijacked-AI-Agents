# Repository presentation and positioning

Recommended category: agent-tool authorization and experimental Linux containment.

**One sentence / GitHub description:**

> Authorization-bound execution for AI agent tools: signed single-use grants, persistent policy state, and experimental offline Linux containment.

**Elevator pitch:** KECHAA separates an agent's request to act from the authority to execute. A local daemon binds commands to task contracts and single-use signed grants; its experimental Linux worker applies bounded operating-system restrictions. Developers can evaluate policy, approvals, replay protection and audit locally, with explicit limits around Linux verification and remote tools.

Primary audience: agent infrastructure engineers and Linux security evaluators. Primary uses: offline command tools, reviewed build/analysis workflows, durable approval/replay control and containment research. Secondary audiences: security researchers and contributors investigating failure paths.

The differentiator is the combination of approval-to-action binding, persisted tightening and signed evidence around a Linux worker. No claim of being first, strongest or a replacement for gVisor/Kata/Docker is justified. gVisor interposes a userspace application kernel; Kata uses VM isolation; bubblewrap assembles namespaces. KECHAA is not an OCI runtime or a VM manager. Its authority model can be evaluated alongside outer isolation, but composition is not automatically verified.

**Topics to apply:** `ai-agents`, `agent-security`, `linux-security`, `sandbox`, `landlock`, `seccomp`, `authorization`, `python`, `audit-log`.

Omit `mcp-server`, database-firewall or framework-specific topics: full MCP/SQL/framework enforcement is not shipped. Do not use a production/certification badge. CI badges should link only to the actual workflow and should not imply kernel certification.

The README is the primary project website until a maintainer chooses to use the existing Pages site. If linking Pages, verify its deployment and keep its examples/status aligned with the README. Use a social preview showing the actual request → grant → worker boundary and the phrase “experimental offline Linux containment”; avoid padlock imagery that implies invulnerability. No generated image is required.

Relevant communities: reproducible Landlock/Linux security discussions, agent-infrastructure maintainers evaluating command tools, and sandbox researchers. Share a minimal working example with explicit limitations and invite review of a concrete boundary. No mass outreach, star solicitation or unrequested messages are part of this work.

Documentation patterns inspected: [gVisor](https://github.com/google/gvisor), [Kata Containers](https://github.com/kata-containers/kata-containers), [bubblewrap](https://github.com/containers/bubblewrap). Borrow the clarity of scope, prerequisites and security responsibility, not their maturity claims or security architecture.
