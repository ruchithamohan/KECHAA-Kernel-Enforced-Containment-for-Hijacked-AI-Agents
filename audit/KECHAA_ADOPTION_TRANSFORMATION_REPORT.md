# KECHAA adoption transformation

## Scope and baseline

Starting reference: **4.4/10 adoption readiness**. This pass uses the supplied weighted rubric and local repository evidence, not a production security rating. The local baseline was clean `main` at `8d444b8769e80fd7da6280071fdfe66947f349a2`, matching GitHub main. No changes were staged or uncommitted. Origin was the intended `ruchithamohan/KECHAA-Kernel-Enforced-Containment-for-Hijacked-AI-Agents` repository.

The repeated task text described S1–S4 as uncommitted. In fact, the user had subsequently instructed that work to be committed and pushed. Its commit, 30 added regressions and [remediation report](KECHAA_S1_S4_REMEDIATION_REPORT.md) are preserved. This pass makes one new adoption commit on top; it does not squash, amend or rewrite that security commit.

The latest user constraint was **do everything except writing test cases**. No test cases or existing tests were changed. Validation uses the existing suite plus actual demos, adapter calls, installation/removal, archive and documentation checks. A workflow/link-checking utility and executable examples are developer tools, not a new test suite.

### Local ground truth

- Implemented: strict policy engine, task contracts, exact-action signed single-use grants, durable posture, authenticated roles, diagnostic Unix API, audit/checkpoints and experimental offline Linux worker.
- Existing install: explicit-prefix source copier with a fixed `-IS` interpreter. Dependencies are pinned separately. A normal pip console script is intentionally refused, so advertising `pip install kechaa` as the quickstart would be false.
- Existing documentation: substantial security/operations detail, but inconsistent timestamps/status, PR-history prose in the opening, no architecture overview/index or single runnable first-use command.
- Existing integration: low-level API/CLI and a Claude hook whose real-harness compatibility is unverified. MCP support checks declarations, not actual protocol execution. No SQL semantic authorization exists.
- Existing tests: 52 discovered, including the 30 remediation additions; 50 passed and 2 Linux-only skips on this host. Older fixtures prevent claiming the full suite is portable to Linux.
- Existing CI: Pages deployment only. No automated code/installation/link workflow.
- Existing demos: a direct-Engine attack/defense script with macOS-specific assumptions and a browser presentation. No portable, self-contained real-Unix-API onboarding path.
- Community: MIT license and security policy, but no contribution guide, issue forms, PR template or current changelog/roadmap.
- GitHub presentation: description, topics and homepage were empty. Current credential has push/triage access, but lacks admin/maintain permission.

## Five professional perspectives

These are five distinct review lenses applied to the same inspected source, not claims of five independent external auditors.

| Perspective | Baseline obstacle | Implemented response | Remaining concern |
|---|---|---|---|
| Open-source product / DX | First success required reading privileged setup and constructing JSON manually; output did not clearly distinguish simulation | Runnable `demo`, concise opening, human ALLOW/BLOCK/PENDING output, optional standalone installation, explicit cleanup | No independent first-time user study; dependency/network/environment setup can still delay success |
| Linux security architecture | Implementation, historical Linux experiments and current gaps were conflated across docs | Architecture/source map, current platform matrix, exact privilege/mount assumptions and evidence boundary; S3 partial status preserved | Current Landlock/mount/cgroup acceptance and real interception remain incomplete |
| AI-agent infrastructure | Raw protocol integration, no small reusable client, unclear MCP/SQL scope | AgentClient, run_command function-call message mapping, command adapter and real local SQLite workload with scoped claims | No full MCP proxy, remote SQL authorization or pinned framework end-to-end workflow |
| Maintainer | Pages-only CI, missing contribution path, archives omitted tests and Python examples | Existing-suite CI, installation/demo/link checks, public archive inventory, lean issue/PR forms, contribution/release guidance | Hosted CI matrix must be observed; older fixtures still need portability work; no new automated cases for new adapter per user instruction |
| Ecosystem strategist | Empty GitHub description/topics and vague breadth | Defensible authorization-bound positioning, scope comparison, ready-to-apply metadata and concrete review opportunities | Applying metadata needs repository administration; no adoption/community activity can be manufactured |

Patterns reviewed from current upstream READMEs: [gVisor](https://github.com/google/gvisor), [Kata Containers](https://github.com/kata-containers/kata-containers), [bubblewrap](https://github.com/containers/bubblewrap). Their useful patterns are explicit architecture, prerequisites and security responsibility. No competitor code was copied or performance/security superiority inferred.

## Weighted adoption scorecard

Final scores are assigned after the local implementation/workflow checks described below. These are reviewer judgments against observable acceptance criteria, not statistically measured user outcomes. Baseline category allocations reconstruct the supplied 44/100 starting reference using the inspected local obstacles.

| Category | Weight | Baseline | Final | Acceptance evidence and remaining deduction |
|---|---:|---:|---:|---|
| Product clarity and positioning | 10 | 5 | 9 | Opening names daemon, grants, offline Linux and evaluation status; use cases/non-goals explicit. No independent 30-second comprehension study |
| README and first impression | 10 | 4 | 9 | Runnable leading example, real abbreviated output, architecture/flow diagrams and bounded capability matrix; no unsupported badges. No independent reader study |
| Installation and time to first success | 15 | 4 | 13 | Fresh venv/dependencies, source demo, installed demo, verify/uninstall actually operated. Cached download and one local platform do not establish universal under-five-minute success |
| Documentation quality | 10 | 6 | 9 | Task index, API/source map, current limits, troubleshooting, release/roadmap; local links checked. Linux operator templates cannot be executed here |
| Examples and demonstrations | 10 | 3 | 7 | Seven independent scenarios operated, real custom client paths, standalone SQL output. Shell/agent grants simulated; MCP not invoked; protected examples need Linux |
| Developer experience and API usability | 10 | 4 | 7 | Thin client, structured errors, no fallback/auto-approval, function-call mapper; manual positive/pending/denied runs. Alpha API and no new adapter regression cases at user request |
| Integration and interoperability | 10 | 3 | 6 | Real local API integration and function-call message translation without services/SDKs. No full MCP, framework version or remote DB integration |
| Security credibility and transparency | 10 | 8 | 8 | S1–S4 preserved, actual/declared/simulated/historical evidence separated. Linux S3/lifecycle gap and finite audit capacity still limit assurance |
| Testing, CI and release maturity | 5 | 3 | 3.5 | Existing regressions run; CI and source/installation workflow added; deterministic archive validation. Hosted matrix, unsigned release and no new test cases limit credit |
| Contribution and community readiness | 5 | 1 | 4 | Reproducible developer loop, issue forms/PR guidance, roadmap and versioning. No staffed disclosure SLA or demonstrated contributor response history |
| Discoverability and repository presentation | 5 | 3 | 3.5 | README/website entry points aligned and accurate metadata prepared. Live description/topics remain unapplied for lack of admin permission |
| **Total** | **100** | **44** | **79** | **4.4/10 → 7.9/10** |

Calculation: sum earned points divided by 100, multiplied by 10. A perfect score is not justified by a document's existence, by simulated commands or by unobserved hosted CI. The target remains 10/10; claiming it now would hide material adoption/evidence gaps.

## Positioning and workflow changes

Chosen positioning: **Authorization-bound execution for agent tools.** This describes the implemented control plane and fits the experimental Linux worker without implying prevention of agent hijacking.

One-sentence GitHub recommendation:

> Authorization-bound execution for AI agent tools: signed single-use grants, persistent policy state, and experimental offline Linux containment.

Primary audience: agent infrastructure engineers evaluating local/offline command tooling, with Linux security evaluators as the next audience. The strongest scenarios are exact-command approval, replay protection, persistent restriction after suspicious requests and auditable offline execution experiments. Kernel containment, model/harness integration and database authorization are separate boundaries.

KECHAA is not a replacement OCI runtime, userspace application kernel or VM. gVisor, Kata and bubblewrap illustrate different isolation scopes. No comparative performance or security ranking was performed. Scope, topics and technical community opportunities are in [repository-presentation.md](../docs/repository-presentation.md).

## Implemented developer workflows

### First five minutes

The supported source path is now venv → pinned dependencies → isolated source launcher → `demo`. The demo creates a fresh diagnostic daemon, uses actual Unix IPC/peer credentials and signed SQLite state, then cleans up its temporary daemon, files and keys. It never silently selects a protected or unconfined execution path.

On this machine, a fresh virtual environment took 1.497 seconds; pinned installation took 0.859 seconds with cached packages available; the first source demo took 0.878 seconds. These are measured local observations, not a promise about a user's download speed or kernel setup. [Workflow command output](adoption-evidence/workflows.json) retains exit codes and timings with local paths sanitized.

Standalone installation, installed demo, manifest verification and conservative removal also succeeded. The installer retains fixed-interpreter `-IS` startup, refuses nonempty prefixes and starts no service. The ordinary pip-generated console script remains unsuitable by design and is clearly documented rather than bypassed.

### Examples and integrations

| Workflow | Actual result | Boundary |
|---|---|---|
| Safe echo / grant replay | ALLOW simulation, replay BLOCK | Real prepare/consume checks; no echo process |
| rm request | BLOCK; disposable sentinel retained | Policy decision before command execution |
| Approval | PENDING_APPROVAL, operator approval, ALLOW simulation | Disposable operator role only; client has no admin API |
| Outside sensitive read | BLOCK | Authorization evidence, not a Linux filesystem read attempt |
| MCP declarations | Offline ALLOW; external BLOCK | Real API, no MCP server invocation |
| SQLite command grant | ALLOW simulation | Script is an explicit identified input; query not run by daemon |
| Standalone SQLite workload | Real SELECT returned `[[1, "review policy"]]` | In-memory local SQL; explicitly no KECHAA containment |
| Function-call and supervised grant | Translation/ordinary grant and process-tree grant simulated | No actual model session or whole-agent sandbox launch |
| Custom command adapter | Exit 0 simulation, 2 pending, 3 denied | Actual calls to disposable Unix daemon; no direct command fallback |

The client is small and framework-neutral: prepare, execute, simulate, check declarations, translate run_command messages and close a run. Protected execute requires an issued grant, expected root daemon and Linux profile. No administrative authority, automatic retry or auto-approval was added. The function-call adapter is a message-shape integration, not proof of compatibility with a hosted model or framework version.

### Documentation and repository

README now leads with a working example and clearly connects policy, grants, administrator, worker and Linux controls. Dedicated guides cover architecture, API, adapter development, examples, current Linux requirements, performance, contribution and release workflow. Stale macOS socket claims were corrected; historical validation remains preserved and dated. The Pages website and old demo guide now point at the current quickstart.

Lean issue forms and a PR template request reproducible synthetic evidence. Changelog distinguishes the existing security commit from unreleased adoption work. The roadmap prioritizes Linux acceptance and a real agent workflow rather than speculative feature proliferation. No unsupported badges, publicity messages or artificial community activity were added.

## Benchmark evidence

[Raw current diagnostic results](adoption-evidence/benchmark.json): 50 measured iterations after one warm-up, three fresh daemon startup samples, real Unix IPC/SQLite/signatures and a canonical four-executable inventory. On Apple ARM64/macOS with Python 3.14.8, median startup was approximately 120.9 ms, health 0.293 ms, preparation 2.160 ms, and prepare+simulate 3.806 ms. One daemon RSS sample was 45,344 KiB.

This is sequential diagnostic overhead. It is not protected execution latency, parallel throughput, peak RSS or a comparison with another sandbox. Execution overhead remains null in the raw record. Hardware, OS/kernel, runtime/dependency versions, configuration and every timing sample are included. [Methodology](../docs/performance.md).

## Verification and release gate

The exact runnable commands and observed outputs are retained under `audit/adoption-evidence/`. All seven independent demo scenarios ran; custom adapter success/pending/denial paths ran against a real disposable daemon. A fresh dependency environment and explicit-prefix install/verify/demo/uninstall completed. `doctor` correctly exited 3 on macOS. The two Linux skips were not changed or counted as passes.

- Final applicable full suite: **52 discovered, 50 passed, 2 Linux-only skips**, exit 0, 6.537 seconds on macOS ARM64 / Python 3.14.8. [Exact output](adoption-evidence/final-suite.txt).
- Markdown checker: 121 local links across 36 Markdown files passed before this report's final links were added; the final check is also recorded in the verification manifest.
- Source archive: repeated builds from identical inputs matched byte-for-byte; every embedded manifest checksum verified. An extracted copy ran the JSON demo and documentation-link check successfully. Final artifacts remain in ignored local output, not a release asset.
- All workflow and issue-form YAML parsed. Workflow names/triggers/jobs and read-only contents permissions were checked locally; this is not an assertion of hosted runner success.
- Remediation preservation: no diff from `8d444b8` in existing tests, Engine, policy, common/path logic, daemon, Linux backend, S1–S4 report or its evidence. No new test cases.
- Complete intended file inventory reviewed, targeted secret/personal-path scan completed, and `git diff --check` passed. Existing tracked release checksums were not replaced.
- GitHub description/topics/homepage are prepared but unchanged; authenticated API reports no administration permission. No repository visibility, security settings, release or tag was modified.

No Linux kernel property was established in this pass. Deployment-specific root commands, release publication commands and historical experiments were not executed just to check documentation; those are explicitly identified as operator templates or historical evidence. Newly documented local developer workflows were executed. This is the practical limit on “validate every command” in a macOS environment.

## Files and scope

Intended changed/added files (no deletions):

- `.github/ISSUE_TEMPLATE/bug.yml`
- `.github/ISSUE_TEMPLATE/proposal.yml`
- `.github/pull_request_template.md`
- `.github/workflows/ci.yml`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `README.md`
- `audit/KECHAA_ADOPTION_TRANSFORMATION_REPORT.md`
- `audit/adoption-evidence/benchmark.json`
- `audit/adoption-evidence/final-suite.txt`
- `audit/adoption-evidence/verification.json`
- `audit/adoption-evidence/workflows.json`
- `demo/README.md`
- `docs/README.md`
- `docs/adapter-development.md`
- `docs/api.md`
- `docs/architecture.md`
- `docs/completion.md`
- `docs/getting-started.md`
- `docs/integrations.md`
- `docs/linux-requirements.md`
- `docs/operations.md`
- `docs/performance.md`
- `docs/release.md`
- `docs/repository-presentation.md`
- `docs/roadmap.md`
- `docs/security.md`
- `docs/validation.md`
- `examples/README.md`
- `examples/agent_tool.py`
- `examples/sqlite_task.py`
- `kechaa/cli.py`
- `kechaa/client.py`
- `kechaa/demo.py`
- `kechaa/protocol.py`
- `tools/benchmark.py`
- `tools/check_docs.py`
- `tools/package.py`
- `website/index.html`

The enforcement Engine, policy/intersection logic, Linux backend, existing tests and S1–S4 report/evidence remain intact. The only shared transport change tolerates macOS ENOTCONN on shutdown after a fully sent request, while still requiring and validating the response; it does not authorize retries or bypass peer authentication. All intended work is reviewed together; local environments, keys, temporary state and generated archives are excluded from the commit.

## Remaining blockers and independent-style final review

An experienced developer can now understand the scope and run a real local control-plane example without contacting the author. A Linux security engineer can locate the trust assumptions, implemented controls and unverified acceptance criteria quickly. An infrastructure maintainer gets a small integration surface, structured failure behavior and a reproducible developer loop.

The project is ready for **external evaluation and focused contributions**, not an unqualified production rollout. It cannot honestly receive 10/10 yet:

1. Complete current Linux S3 mount/filesystem and live-worker revocation/restart acceptance on documented environments.
2. Run one real pinned agent/harness workflow with comprehensive tool interception and bypass attempts.
3. Observe and maintain hosted CI; port older platform-specific fixtures and add adapter regression coverage in a later authorized change.
4. Establish a monitored private vulnerability intake, release signing/versioning and independently retained operational audit checkpoints.
5. Validate fresh onboarding with external users and cold dependency downloads; keep canonical-path/interpreter constraints visible.
6. Have a repository administrator apply the prepared description/topics and confirm the website URL. No unrelated settings were modified.

Finite audit capacity, trusted root/kernel/dependencies, same-UID identity limits, mutable transitive inputs and unmediated remote MCP/SQL remain explicit limitations. None was hidden to increase the score. New feature scope is intentionally small and does not claim those problems are solved.
