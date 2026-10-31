# Release readiness — 0.2.0a1

This is a usable experimental offline Linux slice and a portable diagnostic
control plane. It is **not an enterprise production release**. No numerical
confidence or conference-acceptance probability is justified. Alpha source
publication does not satisfy the production gates below. Native macOS supports
diagnostic/control-plane tools only; protected execution is disabled.

## Evidence-based gates

| Gate | Result |
|---|---|
| Source installation, executable verification, policy workflow | PASS on macOS diagnostics and Debian ARM64 VM |
| Root daemon / unprivileged action / real Unix API | PASS for exercised Linux operations; macOS socket binding blocked by host sandbox |
| Exact grant binding, replay, expiry, persisted policy | PASS for documented operations |
| Filesystem content and metadata boundaries | PASS on dedicated tmpfs workspace; shared-filesystem hardlink failure found and excluded by mandatory mount prerequisite |
| Offline TCP/UDP/IPv4/IPv6/Unix socket denial | PASS for socket attempts; local listener baseline and protected package hook observed |
| Descendant termination, session expiry, cancellation and daemon crash | PASS for bounded documented scenarios; exhaustive race validation not established |
| Local offline package build/install/import | PASS for pip 26.0.1 and the disposable PEP 517 fixture |
| Signed audit, checkpoint, tamper rejection, backup/restore | PASS for exercised operations; independently operated remote anchoring absent |
| Performance | Measured under software-emulated ARM64 and x86_64; not native production benchmarks |
| Real AI-harness session and mandatory interception | BLOCKED / NOT IMPLEMENTED |
| Linux x86_64 execution / native macOS execution | PASS for bounded Debian VM scenarios / DISABLED |
| Enterprise release | BLOCKED |

See completion.md, including its audit-handoff hardening section, for commands and observations. Historical 0.1 observations
remain in validation.md. Passing a finite lab scenario is not proof against all
races, future syscalls, malformed dependencies or hostile concurrent tenants.

## Remaining critical and high-priority blockers

These priorities describe impact on the requested deployment, not assigned CVSS
scores or claims that each item is a demonstrated exploit.

| Priority | Unresolved issue | Needed next work |
|---|---|---|
| Critical | Whole-agent baseline and mandatory interception absent | Protect harness settings and every execution path; verify a real pinned harness session and fail-closed hook behavior |
| Critical | Native macOS containment absent | Independently validate a supported macOS boundary or define a VM-backed macOS product with an explicit host/guest contract |
| High | Writable builds and arbitrary transitive inputs are not frozen | Optional read-only workspace contract operated on ARM64/x86_64; snapshots for writable builds and runtime attestation still needed |
| High | Kernel attempted/observed-effect stream absent | Reliable observation and loss accounting before claiming complete effect evidence or observed-effect drift |
| High | Narrow platform and filesystem coverage | Basic x86_64 Debian 13 scenarios now operated; broaden ext4, distribution, namespace/mount failure paths and native performance |
| High | Lifecycle/resource race coverage incomplete | Aggregate CPU accounting, confirmed cgroup emptiness, crash recovery and bounded tmpfs disk exhaustion operated; independent race review and broader OOM/pids coverage remain |
| High | No approved online workflow or renewable lease | Design and validate destination-specific networking, DNS/UDP/IPv6/IPC and live termination before enabling them |
| High | Incomplete trusted dependency/build attestation | Site hooks disabled and application/dependency ownership checked; complete native SBOM/build provenance, release signing and independent security review remain |
| High | Enterprise operations incomplete | Verified public evidence bundles now available; independently controlled forwarding/anchoring, retention, distribution, role separation and release-key operations remain |
| High | Same-UID sessions are not separate hostile identities | One live session per OS UID and per-run admission cap now enforced; unconfined same-UID peers remain one trust domain and multitenant isolation is not supplied |

The new dedicated-filesystem prerequisite closes the demonstrated cross-root
hardlink case for the supported mount contract. Default recheck mode does not freeze workspace
contents or prevent destructive operations that were authorized inside that root.
Tmpfs received the main scenarios; a basic dedicated ext4 write/chmod/read workflow also passed.

## Follow-up order

1. Independently review the now-operated Linux implementation and repeat the
   documented scenarios on native ARM64 and x86_64 disposable VMs, including
   race/failure/resource paths and broader dedicated ext4 workflows.
2. Establish mandatory whole-agent containment and operate one real supported
   harness version. Keep remote MCP and unwrapped tools outside claimed coverage.
3. Implement immutable input handling and reliable observation, then derive
   deterministic contract drift from trusted observations.
4. Define native macOS or a complete VM-backed product boundary. Add narrowly
   scoped online workflows only after validating all network paths.
5. Complete authenticated packaging, dependency provenance, independent audit
   anchoring, retention and deployment administration; reassess release readiness.

No new test suites or automated test frameworks were created. Validation used
the installed product, local API, real commands and disposable guest fixtures.

## Alpha source and pre-release publication

The official destination is
<https://github.com/ruchithamohan/KECHAA-Kernel-Enforced-Containment-for-Hijacked-AI-Agents>.
The repository was private and empty when publication preparation began on
2026-10-29. Publication does not change repository visibility or certify a
production configuration. A repository administrator controls public visibility
and private vulnerability reporting.

The source archive is an intended release asset. `tools/package.py` builds it
from the reviewed source inventory; `dist/kechaa-0.2.0a1-source.tar.gz.sha256`
records its checksum. Keep the archive even if a text-only GitHub connection
cannot upload binary assets. The ignore list explicitly permits these two files
and excludes older builds, lab data, private state and the architecture PDF.
No Python dependency binaries are bundled. An unsigned checksum is an integrity
check, not an authenticated publisher signature.

If authenticated tag/release tools are unavailable, a maintainer can finish from
an authenticated checkout using the following procedure. First verify the exact
destination, inspect `git status`, fetch without overwriting local work, and
confirm `HEAD` is the reviewed publication commit. Inspect remote tags and
releases: stop if `v0.2.0a1` already exists rather than replacing it. Use normal
repository permissions; a protected-ref rejection requires maintainer review.

```bash
git remote get-url origin
git ls-remote --tags origin
gh release list --repo ruchithamohan/KECHAA-Kernel-Enforced-Containment-for-Hijacked-AI-Agents
python3 tools/package.py
# On macOS substitute: shasum -a 256 -c
(cd dist && sha256sum -c kechaa-0.2.0a1-source.tar.gz.sha256)
git diff --exit-code -- dist/kechaa-0.2.0a1-source.tar.gz.sha256
git tag -a v0.2.0a1 -m 'KECHAA 0.2.0a1 experimental Linux containment alpha'
git push origin refs/tags/v0.2.0a1
gh release create v0.2.0a1 --verify-tag --draft --prerelease \
  --repo ruchithamohan/KECHAA-Kernel-Enforced-Containment-for-Hijacked-AI-Agents \
  --title 'KECHAA 0.2.0a1 — experimental Linux containment alpha' \
  --notes-file docs/release.md \
  dist/kechaa-0.2.0a1-source.tar.gz dist/kechaa-0.2.0a1-source.tar.gz.sha256
```

Before publishing the draft, inspect its notes, tag target and pre-release flag,
download both assets into a new empty directory, and compare their bytes:

```bash
gh release view v0.2.0a1 --json url,isDraft,isPrerelease,tagName,assets
gh release download v0.2.0a1 --dir ./release-download-0.2.0a1
cmp dist/kechaa-0.2.0a1-source.tar.gz release-download-0.2.0a1/kechaa-0.2.0a1-source.tar.gz
cmp dist/kechaa-0.2.0a1-source.tar.gz.sha256 release-download-0.2.0a1/kechaa-0.2.0a1-source.tar.gz.sha256
gh release edit v0.2.0a1 --draft=false --prerelease
gh release view v0.2.0a1 --json url,isDraft,isPrerelease,tagName,assets
```

Do not publish if a comparison fails. These are maintainer instructions, not
claims that a tag or GitHub pre-release already exists. Keep the finite ARM64/x86_64 lab observations separate from real harness integration,
mandatory whole-agent interception, immutable writable builds, complete effect
observation and native macOS containment, which remain unresolved.
