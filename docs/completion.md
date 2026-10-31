# Operational evidence — 2026-10-29, KECHAA 0.2.0a1

This report records actual installed-product operation, not source inspection
presented as execution. No new test suites, fuzzers or benchmark frameworks were
written. Disposable fixtures and an interactive operator session exercised the
CLI and documented Unix API under separate root and UID 1001 identities.
Historical 0.1 diagnostic observations remain in validation.md.

## Environment and provenance

Host: macOS Darwin 27.0.0, ARM64, UID 501. Host diagnostic Python: 3.14.8.
Host Unix socket binding remained denied by the managed sandbox. Native Apple
virtualization reported unavailable. With explicit user approval, trusted QEMU
bottles and a Debian image were downloaded into ignored `.local/vm`; no host
installation, privileged service, kernel/BPF/security change or shell change was
performed. No real credentials or external attack targets were used.

Guest: Debian 13 nocloud ARM64, CPython 3.13.5, Linux **6.12.113+deb13-arm64**,
Debian kernel build 2026-10-15. QEMU 11.1.3 ran a real guest kernel using TCG
software emulation, one vCPU, 768 MiB RAM, a 3 GiB backing disk/overlay, **no NIC,
no bridged networking and no shared host folders**. Source and wheels entered on
a read-only virtual disk or bounded serial transfer. This is VM kernel execution,
not simulated Landlock. The launcher bounds runtime to 3600 seconds and the
serial log to 8 MiB; guest poweroff or `.local/vm/stop-validation` stops the lab.

The guest reported Landlock ABI **6**, cgroup v2 CPU/memory/pids controllers and
pidfds. Actual launches established namespaces, Landlock, seccomp, UID/GID drop
and, after hardening, private read-only mounts. Each prerequisite is checked at
launch. Protected work used a guest-only **64 MiB tmpfs** mounted at `/work/project`.
The root daemon owned `/var/lib/kechaa` and `/run/kechaa`; UID/GID 1001 owned the
workspace. Synthetic outside files lived under `/work/outside` with permissions
that allowed the unconfined action account to read/write them.

Pinned product dependencies: PyYAML 6.0.3, cryptography 48.0.1, cffi 2.0.0 and
pycparser 3.0. Linux wheel SHA-256 values were checked on host and guest against
PyPI metadata. Pip 26.0.1 was an offline lab tool. Image source:
`https://cloud.debian.org/images/cloud/trixie/latest/debian-13-nocloud-arm64.tar.xz`.
Its official HTTPS SHA-512 was verified:

```
ba465e102fd809f0a9ea0c83f1650af1ea3ec3f891ce9e940bf3ac623b2e96affca625522d38705cc906d77dd74c1ce3dd7a82bad8e8bf2de5a259d99a777df8
```

The detached OpenPGP image signature was not verified. QEMU's bottle SHA-256:
`633b1cb3f1fac3e73e0dc7b686284c634a8344c1235f04e0d84d9c5727e221a0`.
These checksum checks do not constitute native dependency-build attestation.

## Required scenario results

PASS means the named operation was actually observed. It does not extend to
unlisted platforms, races or workflows. BLOCKED names missing infrastructure or
capabilities. NOT APPLICABLE identifies intentionally unsupported functionality.

| Scenario | Result | Actual observation |
|---|---|---|
| 1. Fresh install, diagnostics and removal | PASS for exercised explicit-prefix installations | Installed executable reported 0.2.0a1; manifest verifier checked 18 program files; doctor reported ABI 6; no service started by installer. Conservative removal was operated on disposable installations. |
| 2. Policy validation, explanation and changes | PASS | Duplicate YAML key reported source line 2; failed activation retained the active digest. Import/history/rollback/expiry/explanation operated; stale expected-version rollback rejected. |
| 3. Legitimate development workflow | PASS after compatibility fixes | echo, shell reads/writes, Python script, local pip PEP 517 package build/install and subsequent import completed. Ten repeated protected echo actions all exited 0. |
| 4. Prohibited operation | PASS | World-readable dummy credential read returned EACCES; outside content write was denied and content stayed UNCHANGED. Outside chmod returned EROFS; mode stayed 0666. |
| 5. Approval integrity | PASS | Exact approved echo ran; replay, modified argv/cwd, cross-session use, changed explicit artifact and restart-stale grant were rejected. Scoped/short expiry also operated in diagnostic mode; real session expiry terminated sleep. |
| 6. Shell chaining and descendants | PASS for bounded cases | Chained commands retained restrictions; background delayed write did not occur; action cgroup disappeared. Cancellation returned exit 137 and left no marker or action cgroup. |
| 7. Filesystem edge cases | PASS for documented final boundary; earlier FAIL corrected | Symlink to outside dummy file was denied. A pre-existing hardlink initially exposed it; protected preparation now refuses shared filesystems, and cross-filesystem hardlink creation returns EXDEV. |
| 8. Network | PASS for offline boundary; permitted destination NOT APPLICABLE | TCP/UDP IPv4/IPv6 and Unix socket creation returned EPERM. Local listener received the unconfined fixture's dummy payload, then received nothing from its protected run; hook reported read EACCES and socket EPERM. No online allowlist exists. |
| 9. Restart, interruption, cancellation and cleanup | PASS for exercised cases | Graceful shutdown exited 0 after Python 3.13 socket cleanup fix. Daemon SIGKILL left cgroup populated 0 and no delayed write; restart removed stale cgroup and rejected old grant. |
| 10. Persistent posture and policy | PASS | Policy digest survived restart; guarded removed writes and required approval; approved guarded shell still received EROFS. Agent checkpoint relaxation was rejected. Backup/restore preserved state. |
| 11. Audit verification and tampering | PASS | 176-record Linux export verified against signed checkpoint. Deliberately edited disposable evidence was rejected. Live diagnostic corruption held readiness/admission and did not append to the damaged 22-record chain. |
| 12. Malformed IPC, unavailable service and concurrency | PASS for bounded cases | Duplicate JSON rejected; oversized real-socket request rejected; UID 1001 could not open admin socket. Second active execution returned execution_busy. Lost response never restored the grant. |
| 13. Actual AI-harness session | BLOCKED | No Claude/Gemini binary or certified guest agent session. Host Codex CLI 0.163.0 was inventoried, but no model session was claimed as integrated. Generic CLI/API execution was actually operated. |
| 14. Source artifact and clean installation | PASS for exercised archives/installations | Deterministic inventory excludes PDF/state/lab data; archive manifest/SBOM/checksums and installation verification are available. Source checksums are unsigned. These observations precede alpha publication. |

Native macOS containment, positive network exceptions, remote MCP containment,
renewable leases and complete kernel effect observation are **NOT APPLICABLE** to
the implemented profile. Linux x86_64 remains unverified; this lab ran ARM64. A dedicated 32 MiB ext4
volume also completed a basic write/chmod/read workflow. Exhaustive races,
aggregate disk exhaustion, real Git/Node/native builds and native performance
remain unverified. Bounded output, OOM, pids and per-file pressure were exercised
on the final installed build as recorded below.

## Defects found during actual use

1. A missing ELF interpreter in the policy caused echo to fail after controls
   initialized. Policy generation now inventories the loader; preparation rejects
   missing loader/contract permission before adoption. Echo then exited 0.
2. Python 3.13 automatically removed Unix sockets on server close; explicit cleanup
   raised ENOENT. Cleanup now tolerates that completed removal; shutdown exited 0.
3. Blanket ioctl denial prevented CPython's fopen close-on-exec path. Only FIOCLEX
   was admitted; Python scripts ran while general device ioctl denial remained.
4. Shared-filesystem hardlinks defeated apparent path separation. Dedicated,
   uniquely mounted workspace filesystems are now mandatory. The original failure
   is retained as evidence, not counted as a containment success.
5. Package metadata changes needed an OS fence beyond Landlock. Private read-only
   mounts now protect outside metadata; narrow write subtrees retain syscall denial.
6. Offline pip inspected `/etc/debian_version`; the generated policy now explicitly
   includes public OS metadata. A narrow administrative policy update let the same
   local package install complete without enabling networking or credential access.
7. Malformed audit exports previously raised an unhandled KeyError. Strict bounded
   verification now returns structured errors. Lost daemon responses and oversized
   messages also received clearer error handling.

## Commands and evidence

Commands were issued through installed prefixes `/opt/kechaa`, then side-by-side
revisions `/opt/kechaa-r2`, `-r3`, `-r4` while fixing defects. The source archive
was subsequently transferred with SHA-256 verification, extracted separately and
installed as `/opt/kechaa-final`; its actual echo, file workflow, resource-pressure
operations and ext4 operation passed. The current source
retains version 0.2.0a1; installed manifests identify the exact program bytes.
Final artifact checksums are generated alongside the source archive.

The essential actual operation sequence was:

```bash
/opt/kechaa-runtime/bin/python tools/install.py install --prefix /opt/kechaa --python /opt/kechaa-runtime/bin/python
/opt/kechaa/bin/kechaa doctor
/opt/kechaa/bin/kechaa policy init --root /work/project --output /etc/kechaa/policy.yaml
/opt/kechaa/bin/kechaa daemon --experimental-linux --state /var/lib/kechaa --sockets /run/kechaa --policy /etc/kechaa/policy.yaml --agent-group 1001 --duration 3000
kechaa run open --uid 1001 --session lab-session --contract /etc/kechaa/contract.json --confirm
runuser -u agent -- kechaa prepare --run RUN --session SESSION --cwd /work/project -- /usr/bin/echo hello
kechaa grant show --grant GRANT
kechaa grant approve --grant GRANT --action-digest ACTION_HASH --effects-digest EFFECT_HASH
runuser -u agent -- kechaa exec --run RUN --session SESSION --grant GRANT --cwd /work/project -- /usr/bin/echo hello
```

RUN/SESSION/GRANT/digest values came from actual responses, not literal placeholders.
The generic Local API requests used the same operations under authenticated UID
1001; administrative calls used root. Protocol details are in integrations.md.

The local package command inside the approved envelope was:

```bash
/usr/bin/python3.13 -m pip install --no-index --no-build-isolation --no-deps --no-cache-dir --disable-pip-version-check --no-compile -v --target /work/project/protected-site /work/project/package-fixture
```

Its small, understood PEP 517 backend built a pure Python wheel with VALUE=42. It
also attempted to read `/work/outside/dummy-credential` and send it to the guest's
127.0.0.1:18081 listener. The unconfined baseline succeeded at both; the protected
hook returned errno 13 and 1 while installation and import still succeeded. The
fixture is disposable lab material, not a bundled test suite.

The Linux signed checkpoint authenticates 176 events at head
`7ff0d898f17e313546e28cc5396f2aa61377eaca046920a334fb36de3bbc39cb`.
The stopped-state backup contained 177 events at head
`e1ddbaa83a4950bf60835e99d95d271650329799983d389805249c9127ecae81`.
Audit reports `observed_effects_complete:false`; it records authorization and
lifecycle, not a fictional complete kernel deny stream. File/listener observations
and returned errno values provide the additional experiment evidence.

Raw serial transcript, download manifests and VM overlay are in `.local/vm`.
Earlier diagnostic observations, backup/restore and corruption evidence are in
`.local/completion`. These locations are excluded from source artifacts. Private
backup keys remain private; only public-key audit verification is required to
check exported evidence.

## Measured performance and compatibility

These values came from software-emulated ARM64 and are **not native production
benchmarks**. Ten repeated echo prepare+execute operations all exited 0:

| Measurement | Observed value | Scope |
|---|---:|---|
| Grant preparation median | 83.427 ms | Includes IPC, policy, executable digests and audit |
| Prepare + execute median | 403.317 ms | Operator Local API calls; no interactive approval delay |
| Worker lifecycle median | 238.5 ms | Daemon-reported launch through cleanup |
| Protected Python script | 426 ms | One observed script producing build.txt |
| Offline package install | 4788 ms | One successful local fixture; no external dependency retrieval |
| Two-second session expiry | 1856 ms action lifetime | Remaining lifetime after preparation; sleep terminated with exit 124 |
| Recovered daemon RSS | 36784 KiB | ps sample after 5m03s, not peak RSS |
| Recovered daemon CPU | 3 seconds | ps user+system elapsed CPU, rounded display |
| SQLite / 176-event audit export allocated size | 224 / 156 KiB | du sample before stopped-state backup |
| macOS diagnostic startup | 129.273 ms | Non-executing console only |
| macOS diagnostic health median | 0.082 ms | 20 calls; not execution overhead |

An active action's actual cgroup showed memory.max=268435456,
memory.swap.max=0, pids.max=32 and cpu.max="100000 100000". These values establish
configuration, not independently measured pressure limits. The outside package
hook and read/write denials were observed directly. No aggregate false-positive
rate or universal escape rate is reported: the initial echo, Python and pip
compatibility failures were corrected and rerun, while unsupported workflows
remain outside this small baseline.

## Release conclusion

The Linux vertical slice now has real operational evidence and useful offline
package behavior. It remains experimental. Mandatory whole-agent integration,
immutable input semantics, broad platform/race validation, native macOS support,
trusted release attestation and enterprise evidence operations remain production release
blockers. See release.md for priority and required human/infrastructure actions.

## Final-build resource and packaging observations

The installed build used for the resource scenarios had program manifest
`f37d051c2389680c35fb97eb615ddbc747cdb26611b36b5e7fce432beaf7db31` in Linux
and `1be39552ff1ec5d53d1796efe3b9438eec477a0393343e1beb1c68d8cfba3d90` on
macOS. Prefix-specific entrypoints account for different installation manifests.
Both verified 18 program files. A subsequent client/hook hardening requires a
root server peer for protected execution; it does not change the kernel worker. Archive metadata/docs can be updated without
changing these program bytes; the distribution has its own generated checksum.

| Additional operation | Actual outcome |
|---|---|
| Final installed echo | Exit 0; controls ready; 260 ms lifecycle |
| 2801 bytes output with 1024-byte budget | output_limit, exit 124; tree cleaned up |
| Fixed 96 MiB allocation with 64 MiB memory budget | Kernel CONSTRAINT_MEMCG OOM; memory peak 67108864 bytes; oom_kill counter 3; supervisor/action terminated |
| At most eight attempted children with pids.max=6 | Four children admitted alongside supervision; next fork returned EAGAIN; pids limit counter incremented; all children reaped |
| Explicit 2048-byte file write with 1024-byte file budget | EFBIG, exit 1, resulting size 1024 bytes |
| 50-file legitimate workflow | Wrote/read 800 bytes, exit 0, 432 ms lifecycle |
| Dedicated 32 MiB ext4 volume | Protected write/chmod/read succeeded, exit 0, 428 ms lifecycle |
| Oversized request on final daemon | Structured message_size denial; readiness remained true |
| Restore and legacy upgrade | Guarded mode retained by restored Linux daemon; a disposable legacy session lacking a deadline closed safely on macOS restart |
| Clean removal of a fresh 0.2 installation | Manifest-listed executable removed; unrelated sentinel data preserved |

Kernel resource counters are sampled before cgroup removal and recorded with an
explicit completeness flag. They measure cgroup accounting, not full process RSS
or every filesystem/network effect. Shared/cache memory accounting follows Linux
cgroup semantics. No unbounded pressure or host resource experiment was performed.

Two successive source builds produced identical bytes. All archive members passed
the generated SHA-256 manifest; the SBOM had four declared Python dependencies
and explicitly incomplete native coverage. PDFs, state, private keys and VM files
were absent. The operated Linux ARM64/CPython 3.13 wheel set is additionally pinned
by `requirements-linux-arm64-cp313.lock`; this does not assert build reproducibility
of those external wheels. Authenticated production release and a production merge remain blocked.

The final pre-publication Linux export contains **233 records**, with signed head
`adcc9abfeedc1a329d583d425a504ae7c5a37c734e6d669bac4a5c90fb975142`.
It supersedes the earlier 176-record checkpoint for that later export, without
changing the historical observations above. Its signatures/checkpoint were also
verified using the installed macOS diagnostic CLI. The final installed manifests
were `dcf3a046a589efd0cc45efab0c467c98d9d1185611f43e97afabb0129942a4c5`
(Linux) and `df4ed2a15589fe6cbc7c06858a3d963380a1036a1058fa5df4f546433dd1e1c0`
(macOS); prefix-specific entrypoints make these hashes different. Release
documentation/ignore-list edits regenerate the archive checksum and do not
constitute a new kernel-enforcement validation.

## Audit-handoff hardening

On 2026-10-29, the audit handoff's ten issue categories were reviewed against
source and actual operation. This follow-up adds secure startup without Python
site hooks, ownership validation before application/dependency imports, an
optional immutable workspace contract, aggregate CPU accounting, confirmed
cgroup cleanup, exclusive live sessions per OS UID, bounded pending grants and
checkpoint-bound public evidence bundles. It does not close every release gate.
The issue-by-issue remaining work is retained in release.md.

The actual-use environments were macOS Darwin 27 ARM64 / CPython 3.14.8 and two
disposable Debian 13 VMs, Linux 6.12.113+deb13-arm64 and
6.12.113+deb13-amd64 / CPython 3.13.5. Both guests exposed Landlock ABI 6 and used
QEMU 11.1.3 TCG, one CPU, 768 MiB RAM, no NIC, no shared host folders and an
outer 3600-second runtime / 8 MiB serial-log bound. Guest recovery shells were
booted with `init=/bin/bash`; normal systemd boot was not part of this run.
The x86 guest needed QEMU's emulated SMM disabled to avoid a firmware stall;
this changed only the disposable VM model, not host security configuration.
All cgroups, mounts and action accounts were prepared inside the guests.
The profile was `linux-offline-experimental`, version 0.2.0a1 throughout.

| Operation actually performed | Result and evidence |
|---|---|
| Install using `python -IS tools/install.py install`, then `verify`, `version`, `doctor` | PASS on macOS and both guests. Manifests verified 20 program files. macOS explicitly reported no protected execution. |
| Benign `.pth` fixture writing a dummy marker | PASS on ARM64: ordinary `python -I` created the marker; installed KECHAA did not. Fixture and marker removed. |
| World-writable dependency module and application `.pyc` fixture | PASS on ARM64: entrypoint refused both before application operation; worked after fixture removal. |
| Second live session under UID 1001 | PASS: `identity_in_use`; a disposable legacy database's two conflicting sessions both closed on upgrade. Same-UID unconfined peers remain one trust domain. |
| Sixteen unused grants, seventeenth prepare, revoke then prepare | PASS on ARM64: cap refused the extra request; revocation permitted another prepare. A separate final macOS diagnostic console completed 260 prepare/revoke cycles without exhausting the global deadline slots; no commands executed. |
| Exact action, then reuse of its grant | PASS on both architectures. Replay classification was corrected during operation and repeated successfully with the updated build. |
| Immutable contract on writable dedicated tmpfs | PASS on both: `workspace_mutable`, with no command execution. |
| Remount dedicated input volume read-only and run approved script | PASS on ARM64: unconfined UID 1001 helper replacement returned EROFS; protected Python imported the unchanged helper and exited 0. x86 approved read-only echo also passed. |
| Two finite CPU-consuming children, one-second aggregate budget | PASS: tree terminated with `cpu_limit`, exit 124; ARM64 1,033,436 µs / x86_64 1,060,262 µs aggregate CPU. No action cgroups remained. Sampling overshoot is visible. |
| Kill daemon while shell and two 20-second sleeping descendants are active | PASS on ARM64: cgroup reported `populated 0` after daemon SIGKILL; restart reconciled the cgroup and became ready. No exhaustive race claim. |
| Tighten with `untrusted_repository`, stop and restart daemon | PASS on ARM64: guarded mode persisted. The event is a client report, not a kernel observation. |
| Protected x86 workspace write; outside dummy and symlink reads | PASS: legitimate write succeeded; both outside reads returned EACCES (13). |
| x86 TCP/UDP/IPv6/Unix socket creation | PASS: each returned EPERM (1). This run did not establish a positive network workflow or repeat the earlier listener/package scenario. |
| At most twelve 1 MiB files on an 8 MiB dedicated x86 tmpfs | PASS: ENOSPC (28); guest `df -B1` confirmed 8,388,608-byte capacity fully used. Only enumerated disposable files were removed afterward. The quota is an administrator-prepared volume limit, not a KECHAA disk-quota provisioner. |
| Bundle export and verification against signed checkpoint | PASS: ARM64 94-record bundle verified in the guest and using the installed macOS CLI. Removing the final record of an earlier 56-record bundle caused `audit_head` rejection. |
| Live export concurrent with ten bounded prepares | PASS on x86: bundle stayed at checkpoint sequence 36 while live sequence reached 45; exact-prefix verification passed. |
| Protected source installation with non-root-owned extracted source | PASS as a safety refusal. The operator re-extracted the trusted transfer as root-owned guest source; installation then succeeded. No ownership control was disabled. |
| Manifest-based removal | PASS on ARM64; stopped redundant installation removed. Fresh packaged macOS installation/removal also operated; unrelated sentinel preserved. |
| Real harness session, native macOS containment, full kernel effect collection | BLOCKED / NOT IMPLEMENTED. These remain production release blockers. |
| Approved online networking or renewable leases | NOT APPLICABLE to the offline profile; not implemented. |

Representative x86 lifecycle times were 576 ms for echo, 720 ms for the combined
filesystem/socket command, 766 ms for the bounded disk operation and 556 ms for
read-only echo. The two-child CPU workload ended after 1564 ms (ARM64 1474 ms).
These are individual software-emulated observations, not native overhead estimates,
statistical benchmarks or measured false-block percentages. No new test files,
suites, fuzzers or benchmark frameworks were written.

Reproduce the operator flow in a prepared disposable guest: install with `-IS`,
initialize/validate the YAML policy, start `daemon --experimental-linux` with the
separate UID/group and cgroup subtree, open the confirmed contract, then use
`prepare`, administrator `grant show`/`grant approve`, and `exec` with identical
argv/cwd/inputs. Set `input_integrity` and `write` in the contract as described
in operations.md. Change `profiles.development.limits.cpu_seconds` via reviewed
`policy import` for the bounded CPU exercise. Export with `audit bundle` and
verify with `audit verify --file ... --public-key ... --checkpoint ...`.

Raw serial commands, fixture actions, transfer digests, results and public
signed bundles are retained locally under `.local/audit-fixes/` and excluded
from source release artifacts. The ARM64 final bundle head is
`ce8a1dec7b4aed0a88bbcd0e2f52e08c0ee5a6f7b9cb2d0e981c7ad90c710a7a` (94 records).
Its installed program manifest was
`0c32a630a2aa42bfc8eb46ce3f65f3f04bc54e17e8f3fbb766a3b276b943c3d7`.
A subsequent preflight message change removes the obsolete ARM64-only wording;
it changes no enforcement behavior. The rebuilt source archive has its own
checksum. Historical observations above remain historical, rather than claims
that every older scenario was repeated for this commit.

The x86 final public bundle contains 45 records with signed head
`658ef12ca9cfe83cc78f46c6249e2b43a5252ab296142f7c0546489cd38a057f`;
its signatures/checkpoint also verified using the installed macOS CLI. Both VMs
were stopped after daemon shutdown, confirmed empty action cgroups and guest sync.
The source archive contains 43 intended members; consecutive builds matched
byte-for-byte and all internal SHA-256 manifest entries verified. Installation
from the extracted archive, policy validation, manifest verification and removal
passed on macOS, with an unrelated sentinel preserved. PDF, lab data, private
state and keys were excluded. No release signature is claimed.
