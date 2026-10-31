# Security model and trust boundaries

This document defines the implementation boundary. Executed scenarios and their
limits are in [completion.md](completion.md). Linux ARM64 operation was performed
in a disposable VM. Native macOS execution is disabled; x86_64 kernel operation
and exhaustive race coverage remain unverified.

## Authority and trusted components

The kernel, administrator, root-owned interpreter/dependencies, installed source,
daemon, state and signing key are trusted. Root/kernel compromise is out of scope.
The root daemon serves separate Unix sockets: an explicitly configured group can
access the agent socket; the administrator socket is mode 0600. Linux SO_PEERCRED
supplies the caller UID. Administrative operations require both the administrator
socket and daemon-owner UID. An agent-supplied approval flag cannot substitute.
Same-UID session strings provide binding context, not hostile process identity.

Diagnostic mode executes no actions and does not isolate its own OS user. The
Linux launcher is daemon-started in a fresh isolated Python interpreter. The
agent cannot opt out of mandatory controls or request arbitrary privileged
commands. Source/interpreter/administrative path ancestors are checked for root
ownership and non-writability. These checks occur after interpreter startup and
do not constitute complete dependency/import-chain attestation.

## Approval encoding and integrity

Grants bind exact ordered argv, canonical cwd and explicit input paths, cwd
identity, UID/run/session/revision, policy version, active profile, effect digest,
identified executable/artifact digests, epoch and issuance/expiry. Dedicated
workspace filesystem identities and metadata restrictions are in the effect
binding. Approved executable files and ancestors must be root-owned and not
writable by other users. ELF interpreters are explicit approved executable inputs.
The primary executable is opened by descriptor and must be ELF; scripts run
through an explicitly configured interpreter.

SHA-256 binds canonical documents. Ed25519 signs domain-separated messages:
`ASCII("KECHAA-GRANT-1") || NUL || KECHAA-CJSON-1(document)`. Canonical JSON uses
sorted string keys, ASCII escapes, no whitespace/floats/surrogates, and integers
within ±(2^53−1). Set-like collections are sorted; argv is ordered; 64-bit inode
and timestamp values are decimal strings. This constrained encoding is not
claimed to be RFC 8785. Cryptography uses the maintained cryptography library.

Consumption is a conditional SQLite update inside BEGIN IMMEDIATE. Requests are
reidentified before adoption, and the worker rechecks cwd, entrypoint and explicit
artifacts before execution. Grant expiry is bounded by policy, scoped permission
and session expiry, with monotonic checks in the running daemon. Restart revokes
unused/adopted/running authority. A lost response never refunds a consumed grant.

These checks do **not** freeze scripts, mapped libraries or all transitive inputs.
An interpreter can evaluate arbitrary program text inside its capability envelope.
Unconfined processes sharing the action UID can mutate workspace data. Approval
of an effect envelope is not proof that its allowed effects are benign.

## Linux containment

The worker joins a dedicated root-owned cgroup, establishes PID/network/mount/IPC/
UTS namespaces, makes mount propagation private, and forks the action as PID 1.
The private mount namespace becomes recursively read-only via mount_setattr.
Only approved workspace volumes become writable. Whole-volume write envelopes
can perform normal metadata operations; narrow write subtrees retain seccomp
metadata denials because Landlock does not cover every metadata mutation.

Every confirmed workspace root must be the sole mount of a dedicated ext4 or
tmpfs filesystem, with filesystem root `/`, no bind aliases and no nested mounts.
This was added after an actual pre-existing hardlink exposed an outside dummy
file through a shared workspace. Separate filesystems prevent such cross-root
hardlinks; runtime mount manipulation is denied. Mount administration remains
trusted. Actual operation used a 64 MiB tmpfs and a basic workflow on a dedicated 32 MiB ext4 volume.

After namespace/mount setup, the worker drops supplementary groups and all saved
UID/GID authority, applies no_new_privs, Landlock ABI 6 and seccomp, then performs
descriptor-based execution. Rules are pinned through no-follow component walks.
All setup descriptors close on exec. Stdin is /dev/null; stdout/stderr are bounded
daemon pipes; no client sockets/files are inherited.

Landlock restricts content reads, writes, creation, removal, renames, truncation
and executable-file admission. Seccomp rejects alternate syscall ABIs, ptrace,
process memory access, namespace/mount creation, BPF, io_uring, kernel/module/key
operations, socket/socketpair creation and general ioctls. FIOCLEX is allowed only
to set close-on-exec. Narrow write subtrees also deny chmod/chown/xattr/time changes.
The filter is a syscall reduction profile, not proof against every future API.

The empty network namespace and socket-creation denial establish the offline
boundary for TCP, UDP, IPv4/IPv6 and Unix sockets. There is no destination allowlist,
DNS proxy or permitted online mode. Stdout/stderr remain intentional output
channels; reading an allowed file may disclose it through these channels.

PID namespace teardown, reapplied parent-death signals and a pidfd race check
cover supervisor loss. cgroup.kill supplies independent termination and restart
reconciliation. CPU/memory/pids/output/wall/per-file limits bound actions. Disk
capacity must also be bounded by the prepared volume; file-size limits alone do
not limit cumulative disk use. Leases and live permission widening are unavailable.

## Threat coverage and limits

| Attacker-controlled input / property | Mechanism and failure response | Evidence and remaining boundary |
|---|---|---|
| Prompt injection, build hooks, shell expansion and chained commands | Approval binds full argv plus a bounded capability; descendants inherit OS restrictions | Local pip hook read/network denial and successful install observed; harmful approved writes remain possible |
| Changed command/cwd/session, stale or replayed grant | Digests, identities, policy/revision/epoch/UID and atomic single use | Real socket rejection and exact-action execution operated |
| Symlinks, hardlinks, mount aliases | No-follow artifact walks, Landlock, dedicated filesystem/mount prerequisite, mount syscall denial | Symlink denied; initial hardlink failure drove mandatory dedicated-volume restriction; adversarial races not exhaustively verified |
| Mutable executable or input | Trusted executable ancestors, digests and final descriptor checks | Modified explicit input rejected; full immutable snapshots absent |
| Injected environment | Fixed policy environment; no inherited loader/startup variables | Generated envelopes and actual launches operated; arbitrary inherited environment unavailable |
| Credentials, daemon configuration and outside metadata | Sensitive overlap rejection, Landlock and read-only mounts | Dummy content and outside chmod denied; secrets intentionally placed inside approved roots are not discovered |
| Network/exfiltration/IPC/inherited sockets | Empty net namespace, seccomp socket denial, scoped Landlock, no inherited client FDs | TCP/UDP/IPv4/IPv6/Unix creation returned EPERM; local package listener observed no protected delivery |
| Detached children and retained authority | PID namespace, supervisor death handling, cgroup kill, grant/session deadline | Parent exit, bounded cancellation, session expiry and daemon SIGKILL operated |
| Signal/trace/escalate | UID drop, no_new_privs, namespace visibility, Landlock scope and syscall limits | Controls installed; exhaustive signal/trace/capability scenarios not performed |
| Agent self-approval or policy relaxation | Separate administrative socket/UID, strict parser, transactional policy state | Agent approval/checkpoint denied, admin socket DAC denied, malformed activation preserved active version |
| Context compaction, restart or stale history | Persistent bounded contract, mode/labels/revision; restart invalidation | Guarded mode, policy and audit retained; no inference of malicious intent |
| Hook disablement or unwrapped/remote MCP tool | Supported agents must enter through `kechaa agent launch`; MCP/web/external effects fail closed unless an explicit offline effect contract is authorized | Direct host processes outside the launcher and full MCP protocol proxying remain outside the certified boundary until Linux LC tests pass |
| Malformed IPC/concurrency/resource pressure | Strict bounded JSON, deadlines/backpressure, serialized startup handoff and per-grant active workers | Duplicate/oversized requests exercised; Linux concurrent-agent isolation still requires disposable VM certification |
| Daemon/audit failure | No fallback, durable state, cleanup, startup verification | Crash/recovery and corrupted disposable evidence operated; complete machine failure and power-loss durability not verified |
| Supply-chain or release substitution | Pinned dependencies, explicit packaging inventory, checksums | Wheel checksums operated; native provenance and authenticated public releases remain blockers |

## Audit, posture and privacy

Each bounded audit record has sequence, time, actor, previous hash and an Ed25519
signature in the KECHAA-AUDIT-1 domain. Signed checkpoints authenticate selected
heads. Independently retained public keys/checkpoints are required to detect
truncation or whole-state rollback. A local root/key holder can replace the entire
history; the log is not immutable. Remote forwarding is not implemented.

State changes and associated records share transactions. Corrupt live evidence
holds readiness/admission and is not appended to after detected corruption. Full
storage holds execution rather than silently dropping records. Offline backup
includes private keys and a signed manifest; restore uses a pinned public key and
expected head, creates a new directory, and preserves posture while revoking old
grants. Retention/rotation and key rotation are administrative procedures.

No kernel effect collector is shipped. controls_ready records initialization,
not a list of attempted/denied paths. Audit explicitly says
observed_effects_complete:false. Action results plus independently inspected lab
files/listeners support the documented experiments; a nonzero exit alone does
not establish a specific denial. Audit does not contain stdout/stderr, file
contents or raw argv, but durable grant state stores argv/context. Keep secrets
out of arguments and administrative reason text.

Labels reported by adapters can only tighten posture. They are marked client_report,
not trusted kernel observations: +20 for effective untrusted labels, +60 for
credential exposure, guarded removes writes and asks, score 60 locks down.
Only administration can relax mode; labels/history remain. This is deterministic
policy tightening, not observed-effect goal drift or malicious-intent detection.

## Interface provenance

Independent implementation uses documented
[Landlock](https://docs.kernel.org/userspace-api/landlock.html),
[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html),
[seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html),
[mount_setattr](https://man7.org/linux/man-pages/man2/mount_setattr.2.html),
[PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html) and
[PR_SET_PDEATHSIG](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).
Dependency provenance is documented separately. No competitor implementation
was copied or used as a template.
