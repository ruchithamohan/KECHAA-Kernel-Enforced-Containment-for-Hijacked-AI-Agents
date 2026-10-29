# Installation and operation

This alpha is for evaluation. Native macOS execution is unavailable; Linux
execution is experimental and requires a disposable VM. No install command starts
a service, changes PATH, alters login files or configures host kernel features.

## Requirements and offline installation

The control plane requires CPython 3.11+ and the exact versions in
`requirements.txt`. The development environment used Python 3.14.8, PyYAML 6.0.3,
cryptography 48.0.1, cffi 2.0.0 and pycparser 3.0 already present locally.

Provision a reviewed Python environment through your usual package controls. In
an approved connected setup, a typical preparation is:

```bash
python3 -m venv ./runtime
./runtime/bin/python -m pip install -r requirements.txt
./runtime/bin/python -IS tools/install.py install --prefix ./installation --python /absolute/path/runtime/bin/python
./installation/bin/kechaa version
./installation/bin/kechaa preflight
```

The macOS environment reused existing packages. The Debian guest was provisioned
from an approved offline wheelhouse, with checksums verified on host and guest. For offline provisioning, use an administrator-reviewed wheelhouse with
`pip --no-index --find-links`. Wheel hashes/build provenance have not been
independently verified for an enterprise distribution. Do not grant Linux file
capabilities to a general-purpose Python interpreter.

The installer copies only KECHAA source and creates an entry point with a fixed
interpreter and `-IS` Python startup. `.pth`, `sitecustomize`, user sites and
inherited Python paths cannot run before authorization. Use this entrypoint;
a conventional pip-generated console script lacks these startup flags and is
refused. Keep a minimal dedicated runtime with direct, pinned wheel installations;
`.pth` indirection is intentionally unsupported. Root startup checks every
application/dependency entry, including cached bytecode, for ownership, type and
write permissions before importing third-party code. The interpreter, standard
library and administrator remain trusted. These checks are not build attestation.
It records a manifest of installed
file hashes, refuses nonempty prefixes and checks the resulting executable's
version. It checks all four pinned dependency versions and Python's minimum
version before copying files. Prefix components must be real directories; use
canonical paths such as `/private/tmp` instead of a symlink such as `/tmp` on macOS.
Dependencies stay in the chosen environment. The source-checkout entry
point is `python -IS bin/kechaa`; a root daemon must use a root-owned installation.

## First run

Create a dedicated disposable project directory and its `.home` and `.tmp`
subdirectories. Generate and review the YAML policy and a contract such as
`examples/contract.json`, adjusted to the exact target executable paths.

Start the portable foreground diagnostic daemon only where Unix sockets are
permitted:

```bash
kechaa daemon --diagnostic --state ./state --sockets ./sockets --policy policy.yaml --duration 300
kechaa --socket ./sockets/agent.sock status
```

The state and socket parents must already exist. State is mode 0700 and contains
the SQLite database, mode-0600 private key, public key and lock. A diagnostic daemon
does not isolate its own user. If socket binding is denied, do not alter host
security settings; use the explicitly non-executing console:

```bash
kechaa diagnostic --state ./console-state --policy policy.yaml --admin --duration 300
```

See [integrations.md](integrations.md) for JSON requests and the approval workflow.
The first startup imports the initial policy. Later starts use the persisted
active version; `--policy` does not overwrite it. Use `policy import` to change it.

## Experimental Linux preparation

An administrator must provide, inside the disposable Linux VM:

- Linux x86_64 or aarch64, Landlock enabled with ABI ≥6, seccomp filters, PID/network/
  IPC/mount/UTS namespaces, mount_setattr, pidfds and cgroup v2 with cgroup.kill.
- A dedicated root-owned cgroup subtree with cpu, memory and pids already enabled
  for children. KECHAA does not enable these controllers or edit system services.
- A distinct unprivileged action account and non-root agent socket group.
- A fully root-owned application, interpreter, dependency installation and policy;
  state and sockets outside writable project roots.
- A dedicated quota-bounded ext4 or tmpfs filesystem mounted at each contract
  root, with no alternate mounts, bind aliases or nested mounts, containing only
  synthetic source, dummy data and local package fixtures. No host mounts, credentials or external network.

`kechaa preflight --cgroup-root /sys/fs/cgroup/kechaa` reports read-only prerequisites.
Passing it does not prove seccomp, namespace or Landlock operation; every launch
checks those controls again. In the prepared VM, the explicit experimental command
is conceptually:

```bash
kechaa daemon --experimental-linux \
  --state /var/lib/kechaa --sockets /run/kechaa \
  --policy /etc/kechaa/policy.yaml --agent-group 1001 \
  --cgroup-root /sys/fs/cgroup/kechaa
```

Run this through the VM administrator's approved privilege mechanism. No host
sudo command, service installation, kernel boot changes or cgroup preparation
was performed. Guest-only preparation and actual use are recorded in completion.md. Native macOS Seatbelt execution is not used
as an unverified substitute for this profile.

## Shutdown, restart and recovery

EOF ends the diagnostic console. SIGINT/SIGTERM stops a foreground daemon. The
`--duration` bound provides another stop condition. For a VM demonstration, keep
the VM manager's power-off control available as the immediate outer shutdown.

On supported Linux execution, shutdown kills active action cgroups. On restart,
only exact `action-<48 hex digits>` names inside the configured dedicated subtree
are reconciled. Unknown cgroups are never recursively removed. Cleanup failure
holds execution. Unused/stale grants are revoked; runs, labels, scores and policy
versions persist. No lease is resumed or renewed.

Shutdown stops request admission and cancels outstanding handlers. Cleanup is
shielded from repeated cancellation, attempts cgroup and supervisor termination
independently, and bounds each supervisor wait to five seconds. It also confirms `cgroup.events` reports
`populated 0` within five seconds before removing an action boundary. Incomplete cleanup
holds readiness and is recorded in the action result; a failed administrative
termination is reported as `cleanup_incomplete`. Bounded cancellation, session expiry, daemon crash and restart were exercised
on ARM64; exhaustive race and distribution coverage remains unverified. The actual diagnostic socket-initialization failure path was
operated without bypassing the sandbox's denial.

Audit corruption, a missing/mismatched signing key or unsupported state schema
fails startup. Do not delete the state database or generate a replacement key to
make an error disappear. Preserve it for investigation and restore a consistent,
verified backup only after administrative review.

At audit/storage capacity, execution stops instead of silently dropping records.
Export without starting the daemon, including when startup cannot append events:

```bash
kechaa audit export --state ./state --output incident.jsonl
kechaa audit verify --file incident.jsonl --public-key ./state/audit.pub --expected-head INDEPENDENT_HEAD
```

An offline export is read-only and uses one SQLite snapshot. Verification without
`--expected-head` verifies the included chain but cannot establish its completeness.
Exported audit files default to mode 0600. Keep the public key and checkpoints in
an independently administered evidence store. Remote forwarding is operator-managed; use the public evidence bundle below.

## Enterprise administration and data handling

The daemon is local-only; no network API, telemetry, remote KMS or cloud service
is required. Trusted administrators control policy and exception/checkpoint
decisions. The current role model has one OS administrator role; separate policy
author/approver RBAC and authenticated remote policy distribution are not shipped.

Policies activate transactionally and older versions remain in SQLite. Approval
state contains exact argv/context; audit records contain hashes, approved paths,
labels, metadata and administrative reason strings. File contents and action
stdout/stderr are not written to the audit log. Do not include credentials in
arguments or reason fields. Action output is returned only to the requesting client.

There is no automatic rotation/deletion policy. The bounded store holds execution
when full. Archive complete state administratively before establishing a new
empty state directory and reconfirming contracts; maintain the old public key
and final head as a separate evidence segment. This is manual archival, not an
implemented seamless rotation or migration feature.

## Upgrades and removal

Install a new version into a new empty prefix, check `version`, validate the policy,
and preserve a consistent state/key/public-key backup while the old daemon is
stopped. Unknown schema versions are rejected. No automatic schema migration is
provided for this initial schema. Do not run old and new daemons on the same state
or socket directory. Restart invalidates old grants.

Remove only files whose hashes still match the installation manifest:

```bash
python -IS tools/install.py uninstall --prefix ./installation
```

Removal never deletes state, policies, project files, dependencies or hook settings.
Changed installed files cause refusal for manual review. Nonempty directories
(including Python caches) are preserved. Remove the exact hook entry you installed
separately. No system service was installed by this tool, so no service removal is
silently attempted.

The remover bounds and validates the complete manifest before its first deletion,
opens installation directories without following symlinks, and verifies file
hashes and identities. It requires an owner-controlled prefix; stop the program
and any updater first. Concurrent mutation by the installation owner is outside
the removal trust model. A changed file or symlink ancestor causes refusal.
Removal is conservative, not a transaction that can roll back an interrupted
series of unlinks; preserve the manifest and review any partial I/O failure.

## Troubleshooting

| Result | Meaning | Narrow next step |
|---|---|---|
| `execution_unavailable` | Compatibility block; no verified backend in this mode | Use diagnostics or provision a reviewed disposable Linux environment |
| `policy_denied` / `contract_scope` | Request exceeds policy or confirmed task | Inspect `policy explain` and contract; seek an explicit scoped amendment |
| `grant_replay` | Pending, consumed or revoked grant | Inspect the state; never retry it as fresh authorization |
| `grant_expired` / `grant_stale` | Expiry, restart, policy or posture change | Request and review a new grant |
| `inputs_changed` | Input/executable/directory identity changed | Inspect the change and request fresh approval |
| `policy_sensitive` / `sensitive_overlap` | An allow subtree includes protected paths | Narrow the root; don't remove protection to bypass the error |
| `kernel_control` / `worker_initialization_failed` | Mandatory sandbox setup failed | Stop execution and inspect the disposable VM prerequisites |
| `audit_full`, `audit_chain`, `daemon_unhealthy` | Evidence/cleanup prerequisite failed | Preserve state; export and reconcile administratively |

The tool never turns a block into a broad allow rule. Policy errors, unsupported
workflows and real policy violations must be reported separately.

## Bounded contracts, rollback and signed checkpoints

New contracts accept `lifetime_seconds` (1–86400, default 3600). Grants expire no
later than the session. Expiry closes the session and terminates active actions.
A restart preserves its wall-clock deadline and never refreshes its lifetime.
Legacy runs without a lifetime are closed on upgrade, preserving their data and
recording `legacy_run_closed`; confirm a new bounded contract with a new session
identifier. Clock administration is trusted.

```bash
kechaa policy history
kechaa policy import proposed.yaml --expected-version REVIEWED_ACTIVE_DIGEST
kechaa policy rollback --version HISTORICAL_DIGEST --expected-version CURRENT_DIGEST --reason 'Reviewed rollback of policy change'
kechaa audit checkpoint --output checkpoint.json
kechaa audit export --output evidence.jsonl
kechaa audit verify --file evidence.jsonl --public-key /trusted/audit.pub --checkpoint checkpoint.json
```

A checkpoint authenticates a particular prefix/head. Live export now obtains its
own checkpoint first and verifies exactly that prefix while writing; it returns
the matching checkpoint. Prefer `audit bundle` to retain the matching files
together. A separately captured older checkpoint may not match a later export;
a head mismatch must never be ignored. Copy public keys
and checkpoints to independently controlled storage. Local signatures do not
prevent an administrator/key holder from rewriting history or replacing all state.

## Offline backup and restore

Stop the daemon and finish action cleanup before backing up. The command acquires
the same state lock, checks the audit and creates a signed database snapshot in a
new private directory. **Backups contain the private signing key.** Protect them
with administrator-only permissions and your existing encrypted backup system.

```bash
kechaa state backup --state /var/lib/kechaa --output /private-backups/kechaa-snapshot
kechaa state verify --backup /private-backups/kechaa-snapshot --public-key /trusted/audit.pub --expected-head RETAINED_HEAD
kechaa state restore --backup /private-backups/kechaa-snapshot --public-key /trusted/audit.pub --expected-head RETAINED_HEAD --output /var/lib/kechaa-restored --reason 'Reviewed recovery from stopped snapshot'
```

Restoration never overwrites an existing directory or starts a service. An
incomplete restore marker blocks startup. The signed receipt creates an audit
`state_restored` event. Existing grants are invalidated on restart and posture
is retained. Preserve a failed destination for review; do not remove the marker
just to make it start. Whole-state rollback detection still needs the independent
expected head. Automatic in-place schema migrations are not shipped.

Key rotation is an administrative transition to a new state/evidence segment:
stop admission, terminate actions, export and independently retain the final
checkpoint/public key, archive the old state securely, then initialize a new
private state and reconfirm contracts. There is no seamless in-place key rotation.
Do not overwrite a live signing key or reuse a release-signing key for audit.

## Artifact verification and signing

```bash
python tools/package.py
(cd dist && sha256sum -c kechaa-0.2.0a1-source.tar.gz.sha256)
# From the extracted source directory:
sha256sum -c MANIFEST.sha256
```

Run the checksum check from the directory containing the named archive (for
example, `cd dist` first). On macOS use `shasum -a 256 -c`. Build inputs are an
explicit inventory with fixed archive metadata. The SBOM intentionally declares
incomplete native/transitive coverage. Source checksums detect changed bytes;
they do not authenticate a release publisher or verify the runtime dependencies.

Before an authenticated production release, maintainers must provision a separate reviewed signing key
and distribute its fingerprint through an independent channel. One conventional
manual procedure is `gpg --armor --detach-sign ARCHIVE`, followed by
`gpg --verify ARCHIVE.asc ARCHIVE` using the independently pinned public key.
These signing commands have not been run; this release preparation is unsigned.
Never add a release key, daemon key, PDF, lab image or local state to Git.

## Linux filesystem and offline package compatibility

The launcher makes its private mount namespace recursively read-only and reopens
only approved workspace volumes. This never changes the daemon's or host's mount
namespace. If write rules cover whole workspace roots, ordinary metadata changes
are confined by these mounts. If a policy grants only narrower write subtrees,
metadata mutation syscalls remain denied; content writes still follow Landlock.
General device ioctls remain denied; FIOCLEX may set close-on-exec.

`policy init` inventories the ELF loader and public OS release files explicitly.
An existing policy missing a loader is rejected with an actionable message;
KECHAA does not silently add an executable during launch. Contracts must include
the loader too. Offline pip 26.0.1 PEP 517 installation was exercised with
`--no-index --no-build-isolation --no-deps --no-cache-dir --disable-pip-version-check`
and an approved workspace target. That one fixture does not establish support
for arbitrary packages, native builds, network installs, Node.js or Git tooling.

For the operated Linux ARM64 / CPython 3.13 wheel set, an offline, hash-checked
provisioning command is:

```bash
python -m pip install --no-index --find-links /approved/wheelhouse --require-hashes -r requirements-linux-arm64-cp313.lock
```

For the separately operated x86_64 wheel set, substitute
`requirements-linux-x86_64-cp313.lock`. Each lock is platform/interpreter-specific. It is generated from the exact public
wheel hashes verified during VM provisioning; other platforms need a separately
reviewed wheel inventory. No dependency or VM binary is bundled in source releases.

## Audit-hardening upgrade and operations

Only one live session per OS UID is admitted. Close it through the authenticated
agent connection before confirming a replacement, or use another OS account.
An upgrade closes every conflicting legacy live session and records
`identity_conflict_closed`; an administrator must reconfirm the intended contract.
This avoids treating session strings as separate hostile identities. It does not
isolate unconfined processes that already share the account. At most 16 unused
grants per run and 256 global live grants are admitted; revocation releases
admission capacity. The daemon still executes one action at a time.

For read-only analysis, set `"input_integrity":"immutable-workspace"` and
`"write":false` in the contract. An administrator must prepare every dedicated
workspace filesystem read-only at both mount and superblock levels before
approval. A read-only bind mount over writable storage is insufficient. KECHAA
rechecks this metadata at adoption and launch; it does not create snapshots or
freeze administrator-owned runtime files. Ordinary `recheck` contracts preserve
existing writable workflows and their documented mutation limitation.

The CPU budget includes all action descendants using cgroup `cpu.stat`, sampled
every 50 ms, plus per-process RLIMIT_CPU. Sampling and daemon scheduling permit
overshoot; this is not an exact CPU cutoff. Provision a size/quota-bounded volume
for aggregate disk use; per-file size limits do not supply a disk quota.

```bash
kechaa --admin-socket /run/kechaa/admin.sock audit bundle --output ./evidence-new
kechaa audit verify --file ./evidence-new/audit.jsonl --public-key /trusted/audit.pub --checkpoint ./evidence-new/checkpoint.json
```

The bundle contains the verified log prefix, public key, signed checkpoint and
`bundle.json` completeness receipt. It never contains the private signing key.
The receipt is written last; preserve failed/incomplete exports for investigation.
Use your existing approved evidence system to copy completed bundles to separately
administered storage. Verify against an independently retained public key, not
just a key delivered in the same bundle. This is not automatic forwarding,
retention, rotation or independent anchoring.
