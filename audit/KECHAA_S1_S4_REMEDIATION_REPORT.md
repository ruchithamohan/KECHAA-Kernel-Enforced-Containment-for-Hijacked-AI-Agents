# KECHAA S1–S4 security remediation and verification

## Result and evidence boundary

The four reported defects reproduced against commit
`ebe2f2d3790789b44844b980caf973977fe6cfef` before production edits. Their original
control-plane attacks no longer succeed against this working tree. S3 still
needs Linux filesystem enforcement validation before complete acceptance.
Linux live-worker/cgroup termination and restart reconciliation were not rerun
for these changes either. This report does not certify Linux containment.

The complete existing suite originally passed 22 tests despite all four defects.
The final suite discovered 52 tests: **50 passed, 2 skipped, no failures**.
All 22 existing tests remain; two now call the genuine in-process event producer
instead of impersonating one over the public Engine API. Thirty tests were added.
No README, GitHub metadata, version, branch, commit, push or PR was changed/created.

Environment: macOS/Darwin 27.0.0, ARM64, CPython 3.14.8, SQLite 3.54.1; exact
pinned requirements installed in the ignored local `.venv`. Each Unix fixture
starts the actual diagnostic daemon as a separate process with real Unix sockets,
OS peer credentials, SQLite state and Ed25519 keys. Diagnostic mode executes no
protected actions. Tests use synthetic files and disposable state.

Evidence retained alongside this report:

- [Original socket reproduction](security-phase1-evidence/original-reproduction.json).
- [Original reproduction script](security-phase1-evidence/reproduce_original.py), intended for the original implementation; S3's unsafe startup policy is now rejected.
- [Baseline test output](security-phase1-evidence/baseline-suite.txt).
- [Final test output](security-phase1-evidence/final-suite.txt).
- [Environment, counts and tested source hashes](security-phase1-evidence/manifest.json).
- [Linux preflight result](security-phase1-evidence/linux-preflight.json): exit 3, Linux required.

These are observations from this pass. Earlier repository Linux reports remain
historical evidence for earlier code, not validation of this working tree.

## Finding-by-finding disposition

Status applies to the defect and stated verification boundary, not every security
property of the project. The second attack pass used raw Unix requests and public
results rather than Engine/Store helpers as its oracle. It was performed from an
attacker perspective by the same reviewer; it is not third-party certification.

| Finding | Original reproduction | Fix | Regression test | Independent retest | Status |
|---|---|---|---|---|---|
| S1 | Three denials; legitimate action initially denied; 20 benign tool requests restored preparation, including after restart | Durable denial counter; atomic threshold/posture/revocation/audit; authenticated reset; conservative legacy upgrade | `test_remediation_unix`: flooding, spaced denials, concurrent requests, pending revocation, crash/restart; `test_remediation_invariants`: rollback, upgrade, cleanup routing | Raw-socket interleaved noise, 24 concurrent prepares, SIGKILL/restart and attempted agent recovery all failed to restore authorization; admin review restored it | FIXED AND VERIFIED |
| S2 | `effects.read=null` returned `internal_failure`; readiness became false; subsequent valid request got `daemon_unhealthy` | Validate type/size before iteration; normalize/reject paths; bound operation before including it in denial audit | Actual sockets test malformed effects, encoding, structure, oversized declarations/messages/operation names, concurrent valid requests | Alternate values for both read/write rejected; daemon stayed ready and valid requests succeeded; restart also succeeded | FIXED AND VERIFIED |
| S3 | Policy roots `work/a`, `work/b` with read `work`; contract `a`; prepared envelope retained `work` and covered sibling | Reject ambiguous runtime ancestors and nested roots; repeat project/contract intersection at preparation; retain disjoint dependencies | Actual API policy-import rejection and narrowed envelope; exact/child/sibling tests; actual macOS no-follow descriptor walks; two Linux follow-up tests skipped | Parent aliases rejected; explicitly declaring parent as a project root narrowed reads to `a` plus runtime dependencies before/after restart; sibling cwd rejected | PARTIALLY FIXED |
| S4 | Agent API accepted `kernel`, `supervisor`, `tool_gateway`; `admin` already rejected | Endpoint/peer identity supplies role; internal producer API not exposed over Unix; producer included in signals/history/signed audit | Actual agent/admin sockets, persistence/export verification; direct internal producer integration; audit tampering rejected | Source variants, injected UID/admin/producer fields rejected; attacker reason text persisted only as client report | FIXED AND VERIFIED |

S3's implementation defect is corrected and its policy/envelope boundary is
verified. The partial status reflects missing execution of the requested Linux
filesystem/mount acceptance cases, not a known surviving ancestor in a prepared
envelope. S1's verified result is durable authorization lockdown, including real
daemon concurrency/restart. Its Linux process-tree cleanup guarantee remains
subject to the separate unexecuted kernel tests below.

## S1: durable denial-state transition

### Reproduction and root cause

1. Open an administrator-confirmed run with an allowed echo action and a policy
   that denies a cat action referring to `/etc/shadow`.
2. Submit that denied action three times.
3. Submit the normally permitted echo; it is denied by history-based evaluation.
4. Submit 20 allowed empty `FileRead` effect checks.
5. Echo can now obtain a grant. Restart the daemon; echo still obtains a grant.

The old decision derived a denial count from the last 20 entries of a bounded
history table. It changed a local decision mode without persisting lockdown.
Benign events displaced the evidence, and restart had no durable restriction
to restore. The preexisting repeated-denial test stopped before flooding.

### Implementation and invariants

New runs carry `denial_state_version=1` and a counter capped at 3. Each completed
policy/history denial increments it. The third denial commits counter, mode,
revision, pending/issued/adopted grant revocation, history and signed audit in the
same `BEGIN IMMEDIATE` transaction. Already stronger posture is preserved.
The audit/history store an action digest rather than raw argv so a valid large
denied action cannot overflow the 32 KiB history record and undo the transition.

Daemon Engine calls execute synchronously on one event-loop thread and Store
holds an exclusive process lock. No request interleaves between the decision and
transaction. This is not an assertion that Engine supports arbitrary concurrent
Python threads. A committed `RunDenied` tells dispatch to await affected worker
cleanup before responding. Adopted grants are revoked explicitly; the existing
worker startup checks also reject stale revisions. Running workers are terminated
through the existing lifecycle path, rather than relying on a database label.

The counter is independent of retained history. Lockdown rejects benign tool
checks too. `checkpoint` or `run_recover` on the administrative endpoint resets
the counter, retains evidence, revokes old authority and waits for active cleanup.
`run_recover` now refuses closed or expired original contracts. Lease renewal,
new session strings, history flooding and restart do not reset the counter.
Schema/binding/contract errors before policy evaluation are not counted; the
counter is not a general intrusion detector or every-error quota.

Open legacy runs lacking the new version start at lockdown with count 3 and an
audited migration. Old history could already have lost all denials, so absence
of records cannot safely justify normal mode. Unknown/null/boolean/future
versions fail startup instead of being silently interpreted as legacy state.

Verified attacks include 550 post-lock tool requests; 25 benign requests between
denials; concurrent mixed prepares; pending approval after threshold; consumed
and unused grant replay after restart; approximately 48 KiB denied argv; agent
attempts at both recovery APIs. Fault injection proves no partial counter,
revocation, history or audit update on an audit write error. Actual SQLite
integrity and signed-chain checks pass. Power-loss testing was not performed.

## S2: malformed declarations and admission health

### Reproduction and root cause

Send Local API v1 `tool_request` with valid run/session/tool and
`"effects":{"read":null}`. The old list comprehension iterated the value before
checking whether it was a list. Its `TypeError` reached the generic daemon
exception handler, intentionally marking all admission unhealthy.

During the second attack pass, an additional form reproduced the same outcome:
an invalid operation name containing 70,000 characters. The operation was assigned
to the audit context before validation; denial logging then exceeded the signed
event size limit. The new failing socket regression demonstrated readiness=false
before the follow-up fix. Invalid operation values now leave the audit operation
as the bounded `unparsed` marker until validation succeeds.

### Accepted schema and failure behavior

- Entire canonical operation-data object: at most 16 KiB, including run/session.
- Exact top-level fields: `run`, `session`, `tool`, `effects`.
- Tool name: string of 1–128 characters.
- Effects object accepts only `read`, `write`, `network`, `kind`.
- Omitted read/write means an empty array. Present values must be arrays, at most
  64 entries each, containing valid absolute path strings; null is invalid.
- Paths: at most 4096 UTF-8 bytes, no controls, DEL, surrogates, traversal
  components or globs. Repeated separators normalize to the local root.
- Omitted network means offline. Only string `offline` or `external` is accepted;
  external requests still receive a security denial.
- If kind is present, it must be `file_effect_contract` or `mcp_effect_contract`.
  Explicit null is invalid. Existing MCP effect-contract requirements remain.

Canonical-size validation runs before field access; array validation runs before
iteration. Schema/path errors return structured `invalid_request` errors without
internal exception details. No error grants authority. Existing global strict
JSON parsing, 256 KiB message bound, nesting/encoding restrictions, timeouts and
connection limits remain in place. Genuine audit/storage/cleanup failures still
hold admission; the fix does not turn internal errors into successful responses.

Socket tests cover null, strings, integers, booleans, nested objects/arrays,
floats, invalid Unicode/UTF-8, too many paths, long paths/declarations, malformed
paths, unknown fields, duplicate keys, wrong versions/types, excessive nesting,
missing newline and oversized messages. After malformed requests, health remains
ready and valid tool checks succeed; no grants are created. Concurrent malformed
and valid requests are exercised. Sustained audit-capacity exhaustion is a
remaining availability limit, not resolved by input validation.

## S3: project/runtime separation and narrowing

### Reproduction and root cause

Declare project roots `/work/a` and `/work/b`, profile read `/work`, and a contract
restricted to `/work/a`. The old code classified a read as project access only
when it was inside a declared root. `/work` was therefore misclassified as a
runtime read and survived unchanged. Directory allow rules cover descendants;
this retained authority included `/work/b`.

### Exact rule

| Relationship | Result |
|---|---|
| Policy roots overlap/nest | Reject policy; declare the parent once if it represents one project boundary |
| Read equals/is below a policy project root | Intersect with contract roots |
| Project read equals contract root | Retain exact root |
| Project read is a parent of contract root | Narrow to contract root |
| Project read is a child of contract root | Retain only that child |
| Project read is a disjoint sibling of contract roots | Remove |
| Read is a strict ancestor of any policy project root | Reject as ambiguous runtime/project authority |
| Read is disjoint from every policy project root | Retain as separately approved runtime dependency |
| Write outside policy project roots | Existing policy validation rejects it |
| Explicit executable file | Separate policy/contract executable intersection; backend also grants file read required for execution |

`narrow_project_paths` implements this distinction during both validation and
preparation. Inheritance cannot bypass it. Policy imports validate before replacing
the active version; rejected ancestors preserve the previous valid policy.
Trusted system libraries are retained when explicitly approved and disjoint.
No wildcard, new policy role or blanket deletion of runtime dependencies was added.

Path strings normalize before comparison; no-follow descriptor walks already
reject symlinks for input identification and kernel rules. The new tests operate
real file and directory symlinks on macOS, proving descriptor-walk rejection,
not Landlock enforcement of arbitrary runtime file accesses. Tool declarations
remain lexical checks; they do not open files or implement a sandboxed MCP proxy.

The Linux backend still requires each confirmed root to be a dedicated ext4/tmpfs
mount with no bind alias, shared device mount or nested mount. An arbitrary
subdirectory contract accepted in diagnostic mode may be refused for protected
execution. Mount administration is trusted. Two follow-ups are provided in
`tests/test_remediation_linux.py`: synthetic mountinfo admission tests (unit
evidence), and actual Landlock access checks in a forked child for exact/child/
sibling/parent paths, runtime dependencies and a symlink to the sibling. Both
were skipped here. Actual mount/bind-alias creation, race testing and full
protected worker execution remain unverified for this patch.

## S4: authenticated producer provenance

### Reproduction and root cause

On separately reset runs, send agent-socket `trusted_event` requests with source
`kernel`, `supervisor` and `tool_gateway`. All were accepted, tightened posture
and persisted attacker-selected source labels. Source `admin` already required
administrative authority. This was provenance forgery even though the API only
tightened posture; it polluted trusted audit evidence and incident attribution.

### Boundary after remediation

Agent endpoint events must be `client_report` and match run/session/peer UID.
Administrative endpoint events must be `admin` and match the daemon-owner UID.
Caller-supplied source is checked against that derived role; neither socket can
claim internal origin. The CLI exposes only those two public source choices.

Trusted code inside the daemon can call `Engine.internal_event` for kernel,
supervisor or gateway components. That method is not in Unix dispatch. Code
executing inside the daemon is already part of the trusted computing base;
this is not authentication of independently running external producers. No new
kernel collector or external gateway transport was implemented.

Producer dictionaries record authenticated role/UID and, for internal events,
the component. They survive run persistence, history and signed audit export.
Ordinary reports go in `signals`; admin/internal events in `trusted_signals`.
The internal effect checker identifies itself as `effect_check` and records that
the observation concerns declared effects, not observed kernel activity.

Forged sources on both endpoints, case/NUL/object variants and injected
`administrative`, `uid` and `producer` fields are rejected. An `internal_event`
Unix request is unknown. Genuine internal API calls still tighten posture and
export verifiable producer identity. Tampering with exported identity fails
signature verification. Free-form reasons remain text, never an identity oracle.

The diagnostic socket tests use the actual host UID on both sockets; they verify
endpoint distinction and real peer credentials. Direct Engine tests reject the
wrong administrator UID. Distinct-UID Linux DAC/peer-credential deployment tests
were not run. Same-UID hostile processes are not isolated by session strings.

## Changed files and architectural scope

| File | Change |
|---|---|
| `kechaa/engine.py` | Persistent denial state/migration; atomic denial transition; recovery checks; producer role separation/internal event API; tool validation; contract intersection |
| `kechaa/daemon.py` | Await cleanup after committed denial and recovery; validate operation before audit-context assignment |
| `kechaa/policy.py` | Reject nested project roots/ambiguous ancestor reads; shared narrowing helper |
| `kechaa/common.py` | Path controls/UTF-8 byte bounds and consistent leading-slash normalization |
| `kechaa/cli.py` | Public event source choices and help reflect authenticated roles |
| `tests/test_security_control_plane.py` | Preserve two existing internal-producer tests using the genuine internal API |
| `tests/support.py` | Real disposable daemon/socket fixtures, bounded cleanup, macOS early-close handling |
| `tests/test_remediation_unix.py` | 14 actual Unix API regressions |
| `tests/test_remediation_invariants.py` | 10 transactional, policy, filesystem and lifecycle regressions |
| `tests/test_remediation_attack_retest.py` | 4 raw-socket attacker-perspective retests |
| `tests/test_remediation_linux.py` | 2 explicitly gated Linux follow-ups |
| `docs/security.md`, `docs/policy.md` | Current security limits, producer semantics and path/intersection rules |
| This report and `audit/security-phase1-evidence/` | Reproductions, results, source hashes and remaining work |

Kernel implementation, packaging/version and repository metadata are unchanged.
The worker cleanup integration test uses a real child process but replaces the
cgroup termination boundary with a test adapter. Its purpose is to prove the
daemon waits for cleanup after the committed transition. It must not be cited as
Linux process-tree/cgroup proof. Cleanup-failure routing is separately injected
and checked for admission hold.

## Commands and test results

From the repository root, with dependencies installed in `.venv`:

```bash
.venv/bin/python -B -m unittest discover -s tests -v
.venv/bin/python -B -m unittest tests.test_remediation_unix -v
.venv/bin/python -B -m unittest tests.test_remediation_invariants -v
.venv/bin/python -B -m unittest tests.test_remediation_attack_retest -v
.venv/bin/python -B -m unittest tests.test_remediation_linux -v
.venv/bin/python -B tools/certify_linux.py preflight
git diff --check
```

The final full-suite command exited 0: 52 discovered, 50 passed, 2 skipped in
6.625 seconds. Linux preflight exited 3 as expected on macOS. Diff whitespace
checks passed. Early runs exposed the oversized-operation attack and a test
fixture race: macOS could close a rejected socket before the client's
`shutdown(SHUT_WR)`. The fixture now tolerates only ENOTCONN at that point and
still requires a valid parsed response. SQLite test readers now close explicitly.
The final run contains no failures or resource warnings.

| Evidence class | Executed here | What it establishes |
|---|---|---|
| Existing 22 tests | Yes, before/after | Previously covered Engine flows continue to pass; baseline did not detect S1–S4 |
| 14 daemon subprocess/socket tests | Yes | Actual admission parsing, endpoint roles, persisted state, concurrent requests, restart, replay and signed export |
| 10 invariant tests | Yes | Transaction rollback, policy intersection, legacy migration, actual descriptor walk, internal provenance and lifecycle routing; fault injection explicitly scoped |
| 4 raw-socket attack retests | Yes | Original attacks and alternate inputs remain rejected through external interfaces |
| Synthetic Linux mountinfo test | Skipped | No current mount-admission test result; even a future pass is unit evidence |
| Actual Landlock child test | Skipped | No current Linux read-isolation result |
| Repository historical Linux evidence | Not rerun | Background only; not acceptance evidence for this patch |

The existing two older test modules use macOS-specific `/private/tmp` and `/bin`
fixtures; they were not silently represented as portable Linux coverage. The new
fixtures canonicalize their temporary and executable paths. For the Linux
follow-up use the explicit new test modules in a prepared Linux environment.
`tools/certify_linux.py run` is a plan/preflight wrapper, not an executed privileged
certification suite; a generated plan cannot close the remaining validation gap.

## Compatibility and administrative rollout

1. Before upgrading, review/export the current policy and retain a verified audit
   bundle/checkpoint/public key using the existing administrative procedures.
2. Replace ancestor runtime reads with explicit disjoint dependencies and project
   reads. Remove nested root declarations. Import the reviewed compatible policy
   through the authenticated administrative API before stopping the old daemon.
3. Upgrade the reviewed source and restart. Outstanding authority is invalidated.
   The stored active policy is revalidated; an incompatible old policy fails
   startup. If missed, use a reviewed administrative migration procedure; do not
   patch SQLite rows or disable validation to make startup succeed.
4. Legacy live runs enter lockdown. Review the retained contract/history and any
   incident before restoring authority. For an otherwise active unexpired run:

   ```bash
   kechaa --admin-socket /run/kechaa/admin.sock checkpoint --run RUN_ID --mode normal --reason 'Reviewed contract and denial history after upgrade'
   ```

   For a contained run requiring lease recovery, within its original lifetime:

   ```bash
   kechaa --admin-socket /run/kechaa/admin.sock run recover --run RUN_ID --mode guarded --seconds 60 --reason 'Reviewed containment incident and limited recovery'
   ```

   These are operator examples, not automatic recovery steps. A checkpoint does
   not reopen a closed run or clear an independent quarantined body state;
   recovery/new contract is required as appropriate. New grants must be obtained.
5. Update any producer using public `source=kernel/supervisor/tool_gateway` to
   report as `client_report`; genuine daemon code uses the internal API. Do not
   grant clients administrative socket access to preserve a forged label.
6. Consumers of history metadata must account for `denials_since_review` replacing
   `recent_denials`; denied-action history contains `action_digest` rather than
   raw action. Consumers of posture signals must distinguish `signals` from
   `trusted_signals` and use the new producer fields. New tool size/null/path
   restrictions intentionally reject formerly accepted or crashing inputs.

Old signed audit records are not rewritten: some old source labels may have
been supplied by agents. A valid old signature proves record integrity, not
authentic kernel provenance. Export consumers should label legacy provenance
unknown rather than retrofit trust. The versioned run body is additive to the
existing state schema; downgrading to the vulnerable implementation is not a
supported recovery procedure.

## Remaining risks and completion criteria

- **Linux validation outstanding:** run the new actual Landlock test, real
  dedicated-mount/alias/nested-mount scenarios, and real daemon execution with
  revocation during worker startup/running descendants and restart cleanup.
  Retain OS errno/file/process observations and signed audit evidence. S3 cannot
  receive full acceptance on this host. No claim is made about exhaustive races.
- **Audit availability:** every malformed request still creates a bounded denial
  record. A sustained client can fill the finite 50,000-event audit capacity and
  force fail-closed admission. Rotation/archive is administrative; this patch
  does not solve deliberate capacity exhaustion or machine-wide resource DoS.
- **Trusted host/state:** root, kernel, daemon code, interpreter/dependencies,
  mounts and signing key remain trusted. SQLite rollback injection does not
  establish power-loss durability or resistance to a privileged state rollback.
- **Declarative tools:** allowed tool checks do not execute/restrict a remote MCP
  server. Runtime effect observation remains incomplete. No kernel event collector
  was added by creating an internal producer API.
- **Filesystem limits:** disjoint approved runtime directories and executable
  reads remain intentionally accessible. A policy's allowed data can still be
  disclosed through intentional stdout/stderr. Diagnostic envelope narrowing
  alone cannot prove mount/hardlink/symlink runtime containment.
- **Identity:** unconfined hostile processes sharing an OS UID remain outside
  session-string isolation. Production administrators must maintain the existing
  separate-UID/socket permission model.
- **Legacy policy migration:** incompatible active policies need administrator
  preparation; no general offline policy migration mechanism was added.

The reproduced S1, S2 and S4 control-plane defects are fixed and verified within
the stated boundary. S3's policy correction is implemented and verified, but its
full requested Linux acceptance is incomplete. Consequently this work does not
justify an unconditional statement that all four findings and all kernel-level
acceptance criteria are resolved.
