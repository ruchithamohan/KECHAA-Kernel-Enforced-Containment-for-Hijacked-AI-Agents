> Historical 0.1.0a1 diagnostic evidence. For current Linux VM results, fixes,
> and release status see [completion.md](completion.md). Statements below about
> unavailable virtualization describe that earlier attempt only.

# Operational validation, 2026-10-29

## Actual environment

Development/diagnostics: Apple Silicon macOS, Darwin 27.0.0 arm64, CPython 3.14.8.
Product: KECHAA 0.1.0a1, `diagnostic-no-execution`. Dependencies were already
installed locally; no package, VM image or privileged service was downloaded or
installed. The original workspace contained only the architecture PDF and had
no Git history, implementation or tests. The requested remote repository was
empty when inspected.

No Linux VM, container runtime or QEMU was available. Unix-domain socket binding
was attempted twice and failed with `PermissionError: [Errno 1] Operation not
permitted` at `asyncio.create_unix_server` → `sock.bind`. No permission bypass,
host security change, system service or kernel experiment was attempted.

All working data was confined to the ignored `.local/lab` directory. The installed
original executable was `.local/kechaa/bin/kechaa`; the completed local source
installation is `.local/kechaa-0.1.0a1/bin/kechaa`. Actual operations were performed through
that executable's non-executing diagnostic console, not a replacement/mock engine.
No new test cases, test suites or synthetic test framework files were added.
No approved shell command was actually executed through containment.

## Observations against the requested experiments

| Experiment | Operation actually performed / expected property | Observation and evidence | Status |
|---|---|---|---|
| A: install and normal work | Offline explicit-prefix install; invoke installed version, help, preflight, policy init/validate/explain/diff | Executable ran; macOS preflight explicitly reported no execution backend; Linux example YAML validated | VERIFIED for installation/control plane; real development workload UNVERIFIED |
| B: approval integrity | Prepare echo/shell requests; inspect signed grant; approve exact digests; consume through `simulate`; retry and alter command/cwd/session/input | Pending rejected; approved exact request consumed once with `executed:false`; replay → `grant_replay`; changes → `action_changed`, `run_binding`, `inputs_changed`; expired/stale → `grant_expired` | VERIFIED diagnostic state semantics; protected execution and OS peer authentication UNVERIFIED |
| C: filesystem containment | No kernel file-access experiment performed | Backend source exists; Mac execution disabled; no Linux VM | UNVERIFIED |
| D: descendants/background jobs | No child/daemonization experiment performed | PID namespace, parent-death and cgroup code remain unoperated | UNVERIFIED |
| E: network restriction | No listener or connection experiment performed | Offline-only backend; positive endpoint allowances not implemented | UNVERIFIED; positive network workflow UNSUPPORTED |
| F: package lifecycle | No malicious package installed or executed | Node input-identification code is not a verified npm workflow; no exfiltration result claimed | UNVERIFIED |
| G: policy changes | Change echo rule from ask to allow for an exact argument prefix; import; submit duplicate schema key | Valid version activated; duplicate rejected at `<import>:85`; active digest unchanged after failure; diff identified argument-scope and approval changes | VERIFIED in actual persisted control plane |
| H: long-run tightening | Emit untrusted-web, repository and MCP labels; inspect next envelope/mode; invoke checkpoint | Guarded removed write list; score progression 20/40/60 reached lockdown; next request denied; non-admin diagnostic console checkpoint → `admin_required` | VERIFIED reported-label/state semantics; real OS role boundary and observation-driven drift UNVERIFIED |
| I: recovery/resources | Stop/restart console over same SQLite state; inspect run and unused grant; verify/export records | Guarded/lockdown persisted; unused grant became `revoked_restart`; consumption rejected; signed chain verified; small bounded metrics below | VERIFIED graceful control-plane restart; daemon crash/worker/orphan cleanup UNVERIFIED |

Two real-use issues were fixed and their affected operations repeated:

1. macOS inode IDs exceeded the canonical integer range. IDs are now lossless
   decimal strings, and preparation/adoption checks succeeded afterward.
2. `policy explain FILE --cwd ... -- COMMAND` initially lost options to argparse's
   remainder argument. Explicit delimiter handling now preserves command arguments,
   and the documented invocation succeeded afterward.

A copied export was edited from `policy_activated` to `policy_tampered`. Offline
verification exited 2 with `audit_signature`; the original export verified.
This exercised actual product audit verification without modifying live state.

## Preserved evidence

The ignored `.local/evidence` directory contains operation responses, exact
measured timings, original and altered exports, and independently retained audit
heads. Raw exports retain local paths, so they are not included in the public
source archive. The original state and public key remain in
`.local/lab/console-state`; the private key is never printed or packaged.

The original read-only export contained **58 signed records** and verified with head:

```text
c8ce2cc7ccba7518f5219f41ccc10ef645c7c9b3c88d3774a5761a142169746e
```

The original measured installed-file manifest SHA-256 was:

```text
fe145f86757c655636436446f10fb3775bcc3e4473c1bc7c907da4bfe50e635d
```

These are evidence identifiers, not claims of an independently trusted timestamp
or remote transparency service. A later diagnostic run appends new records and
therefore changes the head; the saved export remains independently verifiable.

## Measured performance

These are actual measurements of the original installed **diagnostic control plane**,
using subprocess startup and JSON stdin/stdout round trips. They do not include
Unix-socket transport or kernel enforcement and are not workload benchmarks.

| Measurement | Result | Scope |
|---|---:|---|
| Console startup to ready line | 188.432 ms | One warm development-machine observation |
| Health round trip | median 0.049 ms; min 0.048; max 0.078 | 20 requests in one console process |
| Grant preparation | 3.849, 1.714, 1.732 ms | Three requests with two system executable digests and SQLite/audit commits |
| Console child CPU | 0.189584 s | User + system CPU across the measured console session |
| Child peak RSS | 43,433,984 bytes | macOS `getrusage(RUSAGE_CHILDREN)` for that console child |
| State DB after measured admin session | 143,360 bytes | Before the subsequent restart/role check |

Simple shell execution, repeated protected commands, package installation, builds,
file-intensive work, network-intensive work and long-lived process overhead are
all **UNMEASURED**. No slowdown percentage, false-block rate, approval-fatigue rate,
attack-success rate or competitive performance advantage is claimed.

## Resume review and release packaging

The subsequent source review hardened cancellation cleanup, independent cgroup/
supervisor termination attempts, shutdown admission, status reporting, and release
of database locks on errors. Actual kernel cancellation/termination remains
UNVERIFIED. A further installed diagnostic daemon startup again received EPERM
from Unix-socket binding and returned a structured operational error without
executing an action.

The reviewed build installed as `.local/kechaa-r5` was actually operated through
its console: pending-grant refusal, explicit approval, one-time simulation, replay
refusal, execution refusal, guarded write removal and restart invalidation all
produced the expected state. List-valued label/mode fields and non-object request
data were rejected while subsequent health remained ready. This fixes malformed
input paths that could previously raise an internal exception.

That console started in **118.327 ms**; 20 health requests had median **0.054 ms**,
minimum **0.050 ms**, maximum **0.160 ms**. Its process exited 0 with empty stderr.
These are another small diagnostic observation, not a measured performance
improvement. Its installed manifest digest is
`e315a06cd3d22e57076bd07bf4c010585ec2105225807c448fc2dcf2de6a4b20`.
Its separate 17-record export verified against the saved expected head
`7fd31a47a666c3249af08764886698fd37d8dd559444e222639f136769866475`.
Detailed observations are in ignored `r5-operations.json`, `r5-metrics.json`,
`r5-restart.json` and `r5-audit.jsonl` under `.local/evidence`.

Removal was exercised against a real earlier installation with
`python tools/install.py uninstall --prefix .local/install-r4`. Every
manifest-listed program file and the manifest were removed; a synthetic operator
policy survived, and the separate existing state database's SHA-256 was unchanged.
On another disposable installation, an installed-directory symlink and then an
edited entry point each caused refusal before any program file was removed.
The controlled changes were restored and all original manifest hashes matched.
These observations are retained in `removal.json` and `removal-refusals.json`.

`python tools/package.py` was run twice and its archive hashes compared. The
archives were identical, with 33 public files and no PDF, local state, keys,
bytecode, third-party binaries or symlinks. Extraction used Python's `data` filter
in the ignored workspace. The extracted installer's installation and version
command succeeded. The final archive and its SHA-256 sidecar are in `dist/`;
the final inventory/hash observations are kept in `.local/evidence/packaging.json`.
Reproducibility applies to this source archive, not to unbuilt dependency wheels.

The completed installation's source matches the repository, with manifest SHA-256
`74db7269ff04b4c3637590636dab9f1f3ddd83625b46f5220525119463adec1e`.
Its actual CLI rejected a 25-level YAML import as `policy_depth` while retaining
the active policy and readiness. Direct invocation of the hook with a list-valued
tool name emitted a structured deny with exit 0, rather than an uncaught exception.
This checks adapter error output only; it is not real Claude integration evidence.
The example Linux policy validated, help/version ran, and diagnostic execution
was refused. These results are in `final-package-operations.json`. The resulting
five-record audit export verified against saved head
`79cb814ce45adc20334414783df3516105e2a98c9dc81d303f8af16e5dc586bc`.
Every console process used for these operations exited; no service remains running.

## Procedure for the remaining kernel gate

Use a disposable Linux VM with a clean snapshot, ≤2 vCPUs, ≤2 GiB memory, a bounded
disk, no shared host folders, no credentials and no external network. Keep the VM
power-off control available. Prepare the dedicated unprivileged account, cgroup
subtree and canonical runtime/executable policy described in operations.md.

Record kernel version, Landlock ABI, actual executable/interpreter paths, product
manifest digest, policy version and every command. Install using the documented
path. Run a harmless echo, file read/write and representative offline workflow
before attempting any denial. Runtime dynamic-linker allowlisting and the
metadata-syscall restrictions must be checked against the target distribution.

Then perform the user's A–I sequence with synthetic inside/outside files, a dummy
credential, bounded child/background processes and local-only endpoints. Observe
both OS return values and filesystem/listener results; an audit message or generic
nonzero exit is insufficient. Exercise TCP/UDP/IPv6/Unix socket paths separately.
The current profile cannot satisfy a positive network allowance scenario.

Use only a reviewed local package fixture, not a public malicious package. Repeat
failed scenarios after fixes. Exercise actual daemon loss, restart, cgroup cleanup,
output/runtime budgets and a real harness version. Mark every unavailable property
UNVERIFIED and keep the backend experimental until those gates pass. Do not run
these security experiments against the developer's Mac.
