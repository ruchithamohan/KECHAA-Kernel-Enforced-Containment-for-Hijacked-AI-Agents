# Policy reference, schema 1

Start with `kechaa policy init --root /dedicated/project --output policy.yaml` on
the target OS. This resolves the installed system executable paths and generates
ordinary YAML. Inspect it before activation. `examples/linux-offline.yaml` is
illustrative: `/lib` or `/bin` may be symlinks on your distribution, so the
generated canonical paths are preferable.

Every field is explicit. Unknown fields, duplicate keys, aliases, anchors, YAML
merge keys, custom tags, timestamps, floats, octal/hex numbers, ambiguous booleans
and multiple YAML documents are rejected. Only lowercase `true`/`false` and
decimal integers are accepted as non-string scalars. Quote values such as `yes`
when they are intended as strings. Errors identify the source file and line.

## Top-level fields

| Field | Meaning |
|---|---|
| `schema: 1` | Schema and normalization contract |
| `name` | Stable human-readable policy identifier |
| `default: deny` | Mandatory default; cannot be changed to allow |
| `roots` | Dedicated project roots where actions may work |
| `sensitive` | Additional paths that must not overlap any allowed subtree |
| `grant_ttl_seconds` | 1–120 seconds; expiry limits approval adoption and action lifetime |
| `profiles` | 1–16 reusable effect envelopes |
| `rules` | 1–128 executable/argument rules |

Global roots such as `/`, `/Users`, `/home` and `/tmp` are rejected. File paths
must be absolute and cannot contain traversal or wildcard syntax. A path names
one file or a directory subtree, never a glob. During grant preparation,
credential and agent-configuration paths for the actual OS user and the daemon
state directory are added to the sensitive set. They are not read or scanned.

Landlock allows descendants of an allowed directory. Omitting a sensitive child
from an allowlist does **not** deny that child. KECHAA rejects overlaps instead
of pretending a deny takes precedence inside a broader Landlock allow.

## Profiles

All profiles specify `read`, `write`, `execute`, `network`, `environment`, and
`limits`. The optional `extends` references another profile; cycles and missing
parents are errors. A child may narrow paths, executable sets and budgets, and
must keep the same environment. Defaults do not grow capabilities.

`read` governs file contents and directory listing. It does not promise to hide
all filesystem metadata. `write` includes file creation, overwriting, truncation,
rename and deletion inside each subtree. The Linux backend denies special-node
creation. Private read-only mounts fence metadata changes outside approved
workspace volumes. Narrow write subtrees retain seccomp metadata denials; see
the compatibility limitations before attempting package installation.

`execute` contains exact canonical executable file paths. The primary executable
must be an ELF binary in Linux execution mode. Invoke scripts through an explicit
configured interpreter. Protected mode requires root-owned executable files
and ancestor directories without group/world write permission. The ELF loader
must also appear explicitly in the policy and contract; policy init discovers it
without running the executable or ldd. Interpreters can execute program text:
an executable list is not a claim about every piece of code evaluated.

`network` must be `offline`. No host, TCP-port, UDP, DNS, Unix-socket or proxy
exception can silently pass this schema. The worker uses a new network namespace
and denies socket/socketpair creation via seccomp. Standard output and error are
explicit, bounded output channels back to the caller.

Allowed environment keys are `PATH`, `LANG`, `LC_ALL`, `TZ`, `HOME`, `TMPDIR`,
`XDG_CACHE_HOME`, `npm_config_cache`, and `PYTHONHASHSEED`. Only these exact policy
values are passed to the action. Nothing is inherited from the agent's environment.
`PATH` must be `/usr/bin:/bin`; HOME/cache/temp paths must be inside project roots.
Variables such as `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PYTHONPATH`
and `NODE_OPTIONS` cannot be supplied. Create approved home/temp directories as
ordinary workspace setup before using a profile.

| Limit | Accepted range | Enforcement in experimental Linux mode |
|---|---:|---|
| `wall_seconds` | 1–600 | Daemon timer and worker timer, further limited by grant expiry |
| `cpu_seconds` | 1–300 | Per-process RLIMIT_CPU; cgroup cpu.max also limits aggregate CPU rate |
| `memory_mb` | 32–4096 | cgroup memory.max; swap disabled for the action cgroup |
| `pids` | 1–128 | cgroup pids.max, including supervision overhead |
| `output_bytes` | 1024–4194304 | Combined output budget; exceeding it terminates the action |
| `file_bytes` | 1024–67108864 | Per-file RLIMIT_FSIZE, **not aggregate disk quota** |

A dedicated ext4 or tmpfs filesystem is mandatory for each confirmed workspace
root. Bind aliases, multiple mounts of its device, nested mounts and subdirectory
contracts are rejected. A finite tmpfs size or ext4 volume/quota must bound total
disk consumption. ARM64 tmpfs operation and a basic dedicated ext4 workflow were exercised;
x86_64 remains unverified. Per-action file limits are not aggregate disk quotas.

## Rules and precedence

Each rule has `id`, `executable`, `profile`, `decision`, and optionally
`argv_prefix`, `expires_at`, and `exception_reason`. The prefix matches exact argument tokens after argv[0]; it is not
a shell parser, regular expression or exact-command constraint. Additional
arguments remain permitted within the bounded envelope.

All matching profiles are intersected. A deny overrides ask; ask overrides allow.
Conflicting environments deny the request. No match means deny. An `allow` is
standing administrator authorization for the selected capability, not a proof
that the command is harmless. Default generated rules use `ask`.

The confirmed task contract further narrows project roots, executables and writes.
Guarded mode removes writes and requires approval. Lockdown holds every action
until an administrator reviews the checkpoint. Policy-only CLI checks do not
claim to include the daemon's contract, UID-specific paths or current run state.

## Authoring and activation

```bash
kechaa policy validate policy.yaml
kechaa policy lint policy.yaml
kechaa policy explain policy.yaml --cwd /work/project -- /usr/bin/echo hello
kechaa policy check policy.yaml --mode guarded --cwd /work/project -- /usr/bin/echo hello
kechaa policy diff previous.yaml proposed.yaml
kechaa policy export policy.yaml
kechaa --admin-socket /run/kechaa/admin.sock policy import proposed.yaml
```

Import validates completely before the SQLite transaction changes the active
version. A failed update preserves the active version. Activation revokes unused
grants and terminates active actions rather than attempting to widen or tighten
already-applied Landlock rules. Older normalized versions remain in the state
database. Restore a reviewed prior YAML policy through the same import command
to roll back; never edit database rows manually.

Workspace policy layers, signed remote policy bundles and autonomous policy
generation are unsupported. Unknown schema fields fail
validation rather than pretending these features exist. Workspace overrides
cannot weaken enterprise restrictions because no workspace policy-loading path
exists in the daemon.

## Scoped expiry and versioned rollback

An allow/ask rule can carry an explicit UTC expiration and administrative reason:

```yaml
- id: temporary-local-install
  executable: /usr/bin/python3.13
  profile: development
  decision: allow
  argv_prefix: [-m, pip, install, --no-index]
  expires_at: "2026-10-30T12:00:00Z"
  exception_reason: "Reviewed offline installation in the disposable workspace"
```

Expiring permissions require a nonempty argument prefix. They cannot override
matching deny or ask rules; an expired matching permission becomes deny instead
of falling through to a broader allow. Grant expiry is capped at the rule's
expiry and the session deadline. The shown date is an example, not standing
permission or a production recommendation.

`policy schema` emits the JSON Schema authoring contract. The strict YAML parser
and semantic validator remain authoritative, including alias/duplicate rejection,
path overlap, inheritance and expiry restrictions. `policy preview` performs the
same policy-only explanation as `policy explain`; neither executes a command.

`policy history` lists persisted versions. `policy rollback --version DIGEST
--expected-version CURRENT --reason REASON` validates the historical version,
checks the active digest, activates atomically and revokes old authority.
`policy import FILE --expected-version CURRENT` provides the same stale-review
check. Invalid imports leave the last known-good version active.
