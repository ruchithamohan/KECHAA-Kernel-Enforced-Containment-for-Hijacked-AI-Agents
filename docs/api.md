# Local API v1 reference

One UTF-8 JSON line per Unix connection, with exact envelope fields `v`, `operation`, `data`. Version is integer `1`. Maximum request size is 256 KiB; unknown fields, duplicate JSON keys, floats, invalid encoding and excessive nesting are rejected. Close the request direction after sending the line.

```json
{"v":1,"operation":"health","data":{}}
```

Success: `v`, `ok:true`, `request_id`, `result`. Failure: `v`, `ok:false`, `request_id`, `error` containing `code`, `category`, `message`. `KechaaError` exposes those fields in Python. Operational errors and unavailable transport never mean permission to execute.

## Agent operations

| Operation | Data | Result / meaning |
|---|---|---|
| `health` | `{}` | Profile, availability, protocol versions, public key; health is not kernel certification |
| `policy_get` | `{}` | Active policy/version |
| `run_get`, `run_close` | `run`, `session` | Bound run state or closure |
| `run_history` | `run`, `session`, optional `limit` 1–512 | Bounded history, not the entire signed audit |
| `prepare` | `run`, `session`, `action`, optional boolean `supervised` | Pending/issued grant with exact normalized action, profile and effect summary |
| `grant_status` | `run`, `session`, `grant` | Owning caller's grant state/action/profile |
| `execute`, `simulate` | `run`, `session`, `grant`, exact `action`, optional matching `supervised` | Actual Linux result or explicit diagnostic consumption |
| `event` | `run`, `session`, `label` | Untrusted-input report that can tighten posture |
| `trusted_event` | `run`, `session`, `label`, `source:client_report`, optional `reason` | Despite its legacy name, an agent cannot claim trusted internal provenance |
| `tool_request` | `run`, `session`, `tool`, `effects` | allow/ask/deny on declared effects, not an execution grant |

`action` requires `argv` (1–128 strings, 64 KiB combined), absolute `cwd`, optional `inputs` (at most 16 explicit paths inside cwd). Policy/contract/path rules further constrain it. Exact source validation lives in [effects.py](../kechaa/effects.py).

Tool operation data is capped at 16 KiB canonical JSON. `read`/`write`, if present, are arrays of at most 64 absolute paths; null is invalid. Optional `network` is `offline` or `external`; external is denied. Optional `kind` is `mcp_effect_contract` or `file_effect_contract`. See [security semantics](security.md#s1s4-control-plane-remediation).

## Administrative operations

These require the separate admin socket **and** daemon-owner peer UID.

| Operation | Required data / behavior |
|---|---|
| `run_open` | `uid`, `session`, `contract`, `confirmed:true`; returns run ID |
| `grant_get` | `grant`; returns the signed body for inspection |
| `grant_approve` | `grant`, `action_digest`, `effects_digest` |
| `grant_revoke` | `grant`; revokes and requests active termination |
| `policy_import` | `yaml`, optional `expected_version`; atomic validated activation |
| `policy_history`, `policy_rollback` | Version inspection/reviewed rollback; use CLI help for pagination/digests |
| `checkpoint` | `run`, `mode`, `reason`; resets denial counter after review, retains history |
| `run_recover` | `run`, `mode`, `seconds`, `reason`; within original contract lifetime |
| `run_quarantine`, `lease_renew` | `run`, `reason`, and `seconds` for renewal |
| `trusted_event` | `run`, `label`, `source:admin`, optional `reason` |
| `audit_verify`, `audit_checkpoint`, `audit_anchor` | `{}` |
| `audit_export`, `audit_anchors` | Optional `after`, `limit`; paginated evidence |

Contracts contain roots, executable inventory and a write boolean; lifetime defaults to 3600 seconds. Optional `input_integrity=immutable-workspace` requires read-only dedicated Linux volumes; diagnostics refuse it. Only one live run is permitted per OS UID.

## Errors and lifecycle

`policy_denied` is a security decision. `approval_pending` in the client means no command ran. `grant_replay`, `grant_stale`, `grant_expired`, `inputs_changed` require inspection/new authority, not retry of the same grant. `daemon_unhealthy`, `audit_full` and `cleanup_incomplete` require operator reconciliation. [Troubleshooting](operations.md#troubleshooting).

Execution returns `exit_code`, `termination`, `controls_ready`, and bounded base64 stdout/stderr when available. A nonzero exit alone does not identify a particular kernel denial. The Python adapter uses a bounded 660-second execute timeout; low-level transport defaults to 15 seconds. A caller disconnect never refunds authority. Use run closure or administrator revocation to cancel.

API v1 and policy schema 1 identify wire/schema families, not a promise that alpha semantics will never change. New validation may reject unsafe formerly accepted inputs. Changes and migration guidance belong in [CHANGELOG](../CHANGELOG.md) and release notes. [daemon dispatch](../kechaa/daemon.py) is the authoritative operation inventory.
