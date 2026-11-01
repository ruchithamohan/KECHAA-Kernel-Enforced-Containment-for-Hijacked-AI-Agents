# Getting started

Choose diagnostics to learn the authorization model. Choose a disposable Linux VM to evaluate kernel containment. Completing the first does not certify the second.

## Local evaluation

From a fresh checkout as a non-root user, with Python 3.11+:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -IS bin/kechaa version
.venv/bin/python -IS bin/kechaa demo
.venv/bin/python -IS bin/kechaa demo --scenario approval --json
```

On Debian-derived systems without `venv`, provision the distribution's Python venv package through your normal administrator process. These instructions do not change host services or kernel configuration. Dependency download time depends on your network; the walkthrough itself should take seconds.

The demo starts a real Unix daemon, confirms synthetic contracts, prepares grants, simulates consumption and verifies the audit chain. The included operator automatically approves only the disposable demo's known pending request; this is not an approval agent for your workload. No shell command, SQL query or MCP server is executed by the daemon. [Scenario details](../examples/README.md).

Temporary keys/state/files are removed when the demo exits, including ordinary exceptions and interrupts. SIGKILL or machine failure cannot run Python cleanup; inspect only the particular `kechaa-*` temporary directory left by that interrupted invocation. Never apply a wildcard deletion to real daemon state. No persistent service is installed.

## Install the launcher

The source launcher above is sufficient for development. For an explicit installation:

```bash
.venv/bin/python -IS tools/install.py install --prefix .local/install
.local/install/bin/kechaa version
.local/install/bin/kechaa demo
.venv/bin/python -IS tools/install.py verify --prefix .local/install
```

The prefix must be empty and owner-controlled; its ancestors must be real directories. The interpreter path cannot contain whitespace. The installer pins the invoking `.venv` interpreter and copies source plus a hash manifest. Keep that virtual environment for as long as this installation uses it. It does not fetch dependencies, modify PATH or start a daemon.

`pip install .` metadata exists for Python tooling, but its conventional console entry point lacks required `-IS` startup flags and refuses to run. Use the source or explicit-prefix launcher; do not disable the startup check. For an offline installation, provision the pinned dependencies from a reviewed wheelhouse as described in [operations](operations.md).

Removal, after stopping any daemon launched from this installation:

```bash
.venv/bin/python -IS tools/install.py uninstall --prefix .local/install
```

Removal verifies hashes first and removes only manifest-listed program files. It preserves unrelated files and state. The development `.venv` is a separate user-owned environment.

## Inspect Linux readiness

```bash
.venv/bin/python -IS bin/kechaa doctor
```

Exit 3 on macOS or an unprepared Linux host is expected. `doctor` is a read-only prerequisite probe. It does not install controls and a successful probe is not certification. Continue with [Linux requirements](linux-requirements.md) and [operator setup](operations.md#experimental-linux-preparation).

## Common first-run problems

| Symptom | Action |
|---|---|
| `Start ... with Python -IS` / site-hook refusal | Use `.venv/bin/python -IS bin/kechaa` or the installed launcher |
| Missing/pinned dependency error | Run `.venv/bin/python -m pip install -r requirements.txt`; check that the launcher uses this interpreter |
| Prefix not empty | Choose a new empty prefix for a side-by-side installation |
| Symlink ancestor or whitespace in interpreter path | Use a canonical checkout location without spaces; `/tmp` is a symlink on macOS |
| Unix socket bind denied | Your environment prohibits the real socket demo; use the documented diagnostic console for limited inspection, without claiming socket verification |
| `demo_startup` | Check platform, Unix socket permission and dependency versions; do not run the quickstart with sudo |
| `execution_unavailable` | Diagnostic grants cannot execute; prepare a Linux deployment explicitly |
| `PENDING_APPROVAL` | Have an operator inspect the grant and both digests; do not automatically turn this into ALLOW |
| `policy_denied` / lockdown | Review the contract/history; only authenticated administration can recover |

For persistent run, grant, audit and recovery errors see [operations troubleshooting](operations.md#troubleshooting). Run `--help` at any CLI level to inspect the installed argument contract.
