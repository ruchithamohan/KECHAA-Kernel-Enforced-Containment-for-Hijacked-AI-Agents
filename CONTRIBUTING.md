# Contributing to KECHAA

Start by running the [quickstart](docs/getting-started.md) and reading the [security boundary](docs/security.md). Useful contributions make a concrete workflow easier without weakening authorization: reproduce a setup problem, clarify an error, improve an adapter example, or record a bounded Linux experiment.

## Development loop

From the repository root on macOS or Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -IS bin/kechaa demo
.venv/bin/python tools/check_docs.py
```

Use an ordinary account for development. Do not start the root-owned backend on your workstation. This alpha's official CLI is the isolated source or explicit-prefix launcher, not an editable-install console script. No formatter or heavyweight development framework is required.

Run the existing full suite on macOS:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

The two older test modules use macOS `/private/tmp` and `/bin` fixtures. On Linux, run the existing portable subset instead of pretending those fixtures are portable:

```bash
.venv/bin/python -m unittest tests.test_remediation_unix tests.test_remediation_invariants tests.test_remediation_attack_retest tests.test_remediation_linux -v
```

Linux probes can skip when the host lacks prerequisites. Keep the skip reasons in your report; do not change them to passes. Real kernel results require actual kernel operations. Diagnostic mocks, fixtures and lifecycle adapters are not that evidence. The adoption changes add no new test cases; CI runs existing suites and executable workflows.

Build a source artifact without replacing checked-in historical release checksums:

```bash
.venv/bin/python tools/package.py --output .local/dist
```

The archive includes public source, docs, examples, existing tests and reviewed evidence. It excludes `.local`, private keys/state, VM images and PDFs. No release is published by this command.

## Propose a focused change

Open a bug report with version/commit, OS/kernel, mode, minimal synthetic policy/contract, expected behavior and actual error code. For an integration proposal, name the exact tool/version and explain which execution paths it controls. Discuss major enforcement or state-format changes before implementation.

A pull request should explain the problem, behavior, validation actually performed, security boundary and compatibility impact. Preserve prior evidence; date new observations rather than silently rewriting historical claims. Do not include credentials, signing keys, real customer code or private paths in fixtures and logs. Follow [SECURITY.md](SECURITY.md) for vulnerabilities.

## Review expectations

Keep policy, contract and authenticated identity in the daemon. Never turn a failed transport, pending approval or unsupported platform into direct host execution. Separate diagnostic behavior from Linux guarantees and declared effects from observed effects. Changes to persistent authority need recovery/restart review. Follow existing Python style and prefer small dependencies or the standard library.

Maintainers review correctness, scope and evidence; there is no response-time SLA. Use respectful technical discussion, avoid harassment and report conduct problems privately when a maintainer provides a contact. No unstaffed governance or conduct-response role is implied. [Roadmap](docs/roadmap.md) and [release process](docs/release.md) describe current priorities.
