# Changelog

## Unreleased — adoption and integration

- Add a disposable real-Unix-API `demo` command with human/JSON output and explicit simulation boundaries.
- Add a small agent-side Python client, function-call message mapping, command adapter example and local SQLite workload.
- Add reproducible diagnostic IPC benchmarks; no protected execution performance claim.
- Reorganize onboarding, architecture, API, platform, example and contribution documentation.
- Add CI for existing regressions, documentation links, demonstrations and explicit-prefix installation; no new test cases.
- Include public examples, contribution files and existing tests in source archives; support an explicit output directory.

## 2026-11-01 — S1–S4 remediation (`8d444b8`)

- Persist denial lockdown and revoke affected grants atomically; legacy live runs require administrator review.
- Reject malformed tool declarations without poisoning ordinary daemon admission; bound invalid operation audit context.
- Reject ambiguous ancestor runtime reads and nested project roots; safely intersect contract capabilities.
- Authenticate event producer role from endpoint/internal context; reject client-forged internal provenance.
- Preserve 22 earlier tests and add 30 remediation regressions: 50 passed, 2 Linux-only skips in that pass.

Compatibility: previously accepted unsafe policies/source labels/null declarations can now fail. Denial history is cumulative until administrative review. S3 Linux acceptance remains partial. See [the full report](audit/KECHAA_S1_S4_REMEDIATION_REPORT.md) before upgrading.

## 0.2.0a1 — historical evaluation alpha

Experimental offline Linux execution, signed grants, task contracts, strict policy, audit/checkpoints and diagnostic control plane. Subsequent source changes retain this package version until maintainers make a reviewed release. A version string alone does not identify the security patch level; record the Git commit or source manifest. See [historical observations](docs/completion.md).
