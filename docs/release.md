# Release process and readiness

KECHAA is an evaluation alpha. The package version is currently `0.2.0a1`; record the commit/source manifest to identify later security patches. There is no production-certified configuration. A usable diagnostic demo is not Linux certification.

## Current gates

| Gate | Current status |
|---|---|
| First-use policy/grant/audit workflow | Runnable `demo` through actual Unix sockets; explicitly no execution |
| Source and explicit-prefix installation | Locally verified; dedicated pinned runtime and `-IS` launcher required |
| S1–S4 security changes | Preserved in main; S3 full Linux acceptance partial |
| Linux worker filesystem/network/process controls | Implemented with historical VM observations; current Linux acceptance gaps remain |
| Existing regression automation | CI workflow added; consult its actual run results, not this document, for hosted status |
| Real agent/framework interception and remote MCP mediation | Unverified / not implemented |
| Native execution overhead and broad compatibility | Not established; diagnostic measurements have limited scope |
| Private vulnerability intake, signed releases and independent review | Maintainer action/evidence still required |

Current [Linux requirements](linux-requirements.md), [security model](security.md), [remediation report](../audit/KECHAA_S1_S4_REMEDIATION_REPORT.md) and [roadmap](roadmap.md) take precedence over broad claims inferred from old reports. [completion.md](completion.md) and [validation.md](validation.md) preserve historical experiments.

## Build and inspect

```bash
.venv/bin/python tools/package.py --output .local/dist
```

This creates a deterministic source tarball, checksum, embedded file manifest and limited-scope CycloneDX SBOM. It publishes nothing. The inventory includes public source, docs, examples, existing tests, contribution material and reviewed audit evidence. It excludes local environments, state/keys, PDFs and VM data. No dependency binaries are bundled. Use an explicit output directory to avoid replacing an older release artifact/checksum in `dist`.

Before release, inspect the archive file list and verify every embedded SHA-256 hash. Extract into a new empty location, install the pinned dependencies, run the demo, execute the applicable existing suite and verify an explicit-prefix installation. Build twice from identical source to confirm byte-identical archives. Checksums establish integrity, not publisher identity; the SBOM does not attest every native build component.

## Maintainer publication checklist

Choose a new reviewed alpha version if behavior or security fixes changed; update `pyproject.toml`, `kechaa/__init__.py` and the changelog together. Confirm the intended remote/branch and clean reviewed commit. Do not retag, replace old assets or silently reuse a release version. Review CI results and retained evidence, including skips and unsupported environments.

Create an annotated tag only after release approval. Publish a draft prerelease with the exact archive/checksum and commit-linked notes, inspect it, download assets into a fresh directory and compare their bytes before publication. Signing requires a separately administered release key and independently distributed fingerprint; never use the daemon audit key. No tag, release or signature is created by the adoption workflow.

Keep the previous release and migration instructions available. S1–S4 changes intentionally reject unsafe older policies/source labels/null declarations; follow the report's administrative upgrade procedure. Downgrading to bypass validation is not recovery.

## Production-conscious limits

A supported production release needs independently reviewed Linux boundary tests, real workload/interception verification, a monitored private disclosure channel, authenticated builds/releases and documented operational ownership. Audit retention/anchoring and finite capacity require operator procedures. Same-UID peers remain one identity domain. These gaps cannot be fixed by documentation scores or added badges.

Online networking, Windows and native macOS sandboxing are explicit non-goals for the present scope. They are not mandatory feature additions merely because another project supplies them. Read-only immutable workspace mode is implemented; writable builds and transitive runtime inputs still have mutation limits.
