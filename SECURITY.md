# Security reporting and supported releases

KECHAA 0.2.0a1 is an evaluation alpha. No configuration is certified for
production containment. The supported public capability and validation boundary
is recorded in `docs/release.md` and `docs/completion.md`.

For a suspected vulnerability, avoid posting credentials, private source, signing
keys or a live exploit against another person's system. Preserve the version,
OS/kernel, active profile, policy digest and a minimal reproduction using fake
data. Include whether the result came from real enforcement or diagnostics.

The intended repository is
<https://github.com/ruchithamohan/KECHAA-Kernel-Enforced-Containment-for-Hijacked-AI-Agents>.
Private vulnerability reporting has not been configured or verified. A maintainer
must enable it and publish a monitored private contact before a supported release.
Until then, use a public issue only to request a private contact; do not include
sensitive vulnerability details. No response-time SLA is claimed.

If audit verification fails, stop action admission, preserve state and independently
retained checkpoints, and investigate using offline export/verification. Do not
delete evidence, replace the signing key or weaken policy to clear the error.

Production release requires the operational gates in `docs/release.md` and an
independent security review. Experimental alpha publication does not satisfy
those gates. Source checksums alone do not authenticate a release.
The signing and verification procedure is in `docs/operations.md`. Release keys
must be separate from daemon audit keys and remain outside this repository.
