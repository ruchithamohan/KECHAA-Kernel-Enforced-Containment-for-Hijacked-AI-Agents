# Dependency and implementation provenance

KECHAA is independently implemented in Python from documented operating-system
interfaces and the private architecture specification. No competitor source was
copied, translated, vendored or used as a template. The PDF is excluded from all
source artifacts. Original source is MIT licensed; see LICENSE.

| Dependency | Pinned version | Purpose | License |
|---|---|---|---|
| CPython | >=3.11; operated 3.13.5 and 3.14.8 | Runtime and OS interfaces | PSF |
| PyYAML | 6.0.3 | Strict safe YAML parsing | MIT |
| cryptography | 48.0.1 | Ed25519 signatures | Apache-2.0 OR BSD-3-Clause |
| cffi | 2.0.0 | Cryptography dependency | MIT |
| pycparser | 3.0 | CFFI dependency | BSD-3-Clause |
| SQLite | Interpreter supplied | Transactional state | Public domain |
| OpenSSL/Rust components | Wheel dependent | Cryptographic implementation | Build-specific notices require review |

requirements.txt and pyproject.toml pin the Python dependencies. The generated
CycloneDX SBOM marks its scope as incomplete: it inventories declared Python
dependencies, not the interpreter, wheel build chain or every native component.
The source release bundles no third-party binaries. Binary redistribution needs
its own complete notices, provenance review and independently verified builds.
No legal non-infringement guarantee is made.

The macOS diagnostic environment reused installed dependencies. Linux validation
used official PyPI ARM64 wheels downloaded with authorization, with their SHA-256
hashes checked on both host and guest. Pip 26.0.1 was a lab installation tool, not
a product dependency. QEMU 11.1.3 and its Homebrew bottle dependencies were
extracted project-locally and checked against published SHA-256 values; nothing
was installed into the host system prefix. Debian 13's nocloud ARM64 image was
checked against its official HTTPS SHA-512 checksum. Its detached OpenPGP
signature was not verified. These transport/checksum checks do not establish
reproducible dependency builds or enterprise supply-chain attestation.

Exact local download manifests are preserved under .local/vm (excluded from the
release). Package checksums and the VM configuration are summarized in
completion.md. This document provides the source distribution's dependency notice inventory.
