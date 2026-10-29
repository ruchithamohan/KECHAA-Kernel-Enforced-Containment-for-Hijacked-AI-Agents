#!/usr/bin/env python3
"""Create a deterministic source archive from an explicit public-file inventory."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import json
import tomllib

root = Path(__file__).resolve().parent.parent
project = tomllib.loads((root / 'pyproject.toml').read_text())['project']
version = project['version']
files = [root / name for name in ("README.md", "LICENSE", "SECURITY.md", "pyproject.toml", "requirements.txt", "requirements-linux-arm64-cp313.lock", ".gitignore", "bin/kechaa")]
for directory, pattern in (("kechaa", "*.py"), ("tools", "*.py"), ("docs", "*.md"), ("examples", "*.yaml"), ("examples", "*.json")):
    files.extend((root / directory).rglob(pattern))
destination = root / "dist"
destination.mkdir(exist_ok=True)
archive = destination / ("kechaa-" + version + "-source.tar.gz")
payloads = {}
for path in sorted(set(files)):
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise SystemExit("Refusing unexpected source path: " + str(path))
    relative = path.relative_to(root)
    if relative.suffix.lower() == ".pdf" or ".local" in relative.parts:
        raise SystemExit("Private file reached package inventory")
    payloads[str(relative)] = path.read_bytes()
licenses = {'PyYAML': 'MIT', 'cryptography': 'Apache-2.0 OR BSD-3-Clause', 'cffi': 'MIT', 'pycparser': 'BSD-3-Clause'}
components = []
for dependency in project['dependencies']:
    name, pinned = dependency.split('==')
    components.append({'type': 'library', 'name': name, 'version': pinned, 'bom-ref': 'dependency:' + name,
                       'purl': 'pkg:pypi/' + name.lower() + '@' + pinned,
                       'licenses': [{'expression': licenses[name]}]})
bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
       'metadata': {'component': {'type': 'application', 'name': 'kechaa', 'version': version, 'bom-ref': 'kechaa',
                                  'licenses': [{'license': {'id': 'MIT'}}]},
                    'properties': [{'name': 'kechaa:inventory-scope', 'value': 'Declared Python dependencies only. No installed wheel, Rust, OpenSSL or interpreter attestation; no third-party binaries bundled.'},
                                   {'name': 'kechaa:python-requires', 'value': project['requires-python']}]},
       'components': components,
       'dependencies': [{'ref': 'kechaa', 'dependsOn': [c['bom-ref'] for c in components]}],
       'compositions': [{'aggregate': 'incomplete', 'assemblies': ['kechaa']}]}
payloads['sbom.cdx.json'] = (json.dumps(bom, sort_keys=True, indent=2) + '\n').encode()
payloads['MANIFEST.sha256'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n' for name, data in sorted(payloads.items())).encode()
with archive.open("wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as output:
            for relative, data in sorted(payloads.items()):
                info = tarfile.TarInfo("kechaa-" + version + "/" + relative)
                info.size, info.mtime, info.uid, info.gid = len(data), 0, 0, 0
                info.mode = 0o755 if relative == "bin/kechaa" else 0o644
                output.addfile(info, io.BytesIO(data))
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_suffix(archive.suffix + ".sha256").write_text(checksum + "  " + archive.name + "\n")
print(str(archive))
print(checksum)
