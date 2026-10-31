"""Explicit dependency startup, without site hooks or inherited import paths.

The administrator-provided interpreter and standard library are prerequisites.
This is an ownership check, not third-party build or native-library attestation.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import sysconfig

PINNED = {"PyYAML": "6.0.3", "cryptography": "48.0.1", "cffi": "2.0.0", "pycparser": "3.0"}


def _trusted(path: Path) -> None:
    for component in (path, *path.parents):
        st = component.lstat()
        if st.st_uid != 0 or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
            raise RuntimeError("Root startup requires administrator-owned, non-writable import paths: " + str(component))


def configure() -> dict:
    if not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError("Start KECHAA with Python -IS or the installed entrypoint. Site hooks must not run before authorization.")
    # Before Python 3.14, -S leaves sys.prefix at the base interpreter for venvs.
    # Keep the supplied executable path to locate its explicit venv wheel root.
    environment = Path(sys.executable).absolute().parent.parent
    venv = environment / "pyvenv.cfg"
    if venv.is_file():
        candidates = [environment / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"]
    else:
        candidates = [Path(sysconfig.get_path(name)) for name in ("purelib", "platlib")]
    sites = sorted({str(path.resolve(strict=True)) for path in candidates})
    count = 0
    if os.geteuid() == 0:
        _trusted(Path(__file__).resolve())
        _trusted(Path(sys.executable).resolve())
        if venv.is_file():
            _trusted(venv)
        for site in sites:
            root = Path(site)
            _trusted(root)
            # Checking only the directory misses a pre-existing writable module.
            for parent, directories, files in os.walk(root, followlinks=False):
                for name in directories + files:
                    path = Path(parent) / name
                    st = path.lstat()
                    count += 1
                    if count > 30000:
                        raise RuntimeError("Dependency inventory exceeds 30000 entries; use a minimal dedicated runtime.")
                    if (st.st_uid != 0 or st.st_mode & 0o022 or
                            not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode))):
                        raise RuntimeError("Unsafe dependency entry; protected startup refused: " + str(path))
    # No site.addsitedir: .pth files and sitecustomize must remain inert.
    for site in sites:
        if site not in sys.path:
            sys.path.append(site)
    from importlib.metadata import version
    if any(version(name) != expected for name, expected in PINNED.items()):
        raise RuntimeError("Install the exact reviewed dependencies from requirements.txt in a dedicated runtime.")
    return {"site_hooks": "disabled", "dependency_roots": sites,
            "root_ownership_checked": os.geteuid() == 0, "checked_entries": count,
            "native_build_attestation": False}


def main() -> int:
    try:
        configure()
    except (OSError, ValueError, RuntimeError, ImportError) as exc:
        print("KECHAA startup refused: " + str(exc), file=sys.stderr)
        return 126
    from kechaa.cli import main as cli_main
    return cli_main()
