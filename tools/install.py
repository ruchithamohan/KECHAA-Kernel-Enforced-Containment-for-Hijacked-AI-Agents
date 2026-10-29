#!/usr/bin/env -S python3 -IS
"""Offline, explicit-prefix installation and conservative manifest-based removal."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from contextlib import ExitStack, contextmanager


@contextmanager
def directory(path: Path, *, create: bool = False):
    """Pin a directory without following links in any path component."""
    if not path.is_absolute() or '..' in path.parts:
        raise SystemExit('Use an absolute prefix without parent traversal.')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o755, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def checked_read(parent: int, name: str, limit: int) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise SystemExit('Expected a bounded regular installed file: ' + name)
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if len(data) > limit or identity(before) != identity(after):
            raise SystemExit('Installed file changed while reading; removal refused: ' + name)
        return bytes(data), after
    finally:
        os.close(descriptor)


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit('Duplicate manifest key; removal refused.')
        result[key] = value
    return result


def uninstall(prefix: Path, *, remove: bool = True) -> None:
    # Verify every entry before the first unlink. Directory descriptors prevent
    # ancestor symlinks from redirecting removal outside the inspected prefix.
    with ExitStack() as stack:
        root = stack.enter_context(directory(prefix))
        root_stat = os.fstat(root)
        if root_stat.st_uid != os.geteuid() or root_stat.st_mode & 0o022:
            raise SystemExit('Removal requires an owner-controlled prefix without group/world write access.')
        raw, manifest_stat = checked_read(root, 'kechaa-install.json', 262144)
        data = json.loads(raw, object_pairs_hook=unique_keys)
        if (not isinstance(data, dict) or set(data) != {'schema', 'files'} or
                type(data['schema']) is not int or data['schema'] != 1 or
                not isinstance(data['files'], dict) or not 2 <= len(data['files']) <= 128 or
                not {'bin/kechaa', 'lib/kechaa/__init__.py'} <= set(data['files'])):
            raise SystemExit('Unrecognized installation manifest; removal refused.')
        directories = {'.': root}
        verified = []
        for name, checksum in data['files'].items():
            if ((name != 'bin/kechaa' and not re.fullmatch(r'lib/kechaa/(?:[a-zA-Z_][a-zA-Z_0-9]*/)*[a-zA-Z_][a-zA-Z_0-9]*\.py', name)) or
                    not isinstance(checksum, str) or not re.fullmatch('[0-9a-f]{64}', checksum)):
                raise SystemExit('Unrecognized manifest path or checksum; removal refused.')
            relative = Path(name)
            parent = root
            for part in relative.parents[::-1][1:]:
                key = str(part)
                if key not in directories:
                    descriptor = os.open(part.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
                    stack.callback(os.close, descriptor)
                    st = os.fstat(descriptor)
                    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
                        raise SystemExit('Installed directory is not owner-controlled; removal refused.')
                    directories[key] = descriptor
                parent = directories[key]
            content, st = checked_read(parent, relative.name, 4194304)
            if hashlib.sha256(content).hexdigest() != checksum:
                raise SystemExit('Installed file was changed; preserve it and review manually: ' + name)
            verified.append((parent, relative.name, st))
        # Recheck identities after the complete validation pass. Concurrent
        # writes by the installation owner are outside the removal trust model.
        for parent, name, before in verified + [(root, 'kechaa-install.json', manifest_stat)]:
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise SystemExit('Installation changed during verification; nothing removed.')
        if not remove:
            print(json.dumps({'verified_files': len(verified), 'integrity': 'matches local installation manifest',
                              'authenticated_release': False, 'manifest_sha256': hashlib.sha256(raw).hexdigest()}))
            return
        for parent, name, _ in verified:
            os.unlink(name, dir_fd=parent)
        os.unlink('kechaa-install.json', dir_fd=root)
        for name in sorted((key for key in directories if key != '.'), key=lambda key: len(Path(key).parts), reverse=True):
            relative = Path(name)
            try:
                os.rmdir(relative.name, dir_fd=directories[str(relative.parent)])
            except OSError:
                # Nonempty directories may contain user data or Python caches.
                pass
    print(json.dumps({'removed': 'manifest-listed program files', 'preserved': 'all state, policies, audit records, and unrelated files'}))


def main():
    if os.geteuid() == 0 and (not sys.flags.isolated or not sys.flags.no_site):
        raise SystemExit('Root installation requires: python -IS tools/install.py. Use an administrator-controlled interpreter; site hooks must be disabled.')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('install', 'verify', 'uninstall'))
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--python', default=sys.executable, help='Interpreter already providing pinned dependencies')
    args = parser.parse_args()
    prefix = args.prefix.absolute()
    if prefix.is_symlink():
        raise SystemExit('Refusing a symlink installation prefix.')
    manifest = prefix / 'kechaa-install.json'
    if args.operation in ('verify', 'uninstall'):
        uninstall(prefix, remove=args.operation == 'uninstall')
        return
    if prefix.exists() and any(prefix.iterdir()):
        raise SystemExit('Choose a new empty prefix. Upgrade side-by-side; never overwrite an installation.')
    interpreter = str(Path(args.python).absolute())
    if any(c.isspace() for c in interpreter) or '\x00' in interpreter:
        raise SystemExit('Interpreter path must not contain whitespace or NUL.')
    source = Path(__file__).resolve().parent.parent / 'kechaa'
    probe_source = ('import sys\n'
                    'sys.path.insert(0, ' + repr(str(source.parent)) + ')\n'
                    'from kechaa.bootstrap import configure\n'
                    'configure()\n'
                    'import yaml, cryptography\n'
                    'sys.exit(0 if sys.version_info >= (3, 11) else 1)\n')
    probe = subprocess.run([interpreter, '-IS', '-c', probe_source],
                           check=False, timeout=15, capture_output=True)
    if probe.returncode:
        raise SystemExit('Interpreter requires Python 3.11+ and all exact dependency versions from requirements.txt. Install reviewed dependencies first; this installer never downloads.')
    with directory(prefix, create=True) as descriptor:
        st = os.fstat(descriptor)
        if st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise SystemExit('Installation requires an owner-controlled prefix without group/world write access.')
    records = {}
    for path in sorted(source.rglob('*.py')):
        relative = path.relative_to(source)
        target = prefix / 'lib' / 'kechaa' / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        target.chmod(0o644)
        records[str(target.relative_to(prefix))] = hashlib.sha256(target.read_bytes()).hexdigest()
    binary = prefix / 'bin' / 'kechaa'
    binary.parent.mkdir(mode=0o755, exist_ok=True)
    # A fixed shebang interpreter avoids PATH or shell expansion. Reject unsafe paths.
    launcher = (source.parent / 'bin' / 'kechaa').read_text().split('\n', 1)[1]
    if launcher.count('LIB_DIRECTORY = ""') != 1:
        raise SystemExit('Unrecognized source launcher; installation refused.')
    binary.write_text('#!' + interpreter + ' -IS\n' + launcher.replace('LIB_DIRECTORY = ""', 'LIB_DIRECTORY = "lib"'))
    binary.chmod(0o755)
    records['bin/kechaa'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest.write_text(json.dumps({'schema': 1, 'files': records}, indent=2) + '\n')
    manifest.chmod(0o644)
    subprocess.run([str(binary), 'version'], check=True, timeout=15)
    print(json.dumps({'installed': str(binary), 'services_started': False, 'path_modified': False}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise SystemExit('Installation/removal stopped: ' + str(exc)) from exc
