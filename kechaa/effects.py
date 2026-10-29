"""Bound execution requests and conservative input identification."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
from contextlib import contextmanager
from pathlib import Path

from .common import fields, path_string, require, trusted_path, within


@contextmanager
def open_path(path: str, *, directory: bool = False):
    """Walk from / using directory descriptors; reject symlinks at every component."""
    path = path_string(path)
    parts = [part for part in path.split("/") if part]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for i, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            if i < len(parts) - 1 or directory:
                flags |= os.O_DIRECTORY
            new_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = new_fd
        if directory:
            require(stat.S_ISDIR(os.fstat(fd).st_mode), "cwd_type", "Working directory is not a directory.")
        yield fd
    finally:
        os.close(fd)


def file_digest(fd: int, limit: int = 67108864) -> dict:
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "artifact_type", "Inputs and executables must be bounded regular files.", "compatibility_block")
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    count = 0
    while True:
        chunk = os.read(fd, min(65536, limit + 1 - count))
        if not chunk:
            break
        count += len(chunk)
        require(count <= limit, "artifact_size", "An artifact grew beyond the size limit.")
        h.update(chunk)
    after = os.fstat(fd)
    require((before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "artifact_changed", "An input changed during hashing; request a fresh grant.")
    return {"sha256": h.hexdigest(), "device": str(after.st_dev), "inode": str(after.st_ino), "size": after.st_size,
            "mtime_ns": str(after.st_mtime_ns), "ctime_ns": str(after.st_ctime_ns)}


def elf_interpreter(path: str) -> str | None:
    """Inspect ELF64 without executing the binary or ldd; return its loader.

    The canonical loader must be explicitly present in the approved inventory.
    Only the little-endian ELF64 format of the supported Linux targets is used.
    """
    with open_path(path) as fd:
        header = os.pread(fd, 64, 0)
        if not header.startswith(b"\x7fELF"):
            return None
        require(len(header) == 64 and header[4:6] == b"\x02\x01", "elf_format",
                "Only little-endian ELF64 executables are supported.", "compatibility_block")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        require(size == 56 and count <= 128 and offset + size * count <= os.fstat(fd).st_size,
                "elf_format", "Invalid or oversized ELF program table.", "compatibility_block")
        interpreter = None
        for index in range(count):
            entry = os.pread(fd, size, offset + index * size)
            require(len(entry) == size, "elf_changed", "Executable changed during ELF inspection.")
            kind, _, position, _, _, length, _, _ = struct.unpack("<IIQQQQQQ", entry)
            if kind == 3:  # PT_INTERP
                require(interpreter is None and 2 <= length <= 4096, "elf_format", "Invalid ELF interpreter entry.")
                raw = os.pread(fd, length, position)
                require(len(raw) == length and raw.endswith(b"\x00") and b"\x00" not in raw[:-1],
                        "elf_format", "Invalid ELF interpreter path.")
                interpreter = str(Path(path_string(raw[:-1].decode("utf-8"))).resolve(strict=True))
        return interpreter


def request(value: dict) -> dict:
    fields(value, {"argv", "cwd"}, {"inputs"}, "action")
    argv = value["argv"]
    require(isinstance(argv, list) and 1 <= len(argv) <= 128 and
            all(isinstance(a, str) and len(a.encode("utf-8")) <= 16384 and "\x00" not in a for a in argv),
            "action_argv", "argv must contain 1 to 128 bounded strings without NUL.", "invalid_request")
    path_string(argv[0])
    require(sum(len(a.encode("utf-8")) for a in argv) <= 65536, "action_size", "Combined arguments exceed 64 KiB.", "invalid_request")
    cwd = path_string(value["cwd"])
    inputs = value.get("inputs", [])
    require(isinstance(inputs, list) and len(inputs) <= 16, "action_inputs", "At most 16 explicit input paths are supported.", "invalid_request")
    normalized = sorted({path_string(p) for p in inputs})
    require(all(within(p, cwd) for p in normalized), "action_inputs", "Input paths must be inside the action's working directory.")
    return {"argv": argv[:], "cwd": cwd, "inputs": normalized}


def identify(action: dict, effects: dict, *, privileged: bool = False) -> dict:
    """No command is executed for prediction, including package manager commands."""
    with open_path(action["cwd"], directory=True) as fd:
        st = os.fstat(fd)
        cwd_identity = {"device": str(st.st_dev), "inode": str(st.st_ino)}
    executables = {}
    total_bytes = 0
    for path in effects["execute"]:
        if privileged:
            trusted_path(Path(path), 0)
            loader = elf_interpreter(path)
            require(loader is None or loader in effects["execute"], "elf_interpreter",
                    f"ELF loader {loader} must be included in both the policy and confirmed contract executable lists. Regenerate or narrowly amend the policy.",
                    "policy_misconfiguration")
        # Policy paths must already be canonical, rather than silently following a link.
        with open_path(path) as fd:
            st = os.fstat(fd)
            require(st.st_mode & 0o111 != 0, "executable_mode", "A configured executable is not executable.", "policy_misconfiguration")
            if privileged:
                require(st.st_uid == 0 and not st.st_mode & 0o022, "executable_ownership", "Protected execution requires root-owned executables without group/world write access.")
            executables[path] = file_digest(fd)
            total_bytes += executables[path]["size"]
            require(total_bytes <= 134217728, "executable_budget", "Executable inventory exceeds the 128 MiB hashing budget.", "compatibility_block")
    paths = set(action["inputs"])
    basename = Path(action["argv"][0]).name
    classification = "shell" if basename in ("sh", "bash", "dash", "zsh") else "generic"
    package_names = ("package.json", "package-lock.json", "npm-shrinkwrap.json")
    if basename in ("npm", "node", "nodejs"):
        classification = "node-offline-capability"
        for name in package_names:
            candidate = str(Path(action["cwd"]) / name)
            if os.path.lexists(candidate):
                paths.add(candidate)
    require(len(paths) <= 19, "action_inputs", "Too many identified inputs.")
    artifacts = {}
    for path in sorted(paths):
        require(any(within(path, r) for r in effects["read"]), "input_read", "An input is outside the approved read envelope.")
        with open_path(path) as fd:
            artifacts[path] = file_digest(fd, 16777216)
    return {"cwd_identity": cwd_identity, "executables": executables, "artifacts": artifacts,
            "classification": classification,
            "integrity": "Digests rechecked at adoption; mutable scripts and transitive inputs are not frozen."}
