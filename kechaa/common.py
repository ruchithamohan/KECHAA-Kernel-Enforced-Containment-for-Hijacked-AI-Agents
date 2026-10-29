"""Strict encodings, bounded input, and filesystem primitives."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

MAX_MESSAGE = 262144
ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$")


class KechaaError(Exception):
    def __init__(self, code: str, message: str, category: str = "security_block"):
        super().__init__(message)
        self.code, self.message, self.category = code, message, category

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "category": self.category}


def require(condition: bool, code: str, message: str, category: str = "security_block") -> None:
    if not condition:
        raise KechaaError(code, message, category)


def validate_json(value: Any, depth: int = 0) -> None:
    require(depth <= 32, "schema_depth", "Document nesting exceeds 32 levels.", "invalid_request")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(abs(value) <= 9007199254740991, "schema_integer", "Integer exceeds the canonical range.", "invalid_request")
    elif isinstance(value, str):
        require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "schema_unicode", "Unpaired Unicode surrogate.", "invalid_request")
    elif isinstance(value, list):
        for item in value:
            validate_json(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            require(isinstance(key, str), "schema_key", "Object keys must be strings.", "invalid_request")
            validate_json(key, depth + 1)
            validate_json(item, depth + 1)
    else:
        raise KechaaError("schema_type", "Only strings, integers, booleans, null, lists and objects are supported.", "invalid_request")


def canonical(value: Any) -> bytes:
    """KECHAA-CJSON-1: sorted keys, ASCII escapes, no floats or insignificant space."""
    validate_json(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_key", f"Duplicate JSON key: {key!r}", "invalid_request")
        result[key] = value
    return result


def decode(data: bytes | str, limit: int = MAX_MESSAGE) -> Any:
    require(len(data) <= limit, "message_size", f"Document exceeds {limit} bytes.", "invalid_request")
    try:
        value = json.loads(data, object_pairs_hook=_pairs)
        validate_json(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise KechaaError("invalid_json", "Invalid JSON document.", "invalid_request") from exc


def fields(value: Any, required: set[str], optional: set[str] = frozenset(), where: str = "request") -> dict:
    require(isinstance(value, dict), "schema_object", f"{where} must be an object.", "invalid_request")
    require(set(value) >= required, "schema_missing", f"{where}: missing fields {sorted(required - set(value))}.", "invalid_request")
    require(set(value) <= required | optional, "schema_unknown", f"{where}: unknown fields {sorted(set(value) - required - optional)}.", "invalid_request")
    return value


def identifier(value: Any, where: str = "identifier") -> str:
    require(isinstance(value, str) and bool(ID.fullmatch(value)), "schema_identifier", f"Invalid {where}.", "invalid_request")
    return value


def integer(value: Any, low: int, high: int, where: str) -> int:
    require(type(value) is int and low <= value <= high, "schema_integer", f"{where} must be an integer from {low} to {high}.", "invalid_request")
    return value


def path_string(value: Any) -> str:
    require(isinstance(value, str) and value.startswith("/") and len(value) <= 4096,
            "schema_path", "Paths must be absolute and at most 4096 characters.", "policy_misconfiguration")
    require(not any(c in value for c in "\x00\n\r*?[]") and all(x not in (".", "..") for x in value.split("/")),
            "schema_path", "Paths cannot contain traversal, control characters or globs.", "policy_misconfiguration")
    return os.path.normpath(value)


def within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def overlap(a: str, b: str) -> bool:
    return within(a, b) or within(b, a)


def intersect_paths(left: list[str], right: list[str]) -> list[str]:
    return sorted({a if within(a, b) else b for a in left for b in right if overlap(a, b)})


def read_bounded(path: str | Path, limit: int = MAX_MESSAGE) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_size <= limit, "file_size", "Expected a bounded regular file.", "invalid_request")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) <= limit, "file_size", "File grew past the input limit.", "invalid_request")
        return bytes(data)
    finally:
        os.close(fd)


def secure_directory(path: Path, owner: int, create: bool = False) -> None:
    if owner == 0:
        # A root-owned leaf below an agent-writable parent can be renamed out
        # from under the daemon. Reject the complete administrative path.
        trusted_path(path.parent, 0)
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == owner and st.st_mode & 0o077 == 0,
            "state_permissions", "State directory must be a real directory owned by the daemon with mode 0700.")


def trusted_path(path: Path, owner: int = 0) -> None:
    path = path.absolute()
    require('..' not in path.parts, "trusted_path", "Administrative paths cannot contain parent traversal.")
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(path.parts[1:]):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(path.parts) - 2:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            st = os.fstat(fd)
            require(st.st_uid == owner and not st.st_mode & 0o022,
                    "trusted_path", "Every administrative path component must be administrator-owned and not group/world writable.")
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".kechaa-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
