"""KECHAA Local API v1: one bounded JSON line per Unix-domain connection."""

from __future__ import annotations

import ctypes
import os
import platform
import socket
import stat
import struct

from .common import MAX_MESSAGE, KechaaError, canonical, decode, fields, require


def peer_credentials(sock) -> tuple[int, int]:
    if platform.system() == "Linux":
        _, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        return uid, gid
    if platform.system() == "Darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
        result = libc.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid))
        require(result == 0, "peer_credentials", "Cannot authenticate the Unix-socket peer.")
        return uid.value, gid.value
    raise KechaaError("peer_credentials", "No peer-credential verifier for this operating system.", "compatibility_block")


def call(path: str, operation: str, data: dict | None = None, timeout: int = 15, expected_uid: int | None = None) -> dict:
    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise KechaaError("daemon_unavailable", "Daemon socket is unavailable. Start or recover the configured service; no unrestricted execution fallback is permitted.", "operational_error") from exc
    require(stat.S_ISSOCK(st.st_mode) and not st.st_mode & 0o002, "socket_permissions", "Expected a Unix socket without world-write access.")
    if expected_uid is None:
        expected_uid = st.st_uid
    message = canonical({"v": 1, "operation": operation, "data": data or {}}) + b"\n"
    require(len(message) <= MAX_MESSAGE, "message_size", "Request exceeds 256 KiB.", "invalid_request")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(path)
        uid, _ = peer_credentials(sock)
        require(uid == expected_uid and uid in (0, os.geteuid()), "daemon_identity", "Socket peer is not the expected root or same-user diagnostic daemon.")
        if operation == "execute":
            require(uid == 0, "daemon_identity", "Protected execution requires a root-owned daemon; a same-user service cannot assert kernel containment.")
        sock.sendall(message)
        sock.shutdown(socket.SHUT_WR)
        chunks = bytearray()
        # Execution output can be up to 4 MiB per action, encoded as base64.
        limit = 12582912
        while len(chunks) <= limit:
            piece = sock.recv(min(65536, limit + 1 - len(chunks)))
            if not piece:
                break
            chunks.extend(piece)
        require(bool(chunks), "daemon_disconnected", "Daemon disconnected before returning a result. The grant may already be consumed; inspect recovery state before requesting fresh authorization.", "operational_error")
        response = decode(bytes(chunks), limit)
        fields(response, {"v", "ok", "request_id"}, {"result", "error"}, "response")
        require(response["v"] == 1 and type(response["ok"]) is bool, "protocol_version", "Unsupported or malformed server response.")
        if not response["ok"]:
            err = fields(response["error"], {"code", "message", "category"}, where="error")
            raise KechaaError(err["code"], err["message"], err["category"])
        return response["result"]
