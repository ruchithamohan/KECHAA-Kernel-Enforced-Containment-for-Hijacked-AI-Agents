"""Transactional state and an independently verifiable, signed audit chain."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import io
import os
import re
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import KechaaError, atomic_write, canonical, decode, fields, integer, read_bounded, require, secure_directory

ZERO = "0" * 64
MAX_AUDIT = 50000
MAX_EXPORT = 268435456
HASH = re.compile(r"[0-9a-f]{64}\Z")


def verify_record(item: dict, key: Ed25519PublicKey, previous: str, sequence: int) -> str:
    """Validate untrusted evidence structure before indexing or authenticating it."""
    try:
        fields(item, {"record", "hash", "signature"}, where="audit item")
        record = fields(item["record"], {"schema", "sequence", "time_ms", "type", "actor_uid", "previous", "body"}, where="audit record")
        require(type(record["schema"]) is int and record["schema"] == 1, "audit_schema", "Unsupported audit schema.")
        integer(record["sequence"], 1, MAX_AUDIT, "audit sequence")
        integer(record["time_ms"], 0, 9007199254740991, "audit timestamp")
        integer(record["actor_uid"], -1, 4294967295, "audit actor")
        require(isinstance(record["type"], str) and 1 <= len(record["type"]) <= 96 and isinstance(record["body"], dict), "audit_format", "Invalid audit event type or body.")
        require(isinstance(item["hash"], str) and HASH.fullmatch(item["hash"]) and isinstance(record["previous"], str) and HASH.fullmatch(record["previous"]), "audit_format", "Invalid audit hash encoding.")
        require(isinstance(item["signature"], str) and len(item["signature"]) == 88, "audit_signature", "Invalid audit signature encoding.")
        require(record["sequence"] == sequence and record["previous"] == previous, "audit_chain", "Audit sequence or chain is broken.")
        raw = canonical(record)
        require(len(raw) <= 65536, "audit_size", "Audit record exceeds 64 KiB.")
        key.verify(base64.b64decode(item["signature"], validate=True), b"KECHAA-AUDIT-1\x00" + raw)
        head = hashlib.sha256(raw).hexdigest()
        require(head == item["hash"], "audit_hash", "Audit record hash mismatch.")
        return head
    except (ValueError, InvalidSignature) as exc:
        raise KechaaError("audit_signature", f"Audit record {sequence} has an invalid signature.") from exc
    except KechaaError as exc:
        raise KechaaError(exc.code, f"Audit record {sequence}: {exc.message}", exc.category) from exc


class Store:
    def __init__(self, path: Path):
        self.path = path
        secure_directory(path, os.geteuid(), create=True)
        require(not (path / 'restore-in-progress').exists(), 'restore_incomplete', 'Restoration did not finish. Preserve this directory and restore the verified backup into another new destination.')
        self.lock_fd = os.open(path / "daemon.lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self.lock_fd)
            raise KechaaError("daemon_running", "Another daemon owns this state directory.", "operational_error") from exc
        self.db = None
        try:
            self.initialize(path)
        except BaseException:
            try:
                if self.db is not None:
                    self.db.close()
            finally:
                os.close(self.lock_fd)
            raise

    def initialize(self, path: Path) -> None:
        key_path = path / "signing.key"
        database = path / "state.db"
        if not key_path.exists():
            require(not database.exists(), "key_missing", "Signing key is missing for an existing database; restore it, do not reset state.")
            key = Ed25519PrivateKey.generate()
            raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            # The process lock makes creation single-writer; no replacement of existing keys.
            fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(raw)
                out.flush()
                os.fsync(out.fileno())
        st = key_path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077,
                "key_permissions", "Signing key must be daemon-owned with mode 0600.")
        self.key = Ed25519PrivateKey.from_private_bytes(read_bounded(key_path, 32))
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public_path = path / "audit.pub"
        if public_path.exists():
            require(read_bounded(public_path, 32) == public, "key_changed", "Audit public key does not match the signing key.")
        else:
            atomic_write(public_path, public, 0o644)
        if database.exists():
            st = database.lstat()
            require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077,
                    "database_permissions", "State database must be daemon-owned with mode 0600.")
        self.db = sqlite3.connect(database, isolation_level=None, timeout=3)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA trusted_schema=OFF")
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone():
            require(self.meta("schema") in (None, "1"), "state_schema", "Unsupported database schema; use a reviewed migration before upgrading.")
        os.chmod(database, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.db.execute("PRAGMA max_page_count=32768")
        self.db.execute("PRAGMA journal_size_limit=4194304")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS policies (version TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, uid INTEGER NOT NULL, session TEXT NOT NULL,
            body BLOB NOT NULL, revision INTEGER NOT NULL, mode TEXT NOT NULL, score INTEGER NOT NULL, closed INTEGER NOT NULL);
          CREATE UNIQUE INDEX IF NOT EXISTS run_session ON runs(uid, session);
          CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, run TEXT NOT NULL REFERENCES runs(id),
            state TEXT NOT NULL, body BLOB NOT NULL, signature TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS grant_run ON grants(run, state);
          CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, record BLOB NOT NULL,
            hash TEXT NOT NULL, signature TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS history (seq INTEGER PRIMARY KEY AUTOINCREMENT,
            run TEXT NOT NULL REFERENCES runs(id), time_ms INTEGER NOT NULL,
            kind TEXT NOT NULL, body BLOB NOT NULL, risk INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS history_run ON history(run, seq);
          CREATE TABLE IF NOT EXISTS anchors (id INTEGER PRIMARY KEY AUTOINCREMENT,
            time_ms INTEGER NOT NULL, checkpoint BLOB NOT NULL, signature TEXT NOT NULL);
        """)
        version = self.meta("schema")
        require(version in (None, "1"), "state_schema", "Unsupported database schema; use a reviewed migration before upgrading.")
        if version is None:
            with self.transaction():
                self.set_meta("schema", "1")
        require(self.db.execute("PRAGMA quick_check").fetchone()[0] == "ok", "state_corrupt", "SQLite integrity check failed; restore a verified backup.")
        self.verify()
        receipt_path = path / 'restore-receipt.json'
        if receipt_path.exists():
            raw = read_bounded(receipt_path, 8192)
            receipt_hash = hashlib.sha256(raw).hexdigest()
            receipt = fields(decode(raw), {'receipt', 'signature'}, where='restore receipt')
            self.authenticate('KECHAA-RESTORE-1', receipt['receipt'], receipt['signature'])
            if self.meta('restore_receipt') != receipt_hash:
                with self.transaction():
                    self.event('state_restored', receipt['receipt'], os.geteuid())
                    self.set_meta('restore_receipt', receipt_hash)

    def meta(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def sign(self, domain: str, document: dict) -> str:
        return base64.b64encode(self.key.sign(domain.encode("ascii") + b"\x00" + canonical(document))).decode("ascii")

    def authenticate(self, domain: str, document: dict, signature: str) -> None:
        try:
            self.key.public_key().verify(base64.b64decode(signature, validate=True), domain.encode("ascii") + b"\x00" + canonical(document))
        except (ValueError, InvalidSignature) as exc:
            raise KechaaError("signature_invalid", "Authenticated state failed signature verification.") from exc

    def event(self, kind: str, body: dict, uid: int) -> dict:
        require(self.db.in_transaction, "audit_transaction", "Audit events must share the state transaction.", "operational_error")
        last = self.db.execute("SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq, previous = (last[0] + 1, last[1]) if last else (1, ZERO)
        require(seq <= MAX_AUDIT, "audit_full", "Audit capacity reached. Execution is held; export and archive state through an administrator.", "operational_error")
        record = {"schema": 1, "sequence": seq, "time_ms": time.time_ns() // 1000000,
                  "type": kind, "actor_uid": uid, "previous": previous, "body": body}
        raw = canonical(record)
        require(len(raw) <= 65536, "audit_size", "Audit event exceeds the bounded event size.", "operational_error")
        hashed = hashlib.sha256(raw).hexdigest()
        signature = self.sign("KECHAA-AUDIT-1", record)
        self.db.execute("INSERT INTO audit VALUES(?,?,?,?)", (seq, raw, hashed, signature))
        self.set_meta("audit_head", hashed)
        self.set_meta("audit_sequence", str(seq))
        return {"sequence": seq, "hash": hashed}

    def history(self, run: str, kind: str, body: dict, risk: int = 0) -> int:
        require(self.db.in_transaction, "history_transaction", "History events must share the state transaction.", "operational_error")
        require(isinstance(run, str) and 1 <= len(run) <= 96 and isinstance(kind, str) and 1 <= len(kind) <= 96,
                "history_format", "Invalid history event identity.", "operational_error")
        require(isinstance(risk, int) and 0 <= risk <= 100, "history_risk", "History risk must be bounded.", "operational_error")
        raw = canonical(body)
        require(len(raw) <= 32768, "history_size", "History event exceeds the bounded event size.", "operational_error")
        cursor = self.db.execute("INSERT INTO history(run,time_ms,kind,body,risk) VALUES(?,?,?,?,?)",
                                 (run, time.time_ns() // 1000000, kind, raw, risk))
        # Retain the most recent 512 trusted observations per run. Audit records
        # remain the tamper-evident permanent summary; this bounded table is the
        # online decision cache and must never fail open on read errors.
        self.db.execute("DELETE FROM history WHERE run=? AND seq NOT IN (SELECT seq FROM history WHERE run=? ORDER BY seq DESC LIMIT 512)",
                        (run, run))
        return int(cursor.lastrowid)

    def history_for_run(self, run: str, limit: int = 64) -> list[dict]:
        require(isinstance(run, str) and 1 <= len(run) <= 96, "history_run", "Invalid run id.", "invalid_request")
        require(isinstance(limit, int) and 1 <= limit <= 512, "history_limit", "Invalid history limit.", "invalid_request")
        rows = self.db.execute("SELECT seq,time_ms,kind,body,risk FROM history WHERE run=? ORDER BY seq DESC LIMIT ?", (run, limit)).fetchall()
        return [{"seq": row["seq"], "time_ms": row["time_ms"], "kind": row["kind"],
                 "body": decode(row["body"]), "risk": row["risk"]} for row in rows][::-1]

    def anchor(self, uid: int) -> dict:
        document = self.checkpoint(uid)
        with self.transaction():
            self.db.execute("INSERT INTO anchors(time_ms,checkpoint,signature) VALUES(?,?,?)",
                            (time.time_ns() // 1000000, canonical(document["checkpoint"]), document["signature"]))
            self.event("audit_anchor_created", {"head": document["checkpoint"]["head"],
                        "sequence": document["checkpoint"]["sequence"]}, uid)
        return document

    def anchors(self, after: int = 0, limit: int = 20) -> list[dict]:
        rows = self.db.execute("SELECT id,time_ms,checkpoint,signature FROM anchors WHERE id>? ORDER BY id LIMIT ?", (after, limit)).fetchall()
        return [{"id": row["id"], "time_ms": row["time_ms"], "checkpoint": decode(row["checkpoint"]),
                 "signature": row["signature"]} for row in rows]

    def verify(self) -> dict:
        head, count = ZERO, 0
        for row in self.db.execute("SELECT * FROM audit ORDER BY seq"):
            count += 1
            require(count <= MAX_AUDIT and row["seq"] == count,
                    "audit_chain", "Audit sequence or chain is broken.")
            head = verify_record({"record": decode(row["record"]), "hash": row["hash"], "signature": row["signature"]}, self.key.public_key(), head, count)
        require(self.meta("audit_head") in ((None, ZERO) if count == 0 else (head,)), "audit_truncated", "Audit head does not match persisted state.")
        require(int(self.meta("audit_sequence") or 0) == count, "audit_truncated", "Audit length does not match persisted state.")
        return {"verified": True, "events": count, "head": head,
                "limitation": "Root/key compromise and rollback of the entire database need an independently retained checkpoint to detect."}

    def checkpoint(self, uid: int) -> dict:
        verified = self.verify()
        body = {"schema": 1, "head": verified["head"], "sequence": verified["events"],
                "time_ms": time.time_ns() // 1000000, "policy": self.meta("active_policy")}
        # This attests an exact existing prefix; creating a checkpoint adds no
        # uncheckpointed tail and can be used even at the audit storage limit.
        return {"checkpoint": body, "signature": self.sign("KECHAA-CHECKPOINT-1", body)}

    def export(self, after: int = 0, limit: int = 100) -> list[dict]:
        rows = self.db.execute("SELECT * FROM audit WHERE seq>? ORDER BY seq LIMIT ?", (after, limit))
        return [{"record": decode(row["record"]), "hash": row["hash"], "signature": row["signature"]} for row in rows]

    def close(self) -> None:
        try:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            try:
                self.db.close()
            finally:
                os.close(self.lock_fd)


def verify_export(data: bytes, public_key: bytes, expected_head: str | None = None) -> dict:
    return verify_stream(io.BytesIO(data), public_key, expected_head)


def verify_stream(stream, public_key: bytes, expected_head: str | None = None) -> dict:
    require(len(public_key) == 32, "audit_key", "Expected a raw 32-byte Ed25519 public key.")
    require(expected_head is None or isinstance(expected_head, str) and HASH.fullmatch(expected_head), "audit_head", "Expected head must be a lowercase SHA-256 digest.")
    key = Ed25519PublicKey.from_public_bytes(public_key)
    previous, count, total = ZERO, 0, 0
    while True:
        line = stream.readline(262145)
        if not line:
            break
        total += len(line)
        require(total <= MAX_EXPORT and len(line) <= 262144, "audit_size", "Audit export exceeds the supported byte limit.")
        item = decode(line)
        count += 1
        require(count <= MAX_AUDIT, "audit_size", "Too many audit records.")
        previous = verify_record(item, key, previous, count)
    if expected_head is not None:
        require(previous == expected_head, "audit_head", "Export does not match the independently retained head.")
    return {"verified": True, "events": count, "head": previous, "tail_authenticated": expected_head is not None}


def verify_file(path: Path, public_key: bytes, expected_head: str | None = None) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_size <= MAX_EXPORT, "audit_size", "Expected a bounded regular audit export.")
        return verify_stream(stream, public_key, expected_head)


def verify_checkpoint(document: dict, public_key: bytes) -> dict:
    fields(document, {"checkpoint", "signature"}, where="checkpoint envelope")
    body = fields(document["checkpoint"], {"schema", "head", "sequence", "time_ms", "policy"}, where="checkpoint")
    require(type(body["schema"]) is int and body["schema"] == 1 and isinstance(body["head"], str) and HASH.fullmatch(body["head"]), "audit_checkpoint", "Invalid checkpoint schema or head.")
    integer(body["sequence"], 0, MAX_AUDIT, "checkpoint sequence")
    integer(body["time_ms"], 0, 9007199254740991, "checkpoint timestamp")
    require(len(public_key) == 32 and isinstance(document["signature"], str) and len(document["signature"]) == 88, "audit_checkpoint", "Invalid checkpoint key or signature encoding.")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(base64.b64decode(document["signature"], validate=True), b"KECHAA-CHECKPOINT-1\x00" + canonical(body))
    except (ValueError, InvalidSignature) as exc:
        raise KechaaError("audit_checkpoint", "Checkpoint authentication failed.") from exc
    return body


def export_offline(state: Path, output: Path) -> dict:
    """Read-only, consistent recovery export; never loads the signing key."""
    secure_directory(state, os.geteuid())
    database = state / "state.db"
    st = database.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_size <= 134217728,
            "database_permissions", "Expected a bounded, owner-controlled state database.")
    db = sqlite3.connect(database.absolute().as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        head_row = db.execute("SELECT value FROM meta WHERE key='audit_head'").fetchone()
        head = head_row[0] if head_row else ZERO
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        count = 0
        with os.fdopen(fd, "wb") as stream:
            for record, hashed, signature in db.execute("SELECT record,hash,signature FROM audit ORDER BY seq"):
                count += 1
                require(count <= MAX_AUDIT, "audit_capacity", "Database exceeds supported audit capacity.")
                stream.write(canonical({"record": decode(record), "hash": hashed, "signature": signature}) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return {"exported_events": count, "head": head, "read_only": True, "file": str(output)}
    finally:
        db.close()
