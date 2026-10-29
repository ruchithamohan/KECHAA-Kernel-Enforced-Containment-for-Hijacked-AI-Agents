"""Offline, authenticated backups and restoration into a new private directory."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import os
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import canonical, decode, fields, integer, read_bounded, require, secure_directory
from .store import HASH, MAX_AUDIT, ZERO, verify_record

FILES = {"state.db": 134217728, "audit.pub": 32, "signing.key": 32}


@contextmanager
def stopped_state(state: Path):
    secure_directory(state, os.geteuid())
    fd = os.open(state / 'daemon.lock', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077,
                'state_lock', 'State lock must be a private, owner-controlled regular file.')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            require(False, 'daemon_running', 'Stop the daemon before backing up its state.', 'operational_error')
        yield
    finally:
        os.close(fd)


def file_hash(path: Path, limit: int) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        st = os.fstat(source.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o022 and st.st_size <= limit,
                'backup_file', 'Backup files must be bounded, owner-controlled regular files.')
        hashed, size = hashlib.sha256(), 0
        while chunk := source.read(1048576):
            size += len(chunk)
            require(size <= limit, 'backup_size', 'File grew beyond its supported size.')
            hashed.update(chunk)
        return hashed.hexdigest()


def database_summary(path: Path, public: bytes) -> dict:
    file_hash(path, FILES['state.db'])
    db = sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=3)
    try:
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA query_only=ON')
        require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'backup_database', 'Backup database failed SQLite integrity checking.')
        metadata = dict(db.execute('SELECT key,value FROM meta'))
        require(metadata.get('schema') == '1', 'state_schema', 'Unsupported backup schema; no automatic downgrade or migration is permitted.')
        key = Ed25519PublicKey.from_public_bytes(public)
        head, count = ZERO, 0
        for seq, raw, hashed, signature in db.execute('SELECT seq,record,hash,signature FROM audit ORDER BY seq'):
            count += 1
            require(count <= MAX_AUDIT and count == seq, 'audit_chain', 'Backup audit sequence is broken.')
            head = verify_record({'record': decode(raw), 'hash': hashed, 'signature': signature}, key, head, count)
        require(metadata.get('audit_head', ZERO) == head and metadata.get('audit_sequence', '0') == str(count),
                'audit_truncated', 'Backup audit does not match persisted checkpoint state.')
        return {'head': head, 'events': count, 'state_schema': 1}
    finally:
        db.close()


def write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_private(path: Path) -> None:
    require(not path.exists() and not path.is_symlink(), 'backup_destination', 'Choose a new destination; existing directories are never overwritten.', 'operational_error')
    secure_directory(path, os.geteuid(), create=True)


def backup(state: Path, destination: Path) -> dict:
    with stopped_state(state):
        raw_key = read_bounded(state / 'signing.key', 32)
        key_stat = (state / 'signing.key').lstat()
        require(key_stat.st_uid == os.geteuid() and not key_stat.st_mode & 0o077, 'key_permissions', 'Signing key must have private owner-only permissions.')
        key = Ed25519PrivateKey.from_private_bytes(raw_key)
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        require(read_bounded(state / 'audit.pub', 32) == public, 'key_changed', 'State key and public key disagree; backup refused.')
        summary = database_summary(state / 'state.db', public)
        create_private(destination)
        write_new(destination / 'state.db', b'')
        source = sqlite3.connect((state / 'state.db').absolute().as_uri() + '?mode=ro', uri=True, timeout=3)
        target = sqlite3.connect(destination / 'state.db')
        until = time.monotonic() + 15
        def progress(status, remaining, total):
            require(time.monotonic() < until, 'backup_timeout', 'Backup exceeded 15 seconds; incomplete destination was preserved for review.', 'operational_error')
        try:
            source.backup(target, pages=128, progress=progress, sleep=0.01)
        finally:
            target.close()
            source.close()
        write_new(destination / 'signing.key', raw_key)
        write_new(destination / 'audit.pub', public)
        require(database_summary(destination / 'state.db', public) == summary, 'backup_changed', 'Backup snapshot does not match the stopped source.')
        body = {'schema': 1, 'created_ms': time.time_ns() // 1000000, **summary,
                'files': {name: file_hash(destination / name, limit) for name, limit in FILES.items()}}
        signature = base64.b64encode(key.sign(b'KECHAA-BACKUP-1\x00' + canonical(body))).decode('ascii')
        # Manifest is the completion marker; partial directories are never valid backups.
        write_new(destination / 'manifest.json', canonical({'backup': body, 'signature': signature}) + b'\n')
        sync_directory(destination)
        return {'backup': str(destination), 'verified': True, 'contains_private_key': True, **summary}


def verify(backup_dir: Path, trusted_public: bytes, expected_head: str | None = None) -> dict:
    secure_directory(backup_dir, os.geteuid())
    fields_doc = fields(decode(read_bounded(backup_dir / 'manifest.json', 8192)), {'backup', 'signature'}, where='backup envelope')
    body = fields(fields_doc['backup'], {'schema', 'state_schema', 'created_ms', 'head', 'events', 'files'}, where='backup manifest')
    require(type(body['schema']) is int and body['schema'] == 1 and type(body['state_schema']) is int and body['state_schema'] == 1, 'backup_schema', 'Unsupported backup schema.')
    integer(body['events'], 0, MAX_AUDIT, 'backup event count')
    integer(body['created_ms'], 0, 9007199254740991, 'backup timestamp')
    require(isinstance(body['head'], str) and HASH.fullmatch(body['head']), 'backup_head', 'Invalid backup head.')
    hashes = fields(body['files'], set(FILES), where='backup files')
    require(len(trusted_public) == 32 and isinstance(fields_doc['signature'], str) and len(fields_doc['signature']) == 88, 'backup_signature', 'Invalid pinned key or backup signature encoding.')
    try:
        Ed25519PublicKey.from_public_bytes(trusted_public).verify(base64.b64decode(fields_doc['signature'], validate=True), b'KECHAA-BACKUP-1\x00' + canonical(body))
    except (ValueError, InvalidSignature):
        require(False, 'backup_signature', 'Backup was not authenticated by the independently trusted public key.')
    if expected_head is not None:
        require(expected_head == body['head'], 'backup_head', 'Backup does not match the independently retained audit head.')
    for name, limit in FILES.items():
        require(isinstance(hashes[name], str) and HASH.fullmatch(hashes[name]) and file_hash(backup_dir / name, limit) == hashes[name], 'backup_file', 'Backup file hash mismatch: ' + name)
    require((backup_dir / 'signing.key').lstat().st_mode & 0o077 == 0, 'key_permissions', 'Backup private key permissions are too broad.')
    require(read_bounded(backup_dir / 'audit.pub', 32) == trusted_public, 'backup_key', 'Backup public key does not match the independently trusted key.')
    summary = database_summary(backup_dir / 'state.db', trusted_public)
    require(summary['head'] == body['head'] and summary['events'] == body['events'], 'backup_head', 'Signed backup head does not match its audit database.')
    return {'verified': True, 'tail_authenticated': expected_head is not None, 'files': dict(hashes), **summary}


def restore(backup_dir: Path, destination: Path, trusted_public: bytes, expected_head: str, reason: str) -> dict:
    require(isinstance(expected_head, str) and HASH.fullmatch(expected_head), 'backup_head', 'Restoration requires an independently retained audit head.')
    require(8 <= len(reason) <= 1000, 'restore_reason', 'Give an administrative restore reason of 8 to 1000 characters.', 'invalid_request')
    summary = verify(backup_dir, trusted_public, expected_head)
    expected_files = summary.pop('files')
    create_private(destination)
    write_new(destination / 'restore-in-progress', b'Incomplete restoration. Do not start this directory.\n')
    # Only fixed manifest names are copied. No archive paths or user-selected files.
    for name, limit in FILES.items():
        source = os.open(backup_dir / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        target = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(source, 'rb') as input_file, os.fdopen(target, 'wb') as output:
            size = 0
            while chunk := input_file.read(1048576):
                size += len(chunk)
                require(size <= limit, 'backup_size', 'Backup file changed size during restoration.')
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        require(file_hash(destination / name, limit) == expected_files[name], 'backup_changed', 'Backup changed during restoration; do not start the incomplete destination.')
    key = Ed25519PrivateKey.from_private_bytes(read_bounded(destination / 'signing.key', 32))
    require(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == trusted_public, 'backup_key', 'Restored private key does not match the pinned key.')
    receipt = {'schema': 1, 'backup_head': expected_head, 'reason': reason, 'time_ms': time.time_ns() // 1000000}
    signature = base64.b64encode(key.sign(b'KECHAA-RESTORE-1\x00' + canonical(receipt))).decode('ascii')
    write_new(destination / 'restore-receipt.json', canonical({'receipt': receipt, 'signature': signature}) + b'\n')
    sync_directory(destination)
    (destination / 'restore-in-progress').unlink()
    sync_directory(destination)
    return {'restored': str(destination), 'services_started': False, 'grants_valid_after_startup': False, **summary}
