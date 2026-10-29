"""Bounded live evidence export pinned to one authenticated audit prefix."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .common import canonical, fields, require
from .protocol import call
from .recovery import create_private, sync_directory, write_new
from .store import MAX_EXPORT, ZERO, verify_checkpoint, verify_record


def export_live(socket: str, destination: Path, *, bundle: bool = False) -> dict:
    health = call(socket, 'health')
    public = base64.b64decode(health['public_key'], validate=True)
    checkpoint = call(socket, 'audit_checkpoint')
    bound = verify_checkpoint(checkpoint, public)
    if bundle:
        create_private(destination)
    output = destination / 'audit.jsonl' if bundle else destination
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    count, total, head = 0, 0, ZERO
    key = Ed25519PublicKey.from_public_bytes(public)
    with os.fdopen(fd, 'wb') as stream:
        while count < bound['sequence']:
            page = call(socket, 'audit_export', {'after': count, 'limit': min(50, bound['sequence'] - count)})
            fields(page, {'events', 'head'}, where='export page')
            events = page['events']
            require(isinstance(events, list) and 1 <= len(events) <= min(50, bound['sequence'] - count),
                    'audit_export_gap', 'Audit export did not return the checkpointed prefix; incomplete output was preserved.')
            for event in events:
                count += 1
                head = verify_record(event, key, head, count)
                raw = canonical(event) + b'\n'
                total += len(raw)
                require(total <= MAX_EXPORT, 'audit_size', 'Audit export exceeds the supported byte limit.')
                stream.write(raw)
        require(head == bound['head'], 'audit_head', 'Export differs from the signed checkpoint; do not forward incomplete evidence.')
        stream.flush()
        os.fsync(stream.fileno())
    if bundle:
        write_new(destination / 'audit.pub', public)
        write_new(destination / 'checkpoint.json', canonical(checkpoint) + b'\n')
        # Written last: failed exports never receive a completeness receipt.
        write_new(destination / 'bundle.json', canonical({'schema': 1, 'complete': True, 'events': count, 'head': head,
                  'private_key_included': False, 'observed_effects_complete': False}) + b'\n')
        sync_directory(destination)
    sync_directory(destination.parent)
    return {'exported_events': count, 'head': head, 'file': str(output), 'verified': True,
            'checkpoint': checkpoint, 'public_bundle': bundle,
            'independent_anchor': False,
            'next': 'Verify with an independently retained public key and retain the checkpoint outside the daemon administrator trust domain.'}
