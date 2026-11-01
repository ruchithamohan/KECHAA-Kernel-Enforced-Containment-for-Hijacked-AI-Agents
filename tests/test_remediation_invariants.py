"""Transactional/OS integration tests; worker adapter is NOT kernel evidence."""
import asyncio
import copy
import os
import sqlite3
import sys
import unittest
from unittest.mock import patch

from kechaa.common import KechaaError, canonical, decode, path_string
from kechaa.daemon import Server
from kechaa.effects import open_path
from kechaa.engine import Engine
from kechaa.policy import load, narrow_project_paths
from kechaa.store import Store, verify_export
from tests.support import Fixture
import yaml


class InvariantTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)
        self.store = Store(self.f.state)
        self.addCleanup(self.store.close)
        self.engine = Engine(self.store, load(yaml.safe_dump(self.f.document)), True, self.f.uid)
        opened = self.engine.open_run({'uid': self.f.uid, 'session': 'invariants',
                    'contract': self.f.contract(), 'confirmed': True}, self.f.uid, True)
        self.run = {'run': opened['run'], 'session': 'invariants'}

    def prepare(self, denied=False):
        return self.engine.prepare({**self.run, 'action': self.f.action(denied)}, self.f.uid)

    def test_denial_transaction_rolls_back_state_grants_history_and_audit_together(self):
        grant = self.prepare()
        for _ in range(2):
            with self.assertRaises(KechaaError):
                self.prepare(True)
        def snapshot():
            return {table: [tuple(row) for row in self.store.db.execute('SELECT * FROM ' + table)]
                    for table in ('runs', 'grants', 'history', 'audit', 'meta')}
        before = snapshot()
        with patch.object(self.store, 'event', side_effect=sqlite3.OperationalError('injected write failure')):
            with self.assertRaises(sqlite3.OperationalError):
                self.prepare(True)
        self.assertEqual(snapshot(), before)
        with self.assertRaises(KechaaError):
            self.prepare(True)
        self.assertEqual(self.engine.admin_run(self.run['run'])['mode'], 'lockdown')
        self.assertEqual(self.engine.grant(grant['grant'])[0]['state'], 'revoked_history')
        self.assertTrue(self.store.verify()['verified'])

    def test_legacy_state_requires_review_even_when_denial_history_is_absent(self):
        row = self.engine.admin_run(self.run['run'])
        body = decode(row['body'])
        del body['denial_state_version']
        with self.store.transaction():
            self.store.db.execute('UPDATE runs SET body=? WHERE id=?', (canonical(body), row['id']))
        self.engine = Engine(self.store, None, True, self.f.uid)
        with self.assertRaises(KechaaError):
            self.prepare()
        self.engine = Engine(self.store, None, True, self.f.uid)
        self.assertEqual(self.engine.admin_run(row['id'])['mode'], 'lockdown')
        self.engine.checkpoint({'run': row['id'], 'mode': 'normal', 'reason': 'reviewed legacy state'}, self.f.uid, True)
        self.assertEqual(self.prepare()['state'], 'issued')
        self.assertTrue(self.store.verify()['verified'])

    def test_unknown_or_boolean_denial_version_is_not_silently_migrated(self):
        body = decode(self.engine.admin_run(self.run['run'])['body'])
        for version in (2, True, None):
            with self.subTest(version=version):
                with self.store.transaction():
                    self.store.db.execute('UPDATE runs SET body=? WHERE id=?',
                                          (canonical({**body, 'denial_state_version': version}), self.run['run']))
                with self.assertRaises(KechaaError) as caught:
                    Engine(self.store, None, True, self.f.uid)
                self.assertEqual(caught.exception.code, 'state_schema')

    def test_exact_child_parent_sibling_and_runtime_intersections(self):
        cases = [(['/work'], ['/work'], ['/work'], ['/work']),
                 (['/work'], ['/work'], ['/work/a'], ['/work/a']),
                 (['/work/a/child'], ['/work'], ['/work/a'], ['/work/a/child']),
                 (['/work/b'], ['/work'], ['/work/a'], []),
                 (['/runtime', '/work/a', '/work/b'], ['/work/a', '/work/b'], ['/work/a'], ['/runtime', '/work/a'])]
        for paths, roots, contract, expected in cases:
            with self.subTest(paths=paths, contract=contract):
                self.assertEqual(narrow_project_paths(paths, roots, contract), expected)
        with self.assertRaises(KechaaError):
            narrow_project_paths(['/work'], ['/work/a', '/work/b'], ['/work/a'])

    def test_nested_roots_and_inherited_ancestor_reads_rejected(self):
        for inherited in (False, True):
            document = copy.deepcopy(self.f.document)
            if inherited:
                document['profiles']['dev']['read'].append(str(self.f.a.parent))
                document['profiles']['derived'] = {'extends': 'dev'}
            else:
                document['roots'].append(str(self.f.a / 'child'))
            with self.assertRaises(KechaaError):
                load(yaml.safe_dump(document))

    def test_normalization_and_descriptor_walk_reject_symlink_components(self):
        target = self.f.b / 'outside'
        target.write_text('synthetic secret')
        child = self.f.a / 'child'
        child.mkdir()
        (child / 'inside').write_text('allowed')
        (self.f.a / 'file-link').symlink_to(target)
        (self.f.a / 'dir-link').symlink_to(self.f.b, target_is_directory=True)
        normalized = path_string('//' + str(child).lstrip('/') + '//inside')
        self.assertEqual(normalized, str(child / 'inside'))
        with open_path(normalized) as fd:
            self.assertEqual(os.read(fd, 100), b'allowed')
        for name in ('file-link', 'dir-link/outside', '../b/outside'):
            with self.assertRaises((KechaaError, OSError)):
                with open_path(str(self.f.a) + '/' + name):
                    self.fail('unexpected descriptor')

    def test_internal_producer_identity_survives_restart_and_signed_export(self):
        for source in ('kernel', 'supervisor', 'tool_gateway'):
            self.engine.internal_event(self.run['run'], 'untrusted_web', source=source)
        self.engine = Engine(self.store, None, True, self.f.uid)
        body = decode(self.engine.admin_run(self.run['run'])['body'])
        self.assertEqual([s['producer']['component'] for s in body['trusted_signals']],
                         ['kernel', 'supervisor', 'tool_gateway'])
        events = self.store.export(0, 100)
        exported = b''.join(canonical(item) + b'\n' for item in events)
        public = (self.f.state / 'audit.pub').read_bytes()
        self.assertTrue(verify_export(exported, public, self.store.meta('audit_head'))['verified'])
        records = [item['record'] for item in events if item['record']['type'] == 'posture_changed']
        self.assertTrue(all(r['body']['producer']['uid'] == r['actor_uid'] == self.f.uid for r in records))
        forged = copy.deepcopy(events)
        item = next(item for item in forged if item['record']['type'] == 'posture_changed')
        item['record']['body']['producer']['component'] = 'admin'
        with self.assertRaises(KechaaError):
            verify_export(b''.join(canonical(e) + b'\n' for e in forged), public, self.store.meta('audit_head'))

    def test_admin_role_alone_does_not_override_peer_uid(self):
        for operation, data in ((self.engine.checkpoint, {'run': self.run['run'], 'mode': 'normal', 'reason': 'attempt unauthorized reset'}),
                                (self.engine.trusted_event, {'run': self.run['run'], 'source': 'admin', 'label': 'untrusted_web'})):
            with self.assertRaises(KechaaError) as caught:
                operation(data, self.f.uid + 1, True)
            self.assertEqual(caught.exception.code, 'admin_required')

    def test_lockdown_and_recovery_dispatch_wait_for_live_child_termination(self):
        async def scenario():
            server = Server(self.engine, '/unused-test-cgroup')
            for recovering in (False, True):
                grant = self.prepare() if not recovering else None
                if grant:
                    # Use the real adoption path; no protected command is launched.
                    body = self.engine.consume({**self.run, 'grant': grant['grant'], 'action': self.f.action()}, self.f.uid, True)
                    with self.store.transaction():
                        self.store.db.execute("UPDATE grants SET state='adopted' WHERE id=?", (grant['grant'],))
                child = await asyncio.create_subprocess_exec(sys.executable, '-I', '-c', 'import time; time.sleep(60)')
                server.active['test-child'] = ({'id': 'test-child', 'run': self.run['run']}, child, None)
                async def terminate(process, group):
                    process.kill()
                    await asyncio.wait_for(process.wait(), 5)
                    return []
                try:
                    with patch.object(server, 'terminate_worker', side_effect=terminate):
                        if recovering:
                            await server.dispatch('run_recover', {'run': self.run['run'], 'mode': 'normal', 'seconds': 120,
                                                                 'reason': 'reviewed live child'}, self.f.uid, True)
                        else:
                            for index in range(3):
                                with self.assertRaises(KechaaError):
                                    await server.dispatch('prepare', {**self.run, 'action': self.f.action(True)}, self.f.uid, False)
                                if index < 2:
                                    self.assertIsNone(child.returncode)
                            self.assertEqual(self.engine.grant(grant['grant'])[0]['state'], 'revoked_history')
                    self.assertIsNotNone(child.returncode)
                finally:
                    if child.returncode is None:
                        child.kill()
                        await child.wait()
                    server.active.clear()
            self.assertEqual(self.prepare()['state'], 'issued')
        asyncio.run(scenario())

    def test_failed_cleanup_blocks_execution_after_committed_lockdown(self):
        async def scenario():
            server = Server(self.engine, '/unused-test-cgroup')
            for _ in range(2):
                with self.assertRaises(KechaaError):
                    await server.dispatch('prepare', {**self.run, 'action': self.f.action(True)}, self.f.uid, False)
            server.active['test'] = ({'id': 'test', 'run': self.run['run']}, None, None)
            async def failed_termination(*args):
                # Fault injection at the worker boundary, not a cgroup test.
                server.unhealthy = True
                return ['injected_reap_failure']
            with patch.object(server, 'terminate_worker', side_effect=failed_termination), patch('sys.stderr'):
                with self.assertRaises(KechaaError) as caught:
                    await server.dispatch('prepare', {**self.run, 'action': self.f.action(True)}, self.f.uid, False)
            self.assertEqual(caught.exception.code, 'cleanup_incomplete')
            self.assertEqual(self.engine.admin_run(self.run['run'])['mode'], 'lockdown')
            with self.assertRaises(KechaaError) as caught:
                await server.dispatch('prepare', {**self.run, 'action': self.f.action()}, self.f.uid, False)
            self.assertEqual(caught.exception.code, 'daemon_unhealthy')
        asyncio.run(scenario())
