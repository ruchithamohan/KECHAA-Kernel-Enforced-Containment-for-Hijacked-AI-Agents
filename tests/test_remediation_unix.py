"""Real diagnostic daemon/Unix API regressions, not Linux enforcement tests."""
import base64
import concurrent.futures
import json
import sqlite3
import unittest
from contextlib import closing

from kechaa.common import KechaaError, canonical
from kechaa.store import verify_export
from tests.support import Fixture, SocketDaemon


class RemediationUnixTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)
        self.d = SocketDaemon(self.f)
        self.addCleanup(self.d.stop)
        self.d.start()
        self.run = self.d.open_run()

    def prepare(self, denied=False):
        return self.d.call('prepare', {**self.run, 'action': self.f.action(denied)})

    def tool(self, effects=None):
        return self.d.call('tool_request', {**self.run, 'tool': 'FileRead', 'effects': effects or {}})

    def deny_three(self):
        for _ in range(3):
            with self.assertRaises(KechaaError) as caught:
                self.prepare(True)
            self.assertEqual(caught.exception.code, 'policy_denied')

    def assert_locked(self):
        self.assertEqual(self.d.call('run_get', self.run)['mode'], 'lockdown')
        with self.assertRaises(KechaaError):
            self.prepare()

    def recover(self, operation='checkpoint'):
        data = {'run': self.run['run'], 'mode': 'normal', 'reason': 'reviewed test incident'}
        if operation == 'run_recover':
            data['seconds'] = 120
        with self.assertRaises(KechaaError) as caught:
            self.d.call(operation, data)
        self.assertEqual(caught.exception.code, 'admin_required')
        self.d.call(operation, data, admin=True)

    def test_s1_flood_restart_revocation_and_admin_checkpoint(self):
        grant = self.prepare()
        self.d.call('event', {**self.run, 'label': 'untrusted_repository'})
        pending = self.prepare()
        self.assertEqual(pending['state'], 'pending')
        self.d.call('checkpoint', {'run': self.run['run'], 'mode': 'normal',
                                  'reason': 'reset fixture posture'}, admin=True)
        issued = self.prepare()
        self.deny_three()
        self.assert_locked()
        for _ in range(550):
            self.assertEqual(self.tool()['decision'], 'deny')
        self.assert_locked()
        for item in (grant, pending, issued):
            with self.assertRaises(KechaaError):
                self.d.call('simulate', {**self.run, 'grant': item['grant'], 'action': self.f.action()})
        self.assertEqual(self.d.call('grant_get', {'grant': issued['grant']}, admin=True)['state'], 'revoked_history')
        self.d.stop(crash=True)
        self.d.start()
        self.assert_locked()
        self.recover()
        self.assertEqual(self.prepare()['state'], 'issued')
        self.d.stop(); self.d.start()
        self.assertEqual(self.prepare()['state'], 'issued')

    def test_s1_denials_cannot_be_spaced_out_by_benign_history(self):
        for index in range(3):
            with self.assertRaises(KechaaError):
                self.prepare(True)
            if index < 2:
                for _ in range(25):
                    self.assertEqual(self.tool()['decision'], 'allow')
        self.assert_locked()
        self.recover('run_recover')
        self.assertEqual(self.prepare()['state'], 'issued')

    def test_s1_pending_approval_is_revoked(self):
        self.d.call('event', {**self.run, 'label': 'untrusted_web'})
        pending = self.prepare()
        shown = self.d.call('grant_get', {'grant': pending['grant']}, admin=True)['grant']
        self.deny_three()
        with self.assertRaises(KechaaError):
            self.d.call('grant_approve', {'grant': pending['grant'], 'effects_digest': shown['effects_digest'],
                                         'action_digest': shown['action_digest']}, admin=True)
        self.assertEqual(self.d.call('grant_get', {'grant': pending['grant']}, admin=True)['state'], 'revoked_history')

    def test_s1_concurrent_requests_serialize_transition_and_revoke_prior_grants(self):
        def request(index):
            try:
                return self.prepare(denied=index % 3 == 0)
            except KechaaError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(request, range(30)))
        self.assert_locked()
        for result in results:
            if result is not None:
                with self.assertRaises(KechaaError):
                    self.d.call('simulate', {**self.run, 'grant': result['grant'], 'action': self.f.action()})
        self.assertTrue(self.d.call('audit_verify', admin=True)['verified'])

    def test_s1_large_denials_commit_instead_of_overflowing_history(self):
        action = self.f.action(True)
        action['argv'] += ['x' * 16000, 'x' * 16000, 'x' * 16000]
        for _ in range(3):
            with self.assertRaises(KechaaError) as caught:
                self.d.call('prepare', {**self.run, 'action': action})
            self.assertEqual(caught.exception.code, 'policy_denied')
        self.assert_locked()

    def test_duplicate_consumption_and_restart_replay(self):
        grant = self.prepare()
        data = {**self.run, 'grant': grant['grant'], 'action': self.f.action()}
        def consume(_):
            try:
                return self.d.call('simulate', data)['state']
            except KechaaError:
                return 'rejected'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(consume, range(8)))
        self.assertEqual(results.count('simulated'), 1)
        unused = self.prepare()
        self.d.stop(); self.d.start()
        for item in (grant, unused):
            with self.assertRaises(KechaaError):
                self.d.call('simulate', {**data, 'grant': item['grant']})
        self.assertEqual(self.prepare()['state'], 'issued')

    def test_s2_malformed_effects_leave_daemon_healthy(self):
        bad = [{'read': None}, {'write': None}, {'read': 'secret'}, {'write': 42},
               {'read': {}}, {'write': [[]]}, {'read': [None]}, {'read': [{'path': str(self.f.a)}]},
               {'read': [str(self.f.a)] * 65}, {'read': ['/x' * 2500]},
               {'read': ['relative']}, {'read': ['/work/../etc']}, {'read': ['/work/./a']},
               {'read': ['/x\x00y']}, {'read': ['/x\ty']}, {'read': ['/x\x7fy']},
               {'read': ['/x\ud800']}, {'read': [False]}, {'read': [1.5]},
               {'network': None}, {'network': []}, {'network': {}}, {'network': True},
               {'kind': None}, {'kind': {}}, {'kind': []}, {'unexpected': 'value'},
               {'read': ['/x' + 'a' * 2000] * 10}, None, [], 'invalid']
        for effects in bad:
            with self.subTest(effects=repr(effects)[:80]):
                payload = json.dumps({'v': 1, 'operation': 'tool_request',
                                     'data': {**self.run, 'tool': 'FileRead', 'effects': effects}}).encode() + b'\n'
                reply = self.d.raw(payload)
                self.assertFalse(reply['ok'])
                self.assertEqual(reply['error']['category'], 'invalid_request')
                self.assertNotIn('Traceback', reply['error']['message'])
                self.assertTrue(self.d.call('health')['ready'])
                self.assertEqual(self.tool()['decision'], 'allow')
        with closing(sqlite3.connect(self.f.state / 'state.db')) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM grants').fetchone()[0], 0)

    def test_s2_malformed_ipc_and_concurrent_valid_requests(self):
        payloads = [b'not-json\n', b'\xff\n', b'{"v":1,"v":1}\n', b'[]\n',
                    b'{"v":true,"operation":"health","data":{}}\n',
                    b'{"v":1,"operation":[],"data":{}}\n',
                    b'{"v":1,"operation":"health","data":null}\n',
                    b'{"v":1,"operation":"health","data":{},"extra":1}\n',
                    b'[' * 40 + b']' * 40 + b'\n', b'{}', b'x' * 262145 + b'\n']
        for payload in payloads:
            self.assertFalse(self.d.raw(payload)['ok'])
            self.assertTrue(self.d.call('health')['ready'])
            self.assertEqual(self.tool()['decision'], 'allow')
        bad = json.dumps({'v': 1, 'operation': 'tool_request',
                          'data': {**self.run, 'tool': 'FileRead', 'effects': {'read': None}}}).encode() + b'\n'
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda i: self.d.raw(bad)['ok'] if i % 2 else self.tool()['decision'], range(40)))
        self.assertEqual(results.count(False), 20)
        self.assertEqual(results.count('allow'), 20)
        self.assertTrue(self.d.call('health')['ready'])

    def test_s2_oversized_invalid_operation_cannot_overflow_denial_audit(self):
        for operation in ('x' * 70000, ['x' * 70000], {'x': 'y' * 70000}):
            payload = json.dumps({'v': 1, 'operation': operation, 'data': {}}).encode() + b'\n'
            self.assertFalse(self.d.raw(payload)['ok'])
            self.assertTrue(self.d.call('health')['ready'])
            self.assertEqual(self.tool()['decision'], 'allow')

    def test_s3_policy_import_rejects_ancestor_without_replacing_active_policy(self):
        before = self.d.call('policy_get')['version']
        self.f.document['profiles']['dev']['read'] = [str(self.f.a.parent), str(self.f.runtime)]
        import yaml
        with self.assertRaises(KechaaError) as caught:
            self.d.call('policy_import', {'yaml': yaml.safe_dump(self.f.document)}, admin=True)
        self.assertEqual(caught.exception.code, 'policy_read_overlap')
        self.assertEqual(self.d.call('policy_get')['version'], before)
        effects = self.prepare()['summary']['effects']
        self.assertIn(str(self.f.runtime), effects['read'])
        self.assertIn(str(self.f.a), effects['read'])
        self.assertNotIn(str(self.f.b), effects['read'])
        self.assertNotIn(str(self.f.a.parent), effects['read'])

    def test_s3_traversal_and_symlink_inputs_refused(self):
        target = self.f.b / 'secret'
        target.write_text('synthetic outside data')
        alias = self.f.a / 'alias'
        alias.symlink_to(target)
        for action in ({'argv': [self.f.echo], 'cwd': str(self.f.a / '../b')},
                       {'argv': [self.f.cat], 'cwd': str(self.f.a), 'inputs': [str(alias)]}):
            with self.assertRaises(KechaaError):
                self.d.call('prepare', {**self.run, 'action': action})
            self.assertTrue(self.d.call('health')['ready'])
        self.assertEqual(self.prepare()['state'], 'issued')

    def test_s4_forged_sources_rejected_on_both_endpoints(self):
        for source in ('kernel', 'supervisor', 'tool_gateway', 'admin', None, [], {}, True):
            with self.subTest(source=source):
                with self.assertRaises(KechaaError) as caught:
                    self.d.call('trusted_event', {**self.run, 'source': source, 'label': 'untrusted_web'})
                self.assertEqual(caught.exception.code, 'event_provenance')
                self.assertTrue(self.d.call('health')['ready'])
        for source in ('kernel', 'supervisor', 'tool_gateway', 'client_report'):
            with self.assertRaises(KechaaError):
                self.d.call('trusted_event', {**self.run, 'source': source, 'label': 'untrusted_web'}, admin=True)
        with self.assertRaises(KechaaError):
            self.d.call('internal_event', {**self.run, 'source': 'kernel', 'label': 'agent_compromise'})
        self.assertEqual(self.d.call('run_get', self.run)['mode'], 'normal')
        self.assertEqual(self.prepare()['state'], 'issued')

    def test_s4_actual_producer_persists_and_signed_export_verifies(self):
        public = base64.b64decode(self.d.call('health')['public_key'])
        self.d.call('trusted_event', {**self.run, 'source': 'client_report', 'label': 'untrusted_web'})
        self.d.call('trusted_event', {'run': self.run['run'], 'source': 'admin', 'label': 'policy_violation'}, admin=True)
        self.d.stop(); self.d.start()
        body = self.d.call('run_get', self.run)['body']
        self.assertEqual(body['signals'][-1]['producer'], {'kind': 'client_report', 'uid': self.f.uid})
        self.assertEqual(body['trusted_signals'][-1]['producer'], {'kind': 'admin', 'uid': self.f.uid})
        checkpoint = self.d.call('audit_checkpoint', admin=True)['checkpoint']
        events = self.d.call('audit_export', {'limit': 100}, admin=True)['events']
        encoded = b''.join(canonical(event) + b'\n' for event in events)
        self.assertTrue(verify_export(encoded, public, checkpoint['head'])['verified'])
        signals = [e['record'] for e in events if e['record']['type'] == 'posture_changed']
        self.assertEqual([e['body']['producer']['kind'] for e in signals], ['client_report', 'admin'])
        self.assertTrue(all(e['actor_uid'] == self.f.uid for e in signals))

    def test_shutdown_recovery_database_and_audit_integrity(self):
        self.prepare()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: self.tool(), range(12)))
        self.d.stop()
        self.assertFalse((self.d.sockets / 'agent.sock').exists())
        with closing(sqlite3.connect(self.f.state / 'state.db')) as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
        self.d.start()
        self.assertTrue(self.d.call('audit_verify', admin=True)['verified'])
        self.assertEqual(self.prepare()['state'], 'issued')
