"""Black-box attack retest: raw Unix requests and externally visible outcomes.

No Engine/Store calls or policy helpers are used as an oracle. This is a second
attacker-perspective pass by the same reviewer, not third-party certification.
"""
import concurrent.futures
import json
import unittest
import yaml

from tests.support import Fixture, SocketDaemon


class AttackRetest(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)
        self.d = SocketDaemon(self.f)
        self.addCleanup(self.d.stop)
        self.d.start()
        self.run = self.d.open_run('attacker')

    def wire(self, operation, data, admin=False):
        return self.d.raw(json.dumps({'v': 1, 'operation': operation, 'data': data}).encode() + b'\n', admin)

    def allowed(self):
        return self.wire('prepare', {**self.run, 'action': {'argv': [self.f.echo, 'attack-retest'], 'cwd': str(self.f.a)}})

    def test_s1_rebuild_attack_with_interleaved_noise_and_restart(self):
        for index in range(3):
            self.assertFalse(self.wire('prepare', {**self.run, 'action': {
                'argv': [self.f.cat, '/etc/shadow'], 'cwd': str(self.f.a)}})['ok'])
            for _ in range(30):
                self.wire('tool_request', {**self.run, 'tool': 'FileRead', 'effects': {}})
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            replies = list(pool.map(lambda _: self.allowed(), range(24)))
        self.assertTrue(all(not r['ok'] for r in replies))
        self.d.stop(crash=True)
        self.d.start()
        self.assertFalse(self.allowed()['ok'])
        for operation in ('checkpoint', 'run_recover'):
            data = {'run': self.run['run'], 'mode': 'normal', 'reason': 'attacker requests restoration'}
            if operation == 'run_recover':
                data['seconds'] = 60
            self.assertFalse(self.wire(operation, data)['ok'])
        self.assertFalse(self.allowed()['ok'])
        self.assertTrue(self.wire('checkpoint', {'run': self.run['run'], 'mode': 'normal',
                        'reason': 'authenticated review complete'}, True)['ok'])
        self.assertTrue(self.allowed()['ok'])

    def test_s2_alternate_malformed_forms_never_poison_admission(self):
        values = [None, True, 0, '', {}, [[]], [None], ['../escape'], ['/a\u0001b'], ['/a\udfff'], ['/a' * 3000]]
        for field in ('read', 'write'):
            for value in values:
                reply = self.wire('tool_request', {**self.run, 'tool': 'FileRead', 'effects': {field: value}})
                self.assertFalse(reply['ok'])
                self.assertEqual(reply['error']['category'], 'invalid_request')
                self.assertTrue(self.wire('health', {})['result']['ready'])
                good = self.wire('tool_request', {**self.run, 'tool': 'FileRead', 'effects': {'read': [str(self.f.a)]}})
                self.assertEqual(good['result']['decision'], 'allow')
        self.d.stop()
        self.d.start()
        self.assertTrue(self.allowed()['ok'])

    def test_s3_ancestor_aliases_rejected_and_explicit_parent_root_narrows(self):
        for ancestor in (str(self.f.a.parent), '//' + str(self.f.a.parent).lstrip('/'), str(self.f.a.parent) + '/'):
            self.f.document['profiles']['dev']['read'] = [ancestor, str(self.f.runtime)]
            self.assertFalse(self.wire('policy_import', {'yaml': yaml.safe_dump(self.f.document)}, True)['ok'])
        # Explicit project parent has unambiguous semantics and must intersect.
        self.f.document['roots'] = [str(self.f.a.parent)]
        self.f.document['profiles']['dev']['read'] = [str(self.f.a.parent), str(self.f.runtime)]
        self.assertTrue(self.wire('policy_import', {'yaml': yaml.safe_dump(self.f.document)}, True)['ok'])
        for restart in (False, True):
            if restart:
                self.d.stop()
                self.d.start()
            reads = self.allowed()['result']['summary']['effects']['read']
            self.assertEqual(set(reads), {str(self.f.a), str(self.f.runtime)})
            sibling = self.wire('prepare', {**self.run, 'action': {'argv': [self.f.echo], 'cwd': str(self.f.b)}})
            self.assertFalse(sibling['ok'])

    def test_s4_role_injection_and_forgery_do_not_survive_as_trusted_records(self):
        for source in ('kernel', 'supervisor', 'tool_gateway', 'admin', 'Kernel', 'kernel\x00', {'kind': 'kernel'}):
            self.assertFalse(self.wire('trusted_event', {**self.run, 'label': 'untrusted_web', 'source': source})['ok'])
        for injection in ({'administrative': True}, {'uid': 0}, {'producer': {'kind': 'internal', 'component': 'kernel'}}):
            self.assertFalse(self.wire('trusted_event', {**self.run, 'label': 'untrusted_web',
                             'source': 'client_report', **injection})['ok'])
        self.assertTrue(self.wire('trusted_event', {**self.run, 'label': 'untrusted_web',
                        'source': 'client_report', 'reason': 'source=kernel (attacker text)'})['ok'])
        self.d.stop()
        self.d.start()
        body = self.wire('run_get', self.run)['result']['body']
        self.assertEqual(body['trusted_signals'], [])
        self.assertEqual(body['signals'][-1]['producer']['kind'], 'client_report')
        events = self.wire('audit_export', {'limit': 100}, True)['result']['events']
        changes = [e['record']['body'] for e in events if e['record']['type'] == 'posture_changed']
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]['source'], 'client_report')
