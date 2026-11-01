"""Disposable fixtures for real control-plane and Unix-socket tests.

The diagnostic daemon uses real keys, SQLite, sockets and OS peer credentials.
It never launches protected actions and supplies no kernel-enforcement evidence.
"""
import json
import errno
import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from kechaa.protocol import call


class Fixture:
    def __init__(self):
        # Keep AF_UNIX paths below macOS's 104-byte limit, without /tmp symlinks.
        self.temp = tempfile.TemporaryDirectory(prefix="kechaa-", dir=Path('/tmp').resolve())
        self.base = Path(self.temp.name)
        self.a, self.b = self.base / 'work/a', self.base / 'work/b'
        self.runtime = self.base / 'runtime'
        for path in (self.a, self.b, self.runtime):
            path.mkdir(parents=True)
        self.echo = str(Path(shutil.which('echo')).resolve())
        self.cat = str(Path(shutil.which('cat')).resolve())
        self.uid = os.geteuid()
        self.state = self.base / 'state'
        self.policy_file = self.base / 'policy.yaml'
        self.document = {
            'schema': 1, 'name': 'regression', 'default': 'deny',
            'roots': [str(self.a), str(self.b)], 'sensitive': [], 'grant_ttl_seconds': 120,
            'profiles': {'dev': {
                'read': [str(self.a), str(self.b), str(self.runtime)],
                'write': [str(self.a), str(self.b)], 'execute': [self.echo, self.cat],
                'network': 'offline', 'environment': {'PATH': '/usr/bin:/bin', 'LANG': 'C'},
                'limits': {'wall_seconds': 10, 'cpu_seconds': 5, 'memory_mb': 64,
                           'pids': 8, 'output_bytes': 65536, 'file_bytes': 1048576}}},
            'rules': [{'id': 'echo', 'executable': self.echo, 'profile': 'dev', 'decision': 'allow'},
                      {'id': 'cat', 'executable': self.cat, 'profile': 'dev', 'decision': 'allow'}]}
        self.write_policy()

    def write_policy(self):
        self.policy_file.write_text(yaml.safe_dump(self.document))

    def contract(self):
        return {'roots': [str(self.a)], 'executables': [self.echo, self.cat],
                'write': True, 'lifetime_seconds': 3600}

    def action(self, denied=False):
        return {'argv': [self.cat, '/etc/shadow'] if denied else [self.echo, 'hello'], 'cwd': str(self.a)}

    def close(self):
        self.temp.cleanup()


class SocketDaemon:
    def __init__(self, fixture):
        self.fixture = fixture
        self.sockets = fixture.base / 'sock'
        self.process = None

    def start(self):
        project = Path(__file__).resolve().parents[1]
        self.process = subprocess.Popen(
            [sys.executable, '-BIS', str(project / 'bin/kechaa'), 'daemon', '--diagnostic',
             '--state', str(self.fixture.state), '--sockets', str(self.sockets),
             '--policy', str(self.fixture.policy_file), '--duration', '120'],
            cwd=project, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not select.select([self.process.stdout], [], [], 15)[0]:
            self.stop()
            raise RuntimeError('Diagnostic daemon startup timed out')
        line = self.process.stdout.readline()
        if not line or json.loads(line).get('event') != 'ready':
            _, err = self.process.communicate(timeout=5)
            raise RuntimeError('Diagnostic daemon startup failed: ' + err.decode())
        return self

    def stop(self, crash=False):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.kill() if crash else self.process.terminate()
        try:
            out, err = self.process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            out, err = self.process.communicate(timeout=5)
            raise AssertionError('Daemon shutdown timed out')
        code = self.process.returncode
        self.process = None
        if not crash and (code != 0 or err):
            raise AssertionError(f'Daemon shutdown failed: {code} {err.decode()}')

    def call(self, operation, data=None, admin=False):
        path = self.sockets / ('admin.sock' if admin else 'agent.sock')
        return call(str(path), operation, data, expected_uid=self.fixture.uid)

    def raw(self, payload, admin=False):
        path = self.sockets / ('admin.sock' if admin else 'agent.sock')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(10)
            peer.connect(str(path))
            peer.sendall(payload)
            try:
                peer.shutdown(socket.SHUT_WR)
            except OSError as exc:
                # A promptly rejected complete request can already have a
                # response queued and a closed server end on macOS. Still read
                # and validate that response; only tolerate this close race.
                if exc.errno != errno.ENOTCONN:
                    raise
            data = bytearray()
            while chunk := peer.recv(65536):
                data.extend(chunk)
        return json.loads(data)

    def open_run(self, session='regression'):
        result = self.call('run_open', {'uid': self.fixture.uid, 'session': session,
                           'contract': self.fixture.contract(), 'confirmed': True}, admin=True)
        return {'run': result['run'], 'session': session}
