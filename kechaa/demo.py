"""Disposable, real Unix API walkthrough. Every command grant is simulated."""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import time

import yaml

from .client import AgentClient
from .common import KechaaError, require
from .protocol import call

SCENARIOS = ('allow', 'approval', 'destructive', 'filesystem', 'mcp', 'sql', 'agent')


class DemoSession:
    """Own only a fresh temporary diagnostic daemon; never attach to user state."""
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kechaa-', dir=Path('/tmp').resolve())
        self.base = Path(self.temp.name)
        self.process = None
        try:
            self.root = self.base / 'workspace'
            self.root.mkdir()
            self.sockets = self.base / 'sockets'
            self.executables = {}
            for name in ('echo', 'cat', 'rm'):
                binary = shutil.which(name)
                require(binary is not None, 'demo_prerequisite', f'Demo requires {name} on PATH.', 'compatibility_block')
                self.executables[name] = str(Path(binary).resolve(strict=True))
            self.executables['python'] = str(Path(sys.executable).resolve(strict=True))
            self.sentinel = self.root / 'keep.txt'
            self.sentinel.write_text('This file must survive the blocked request.\n')
            self.sql_task = self.root / 'query.py'
            self.sql_task.write_text("import sqlite3\nwith sqlite3.connect(':memory:') as db:\n"
                "    db.execute('CREATE TABLE tasks (title TEXT)')\n"
                "    db.execute(\"INSERT INTO tasks VALUES ('review policy')\")\n"
                "    print(db.execute('SELECT title FROM tasks').fetchone()[0])\n")
            profile = {'read': [str(self.root)], 'write': [], 'execute': list(self.executables.values()),
                       'network': 'offline', 'environment': {'PATH': '/usr/bin:/bin', 'LANG': 'C'},
                       'limits': {'wall_seconds': 10, 'cpu_seconds': 5, 'memory_mb': 64, 'pids': 8,
                                  'output_bytes': 65536, 'file_bytes': 1048576}}
            document = {'schema': 1, 'name': 'disposable-demo', 'default': 'deny',
                        'roots': [str(self.root)], 'sensitive': [], 'grant_ttl_seconds': 120,
                        'profiles': {'readonly': profile}, 'rules': [
                            {'id': name, 'executable': path, 'profile': 'readonly',
                             'decision': 'deny' if name == 'rm' else 'allow'}
                            for name, path in self.executables.items()]}
            document['rules'].append({'id': 'review', 'executable': self.executables['echo'],
                                     'argv_prefix': ['review'], 'profile': 'readonly', 'decision': 'ask'})
            policy = self.base / 'policy.yaml'
            policy.write_text(yaml.safe_dump(document))
            package = Path(__file__).resolve().parent
            launcher = next((p for p in (package.parent / 'bin/kechaa', package.parent.parent / 'bin/kechaa') if p.is_file()), None)
            require(launcher is not None, 'demo_launcher', 'Use the source or installed KECHAA launcher.', 'operational_error')
            started = time.perf_counter()
            self.process = subprocess.Popen([sys.executable, '-BIS', str(launcher), 'daemon', '--diagnostic',
                    '--state', str(self.base / 'state'), '--sockets', str(self.sockets), '--policy', str(policy),
                    '--duration', '120'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            require(bool(select.select([self.process.stdout], [], [], 15)[0]), 'demo_startup',
                    'Daemon startup timed out; check installation and Unix socket permissions.', 'operational_error')
            line = self.process.stdout.readline()
            require(bool(line) and json.loads(line).get('event') == 'ready', 'demo_startup',
                    'Diagnostic daemon did not start; check pinned dependencies and Unix socket permissions.', 'operational_error')
            self.startup_ms = (time.perf_counter() - started) * 1000
            self.counter = 0
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def admin(self, operation: str, data: dict | None = None) -> dict:
        return call(str(self.sockets / 'admin.sock'), operation, data, expected_uid=os.geteuid())

    def client(self) -> AgentClient:
        self.counter += 1
        session = f'demo-{self.counter}'
        opened = self.admin('run_open', {'uid': os.geteuid(), 'session': session, 'confirmed': True,
                    'contract': {'roots': [str(self.root)], 'executables': list(self.executables.values()),
                                 'write': False, 'lifetime_seconds': 120}})
        return AgentClient(str(self.sockets / 'agent.sock'), opened['run'], session, os.geteuid())

    def __exit__(self, *exc):
        if self.process is not None:
            try:
                if self.process.poll() is None:
                    self.process.terminate()
                self.process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=5)
            finally:
                self.process = None
        self.temp.cleanup()


def walkthrough(scenario: str = 'all') -> dict:
    rows = []
    def record(name, decision, detail):
        rows.append({'scenario': name, 'decision': decision, 'detail': detail})
    with DemoSession() as demo:
        for name in SCENARIOS if scenario == 'all' else (scenario,):
            client = demo.client()
            try:
                if name in ('allow', 'approval', 'agent', 'sql'):
                    argv = [demo.executables['echo'], 'review' if name == 'approval' else 'hello']
                    if name == 'sql':
                        argv = [demo.executables['python'], str(demo.sql_task)]
                    if name == 'agent':
                        translated = client.prepare_tool_call({'id': 'example-call', 'type': 'function',
                            'function': {'name': 'run_command', 'arguments': json.dumps({'argv': argv, 'cwd': str(demo.root)})}})
                        prepared = translated['prepared']
                    else:
                        prepared = client.prepare(argv, str(demo.root), inputs=[str(demo.sql_task)] if name == 'sql' else [])
                    if name == 'approval':
                        require(prepared['state'] == 'pending', 'demo_result', 'Expected pending approval.')
                        record(name, 'PENDING_APPROVAL', 'No command ran. The disposable operator inspects both grant digests.')
                        grant = demo.admin('grant_get', {'grant': prepared['grant']})['grant']
                        demo.admin('grant_approve', {'grant': prepared['grant'], 'action_digest': grant['action_digest'],
                                                     'effects_digest': grant['effects_digest']})
                    result = client.simulate(prepared)
                    require(result['executed'] is False, 'demo_result', 'Diagnostic result must not execute.')
                    record(name, 'ALLOW', 'Signed grant consumed with executed=false (simulation).')
                    if name == 'agent':
                        boundary = client.prepare(argv, str(demo.root), supervised=True)
                        client.simulate(boundary)
                        record(name, 'ALLOW', 'Whole-agent process-tree grant simulated; no agent or kernel sandbox launched.')
                    if name == 'allow':
                        try:
                            client.simulate(prepared)
                        except KechaaError as error:
                            require(error.code == 'grant_replay', 'demo_result', 'Unexpected replay response.')
                            record('replay', 'BLOCK', 'Consumed grant cannot be reused.')
                        else:
                            raise KechaaError('demo_result', 'Replay unexpectedly accepted.')
                elif name in ('destructive', 'filesystem'):
                    try:
                        client.prepare([demo.executables['rm'], '-f', str(demo.sentinel)] if name == 'destructive'
                                       else [demo.executables['cat'], '/etc/shadow'], str(demo.root))
                    except KechaaError as error:
                        require(error.code == 'policy_denied', 'demo_result', 'Unexpected denial response.')
                        record(name, 'BLOCK', 'Policy denied the request before execution.')
                    else:
                        raise KechaaError('demo_result', 'Expected policy denial.')
                    require(demo.sentinel.is_file(), 'demo_result', 'Disposable sentinel is missing.')
                elif name == 'mcp':
                    for network in ('offline', 'external'):
                        result = client.check_tool('mcp__files__read', {'kind': 'mcp_effect_contract',
                            'read': [str(demo.sentinel)], 'write': [], 'network': network})
                        expected = 'allow' if network == 'offline' else 'deny'
                        require(result['decision'] == expected, 'demo_result', 'Unexpected tool decision.')
                        record(name, 'ALLOW' if expected == 'allow' else 'BLOCK',
                               network + ' declared effects; no MCP server was invoked.')
            finally:
                client.close()
        audit = demo.admin('audit_verify')
        require(audit['verified'], 'demo_result', 'Audit verification failed.')
    return {'profile': 'diagnostic-no-execution', 'executed': False, 'results': rows,
            'audit_verified': True, 'cleanup': 'temporary daemon, keys, state and files removed'}
