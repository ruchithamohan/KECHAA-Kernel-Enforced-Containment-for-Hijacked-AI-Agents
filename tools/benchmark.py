#!/usr/bin/env python3
"""Reproducible diagnostic IPC measurement, never a kernel execution benchmark."""
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kechaa.demo import DemoSession
from kechaa.protocol import call


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=50)
    parser.add_argument('--output', type=Path, required=True, help='New JSON file; refuses overwrite')
    args = parser.parse_args()
    if not 1 <= args.iterations <= 500:
        parser.error('iterations must be 1..500')
    samples = {'startup_ms': [], 'health_ms': [], 'prepare_ms': [], 'prepare_simulate_ms': [], 'daemon_rss_kib': []}
    for _ in range(3):
        with DemoSession() as demo:
            samples['startup_ms'].append(demo.startup_ms)
    with DemoSession() as demo:
        client = demo.client()
        # One warm-up operation; all measured actions consume their grants.
        client.simulate(client.prepare([demo.executables['echo'], 'hello'], str(demo.root)))
        batch_started = time.perf_counter()
        for _ in range(args.iterations):
            start = time.perf_counter()
            call(client.socket, 'health', expected_uid=os.geteuid())
            samples['health_ms'].append((time.perf_counter() - start) * 1000)
            start = time.perf_counter()
            grant = client.prepare([demo.executables['echo'], 'hello'], str(demo.root))
            samples['prepare_ms'].append((time.perf_counter() - start) * 1000)
            client.simulate(grant)
            samples['prepare_simulate_ms'].append((time.perf_counter() - start) * 1000)
        batch_seconds = time.perf_counter() - batch_started
        try:
            rss = int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(demo.process.pid)], text=True).strip())
            samples['daemon_rss_kib'].append(rss)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        audit = demo.admin('audit_verify')
        client.close()
    hardware = platform.machine()
    if platform.system() == 'Darwin':
        try:
            hardware = subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True).strip()
        except (OSError, subprocess.SubprocessError):
            pass
    summary = {name: {'median': statistics.median(values), 'min': min(values), 'max': max(values)}
               for name, values in samples.items() if values}
    result = {'scope': 'diagnostic Unix API only; executed=false', 'iterations': args.iterations,
        'environment': {'os': platform.system(), 'kernel': platform.release(), 'arch': platform.machine(),
                        'hardware': hardware, 'logical_cpus': os.cpu_count(), 'python': platform.python_version(),
                        'sqlite': sqlite3.sqlite_version, 'dependencies': {name: importlib.metadata.version(name)
                            for name in ('PyYAML', 'cryptography', 'cffi', 'pycparser')}},
        'configuration': {'profile': 'diagnostic-no-execution', 'concurrency': 1, 'warmups': 1,
                          'grant_ttl_seconds': 120, 'startup_samples': 3,
                          'inventory': 'canonical echo, cat, rm and current Python executable'},
        'method': 'perf_counter; real Unix IPC, executable hashing, SQLite and signatures; health then prepare+simulate',
        'summary': summary, 'raw': samples, 'sequential_iterations_per_second': args.iterations / batch_seconds,
        'batch_seconds': batch_seconds, 'audit_verified': audit['verified'],
        'execution_overhead_ms': None, 'limitations': 'No protected execution, comparative baseline, concurrent throughput or peak RSS measurement.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'summary': summary}, indent=2))


if __name__ == '__main__':
    main()
