import json
from tests.support import Fixture, SocketDaemon
from kechaa.common import KechaaError

def attempt(daemon, operation, data):
    try:
        return {'ok': True, 'result': daemon.call(operation, data)}
    except KechaaError as error:
        return {'ok': False, 'error': error.as_dict()}

results = {}
for finding in ('S1', 'S2', 'S3', 'S4'):
    f = Fixture()
    if finding == 'S3':
        f.document['profiles']['dev']['read'] = [str(f.a.parent), str(f.runtime)]
        f.write_policy()
    d = SocketDaemon(f).start()
    try:
        run = d.open_run()
        if finding == 'S1':
            denied = [attempt(d, 'prepare', {**run, 'action': f.action(True)})['ok'] for _ in range(3)]
            before = attempt(d, 'prepare', {**run, 'action': f.action()})
            for _ in range(20):
                d.call('tool_request', {**run, 'tool': 'FileRead', 'effects': {}})
            after = attempt(d, 'prepare', {**run, 'action': f.action()})
            d.stop(); d.start()
            restarted = attempt(d, 'prepare', {**run, 'action': f.action()})
            results[finding] = {'denial_attempts_allowed': denied, 'before_flood': before['ok'],
                                'after_flood': after['ok'], 'after_restart': restarted['ok']}
        elif finding == 'S2':
            result = attempt(d, 'tool_request', {**run, 'tool': 'FileRead', 'effects': {'read': None}})
            results[finding] = {'response': result, 'ready': d.call('health')['ready'],
                               'subsequent': attempt(d, 'tool_request', {**run, 'tool': 'FileRead', 'effects': {}})}
        elif finding == 'S3':
            prepared = d.call('prepare', {**run, 'action': f.action()})
            reads = prepared['summary']['effects']['read']
            results[finding] = {'parent_retained': str(f.a.parent) in reads,
                               'sibling_read_covered': any(str(f.b).startswith(p + '/') or str(f.b) == p for p in reads)}
        else:
            values = {}
            for source in ('kernel', 'supervisor', 'tool_gateway', 'admin'):
                # Inspect each source on a separately administered fresh run.
                if values:
                    d.call('run_close', run)
                    run = d.open_run('source-' + source)
                value = attempt(d, 'trusted_event', {**run, 'source': source, 'label': 'untrusted_web'})
                values[source] = value['ok']
            results[finding] = values
    finally:
        d.stop(); f.close()
print(json.dumps(results, indent=2))
