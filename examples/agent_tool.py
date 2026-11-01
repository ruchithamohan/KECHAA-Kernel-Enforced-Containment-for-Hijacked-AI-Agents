"""Custom agent integration against an already administered KECHAA run.

Source checkout: python examples/agent_tool.py --help
No automatic administrative approval or direct subprocess fallback.
"""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kechaa.client import AgentClient
from kechaa.common import KechaaError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--run', required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--cwd', required=True)
    parser.add_argument('--simulate', action='store_true', help='Use same-UID diagnostics; never execute')
    parser.add_argument('argv', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.argv[1:] if args.argv[:1] == ['--'] else args.argv
    client = AgentClient(args.socket, args.run, args.session, os.geteuid() if args.simulate else 0)
    try:
        prepared = client.prepare(argv, args.cwd)
        if prepared['state'] == 'pending':
            print(json.dumps({'decision': 'PENDING_APPROVAL', 'grant': prepared['grant'],
                              'next': 'Ask the operator to inspect the grant. No command ran.'}))
            return 2
        result = client.simulate(prepared) if args.simulate else client.execute(prepared)
        print(json.dumps(result, indent=2))
        return result.get('exit_code', 0)
    except KechaaError as error:
        print(json.dumps({'decision': 'BLOCK', 'error': error.as_dict()}))
        return 3
    except (OSError, ValueError):
        print(json.dumps({'decision': 'BLOCK', 'error': 'Transport failed. Inspect grant state before requesting new authority.'}))
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
