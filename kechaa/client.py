"""Small agent-side Local API adapter. No approvals, retries or host fallback."""
from __future__ import annotations

from dataclasses import dataclass

from .common import fields, decode, require
from .protocol import call


@dataclass(frozen=True)
class AgentClient:
    socket: str
    run: str
    session: str
    daemon_uid: int = 0

    def _call(self, operation: str, data: dict) -> dict:
        return call(self.socket, operation, {'run': self.run, 'session': self.session, **data},
                    expected_uid=self.daemon_uid, timeout=660 if operation == 'execute' else 15)

    def prepare(self, argv: list[str], cwd: str, *, inputs: list[str] | None = None,
                supervised: bool = False) -> dict:
        return self._call('prepare', {'action': {'argv': argv, 'cwd': cwd, 'inputs': [] if inputs is None else inputs},
                                      'supervised': supervised})

    def execute(self, prepared: dict) -> dict:
        """Consume the exact issued request. Pending approval is an error."""
        require(prepared.get('state') == 'issued', 'approval_pending',
                'An administrator must inspect and approve the grant before execution.')
        require(prepared.get('profile') == 'linux-offline-experimental' and self.daemon_uid == 0,
                'execution_unavailable', 'Execution requires a prepared root-owned Linux daemon.')
        return self._call('execute', self._consumption(prepared))

    def simulate(self, prepared: dict) -> dict:
        """Explicit diagnostic consumption; never executes the command."""
        require(prepared.get('profile') == 'diagnostic-no-execution', 'simulation_profile',
                'Simulation is only available against a diagnostic daemon.')
        return self._call('simulate', self._consumption(prepared))

    @staticmethod
    def _consumption(prepared: dict) -> dict:
        return {'grant': prepared['grant'], 'action': prepared['action'],
                'supervised': prepared.get('supervised_agent', False)}

    def check_tool(self, tool: str, effects: dict) -> dict:
        """Review declarations only. This does not execute or proxy a tool."""
        return self._call('tool_request', {'tool': tool, 'effects': effects})

    def prepare_tool_call(self, tool_call: dict) -> dict:
        """Translate an OpenAI-style function call without an SDK or API key.

        Only the application's run_command function is mapped. Agent-produced
        arguments never become administrative operations or direct subprocesses.
        """
        fields(tool_call, {'id', 'type', 'function'})
        require(tool_call['type'] == 'function' and isinstance(tool_call['id'], str),
                'tool_call', 'Expected a function tool call.', 'invalid_request')
        function = fields(tool_call['function'], {'name', 'arguments'})
        require(function['name'] == 'run_command' and isinstance(function['arguments'], str),
                'tool_call', 'Only run_command with JSON arguments is supported.', 'invalid_request')
        arguments = fields(decode(function['arguments']), {'argv', 'cwd'}, {'inputs'})
        return {'tool_call_id': tool_call['id'], 'prepared': self.prepare(**arguments)}

    def close(self) -> dict:
        """End this run and request termination of its active action."""
        return self._call('run_close', {})
