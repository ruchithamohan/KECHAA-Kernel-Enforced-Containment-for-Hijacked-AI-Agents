import os
import tempfile
import unittest
from pathlib import Path

import yaml

from kechaa.common import KechaaError
from kechaa.engine import Engine
from kechaa.policy import load
from kechaa.store import Store


class AdversarialControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temp.name) / "agent-a"
        self.other = Path(self.temp.name) / "agent-b"
        self.root.mkdir()
        self.other.mkdir()
        self.state = Path(self.temp.name) / "state"
        self.uid = os.geteuid()
        document = {
            "schema": 1,
            "name": "adversarial-policy",
            "default": "deny",
            "roots": [str(self.root), str(self.other)],
            "sensitive": [str(Path.home() / ".ssh")],
            "grant_ttl_seconds": 60,
            "profiles": {
                "a": {
                    "read": [str(self.root), "/bin"],
                    "write": [str(self.root)],
                    "execute": ["/bin/echo", "/bin/cat"],
                    "network": "offline",
                    "environment": {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": str(self.root), "TMPDIR": str(self.root)},
                    "limits": {"wall_seconds": 10, "cpu_seconds": 5, "memory_mb": 64, "pids": 4, "output_bytes": 65536, "file_bytes": 1048576},
                }
            },
            "rules": [{"id": "echo", "executable": "/bin/echo", "profile": "a", "decision": "allow"}],
        }
        self.store = Store(self.state)
        self.engine = Engine(self.store, load(yaml.safe_dump(document), "<adversarial-policy>"), True, self.uid)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def open_run(self, session="agent-a", root=None, uid=None):
        root = self.root if root is None else root
        target = self.uid if uid is None else uid
        contract = {"roots": [str(root)], "executables": ["/bin/echo"], "write": True, "lifetime_seconds": 60}
        return self.engine.open_run({"uid": target, "session": session, "contract": contract, "confirmed": True}, self.uid, True)

    def test_forged_grant_id_is_rejected(self):
        run = self.open_run()
        with self.assertRaises(KechaaError) as ctx:
            self.engine.consume({"grant": "a" * 48, "run": run["run"], "session": "agent-a",
                                 "action": {"argv": ["/bin/echo", "x"], "cwd": str(self.root)}}, self.uid, True)
        self.assertEqual(ctx.exception.code, "grant_missing")

    def test_grant_replay_is_rejected(self):
        run = self.open_run()
        grant = self.engine.prepare({"run": run["run"], "session": "agent-a",
                                     "action": {"argv": ["/bin/echo", "x"], "cwd": str(self.root)}}, self.uid)
        self.engine.consume({"grant": grant["grant"], "run": run["run"], "session": "agent-a", "action": grant["action"]}, self.uid, True)
        with self.assertRaises(KechaaError) as ctx:
            self.engine.consume({"grant": grant["grant"], "run": run["run"], "session": "agent-a", "action": grant["action"]}, self.uid, True)
        self.assertEqual(ctx.exception.code, "grant_replay")

    def test_agent_cannot_reset_history_by_engine_restart(self):
        run = self.open_run()
        for index in range(3):
            self.engine.tool_request({"run": run["run"], "session": "agent-a", "tool": f"mcp__bad__{index}",
                                      "effects": {"network": "external", "read": [], "write": []}}, self.uid)
        self.engine = Engine(self.store, None, True, self.uid)
        with self.assertRaises(KechaaError) as ctx:
            self.engine.prepare({"run": run["run"], "session": "agent-a",
                                 "action": {"argv": ["/bin/echo", "after-restart"], "cwd": str(self.root)}}, self.uid)
        self.assertEqual(ctx.exception.code, "policy_denied")

    def test_agent_identity_confusion_cannot_cross_contract_roots(self):
        run_a = self.open_run("agent-a", self.root)
        other_uid = self.uid + 1
        run_b = self.open_run("agent-b", self.other, uid=other_uid)
        with self.assertRaises(KechaaError) as ctx:
            self.engine.prepare({"run": run_a["run"], "session": "agent-b",
                                 "action": {"argv": ["/bin/echo", "x"], "cwd": str(self.other)}}, self.uid)
        self.assertEqual(ctx.exception.code, "run_binding")
        with self.assertRaises(KechaaError) as ctx:
            self.engine.prepare({"run": run_b["run"], "session": "agent-b",
                                 "action": {"argv": ["/bin/echo", "x"], "cwd": str(self.root)}}, other_uid)
        self.assertEqual(ctx.exception.code, "contract_scope")


if __name__ == "__main__":
    unittest.main()
