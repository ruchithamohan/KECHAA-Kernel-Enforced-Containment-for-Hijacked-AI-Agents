import os
import tempfile
import time
import unittest
from pathlib import Path

import yaml

from kechaa.common import KechaaError, canonical, decode
from kechaa.engine import Engine
from kechaa.policy import load
from kechaa.store import Store


class SecurityControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        self.state = Path(self.temp.name) / "state"
        self.uid = os.geteuid()
        self.policy = self._policy()
        self.store = Store(self.state)
        self.engine = Engine(self.store, self.policy, True, self.uid)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def _policy(self):
        document = {
            "schema": 1,
            "name": "test-policy",
            "default": "deny",
            "roots": [str(self.root)],
            "sensitive": [str(Path.home() / ".ssh")],
            "grant_ttl_seconds": 60,
            "profiles": {
                "dev": {
                    "read": [str(self.root), "/bin"],
                    "write": [str(self.root)],
                    "execute": ["/bin/echo", "/bin/cat"],
                    "network": "offline",
                    "environment": {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": str(self.root), "TMPDIR": str(self.root)},
                    "limits": {"wall_seconds": 10, "cpu_seconds": 5, "memory_mb": 64, "pids": 4, "output_bytes": 65536, "file_bytes": 1048576},
                }
            },
            "rules": [
                {"id": "echo", "executable": "/bin/echo", "profile": "dev", "decision": "allow"},
                {"id": "cat", "executable": "/bin/cat", "profile": "dev", "decision": "allow"},
            ],
        }
        return load(yaml.safe_dump(document), "<test-policy>")

    def _open_run(self, session="session", lifetime=60):
        contract = {"roots": [str(self.root)], "executables": ["/bin/echo", "/bin/cat"], "write": True, "lifetime_seconds": lifetime}
        return self.engine.open_run({"uid": self.uid, "session": session, "contract": contract, "confirmed": True}, self.uid, True)

    def test_history_records_prepare_and_simulate(self):
        run = self._open_run()
        result = self.engine.prepare({"run": run["run"], "session": "session", "action": {"argv": ["/bin/echo", "hello"], "cwd": str(self.root)}}, self.uid)
        self.assertEqual(result["state"], "issued")
        simulated = self.engine.consume({"grant": result["grant"], "run": run["run"], "session": "session", "action": result["action"]}, self.uid, True)
        self.assertEqual(simulated["id"], result["grant"])
        kinds = [item["kind"] for item in self.store.history_for_run(run["run"], 10)]
        self.assertIn("contract_confirmed", kinds)
        self.assertIn("grant_prepared", kinds)
        self.assertIn("grant_consumed", kinds)

    def test_sensitive_argv_path_is_denied_and_recorded(self):
        run = self._open_run()
        secret = str(Path.home() / ".ssh" / "id_rsa")
        with self.assertRaises(KechaaError) as ctx:
            self.engine.prepare({"run": run["run"], "session": "session", "action": {"argv": ["/bin/cat", secret], "cwd": str(self.root)}}, self.uid)
        self.assertEqual(ctx.exception.code, "policy_denied")
        history = self.store.history_for_run(run["run"], 10)
        self.assertEqual(history[-1]["kind"], "policy_denied")
        self.assertIn("sensitive path", history[-1]["body"]["reason"])

    def test_repeated_denials_force_history_lockdown(self):
        run = self._open_run()
        for index in range(3):
            with self.assertRaises(KechaaError):
                self.engine.prepare({"run": run["run"], "session": "session", "action": {"argv": ["/bin/cat", str(Path.home() / ".ssh" / f"key{index}")], "cwd": str(self.root)}}, self.uid)
        with self.assertRaises(KechaaError) as ctx:
            self.engine.prepare({"run": run["run"], "session": "session", "action": {"argv": ["/bin/echo", "normally-ok"], "cwd": str(self.root)}}, self.uid)
        self.assertEqual(ctx.exception.code, "policy_denied")
        self.assertIn("recent denials", ctx.exception.message)

    def test_quarantine_blocks_and_recovery_requires_admin(self):
        run = self._open_run()
        quarantined = self.engine.quarantine({"run": run["run"], "reason": "confirmed compromised agent"}, self.uid, True)
        self.assertEqual(quarantined["state"], "quarantined")
        with self.assertRaises(KechaaError) as ctx:
            self.engine.run(run["run"], "session", self.uid)
        self.assertEqual(ctx.exception.code, "run_contained")
        recovered = self.engine.recover_run({"run": run["run"], "mode": "guarded", "seconds": 30, "reason": "operator reviewed incident"}, self.uid, True)
        self.assertEqual(recovered["state"], "active")
        self.assertEqual(self.engine.run(run["run"], "session", self.uid)["mode"], "guarded")

    def test_lease_expiry_closes_run_and_revokes(self):
        run = self._open_run(lifetime=1)
        time.sleep(1.1)
        terminated = self.engine.expire_runs()
        self.assertIn(run["run"], terminated)
        with self.assertRaises(KechaaError) as ctx:
            self.engine.run(run["run"], "session", self.uid)
        self.assertEqual(ctx.exception.code, "run_closed")

    def test_trusted_event_quarantines_without_agent_cooperation(self):
        run = self._open_run()
        result = self.engine.trusted_event({"run": run["run"], "session": "session", "label": "agent_compromise", "source": "supervisor"}, self.uid)
        self.assertEqual(result["state"], "quarantined")
        self.assertTrue(result["terminate_active"])

    def test_audit_anchor_is_persisted_and_listed(self):
        run = self._open_run()
        anchor = self.store.anchor(self.uid)
        self.assertEqual(anchor["checkpoint"]["policy"], self.policy.version)
        anchors = self.store.anchors()
        self.assertEqual(len(anchors), 1)
        self.assertEqual(anchors[0]["checkpoint"]["head"], anchor["checkpoint"]["head"])


if __name__ == "__main__":
    unittest.main()
