#!/usr/bin/env python3
"""Controlled KECHAA attack-and-defense demonstration.

Runs entirely in a temporary directory. It does not execute untrusted network or
privileged operations; it demonstrates the control-plane sequence that Linux
certification must pair with kernel enforcement.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kechaa.engine import Engine
from kechaa.policy import load
from kechaa.store import Store
from kechaa.common import KechaaError


def build_policy(root: Path) -> object:
    document = {
        "schema": 1,
        "name": "phase3-demo",
        "default": "deny",
        "roots": [str(root)],
        "sensitive": [str(Path.home() / ".ssh")],
        "grant_ttl_seconds": 30,
        "profiles": {
            "readonly": {
                "read": [str(root), "/bin"],
                "write": [],
                "execute": ["/bin/echo", "/bin/cat"],
                "network": "offline",
                "environment": {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": str(root / ".home"), "TMPDIR": str(root / ".tmp")},
                "limits": {"wall_seconds": 10, "cpu_seconds": 5, "memory_mb": 64, "pids": 8, "output_bytes": 65536, "file_bytes": 1048576},
            }
        },
        "rules": [
            {"id": "echo", "executable": "/bin/echo", "profile": "readonly", "decision": "allow"},
            {"id": "cat", "executable": "/bin/cat", "profile": "readonly", "decision": "allow"},
        ],
    }
    return load(yaml.safe_dump(document), "<phase3-demo>")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="kechaa-phase3-demo-", dir="/private/tmp") as tmp:
        base = Path(tmp)
        root = base / "project"
        root.mkdir()
        (root / ".home").mkdir()
        (root / ".tmp").mkdir()
        (root / "task.txt").write_text("summarize this harmless task\n")
        state = base / "state"
        uid = os.geteuid()
        store = Store(state)
        engine = Engine(store, build_policy(root), True, uid)
        contract = {"roots": [str(root)], "executables": ["/bin/echo", "/bin/cat"], "write": False, "lifetime_seconds": 60}
        run = engine.open_run({"uid": uid, "session": "agent-a", "contract": contract, "confirmed": True}, uid, True)
        permitted = engine.prepare({"run": run["run"], "session": "agent-a", "supervised": True,
                                    "action": {"argv": ["/bin/cat", str(root / "task.txt")], "cwd": str(root)}}, uid)
        consumed = engine.consume({"grant": permitted["grant"], "run": run["run"], "session": "agent-a",
                                   "supervised": True, "action": permitted["action"]}, uid, True)
        injected = engine.tool_request({"run": run["run"], "session": "agent-a", "tool": "WebFetch",
                                        "effects": {"network": "external", "read": [], "write": []}}, uid)
        try:
            follow_up = engine.prepare({"run": run["run"], "session": "agent-a", "supervised": True,
                                        "action": {"argv": ["/bin/echo", "post-injection"], "cwd": str(root)}}, uid)
            later = {"decision": follow_up["decision"], "state": follow_up["state"],
                     "meaning": "not silently executed; guarded posture requires administrator approval"}
        except KechaaError as exc:
            later = {"decision": "blocked", "code": exc.code, "message": exc.message}
        history = engine.history({"run": run["run"], "session": "agent-a", "limit": 20}, uid)
        print(json.dumps({"schema": 1, "demo": "phase3_attack_defense", "permitted_grant": consumed["id"],
                          "malicious_instruction_vector": "external WebFetch effect", "gateway_decision": injected,
                          "post_injection_action": later, "history_kinds": [item["kind"] for item in history["history"]],
                          "evidence": "history-aware posture changed after external tool request; subsequent operation is not silently allowed"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
