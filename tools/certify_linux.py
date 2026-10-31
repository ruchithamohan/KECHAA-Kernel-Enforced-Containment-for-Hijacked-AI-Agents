#!/usr/bin/env python3
"""Non-destructive KECHAA Linux containment certification harness.

This harness intentionally refuses to claim success unless it is running on a
prepared Linux host. It provides a stable scenario inventory for disposable VM
runs and a host precheck that CI/labs can use before executing privileged tests.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from pathlib import Path

SCENARIOS = [
    {"id": "LC-001", "issue": 2, "name": "allowed_echo", "expected": "approved echo exits 0 inside workspace"},
    {"id": "LC-002", "issue": 2, "name": "outside_secret_read_denied", "expected": "outside synthetic secret read fails at OS level"},
    {"id": "LC-003", "issue": 2, "name": "outside_write_denied", "expected": "outside write/chmod/rename fail and target remains unchanged"},
    {"id": "LC-004", "issue": 2, "name": "network_denied", "expected": "TCP UDP IPv4 IPv6 and Unix socket creation fail"},
    {"id": "LC-005", "issue": 2, "name": "grant_replay_denied", "expected": "consumed grant cannot authorize another execution"},
    {"id": "LC-006", "issue": 2, "name": "expired_authorization_denied", "expected": "expired grant or lease blocks execution"},
    {"id": "LC-007", "issue": 2, "name": "descendant_cleanup", "expected": "background and double-fork descendants are killed"},
    {"id": "LC-008", "issue": 2, "name": "daemon_restart_recovery", "expected": "restart kills stale action cgroups and rejects stale grants"},
    {"id": "LC-009", "issue": 1, "name": "supervised_bypass_denied", "expected": "direct unwrapped execution path is unavailable in supported session"},
    {"id": "LC-010", "issue": 3, "name": "unsupported_tool_denied", "expected": "MCP/web/non-shell tool without effect contract fails closed"},
    {"id": "LC-011", "issue": 1, "name": "supervised_agent_process_tree", "expected": "agent launch enters cgroup namespaces Landlock seccomp and descendants inherit restrictions"},
    {"id": "LC-012", "issue": 7, "name": "multi_agent_separation", "expected": "two launched agents receive distinct runs cgroups histories and cannot access each other's workspace"},
    {"id": "LC-013", "issue": 9, "name": "attack_defense_demo", "expected": "external malicious instruction tightens posture and subsequent action requires approval or denial"},
]


PROCEDURE = """#!/usr/bin/env bash
set -euo pipefail

# Run only inside a disposable Linux VM. Do not run on a developer workstation.
# Tested target profile: Linux x86_64/aarch64, cgroup v2, Landlock ABI >= 6,
# root-owned KECHAA daemon, distinct unprivileged agent account.

python3 tools/certify_linux.py preflight --cgroup-root /sys/fs/cgroup/kechaa
python3 -m kechaa policy validate examples/linux-offline.yaml
python3 tools/demo_attack_defense.py

# Prepare cgroup subtree before starting the daemon, for example:
#   mkdir -p /sys/fs/cgroup/kechaa
#   chown root:root /sys/fs/cgroup/kechaa
#   chmod 700 /sys/fs/cgroup/kechaa
#   echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
#
# Start daemon in the VM with a generated Linux policy and run the LC-* cases
# listed by `tools/certify_linux.py plan`. Certification is complete only after
# LC-001..LC-013 execute and produce retained audit checkpoints.
"""


def preflight(cgroup_root: str) -> dict:
    result = {"os": platform.system(), "arch": platform.machine(), "uid": os.geteuid(), "ready": False, "failures": []}
    if platform.system() != "Linux":
        result["failures"].append("Linux is required for kernel containment certification.")
        return result
    if os.geteuid() != 0:
        result["failures"].append("Root-owned daemon setup is required; run only inside a disposable VM.")
    root = Path(cgroup_root)
    for name in ("cgroup.controllers", "cgroup.subtree_control"):
        if not (root / name).exists():
            result["failures"].append(f"missing cgroup v2 file: {root / name}")
    result["ready"] = not result["failures"]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "preflight", "procedure", "run"))
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup/kechaa")
    args = parser.parse_args(argv)
    if args.command == "plan":
        print(json.dumps({"schema": 1, "destructive": False, "scenarios": SCENARIOS}, indent=2))
        return 0
    if args.command == "procedure":
        print(PROCEDURE)
        return 0
    result = preflight(args.cgroup_root)
    if args.command == "run":
        result = {**result, "certified": False, "reason": "Automated privileged LC execution is intentionally not run unless this host passes preflight and an operator supplies a disposable VM test workspace.",
                  "required_scenarios": [item["id"] for item in SCENARIOS]}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 4
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
