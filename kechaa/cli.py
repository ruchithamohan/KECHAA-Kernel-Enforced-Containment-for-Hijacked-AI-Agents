"""Task-oriented command line for operators and generic agent adapters."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import platform
import shutil
import sqlite3
import sys
from pathlib import Path

import yaml

from . import __version__
from .backends import preflight
from .common import KechaaError, canonical, decode, read_bounded, require
from .policy import diff, evaluate, lint, load
from .protocol import call


def output(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kechaa", description="Bind an action approval to a bounded effect envelope. Alpha: no production-ready profile.")
    p.add_argument("--socket", default="/run/kechaa/agent.sock", help="Agent Unix socket")
    p.add_argument("--admin-socket", default="/run/kechaa/admin.sock", help="Separate administrative Unix socket")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="Version, supported platforms, and release status")
    diag = sub.add_parser("preflight", aliases=["doctor"], help="Read-only platform capability report; never changes kernel configuration")
    diag.add_argument("--cgroup-root", default="/sys/fs/cgroup/kechaa")
    sub.add_parser("status", help="Daemon health, policy version and active profile")
    daemon = sub.add_parser("daemon", help="Run a foreground daemon; installation never starts it automatically")
    daemon.add_argument("--state", type=Path, required=True)
    daemon.add_argument("--sockets", type=Path, required=True)
    daemon.add_argument("--policy", type=Path, help="Initial policy; persisted active policy takes precedence on restart")
    mode = daemon.add_mutually_exclusive_group(required=True)
    mode.add_argument("--diagnostic", action="store_true", help="Portable control-plane mode that NEVER executes an action")
    mode.add_argument("--experimental-linux", action="store_true", help="Experimental Linux backend; use only in a disposable VM")
    daemon.add_argument("--cgroup-root", default="/sys/fs/cgroup/kechaa")
    daemon.add_argument("--agent-group", type=int)
    daemon.add_argument("--duration", type=int, default=0, help="Exit after this many seconds (0 runs until signalled)")
    console = sub.add_parser("diagnostic", help="Non-executing operator console over stdin; no socket or peer-authentication claims")
    console.add_argument("--state", type=Path, required=True)
    console.add_argument("--policy", type=Path)
    console.add_argument("--admin", action="store_true", help="Allow administrative operations in this diagnostic console only")
    console.add_argument("--duration", type=int, default=300, help="Bounded console lifetime, 1 to 3600 seconds")
    pol = sub.add_parser("policy", help="Validate, explain, diff and administer YAML policies").add_subparsers(dest="policy_command", required=True)
    pol.add_parser("schema", help="Export the JSON Schema authoring contract; semantic validation is still mandatory")
    for name in ("validate", "lint", "export"):
        pol.add_parser(name).add_argument("file", type=Path)
    for name in ("check", "explain", "preview"):
        q = pol.add_parser(name)
        q.add_argument("file", type=Path)
        q.add_argument("--cwd", required=True)
        q.add_argument("--mode", choices=("normal", "guarded", "lockdown"), default="normal")
        q.add_argument("argv", nargs="*")
    q = pol.add_parser("diff")
    q.add_argument("old", type=Path)
    q.add_argument("new", type=Path)
    q = pol.add_parser("import")
    q.add_argument("file", type=Path)
    q.add_argument("--expected-version", help="Reject activation if the active policy changed after review")
    q = pol.add_parser("history")
    q.add_argument("--after", type=int, default=0)
    q.add_argument("--limit", type=int, default=50)
    q = pol.add_parser("rollback")
    q.add_argument("--version", required=True)
    q.add_argument("--expected-version", required=True)
    q.add_argument("--reason", required=True)
    q = pol.add_parser("init")
    q.add_argument("--root", type=Path, required=True)
    q.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("run", help="Confirm, inspect, resume or end durable task contracts").add_subparsers(dest="run_command", required=True)
    q = run.add_parser("open")
    q.add_argument("--uid", type=int, required=True)
    q.add_argument("--session", required=True)
    q.add_argument("--contract", type=Path, required=True)
    q.add_argument("--confirm", action="store_true", help="Administrator has inspected the displayed contract")
    for name in ("show", "close", "history"):
        q = run.add_parser(name)
        q.add_argument("--run", required=True)
        q.add_argument("--session", required=True)
        if name == "history":
            q.add_argument("--limit", type=int, default=64)
    q = run.add_parser("renew")
    q.add_argument("--run", required=True)
    q.add_argument("--seconds", type=int, required=True)
    q.add_argument("--reason", required=True)
    q = run.add_parser("quarantine")
    q.add_argument("--run", required=True)
    q.add_argument("--reason", required=True)
    q = run.add_parser("recover")
    q.add_argument("--run", required=True)
    q.add_argument("--mode", choices=("normal", "guarded", "lockdown"), required=True)
    q.add_argument("--seconds", type=int, required=True)
    q.add_argument("--reason", required=True)
    for name in ("prepare", "exec", "simulate"):
        q = sub.add_parser(name, help={"prepare": "Inspect an envelope and request a grant", "exec": "Consume a grant and execute only through the daemon backend", "simulate": "DIAGNOSTIC ONLY: consume a grant WITHOUT executing"}[name])
        q.add_argument("--run", required=True)
        q.add_argument("--session", required=True)
        q.add_argument("--cwd", required=True)
        q.add_argument("--input", action="append", default=[])
        if name != "prepare":
            q.add_argument("--grant", required=True)
        q.add_argument("argv", nargs=argparse.REMAINDER)
    agent = sub.add_parser("agent", help="Mandatory whole-agent launcher; supported agents must enter through this boundary").add_subparsers(dest="agent_command", required=True)
    for name in ("prepare", "launch", "simulate"):
        q = agent.add_parser(name, help={"prepare": "Inspect a supervised whole-agent launch envelope",
                                         "launch": "Consume a supervised grant and launch through the Linux containment worker",
                                         "simulate": "DIAGNOSTIC ONLY: consume a supervised grant without executing"}[name])
        q.add_argument("--run", required=True)
        q.add_argument("--session", required=True)
        q.add_argument("--cwd", required=True)
        q.add_argument("--input", action="append", default=[])
        if name != "prepare":
            q.add_argument("--grant", required=True)
        q.add_argument("argv", nargs=argparse.REMAINDER)
    grant = sub.add_parser("grant", help="Administrator-only approval, inspection and revocation").add_subparsers(dest="grant_command", required=True)
    for name in ("show", "approve", "revoke"):
        q = grant.add_parser(name)
        q.add_argument("--grant", required=True)
        if name == "approve":
            q.add_argument("--effects-digest", required=True, help="Digest from the inspected grant")
            q.add_argument("--action-digest", required=True, help="Digest from the inspected grant")
    q = sub.add_parser("event", help="Report untrusted input; can only tighten posture")
    q.add_argument("--run", required=True)
    q.add_argument("--session", required=True)
    q.add_argument("--label", choices=("untrusted_web", "untrusted_repository", "untrusted_mcp", "credential_exposure"), required=True)
    q = sub.add_parser("trusted-event", help="Administrator/supervisor posture event; can only tighten or quarantine")
    q.add_argument("--run", required=True)
    q.add_argument("--session")
    q.add_argument("--label", choices=("untrusted_web", "untrusted_repository", "untrusted_mcp", "credential_exposure", "tool_denied", "bypass_attempt", "policy_violation", "agent_compromise"), required=True)
    q.add_argument("--source", choices=("supervisor", "tool_gateway", "kernel", "admin", "client_report"), required=True)
    q.add_argument("--reason")
    q = sub.add_parser("tool-check", help="Trusted tool gateway authorization check for non-shell tool effects")
    q.add_argument("--run", required=True)
    q.add_argument("--session", required=True)
    q.add_argument("--tool", required=True)
    q.add_argument("--read", action="append", default=[])
    q.add_argument("--write", action="append", default=[])
    q.add_argument("--network", choices=("offline", "external"), default="offline")
    q = sub.add_parser("mcp-check", help="Authorize an MCP tool only from a trusted explicit effect contract; does not execute MCP servers")
    q.add_argument("--run", required=True)
    q.add_argument("--session", required=True)
    q.add_argument("--server", required=True)
    q.add_argument("--tool", required=True)
    q.add_argument("--read", action="append", default=[])
    q.add_argument("--write", action="append", default=[])
    q.add_argument("--network", choices=("offline", "external"), default="offline")
    q = sub.add_parser("checkpoint", help="Administrator-only posture change; preserves labels and audit history")
    q.add_argument("--run", required=True)
    q.add_argument("--mode", choices=("normal", "guarded", "lockdown"), required=True)
    q.add_argument("--reason", required=True, help="Administrative reason; do not include secrets")
    audit = sub.add_parser("audit", help="Verify and export signed, hash-chained records").add_subparsers(dest="audit_command", required=True)
    q = audit.add_parser("verify")
    q.add_argument("--file", type=Path, help="Offline JSONL export; omit to verify daemon state")
    q.add_argument("--public-key", type=Path)
    q.add_argument("--expected-head", help="Independently retained head detects tail truncation")
    q.add_argument("--checkpoint", type=Path, help="Authenticate the expected head using a saved signed checkpoint")
    q = audit.add_parser("checkpoint")
    q.add_argument("--output", type=Path, required=True, help="New file for the signed checkpoint; copy it to independent storage")
    audit.add_parser("anchor", help="Persist a signed checkpoint in the local state before copying/exporting it independently")
    q = audit.add_parser("anchors", help="List locally retained checkpoint anchors")
    q.add_argument("--after", type=int, default=0)
    q.add_argument("--limit", type=int, default=20)
    q = audit.add_parser("export")
    q.add_argument("--output", type=Path, required=True)
    q.add_argument("--state", type=Path, help="Offline read-only export from a stopped or full daemon database")
    state = sub.add_parser("state", help="Offline authenticated backup and restoration; never overwrites live state").add_subparsers(dest="state_command", required=True)
    q = state.add_parser("backup")
    q.add_argument("--state", type=Path, required=True)
    q.add_argument("--output", type=Path, required=True, help="New private directory; includes the private signing key")
    for name in ("verify", "restore"):
        q = state.add_parser(name)
        q.add_argument("--backup", type=Path, required=True)
        q.add_argument("--public-key", type=Path, required=True, help="Independently trusted original public key")
        q.add_argument("--expected-head", required=name == "restore")
        if name == "restore":
            q.add_argument("--output", type=Path, required=True, help="New state directory; existing paths are refused")
            q.add_argument("--reason", required=True)
    q = sub.add_parser("hook", help="Claude adapter; real harness compatibility remains unverified")
    q.add_argument("harness", choices=("claude",))
    q.add_argument("--run", required=True)
    q.add_argument("--session", required=True)
    q.add_argument("--wrapper", required=True, help="Absolute administrator-owned kechaa executable")
    q.add_argument("--shell", required=True, help="Canonical configured shell path")
    return p


def argv_value(values: list[str]) -> list[str]:
    if values and values[0] == "--":
        values = values[1:]
    require(bool(values), "argv_missing", "Provide an executable and its arguments after --.", "invalid_request")
    require(os.path.isabs(values[0]), "argv_path", "Name an absolute executable path; use its canonical path from policy init.", "invalid_request")
    return values


def initialize_policy(root: Path) -> dict:
    root = root.resolve(strict=True)
    require(root.is_dir(), "policy_root", "Choose an existing dedicated workspace directory.", "invalid_request")
    names = ("sh", "echo", "cat", "ls", "mkdir", "cp", "git", "python3", "make", "sleep")
    executables = sorted({str(Path(p).resolve()) for name in names if (p := shutil.which(name, path="/usr/bin:/bin"))})
    entrypoints = executables[:]
    if platform.system() == "Linux":
        from .effects import elf_interpreter
        executables = sorted(set(executables) | {loader for path in executables if (loader := elf_interpreter(path))})
    runtime = ("/usr", "/bin", "/lib", "/lib64") if platform.system() == "Linux" else ("/usr", "/bin", "/System/Library")
    reads = sorted({str(root)} | {str(Path(p).resolve()) for p in runtime if Path(p).exists()})
    if platform.system() == "Linux":
        # Offline package tools still inspect public OS release metadata.
        reads = sorted(set(reads) | {str(Path(p).resolve()) for p in ('/etc/os-release', '/etc/debian_version') if Path(p).is_file()})
    profiles = {"development": {"read": reads, "write": [str(root)], "execute": executables, "network": "offline",
                "environment": {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": str(root / ".home"), "TMPDIR": str(root / ".tmp")},
                "limits": {"wall_seconds": 60, "cpu_seconds": 30, "memory_mb": 256, "pids": 32, "output_bytes": 1048576, "file_bytes": 16777216}}}
    return {"schema": 1, "name": "restricted-development", "default": "deny", "roots": [str(root)],
            "sensitive": [], "grant_ttl_seconds": 60, "profiles": profiles,
            "rules": [{"id": f"executable-{i}", "executable": p, "profile": "development", "decision": "ask"} for i, p in enumerate(entrypoints)]}


def handle(args) -> int:
    cmd = args.command
    if cmd == "version":
        output({"version": __version__, "python": platform.python_version(), "os": platform.system(),
                "control_plane": ["Linux", "macOS"], "production_ready": False, "release": "alpha"})
    elif cmd in ("preflight", "doctor"):
        result = preflight(args.cgroup_root)
        output(result)
        return 0 if result.get("execution_available") else 3
    elif cmd == "status":
        output(call(args.socket, "health"))
    elif cmd == "daemon":
        from .daemon import serve
        require(0 <= args.duration <= 86400, "duration", "Duration must be 0 to 86400 seconds.", "invalid_request")
        asyncio.run(serve(args.state.resolve(), args.sockets.resolve(), args.policy, args.diagnostic, args.cgroup_root, args.agent_group, args.duration))
    elif cmd == "diagnostic":
        from .daemon import diagnostic_console
        require(1 <= args.duration <= 3600, "duration", "Console duration must be 1 to 3600 seconds.", "invalid_request")
        asyncio.run(diagnostic_console(args.state.resolve(), args.policy, args.admin, args.duration))
    elif cmd == "policy":
        operation = args.policy_command
        if operation == "schema":
            from .schema import policy_schema
            output(policy_schema())
        elif operation == "history":
            output(call(args.admin_socket, "policy_history", {"after": args.after, "limit": args.limit}))
        elif operation == "rollback":
            output(call(args.admin_socket, "policy_rollback", {"version": args.version, "expected_version": args.expected_version, "reason": args.reason}))
        elif operation == "init":
            document = initialize_policy(args.root)
            text = yaml.safe_dump(document, sort_keys=False)
            load(text, str(args.output))
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write("# Generated explicit capabilities; inspect before administrative activation.\n" + text)
            output({"created": str(args.output), "decision": "ask", "network": "offline"})
        elif operation == "diff":
            output(diff(load(read_bounded(args.old), str(args.old)), load(read_bounded(args.new), str(args.new))))
        else:
            raw = read_bounded(args.file)
            policy = load(raw, str(args.file))
            if operation == "validate":
                output({"valid": True, "version": policy.version, "schema": 1})
            elif operation == "lint":
                output({"version": policy.version, "findings": lint(policy)})
            elif operation == "export":
                print(canonical(policy.document).decode("ascii"))
            elif operation == "import":
                data = {"yaml": raw.decode("utf-8")}
                if args.expected_version is not None:
                    data["expected_version"] = args.expected_version
                output(call(args.admin_socket, "policy_import", data))
            else:
                result = evaluate(policy, argv_value(args.argv), str(Path(args.cwd).resolve()), args.mode)
                output({"policy": policy.version, "scope": "policy only; daemon also intersects contract, identity and run state", **result})
                return 2 if result["decision"] == "deny" else 0
    elif cmd == "run":
        if args.run_command == "open":
            contract = decode(read_bounded(args.contract))
            if not args.confirm:
                output({"proposed_contract": contract, "next": "Inspect this contract, then repeat with --confirm using the administrative socket."})
                return 2
            output(call(args.admin_socket, "run_open", {"uid": args.uid, "session": args.session, "contract": contract, "confirmed": True}))
        elif args.run_command in ("show", "close", "history"):
            operation = {"show": "run_get", "close": "run_close", "history": "run_history"}[args.run_command]
            data = {"run": args.run, "session": args.session}
            if args.run_command == "history":
                data["limit"] = args.limit
            output(call(args.socket, operation, data))
        elif args.run_command == "renew":
            output(call(args.admin_socket, "lease_renew", {"run": args.run, "seconds": args.seconds, "reason": args.reason}))
        elif args.run_command == "quarantine":
            output(call(args.admin_socket, "run_quarantine", {"run": args.run, "reason": args.reason}))
        elif args.run_command == "recover":
            output(call(args.admin_socket, "run_recover", {"run": args.run, "mode": args.mode, "seconds": args.seconds, "reason": args.reason}))
    elif cmd in ("prepare", "exec", "simulate"):
        action = {"argv": argv_value(args.argv), "cwd": str(Path(args.cwd).resolve()), "inputs": [str(Path(p).resolve()) for p in args.input]}
        data = {"run": args.run, "session": args.session, "action": action}
        if cmd != "prepare":
            data["grant"] = args.grant
        result = call(args.socket, "execute" if cmd == "exec" else cmd, data, timeout=620 if cmd == "exec" else 15)
        if cmd == "exec":
            sys.stdout.buffer.write(base64.b64decode(result["stdout"]))
            sys.stderr.buffer.write(base64.b64decode(result["stderr"]))
            if result["termination"] != "exited" or not result["controls_ready"] or "cleanup" in result:
                sys.stderr.buffer.flush()
                print(json.dumps({"kechaa": "action_did_not_complete_normally", "grant": result["grant"],
                                  "termination": result["termination"], "controls_ready": result["controls_ready"],
                                  "cleanup": result.get("cleanup", "complete"),
                                  "initialization_error": result.get("initialization_error"),
                                  "next": "Inspect grant/audit state and daemon readiness before requesting a new grant."}), file=sys.stderr)
            code = result["exit_code"]
            return code if 0 <= code <= 255 else 128 + min(127, abs(code))
        output(result)
    elif cmd == "agent":
        action = {"argv": argv_value(args.argv), "cwd": str(Path(args.cwd).resolve()), "inputs": [str(Path(p).resolve()) for p in args.input]}
        data = {"run": args.run, "session": args.session, "action": action, "supervised": True}
        if args.agent_command != "prepare":
            data["grant"] = args.grant
        result = call(args.socket, "execute" if args.agent_command == "launch" else args.agent_command.replace("agent_", ""), data,
                      timeout=620 if args.agent_command == "launch" else 15)
        if args.agent_command == "launch":
            sys.stdout.buffer.write(base64.b64decode(result["stdout"]))
            sys.stderr.buffer.write(base64.b64decode(result["stderr"]))
            if result["termination"] != "exited" or not result["controls_ready"] or "cleanup" in result:
                sys.stderr.buffer.flush()
                print(json.dumps({"kechaa": "supervised_agent_did_not_complete_normally", "grant": result["grant"],
                                  "termination": result["termination"], "controls_ready": result["controls_ready"],
                                  "cleanup": result.get("cleanup", "complete"),
                                  "initialization_error": result.get("initialization_error")}), file=sys.stderr)
            code = result["exit_code"]
            return code if 0 <= code <= 255 else 128 + min(127, abs(code))
        output(result)
    elif cmd == "grant":
        data = {"grant": args.grant}
        operation = {"show": "grant_get", "approve": "grant_approve", "revoke": "grant_revoke"}[args.grant_command]
        if args.grant_command == "approve":
            data.update(effects_digest=args.effects_digest, action_digest=args.action_digest)
        output(call(args.admin_socket, operation, data))
    elif cmd == "event":
        output(call(args.socket, "event", {"run": args.run, "session": args.session, "label": args.label}))
    elif cmd == "trusted-event":
        data = {"run": args.run, "label": args.label, "source": args.source}
        if args.session:
            data["session"] = args.session
        if args.reason:
            data["reason"] = args.reason
        output(call(args.admin_socket if args.source == "admin" else args.socket, "trusted_event", data))
    elif cmd == "tool-check":
        output(call(args.socket, "tool_request", {"run": args.run, "session": args.session, "tool": args.tool,
               "effects": {"read": [str(Path(p).resolve()) for p in args.read],
                           "write": [str(Path(p).resolve()) for p in args.write], "network": args.network}}))
    elif cmd == "mcp-check":
        require(args.server.replace("_", "").replace("-", "").isalnum() and args.tool.replace("_", "").replace("-", "").isalnum(),
                "mcp_name", "MCP server and tool names must be bounded alphanumeric identifiers.", "invalid_request")
        output(call(args.socket, "tool_request", {"run": args.run, "session": args.session,
               "tool": f"mcp__{args.server}__{args.tool}",
               "effects": {"kind": "mcp_effect_contract", "read": [str(Path(p).resolve()) for p in args.read],
                           "write": [str(Path(p).resolve()) for p in args.write], "network": args.network}}))
    elif cmd == "checkpoint":
        output(call(args.admin_socket, "checkpoint", {"run": args.run, "mode": args.mode, "reason": args.reason}))
    elif cmd == "audit":
        if args.audit_command == "verify":
            if args.file:
                from .store import verify_file, verify_checkpoint
                require(args.public_key is not None, "audit_key", "Offline verification requires the independently retained public key.", "invalid_request")
                public = read_bounded(args.public_key, 32)
                expected = args.expected_head
                if args.checkpoint:
                    checkpoint = verify_checkpoint(decode(read_bounded(args.checkpoint, 8192)), public)
                    require(expected is None or expected == checkpoint["head"], "audit_head", "Expected head and signed checkpoint disagree.")
                    expected = checkpoint["head"]
                output(verify_file(args.file, public, expected))
            else:
                require(not args.checkpoint and not args.expected_head, "audit_file", "Checkpoint/head verification requires an offline export file.", "invalid_request")
                output(call(args.admin_socket, "audit_verify"))
        elif args.audit_command == "checkpoint":
            from .recovery import write_new
            checkpoint = call(args.admin_socket, "audit_checkpoint")
            write_new(args.output, canonical(checkpoint) + b'\n')
            output({"checkpoint": str(args.output), "head": checkpoint["checkpoint"]["head"]})
        elif args.audit_command == "anchor":
            output(call(args.admin_socket, "audit_anchor"))
        elif args.audit_command == "anchors":
            output(call(args.admin_socket, "audit_anchors", {"after": args.after, "limit": args.limit}))
        else:
            if args.state:
                from .store import export_offline
                output(export_offline(args.state, args.output))
                return 0
            after = 0
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                while True:
                    result = call(args.admin_socket, "audit_export", {"after": after, "limit": 50})
                    events = result["events"]
                    if not events:
                        break
                    for event in events:
                        stream.write(canonical(event) + b"\n")
                        after = event["record"]["sequence"]
                    require(after <= 50000, "audit_size", "Audit export exceeds capacity.", "operational_error")
                stream.flush()
                os.fsync(stream.fileno())
            output({"exported_events": after, "file": str(args.output), "head": result["head"]})
    elif cmd == "state":
        from . import recovery
        if args.state_command == "backup":
            output(recovery.backup(args.state.absolute(), args.output.absolute()))
        elif args.state_command == "verify":
            result = recovery.verify(args.backup.absolute(), read_bounded(args.public_key, 32), args.expected_head)
            result.pop('files')
            output(result)
        else:
            output(recovery.restore(args.backup.absolute(), args.output.absolute(), read_bounded(args.public_key, 32), args.expected_head, args.reason))
    elif cmd == "hook":
        from .harness import claude, verdict
        try:
            event = decode(sys.stdin.buffer.read(262145))
            result = claude(event, args.socket, args.run, args.session, args.wrapper, args.shell)
        except KechaaError as exc:
            result = verdict("deny", exc.message)
        output(result)
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = list(sys.argv[1:] if argv is None else argv)
        tail = None
        if "--" in arguments:
            separator = arguments.index("--")
            arguments, tail = arguments[:separator], arguments[separator + 1:]
        args = parser().parse_args(arguments)
        if tail is not None:
            require(hasattr(args, "argv"), "unexpected_argv", "This command does not accept an execution argv after --.", "invalid_request")
            args.argv = tail
        return handle(args)
    except KechaaError as exc:
        print(json.dumps({"ok": False, "error": exc.as_dict()}, ensure_ascii=True), file=sys.stderr)
        return 3 if exc.category == "compatibility_block" else 2
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": {"code": "operational_error", "message": str(exc), "category": "operational_error"}}, ensure_ascii=True), file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        return 130
