"""Thin Claude hook adapter; authorization is always delegated to the daemon."""

from __future__ import annotations

import os
import shlex

from .common import KechaaError, require
from .protocol import call as transport_call


def call(path: str, operation: str, data: dict) -> dict:
    # A fake same-user service must not claim a protected profile to the hook.
    return transport_call(path, operation, data, expected_uid=0)


def verdict(decision: str, reason: str, command: str | None = None) -> dict:
    output = {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}
    if command is not None:
        output["updatedInput"] = {"command": command}
    return {"hookSpecificOutput": output}


def claude(event: dict, socket: str, run: str, session: str, wrapper: str, shell: str) -> dict:
    try:
        require(isinstance(event, dict) and event.get("session_id") == session,
                "harness_session", "Harness session does not match the administrator-confirmed run.")
        kind = event.get("hook_event_name")
        base = {"run": run, "session": session}
        if kind == "SessionEnd":
            call(socket, "run_close", base)
            return {}
        if kind == "SessionStart":
            status = call(socket, "run_get", base)
            return {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext":
                    f"KECHAA run {run}, mode {status['mode']}. Bash actions require daemon-issued grants."}}
        require(kind == "PreToolUse", "hook_event", "Unsupported hook event; configure only SessionStart, PreToolUse and SessionEnd.")
        tool = event.get("tool_name", "")
        require(isinstance(tool, str) and 1 <= len(tool) <= 256, "hook_tool", "Missing or invalid tool name; no command is authorized.")
        if tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__"):
            reviewed = call(socket, "tool_request", {**base, "tool": tool, "effects": {"network": "external", "read": [], "write": []}})
            return verdict("deny", reviewed["reason"])
        require(tool == "Bash", "tool_unsupported", "This adapter supports Bash actions only; route filesystem operations through the controlled execution API.")
        tool_input = event.get("tool_input")
        require(isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str), "hook_input", "Missing Bash command.")
        require(not tool_input.get("run_in_background", False), "lease_unsupported", "Background leases are unavailable. Use a bounded foreground action.")
        command = tool_input["command"]
        cwd = event.get("cwd")
        require(isinstance(cwd, str) and os.path.isabs(cwd), "hook_cwd", "Missing absolute working directory.")
        prefix = [wrapper, "--socket", socket, "exec", "--run", run, "--session", session, "--grant"]
        tokens = shlex.split(command)
        if tokens[:len(prefix)] == prefix and len(tokens) > len(prefix) + 1:
            grant_id = tokens[len(prefix)]
            existing = call(socket, "grant_status", {**base, "grant": grant_id})
            action = existing["action"]
            expected = prefix + [grant_id, "--cwd", action["cwd"], "--"] + action["argv"]
            require(tokens == expected and cwd == action["cwd"], "wrapper_changed", "Wrapped command differs from its approved request.")
            require(existing["state"] == "issued", "approval_pending", "Grant requires administrative approval or is no longer usable.")
            require(existing["profile"] != "diagnostic-no-execution", "execution_unavailable", "Diagnostic daemon cannot execute harness actions.")
            # Re-quote every token, eliminating shell metacharacter interpretation.
            return verdict("allow", "Daemon-approved, single-use KECHAA envelope.", shlex.join(expected))
        action = {"argv": [shell, "-c", command], "cwd": cwd, "inputs": []}
        result = call(socket, "prepare", {**base, "action": action})
        wrapped = shlex.join(prefix + [result["grant"], "--cwd", cwd, "--"] + action["argv"])
        if result["profile"] == "diagnostic-no-execution":
            return verdict("deny", "Diagnostic mode: no protected execution is available. Grant preparation succeeded, but this action will not run.")
        if result["state"] != "issued":
            return verdict("deny", f"Administrative approval required for grant {result['grant']}. Inspect its action and effects with grant show, approve their digests, then retry this exact wrapper: {wrapped}")
        return verdict("allow", "Policy-approved bounded envelope; all effects outside it remain denied.", wrapped)
    except (KechaaError, OSError, ValueError) as exc:
        reason = exc.message if isinstance(exc, KechaaError) else "Hook could not verify daemon authorization. No command is authorized."
        return verdict("deny", reason)
