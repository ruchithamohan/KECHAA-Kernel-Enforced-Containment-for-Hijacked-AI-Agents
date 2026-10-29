"""macOS capability reporting. Native execution deliberately has no fail-open path."""

from pathlib import Path

from ..common import KechaaError


def inspect() -> dict:
    return {"control_plane_available": True, "execution_available": False,
            "sandbox_exec_present": Path("/usr/bin/sandbox-exec").is_file(),
            "native_profile": "unavailable",
            "reason": "Native macOS process-tree lifetime and resource enforcement are unverified. Protected execution is disabled.",
            "safe_next_step": "Use the macOS policy/client tools with a separately administered Linux VM. No implicit host execution or remote transport is provided."}


def execute() -> None:
    raise KechaaError("macos_execution_unavailable", inspect()["reason"], "compatibility_block")
