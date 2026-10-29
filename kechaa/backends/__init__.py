"""Platform backends report capabilities explicitly; none silently degrades."""

import os
import platform


def preflight(cgroup_root: str = "/sys/fs/cgroup/kechaa") -> dict:
    system = platform.system()
    result = {"os": system, "kernel": platform.release(), "architecture": platform.machine(),
              "production_ready": False, "active_profile": "diagnostic-no-execution",
              "execution_verified": False}
    if system == "Linux":
        from .linux import inspect
        result.update(inspect(cgroup_root))
    elif system == "Darwin":
        from .macos import inspect
        result.update(inspect())
    else:
        result.update(execution_available=False, reason="No enforcement backend for this operating system.")
    result["uid"] = os.geteuid()
    return result
