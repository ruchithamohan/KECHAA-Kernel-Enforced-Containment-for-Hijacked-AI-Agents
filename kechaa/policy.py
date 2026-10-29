"""One policy engine for the CLI, daemon, and all adapters."""

from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from .common import (KechaaError, canonical, digest, fields, identifier, integer,
                     intersect_paths, overlap, path_string, require, within)

LIMITS = {"wall_seconds": (1, 600), "cpu_seconds": (1, 300), "memory_mb": (32, 4096),
          "pids": (1, 128), "output_bytes": (1024, 4194304), "file_bytes": (1024, 67108864)}
ENVIRONMENT = {"PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR", "XDG_CACHE_HOME", "npm_config_cache", "PYTHONHASHSEED"}
DEFAULT_SENSITIVE = ["/root", "/proc", "/sys", "/etc/shadow", "/etc/gshadow", "/etc/ssh", "/var/lib/kechaa", "/run/kechaa"]


def expiry_ms(value: str) -> int:
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value),
            "policy_expiry", "expires_at must be a quoted UTC timestamp, YYYY-MM-DDTHH:MM:SSZ.")
    try:
        stamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        require(stamp.year >= 1970, "policy_expiry", "Expiration must be in 1970 or later.")
        return int(stamp.timestamp()) * 1000
    except ValueError as exc:
        raise KechaaError("policy_expiry", "Invalid UTC expiration date.") from exc


@dataclass(frozen=True)
class Policy:
    document: dict
    version: str
    source: str


def load(data: bytes | str, source: str = "<policy>") -> Policy:
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeError as exc:
            raise KechaaError("policy_yaml", f"{source}:1: policy must be UTF-8.", "policy_misconfiguration") from exc
    require(len(data.encode("utf-8")) <= 262144, "policy_size", f"{source}:1: policy exceeds 256 KiB.", "policy_misconfiguration")
    locations: dict[tuple, int] = {}
    try:
        # Parse events first: aliases and anchors are forbidden, including merge keys.
        depth = 0
        for event in yaml.parse(data, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise KechaaError("policy_yaml", f"{source}:{event.start_mark.line + 1}: aliases and anchors are unsupported.", "policy_misconfiguration")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                require(depth <= 24, "policy_depth", f"{source}:{event.start_mark.line + 1}: nesting exceeds 24 levels.", "policy_misconfiguration")
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
        root = yaml.compose(data, Loader=yaml.SafeLoader)
        require(root is not None, "policy_empty", f"{source}:1: empty policy.", "policy_misconfiguration")

        def walk(node: Any, key: tuple = (), depth: int = 0) -> Any:
            locations[key] = node.start_mark.line + 1
            require(depth < 24, "policy_depth", f"{source}:{locations[key]}: nesting exceeds 24 levels.", "policy_misconfiguration")
            if isinstance(node, MappingNode):
                require(node.tag == "tag:yaml.org,2002:map", "policy_tag", f"{source}:{locations[key]}: unsupported YAML tag.", "policy_misconfiguration")
                result = {}
                for k, v in node.value:
                    require(isinstance(k, ScalarNode) and k.tag == "tag:yaml.org,2002:str", "policy_key", f"{source}:{k.start_mark.line + 1}: keys must be strings.", "policy_misconfiguration")
                    require(k.value not in result and k.value != "<<", "policy_duplicate", f"{source}:{k.start_mark.line + 1}: duplicate or merge key {k.value!r}.", "policy_misconfiguration")
                    result[k.value] = walk(v, key + (k.value,), depth + 1)
                return result
            if isinstance(node, SequenceNode):
                require(node.tag == "tag:yaml.org,2002:seq", "policy_tag", f"{source}:{locations[key]}: unsupported YAML tag.", "policy_misconfiguration")
                return [walk(v, key + (i,), depth + 1) for i, v in enumerate(node.value)]
            require(isinstance(node, ScalarNode), "policy_node", "Unsupported YAML node.", "policy_misconfiguration")
            if node.tag == "tag:yaml.org,2002:str":
                return node.value
            if node.tag == "tag:yaml.org,2002:int" and node.value.isascii() and node.value.isdecimal():
                return int(node.value, 10)
            if node.tag == "tag:yaml.org,2002:bool" and node.value in ("true", "false"):
                return node.value == "true"
            raise KechaaError("policy_scalar", f"{source}:{locations[key]}: use strings, decimal integers, or true/false; quote ambiguous YAML words.", "policy_misconfiguration")

        value = walk(root)
        normalized = validate(value, source, locations)
        return Policy(normalized, digest(normalized), source)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else 1
        raise KechaaError("policy_yaml", f"{source}:{line}: {getattr(exc, 'problem', 'invalid YAML')}", "policy_misconfiguration") from exc
    except (RecursionError, ValueError) as exc:
        raise KechaaError("policy_yaml", f"{source}:1: unsupported YAML scalar or nesting depth.", "policy_misconfiguration") from exc


def validate(value: dict, source: str = "<policy>", locations: dict | None = None) -> dict:
    locations = locations or {}
    current: tuple = ()
    try:
        fields(value, {"schema", "name", "default", "roots", "sensitive", "grant_ttl_seconds", "profiles", "rules"})
        require(type(value["schema"]) is int and value["schema"] == 1, "policy_version", "Only policy schema 1 is supported.")
        identifier(value["name"], "policy name")
        require(value["default"] == "deny", "policy_default", "The default decision must be deny.")
        integer(value["grant_ttl_seconds"], 1, 120, "grant_ttl_seconds")

        def paths(items: Any) -> list[str]:
            require(isinstance(items, list) and len(items) <= 64, "policy_paths", "Expected a list of at most 64 paths.")
            normalized = [path_string(x) for x in items]
            require(len(normalized) == len(set(normalized)), "policy_paths", "Duplicate paths are not permitted.")
            return sorted(normalized)

        current = ("roots",)
        roots = paths(value["roots"])
        require(roots and all(x not in ("/", "/home", "/Users", "/tmp", "/private/tmp", "/var", "/private/var") for x in roots),
                "policy_roots", "Choose dedicated project directories, not global or home-parent roots.")
        sensitive = sorted(set(paths(value["sensitive"]) + DEFAULT_SENSITIVE))
        require(not any(overlap(r, s) for r in roots for s in sensitive), "policy_sensitive", "A project root overlaps a sensitive path; Landlock cannot subtract a child deny.")
        profiles = value["profiles"]
        require(isinstance(profiles, dict) and 1 <= len(profiles) <= 16, "policy_profiles", "Provide 1 to 16 named profiles.")
        normalized_profiles: dict[str, dict] = {}
        resolving: set[str] = set()

        def profile(name: str) -> dict:
            nonlocal current
            if name in normalized_profiles:
                return normalized_profiles[name]
            current = ("profiles", name)
            identifier(name, "profile name")
            require(name in profiles and name not in resolving, "policy_inheritance", "Missing profile or inheritance cycle.")
            resolving.add(name)
            item = profiles[name]
            fields(item, {"read", "write", "execute", "network", "environment", "limits"}, {"extends"}, "profile")
            require(item["network"] == "offline", "network_unsupported", "This version supports only offline envelopes; TCP, UDP, DNS and local sockets are denied.", "compatibility_block")
            output = {key: paths(item[key]) for key in ("read", "write", "execute")}
            require(output["execute"], "policy_execute", "A profile must name at least one executable.")
            require(all(any(within(w, r) for r in roots) for w in output["write"]), "policy_write", "Writes must remain within declared project roots.")
            require(not any(overlap(p, s) for p in output["read"] + output["write"] + output["execute"] for s in sensitive),
                    "policy_sensitive", "An allowed path overlaps a sensitive path; choose narrower allow paths.")
            require(not any(overlap(e, w) for e in output["execute"] for w in output["write"]), "policy_exec_write", "Executable paths cannot overlap writable paths.")
            env = fields(item["environment"], set(), ENVIRONMENT, "environment")
            require(all(isinstance(v, str) and len(v) <= 4096 and "\x00" not in v for v in env.values()), "policy_environment", "Environment values must be bounded strings without NUL.")
            require(env.get("PATH", "/usr/bin:/bin") == "/usr/bin:/bin", "policy_environment", "PATH must be /usr/bin:/bin; name executables explicitly.")
            for env_key in ("HOME", "TMPDIR", "XDG_CACHE_HOME", "npm_config_cache"):
                if env_key in env:
                    require(any(within(path_string(env[env_key]), r) for r in roots), "policy_environment", f"{env_key} must be inside a project root.")
            limits = fields(item["limits"], set(LIMITS), where="limits")
            for key, bounds in LIMITS.items():
                current = ("profiles", name, "limits", key)
                integer(limits[key], *bounds, key)
            output.update(network="offline", environment=dict(sorted(env.items())), limits=limits.copy())
            if "extends" in item:
                parent = profile(identifier(item["extends"], "parent profile"))
                for key in ("read", "write"):
                    require(all(any(within(p, q) for q in parent[key]) for p in output[key]), "policy_inheritance", "Inherited capabilities may only narrow.")
                require(set(output["execute"]) <= set(parent["execute"]), "policy_inheritance", "Inherited executable lists may only narrow.")
                require(output["environment"] == parent["environment"], "policy_inheritance", "Inherited environment must remain identical.")
                require(all(output["limits"][k] <= parent["limits"][k] for k in LIMITS), "policy_inheritance", "Inherited limits may only decrease.")
            resolving.remove(name)
            normalized_profiles[name] = output
            return output

        for name in profiles:
            profile(name)
        rules = value["rules"]
        require(isinstance(rules, list) and 1 <= len(rules) <= 128, "policy_rules", "Provide 1 to 128 rules.")
        seen = set()
        result_rules = []
        for i, item in enumerate(rules):
            current = ("rules", i)
            fields(item, {"id", "executable", "profile", "decision"}, {"argv_prefix", "expires_at", "exception_reason"}, "rule")
            name = identifier(item["id"], "rule id")
            require(name not in seen, "policy_duplicate_rule", "Duplicate rule id.")
            seen.add(name)
            exe = path_string(item["executable"])
            require(isinstance(item["profile"], str) and item["profile"] in normalized_profiles, "policy_profile", "Rule references an unknown profile.")
            require(item["decision"] in ("allow", "ask", "deny"), "policy_decision", "Decision must be allow, ask, or deny.")
            require(exe in normalized_profiles[item["profile"]]["execute"], "policy_rule_exec", "Rule executable must be listed in its profile.")
            prefix = item.get("argv_prefix", [])
            require(isinstance(prefix, list) and len(prefix) <= 64 and all(isinstance(p, str) and len(p) <= 4096 and "\x00" not in p for p in prefix), "policy_argv", "argv_prefix must be a bounded list of exact argument strings.")
            normalized = {"id": name, "executable": exe, "profile": item["profile"], "decision": item["decision"], "argv_prefix": prefix}
            if "expires_at" in item or "exception_reason" in item:
                current = ("rules", i, "expires_at")
                require("expires_at" in item and "exception_reason" in item, "policy_expiry", "An expiring rule requires expires_at and exception_reason.")
                expiry_ms(item["expires_at"])
                require(item["decision"] in ("allow", "ask") and prefix, "policy_expiry", "Expiring permissions require an argument prefix and cannot override a deny rule.")
                require(isinstance(item["exception_reason"], str) and 8 <= len(item["exception_reason"]) <= 1000, "policy_expiry", "Provide an administrative exception reason of 8 to 1000 characters.")
                normalized.update(expires_at=item["expires_at"], exception_reason=item["exception_reason"])
            result_rules.append(normalized)
        return {"schema": 1, "name": value["name"], "default": "deny", "roots": roots,
                "sensitive": sensitive, "grant_ttl_seconds": value["grant_ttl_seconds"],
                "profiles": dict(sorted(normalized_profiles.items())), "rules": sorted(result_rules, key=lambda r: r["id"])}
    except KechaaError as exc:
        field_path = '.'.join(str(item) for item in current) or '<root>'
        while current not in locations and current:
            current = current[:-1]
        raise KechaaError(exc.code, f"{source}:{locations.get(current, 1)} ({field_path}): {exc.message}", "policy_misconfiguration") from exc


def evaluate(policy: Policy, argv: list[str], cwd: str, mode: str = "normal") -> dict:
    p = policy.document
    matched = [r for r in p["rules"] if argv[0] == r["executable"] and argv[1:1 + len(r["argv_prefix"])] == r["argv_prefix"]]
    reason = "Matched rules intersect capabilities; deny takes precedence over ask, then allow."
    if mode == "lockdown":
        return {"decision": "deny", "category": "security_block", "reason": "Run is in lockdown; an administrator must review the checkpoint.", "matched": []}
    if not any(within(cwd, r) for r in p["roots"]):
        return {"decision": "deny", "category": "security_block", "reason": "Working directory is outside the confirmed policy roots.", "matched": []}
    if not matched:
        return {"decision": "deny", "category": "security_block", "reason": "No executable and argument rule matched. Ask an administrator for a narrow policy rule.", "matched": []}
    deadlines = [expiry_ms(r["expires_at"]) for r in matched if "expires_at" in r]
    if deadlines and min(deadlines) <= time.time_ns() // 1000000:
        return {"decision": "deny", "category": "security_block", "reason": "A matching scoped permission expired. It remains a deny until an administrator reviews a replacement policy.", "matched": [r["id"] for r in matched]}
    decision = max((r["decision"] for r in matched), key={"allow": 0, "ask": 1, "deny": 2}.get)
    effect = copy.deepcopy(p["profiles"][matched[0]["profile"]])
    for rule in matched[1:]:
        other = p["profiles"][rule["profile"]]
        for key in ("read", "write"):
            effect[key] = intersect_paths(effect[key], other[key])
        effect["execute"] = sorted(set(effect["execute"]) & set(other["execute"]))
        effect["limits"] = {k: min(effect["limits"][k], other["limits"][k]) for k in LIMITS}
        if effect["environment"] != other["environment"]:
            decision, reason = "deny", "Matched profiles have conflicting environments; administrator must resolve the policy."
    if mode == "guarded":
        effect["write"] = []
        if decision == "allow":
            decision = "ask"
        reason += " Guarded mode removes write access and requires administrative approval."
    effect.update(schema=1, profile="offline-v1", sensitive=p["sensitive"], confidence="bounded_capability",
                  provenance="explicit YAML capabilities; arbitrary script effects are unknown",
                  syscalls="offline-v1", observations="process lifecycle only; filesystem/network effects incomplete")
    return {**({"expires_ms": min(deadlines)} if deadlines else {}),
            "decision": decision, "category": "security_block" if decision == "deny" else "policy_decision",
            "reason": reason, "matched": [r["id"] for r in matched], "effects": effect}


def lint(policy: Policy) -> list[dict]:
    findings = []
    for name, p in policy.document["profiles"].items():
        if p["write"]:
            findings.append({"profile": name, "level": "notice", "message": "Writes include create, overwrite, rename and delete throughout each named subtree."})
        if any(path in ("/usr", "/System", "/Library") for path in p["read"]):
            findings.append({"profile": name, "level": "warning", "message": "Broad runtime reads expose every readable file under the named runtime directory. Review local secrets there."})
    for r in policy.document["rules"]:
        if r["decision"] == "allow":
            findings.append({"rule": r["id"], "level": "warning", "message": "Allow is standing administrator approval for this bounded capability, including arbitrary arguments after the prefix."})
    return findings


def diff(old: Policy, new: Policy) -> dict:
    changes = []
    def walk(before, after, path: str) -> None:
        if canonical(before) == canonical(after):
            return
        if isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(set(before) | set(after)):
                walk(before.get(key), after.get(key), f"{path}.{key}" if path else key)
            return
        entry = {"field": path, "before": before, "after": after, "impact": "requires_review"}
        if path.endswith(".decision") and before in ("deny", "ask", "allow") and after in ("deny", "ask", "allow"):
            ranks = {"deny": 0, "ask": 1, "allow": 2}
            entry["impact"] = "widens_approval" if ranks[after] > ranks[before] else "tightens_approval"
        elif type(before) is int and type(after) is int and (".limits." in path or path == "grant_ttl_seconds"):
            entry["impact"] = "increases_budget" if after > before else "decreases_budget"
        elif isinstance(before, list) and isinstance(after, list):
            entry["added"] = [x for x in after if x not in before]
            entry["removed"] = [x for x in before if x not in after]
            entry["impact"] = "changes_capability_or_match_scope"
        elif ".environment." in path:
            entry["impact"] = "changes_execution_context"
        changes.append(entry)
    before, after = copy.deepcopy(old.document), copy.deepcopy(new.document)
    before["rules"] = {r["id"]: r for r in before["rules"]}
    after["rules"] = {r["id"]: r for r in after["rules"]}
    walk(before, after, "")
    return {"old_version": old.version, "new_version": new.version, "changes": changes}
