"""Authority lives here; adapters translate requests but never make grants."""

from __future__ import annotations

import base64
import pwd
import secrets
import time

from . import effects
from .common import (KechaaError, canonical, decode, digest, fields, identifier,
                     integer, overlap, path_string, require, within)
from .policy import Policy, evaluate, load, validate
from .store import Store

MODES = {"normal": 0, "guarded": 1, "lockdown": 2, "quarantined": 3}
LABELS = {"untrusted_web", "untrusted_repository", "untrusted_mcp", "credential_exposure"}
TRUSTED_LABELS = LABELS | {"tool_denied", "bypass_attempt", "policy_violation", "agent_compromise"}


class Engine:
    def __init__(self, store: Store, initial: Policy | None, diagnostic: bool, owner: int):
        self.store, self.diagnostic, self.owner = store, diagnostic, owner
        self.epoch = secrets.token_hex(16)
        self.deadlines: dict[str, float] = {}
        self.run_deadlines: dict[str, tuple[int, float]] = {}
        self.started = time.monotonic()
        active = store.meta("active_policy")
        if active:
            row = store.db.execute("SELECT document FROM policies WHERE version=?", (active,)).fetchone()
            require(row is not None, "policy_missing", "Active policy version is missing from state.")
            doc = validate(decode(row[0]), "<active-policy>")
            require(digest(doc) == active, "policy_corrupt", "Stored policy digest does not match active version.")
            self.policy = Policy(doc, active, "<active-policy>")
        else:
            require(initial is not None, "policy_required", "First startup requires a validated policy.", "operational_error")
            self.policy = initial
        with store.transaction():
            if not active:
                self._activate(self.policy)
            count = store.db.execute("SELECT COUNT(*) FROM grants WHERE state IN ('pending','issued','adopted','running')").fetchone()[0]
            store.db.execute("UPDATE grants SET state='revoked_restart' WHERE state IN ('pending','issued','adopted','running')")
            store.event("daemon_started", {"epoch": self.epoch, "revoked_grants": count, "policy": self.policy.version,
                        "profile": self.profile, "observation": "No kernel effect stream is available."}, owner)
        now_ms = time.time_ns() // 1000000
        for row in store.db.execute("SELECT id,body FROM runs WHERE closed=0").fetchall():
            run_body = decode(row["body"])
            require(isinstance(run_body, dict), "state_corrupt", "Persisted run body is malformed.")
            if "expires_ms" not in run_body:
                with store.transaction():
                    store.db.execute("UPDATE runs SET closed=1,revision=revision+1 WHERE id=?", (row['id'],))
                    store.event('legacy_run_closed', {'run': row['id'], 'reason': 'Session lacks a confirmed lifetime; require a new bounded contract.'}, owner)
            else:
                expiry = integer(run_body["expires_ms"], 0, 9007199254740991, "run expiration")
                self.run_deadlines[row["id"]] = (expiry, time.monotonic() + max(0, expiry - now_ms) / 1000)

    @property
    def profile(self) -> str:
        return "diagnostic-no-execution" if self.diagnostic else "linux-offline-experimental"

    def _activate(self, policy: Policy) -> None:
        previous = self.store.meta("active_policy")
        self.store.db.execute("INSERT OR IGNORE INTO policies VALUES(?,?)", (policy.version, canonical(policy.document)))
        self.store.set_meta("active_policy", policy.version)
        self.store.event("policy_activated", {"version": policy.version, "previous": previous,
                         "exceptions": [{"rule": r["id"], "expires_at": r["expires_at"], "reason": r["exception_reason"]}
                                        for r in policy.document["rules"] if "expires_at" in r]}, self.owner)

    def admin(self, uid: int, administrative: bool) -> None:
        require(administrative and uid == self.owner, "admin_required", "This operation requires the separate administrative socket and daemon-owner OS identity.")

    def run(self, run_id: str, session: str, uid: int) -> dict:
        identifier(run_id, "run id")
        identifier(session, "session id")
        row = self.store.db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        require(row is not None and row["uid"] == uid and row["session"] == session,
                "run_binding", "Run, session, and authenticated peer UID do not match.")
        require(not row["closed"], "run_closed", "The run has ended. An administrator must confirm a new contract.")
        body = decode(row["body"])
        require(body.get("state", "active") not in ("suspended", "quarantined", "terminated"),
                "run_contained", "The run is suspended, quarantined, or terminated; administrator recovery is required.")
        lease = body.get("lease", {})
        now = time.time_ns() // 1000000
        require(isinstance(lease, dict) and now < integer(lease.get("expires_ms", 0), 0, 9007199254740991, "lease expiration"),
                "lease_expired", "The agent authorization lease expired. Administrator renewal or recovery is required.")
        deadline = self.run_deadlines.get(run_id)
        require(deadline is None or now < deadline[0] and time.monotonic() < deadline[1],
                "run_expired", "The confirmed session lifetime expired. An administrator must review a new session contract.")
        return dict(row)

    def admin_run(self, run_id: str) -> dict:
        identifier(run_id, "run id")
        row = self.store.db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        require(row is not None, "run_missing", "Run does not exist.")
        return dict(row)

    @staticmethod
    def public_run(row: dict) -> dict:
        return {k: decode(v) if k == "body" else v for k, v in row.items()}

    def open_run(self, data: dict, uid: int, administrative: bool) -> dict:
        self.admin(uid, administrative)
        fields(data, {"uid", "session", "contract", "confirmed"})
        target = integer(data["uid"], 1 if not self.diagnostic else 0, 2147483647, "uid")
        identifier(data["session"], "session")
        require(data["confirmed"] is True, "contract_confirmation", "Administrator must inspect and explicitly confirm the task contract.")
        contract = fields(data["contract"], {"roots", "executables", "write"}, {"lifetime_seconds"}, where="contract")
        lifetime = integer(contract.get("lifetime_seconds", 3600), 1, 86400, "contract lifetime_seconds")
        require(type(contract["write"]) is bool, "contract_write", "Contract write must be true or false.")
        require(isinstance(contract["roots"], list) and 1 <= len(contract["roots"]) <= 16,
                "contract_roots", "Contract needs 1 to 16 roots.")
        roots = sorted({path_string(p) for p in contract["roots"]})
        require(all(any(within(p, r) for r in self.policy.document["roots"]) for p in roots), "contract_roots", "Contract roots cannot exceed administrator policy roots.")
        require(isinstance(contract["executables"], list) and 1 <= len(contract["executables"]) <= 64,
                "contract_executables", "Contract needs 1 to 64 executables.")
        executables = sorted({path_string(p) for p in contract["executables"]})
        configured = {p for profile in self.policy.document["profiles"].values() for p in profile["execute"]}
        require(set(executables) <= configured, "contract_executables", "Contract executable is not configured in policy.")
        require(self.store.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0] < 1000, "run_capacity", "Run capacity reached; archive state administratively.", "operational_error")
        existing = self.store.db.execute("SELECT id FROM runs WHERE uid=? AND session=?", (target, data["session"])).fetchone()
        require(existing is None, "session_exists", "Session already exists; resume its persisted run instead of resetting posture.")
        run_id = secrets.token_hex(16)
        opened = time.time_ns() // 1000000
        expires = opened + lifetime * 1000
        body = {"contract": {"roots": roots, "executables": executables, "write": contract["write"], "lifetime_seconds": lifetime}, "labels": [],
                "opened_ms": opened, "expires_ms": expires, "lease": {"issued_ms": opened, "expires_ms": expires, "renewals": 0},
                "state": "active", "posture": "normal", "trusted_signals": [],
                "signals": [], "actions": 0, "denials": 0, "policy_at_confirmation": self.policy.version, "observed_effects_complete": False}
        with self.store.transaction():
            self.store.db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)", (run_id, target, data["session"], canonical(body), 1, "normal", 0, 0))
            self.store.event("contract_confirmed", {"run": run_id, "uid": target, "session_digest": digest(data["session"]), "contract": body["contract"]}, uid)
            self.store.history(run_id, "contract_confirmed", {"lease_expires_ms": expires, "mode": "normal"})
        self.run_deadlines[run_id] = (body["expires_ms"], time.monotonic() + lifetime)
        return {"run": run_id, "session": data["session"], "profile": self.profile, "contract": body["contract"], "expires_ms": body["expires_ms"]}

    def history(self, data: dict, uid: int) -> dict:
        fields(data, {"run", "session"}, {"limit"})
        row = self.run(data["run"], data["session"], uid)
        return {"run": row["id"], "history": self.store.history_for_run(row["id"], integer(data.get("limit", 64), 1, 512, "history limit"))}

    def renew_lease(self, data: dict, uid: int, administrative: bool) -> dict:
        self.admin(uid, administrative)
        fields(data, {"run", "seconds", "reason"})
        row = self.admin_run(data["run"])
        require(not row["closed"], "run_closed", "Closed runs cannot be renewed.")
        seconds = integer(data["seconds"], 1, 86400, "lease seconds")
        require(isinstance(data["reason"], str) and 8 <= len(data["reason"]) <= 1000, "lease_reason", "Renewal requires an administrative reason.", "invalid_request")
        body = decode(row["body"])
        require(body.get("state", "active") in ("active", "suspended"), "run_contained", "Quarantined or terminated runs require explicit recovery.")
        now = time.time_ns() // 1000000
        expires = min(body["expires_ms"], now + seconds * 1000)
        body["lease"] = {"issued_ms": now, "expires_ms": expires, "renewals": int(body.get("lease", {}).get("renewals", 0)) + 1}
        if body.get("state") == "suspended":
            body["state"] = "active"
        with self.store.transaction():
            self.store.db.execute("UPDATE runs SET body=?,revision=revision+1 WHERE id=?", (canonical(body), row["id"]))
            self.store.db.execute("UPDATE grants SET state='revoked_lease' WHERE run=? AND state IN ('issued','pending')", (row["id"],))
            self.store.history(row["id"], "lease_renewed", {"expires_ms": expires, "reason": data["reason"]})
            self.store.event("lease_renewed", {"run": row["id"], "expires_ms": expires, "reason": data["reason"]}, uid)
        self.run_deadlines[row["id"]] = (body["expires_ms"], time.monotonic() + max(0, body["expires_ms"] - now) / 1000)
        return {"run": row["id"], "lease_expires_ms": expires, "terminate_active": True}

    def _risk_transition(self, row: dict, body: dict, label: str, source: str) -> tuple[str, int, str]:
        high = {"credential_exposure", "bypass_attempt", "agent_compromise"}
        medium = {"untrusted_web", "untrusted_repository", "untrusted_mcp", "tool_denied", "policy_violation"}
        points = 60 if label in high else 20 if label in medium else 10
        score = min(100, row["score"] + points)
        mode = "quarantined" if score >= 90 or label == "agent_compromise" else "lockdown" if score >= 60 else "guarded"
        if MODES[row["mode"]] > MODES[mode]:
            mode = row["mode"]
        reason = f"{source}:{label} raised cumulative risk to {score}."
        return mode, points, reason

    def trusted_event(self, data: dict, uid: int, administrative: bool = False) -> dict:
        fields(data, {"run", "label", "source"}, {"session", "reason"})
        require(administrative or "session" in data, "session_required", "Non-administrative posture events must be bound to a session.", "invalid_request")
        row = self.admin_run(data["run"]) if administrative and "session" not in data else self.run(data["run"], data["session"], uid)
        require(isinstance(data["label"], str) and data["label"] in TRUSTED_LABELS, "label_unknown", "Unknown trusted posture label.", "invalid_request")
        require(isinstance(data["source"], str) and data["source"] in ("supervisor", "tool_gateway", "kernel", "admin", "client_report"),
                "event_source", "Trusted event source is not recognized.", "invalid_request")
        if data["source"] == "admin":
            self.admin(uid, administrative)
        body = decode(row["body"])
        mode, points, reason = self._risk_transition(row, body, data["label"], data["source"])
        body["labels"] = sorted(set(body.get("labels", [])) | {data["label"]})
        body["posture"] = mode
        if mode == "quarantined":
            body["state"] = "quarantined"
        signal = {"signal": data["label"], "source": data["source"], "points": points, "reason": data.get("reason", reason)}
        body["trusted_signals"] = (body.get("trusted_signals", []) + [signal])[-64:]
        with self.store.transaction():
            self.store.db.execute("UPDATE runs SET body=?,mode=?,revision=revision+1,score=MIN(100,score+?) WHERE id=?",
                                  (canonical(body), mode, points, row["id"]))
            self.store.db.execute("UPDATE grants SET state='revoked_posture' WHERE run=? AND state IN ('issued','pending')", (row["id"],))
            self.store.history(row["id"], "posture_changed", {"label": data["label"], "source": data["source"], "mode": mode, "reason": signal["reason"]}, min(100, row["score"] + points))
            self.store.event("posture_changed", {"run": row["id"], "label": data["label"], "source": data["source"], "mode": mode,
                             "response": "Active action must terminate; future actions require a new envelope."}, uid)
        return {"run": row["id"], "mode": mode, "state": body.get("state", "active"), "changed": True, "terminate_active": True}

    def tool_request(self, data: dict, uid: int) -> dict:
        fields(data, {"run", "session", "tool", "effects"})
        row = self.run(data["run"], data["session"], uid)
        require(isinstance(data["tool"], str) and 1 <= len(data["tool"]) <= 128, "tool_name", "Invalid tool name.", "invalid_request")
        effects = fields(data["effects"], set(), {"read", "write", "network", "kind"}, where="tool effects")
        tool = data["tool"]
        body = decode(row["body"])
        contract = body["contract"]
        decision, reason, risk = "allow", "Tool effects are within the confirmed run contract.", row["score"]
        reads = [path_string(path) for path in effects.get("read", [])]
        writes = [path_string(path) for path in effects.get("write", [])]
        network = effects.get("network", "offline")
        require(isinstance(effects.get("read", []), list) and isinstance(effects.get("write", []), list),
                "tool_effects", "Tool read/write effects must be path lists.", "invalid_request")
        require(network in ("offline", "external"), "tool_network", "Tool network effect must be offline or external.", "invalid_request")
        sensitive = set(self.policy.document["sensitive"])
        home = pwd.getpwuid(uid).pw_dir.rstrip("/")
        sensitive |= {home + suffix for suffix in ("/.ssh", "/.aws", "/.azure", "/.kube", "/.config/gcloud", "/.claude", "/.codex")}
        if tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__") or network == "external":
            decision, reason, risk = "deny", "External web/MCP/network tool effects are unsupported by this offline profile and fail closed.", min(100, row["score"] + 20)
        elif any(any(within(path, item) or within(item, path) for item in sensitive) for path in reads + writes):
            decision, reason, risk = "deny", "Tool effects overlap sensitive credential/configuration paths.", min(100, row["score"] + 60)
        elif any(not any(within(path, root) for root in contract["roots"]) for path in reads + writes):
            decision, reason, risk = "deny", "Tool effects exceed the confirmed run roots.", min(100, row["score"] + 20)
        elif writes and (not contract["write"] or row["mode"] != "normal"):
            decision, reason = "ask", "Write-capable tool requires administrator approval or recovery in the current posture."
        with self.store.transaction():
            self.store.history(row["id"], "tool_request", {"tool": tool, "effects": effects, "decision": decision, "reason": reason}, risk)
            if decision == "deny":
                event = "untrusted_mcp" if tool.startswith("mcp__") else "untrusted_web" if tool in ("WebFetch", "WebSearch") or network == "external" else "tool_denied"
                mode, points, posture_reason = self._risk_transition(row, body, event, "tool_gateway")
                body["labels"] = sorted(set(body.get("labels", [])) | {event})
                body["posture"] = mode
                if mode == "quarantined":
                    body["state"] = "quarantined"
                body["trusted_signals"] = (body.get("trusted_signals", []) + [{"signal": event, "source": "tool_gateway", "points": points, "reason": posture_reason}])[-64:]
                self.store.db.execute("UPDATE runs SET body=?,mode=?,revision=revision+1,score=MIN(100,score+?) WHERE id=?",
                                      (canonical(body), mode, points, row["id"]))
                self.store.db.execute("UPDATE grants SET state='revoked_posture' WHERE run=? AND state IN ('issued','pending')", (row["id"],))
                self.store.event("tool_request_denied", {"run": row["id"], "tool": tool, "reason": reason, "mode": mode}, uid)
                return {"decision": decision, "reason": reason, "run": row["id"], "mode": mode, "terminate_active": True}
            self.store.event("tool_request_reviewed", {"run": row["id"], "tool": tool, "decision": decision}, uid)
        return {"decision": decision, "reason": reason, "run": row["id"], "mode": row["mode"], "terminate_active": False}

    def quarantine(self, data: dict, uid: int, administrative: bool) -> dict:
        self.admin(uid, administrative)
        fields(data, {"run", "reason"})
        row = self.admin_run(data["run"])
        require(isinstance(data["reason"], str) and 8 <= len(data["reason"]) <= 1000, "quarantine_reason", "Quarantine requires an administrative reason.", "invalid_request")
        body = decode(row["body"])
        body["state"] = "quarantined"
        body["posture"] = "quarantined"
        with self.store.transaction():
            self.store.db.execute("UPDATE runs SET body=?,mode='quarantined',revision=revision+1,score=100 WHERE id=?", (canonical(body), row["id"]))
            self.store.db.execute("UPDATE grants SET state='revoked_quarantine' WHERE run=? AND state IN ('issued','pending')", (row["id"],))
            self.store.history(row["id"], "quarantined", {"reason": data["reason"]}, 100)
            self.store.event("run_quarantined", {"run": row["id"], "reason": data["reason"]}, uid)
        return {"run": row["id"], "state": "quarantined", "terminate_active": True}

    def recover_run(self, data: dict, uid: int, administrative: bool) -> dict:
        self.admin(uid, administrative)
        fields(data, {"run", "mode", "seconds", "reason"})
        row = self.admin_run(data["run"])
        require(data["mode"] in ("normal", "guarded", "lockdown"), "recover_mode", "Recovery mode must be normal, guarded or lockdown.", "invalid_request")
        require(isinstance(data["reason"], str) and 8 <= len(data["reason"]) <= 1000, "recover_reason", "Recovery requires an administrative reason.", "invalid_request")
        seconds = integer(data["seconds"], 1, 86400, "lease seconds")
        now = time.time_ns() // 1000000
        body = decode(row["body"])
        expires = min(body["expires_ms"], now + seconds * 1000)
        body["state"] = "active"
        body["posture"] = data["mode"]
        body["lease"] = {"issued_ms": now, "expires_ms": expires, "renewals": int(body.get("lease", {}).get("renewals", 0)) + 1}
        with self.store.transaction():
            self.store.db.execute("UPDATE runs SET body=?,mode=?,revision=revision+1 WHERE id=?", (canonical(body), data["mode"], row["id"]))
            self.store.db.execute("UPDATE grants SET state='revoked_recovery' WHERE run=? AND state IN ('issued','pending')", (row["id"],))
            self.store.history(row["id"], "recovered", {"mode": data["mode"], "expires_ms": expires, "reason": data["reason"]})
            self.store.event("run_recovered", {"run": row["id"], "mode": data["mode"], "expires_ms": expires, "reason": data["reason"]}, uid)
        return {"run": row["id"], "state": "active", "mode": data["mode"], "lease_expires_ms": expires}

    def _history_decision(self, row: dict, action: dict, decision: dict) -> dict:
        body = decode(row["body"])
        history = self.store.history_for_run(row["id"], 64)
        recent_denials = [item for item in history[-20:] if item["kind"] in ("request_denied", "policy_denied", "suspicious_action")]
        reasons = []
        mode = row["mode"]
        require(body.get("state", "active") == "active", "run_contained", "Run is not active; administrator recovery is required.")
        require(mode != "quarantined", "run_quarantined", "Run is quarantined; administrator recovery is required.")
        if len(recent_denials) >= 3:
            mode = "lockdown"
            reasons.append("three or more recent denials require administrator checkpoint before more execution")
        argv_paths = [arg for arg in action["argv"][1:] if isinstance(arg, str) and arg.startswith("/")]
        sensitive_hits = [arg for arg in argv_paths if any(within(arg, sensitive) or within(sensitive, arg) for sensitive in decision.get("effects", {}).get("sensitive", []))]
        if sensitive_hits:
            mode = "lockdown"
            reasons.append("argv references sensitive path outside explicit approved inputs")
        if mode == "lockdown":
            return {"decision": "deny", "category": "security_block", "reason": "; ".join(reasons) or "Run is in lockdown.",
                    "matched": decision.get("matched", []), "history": {"recent_denials": len(recent_denials)}}
        if mode == "guarded" and decision["decision"] == "allow":
            decision = {**decision, "decision": "ask", "reason": decision["reason"] + " History-aware guarded posture requires approval."}
        decision["history"] = {"recent_denials": len(recent_denials), "mode": mode, "risk": row["score"]}
        return decision

    def prepare(self, data: dict, uid: int) -> dict:
        fields(data, {"run", "session", "action"}, {"supervised"})
        row = self.run(data["run"], data["session"], uid)
        action = effects.request(data["action"])
        supervised = data.get("supervised", False)
        require(type(supervised) is bool, "supervised_flag", "Supervised launch marker must be boolean.", "invalid_request")
        contract = decode(row["body"])["contract"]
        require(any(within(action["cwd"], r) for r in contract["roots"]), "contract_scope", "Working directory exceeds the confirmed task contract.")
        require(action["argv"][0] in contract["executables"], "contract_executable", "Executable is outside the confirmed task contract.")
        decision = evaluate(self.policy, action["argv"], action["cwd"], row["mode"])
        if decision["decision"] != "deny":
            decision = self._history_decision(row, action, decision)
        if decision["decision"] == "deny":
            with self.store.transaction():
                self.store.history(row["id"], "policy_denied", {"reason": decision["reason"], "action": action,
                                   "matched": decision.get("matched", []), "history": decision.get("history", {})}, min(100, row["score"] + 20))
        require(decision["decision"] != "deny", "policy_denied", decision["reason"])
        envelope = decision["effects"]
        if not self.diagnostic:
            from .backends.linux import workspace_filesystems
            envelope["workspace_filesystems"] = workspace_filesystems(contract["roots"])
        # The contract narrows project access while retaining separately approved runtime reads.
        policy_roots = self.policy.document["roots"]
        for key in ("read", "write"):
            project = [p for p in envelope[key] if any(within(p, r) for r in policy_roots)]
            runtime = [p for p in envelope[key] if p not in project]
            narrowed = {p if within(p, r) else r for p in project for r in contract["roots"] if within(p, r) or within(r, p)}
            envelope[key] = sorted(set(runtime) | narrowed)
        envelope["execute"] = sorted(set(envelope["execute"]) & set(contract["executables"]))
        if not contract["write"]:
            envelope["write"] = []
        if not self.diagnostic:
            envelope['metadata_mutations'] = 'workspace' if set(envelope['write']) <= set(contract['roots']) else 'denied'
            envelope['mounts'] = 'private-readonly-except-approved-workspace-volumes'
            envelope['syscalls'] = 'offline-v2'
        home = pwd.getpwuid(uid).pw_dir.rstrip("/")
        protected = [home + suffix for suffix in ("/.ssh", "/.aws", "/.azure", "/.kube", "/.config/gcloud",
                     "/.claude", "/.codex", "/.bashrc", "/.zshrc", "/.profile", "/.gitconfig")]
        protected += [str(self.store.path)]
        require(not any(overlap(p, s) for p in envelope["read"] + envelope["write"] + envelope["execute"] for s in protected),
                "sensitive_overlap", "An allowed subtree overlaps this OS user's credential/configuration paths or daemon state; choose a dedicated project root.", "policy_misconfiguration")
        envelope["sensitive"] = sorted(set(envelope["sensitive"]) | set(protected))
        envelope["stdio"] = {"stdin": "/dev/null", "output": "bounded daemon-owned pipes", "inherited_descriptors": "none beyond stdio"}
        envelope["devices"] = {"/dev/null": "read and write; ioctl denied"}
        identified = effects.identify(action, envelope, privileged=not self.diagnostic)
        self.expire()
        require(len(self.deadlines) < 256, "grant_capacity", "At most 256 live grants are supported; consume or revoke pending grants.", "operational_error")
        grant_id = secrets.token_hex(24)
        ttl = self.policy.document["grant_ttl_seconds"]
        now = time.time_ns() // 1000000
        expires = min(now + ttl * 1000, decision.get("expires_ms", now + ttl * 1000),
                      self.run_deadlines.get(row["id"], (now + ttl * 1000, 0))[0])
        require(expires > now, "grant_expired", "The scoped policy permission expired during preparation; request administrative review.")
        body = {"schema": 1, "id": grant_id, "run": row["id"], "session": data["session"], "uid": uid,
                "revision": row["revision"], "mode": row["mode"], "policy": self.policy.version, "epoch": self.epoch,
                "issued_ms": now, "expires_ms": expires, "profile": self.profile,
                "action": action, "action_digest": digest(action), "effects": envelope, "effects_digest": digest(envelope),
                "inputs": identified, "inputs_digest": digest(identified), "decision": decision["decision"]}
        if supervised:
            body["supervised_agent"] = True
            body["boundary"] = {"schema": 1, "kind": "whole-agent-process-tree", "mandatory": not self.diagnostic,
                                "run": row["id"], "session": data["session"],
                                "mechanisms": ["single-use grant", "lease-bound run", "cgroup-v2", "pid namespace",
                                               "mount namespace", "network namespace", "Landlock", "seccomp", "credential drop"],
                                "coverage": "entry process and descendants launched by the KECHAA Linux worker",
                                "unsupported": "processes started outside the KECHAA launcher are outside the claimed supported boundary"}
        signature = self.store.sign("KECHAA-GRANT-1", body)
        state = "pending" if decision["decision"] == "ask" else "issued"
        with self.store.transaction():
            self.store.db.execute("INSERT INTO grants VALUES(?,?,?,?,?)", (grant_id, row["id"], state, canonical(body), signature))
            self.store.history(row["id"], "grant_prepared", {"grant": grant_id, "decision": decision["decision"],
                               "action_digest": body["action_digest"], "effects_digest": body["effects_digest"],
                               "history": decision.get("history", {})}, row["score"])
            if supervised:
                self.store.history(row["id"], "supervised_agent_prepared", {"grant": grant_id, "boundary": body["boundary"]}, row["score"])
            self.store.event("grant_prepared" if state == "pending" else "grant_issued", {
                "grant": grant_id, "run": row["id"], "state": state, "policy": self.policy.version,
                "action_digest": body["action_digest"], "effects_digest": body["effects_digest"],
                "inputs_digest": body["inputs_digest"], "effects": envelope, "expires_ms": body["expires_ms"],
                "matched_rules": decision["matched"], "supervised_agent": supervised}, uid)
        self.deadlines[grant_id] = time.monotonic() + (expires - now) / 1000
        return {"grant": grant_id, "state": state, "decision": decision["decision"], "summary": decision,
                "action": action, "inputs": identified, "expires_ms": body["expires_ms"], "profile": self.profile,
                "supervised_agent": supervised, "boundary": body.get("boundary"),
                "next": "Administrator: grant approve --grant <id> after reviewing grant show." if state == "pending" else "Present the exact action to exec; grants are single-use."}

    def grant(self, grant_id: str) -> tuple[dict, dict]:
        identifier(grant_id, "grant id")
        row = self.store.db.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
        require(row is not None, "grant_missing", "Grant does not exist.")
        body = decode(row["body"])
        self.store.authenticate("KECHAA-GRANT-1", body, row["signature"])
        require(body["id"] == grant_id and body["run"] == row["run"], "grant_binding", "Stored grant identity is inconsistent.")
        return dict(row), body

    def valid_time(self, body: dict) -> None:
        now = time.time_ns() // 1000000
        require(body["epoch"] == self.epoch and body["issued_ms"] <= now < body["expires_ms"] and
                time.monotonic() < self.deadlines.get(body["id"], 0), "grant_expired", "Grant expired or predates a daemon restart; request a fresh approval.")

    def approve(self, data: dict, uid: int, administrative: bool) -> dict:
        self.admin(uid, administrative)
        fields(data, {"grant", "effects_digest", "action_digest"})
        row, body = self.grant(data["grant"])
        require(row["state"] == "pending", "grant_state", "Only a pending grant can be approved.")
        self.valid_time(body)
        run = self.run(body["run"], body["session"], body["uid"])
        require(run["revision"] == body["revision"] and body["policy"] == self.policy.version, "grant_stale", "Run posture or policy changed; request a fresh grant.")
        require(body["effects_digest"] == data["effects_digest"] and body["action_digest"] == data["action_digest"],
                "approval_binding", "Approval digests do not match the displayed action and envelope.")
        with self.store.transaction():
            self.store.db.execute("UPDATE grants SET state='issued' WHERE id=? AND state='pending'", (body["id"],))
            self.store.event("grant_approved", {"grant": body["id"], "run": body["run"], "action_digest": body["action_digest"], "effects_digest": body["effects_digest"]}, uid)
        return {"grant": body["id"], "state": "issued"}

    def consume(self, data: dict, uid: int, simulation: bool) -> dict:
        fields(data, {"grant", "run", "session", "action"}, {"supervised"})
        row, body = self.grant(data["grant"])
        run = self.run(data["run"], data["session"], uid)
        supervised = data.get("supervised", False)
        require(type(supervised) is bool, "supervised_flag", "Supervised launch marker must be boolean.", "invalid_request")
        require(supervised == bool(body.get("supervised_agent", False)), "grant_binding",
                "A supervised agent grant can only be consumed through the supervised launcher, and ordinary grants cannot be upgraded at launch.")
        require(body["run"] == run["id"] and body["session"] == data["session"] and body["uid"] == uid,
                "grant_binding", "Grant is bound to a different run, session, or OS user.")
        self.valid_time(body)
        require(row["state"] == "issued", "grant_replay", "Grant is pending, consumed, or revoked; it cannot authorize another execution.")
        require(body["revision"] == run["revision"] and body["policy"] == self.policy.version and body["profile"] == self.profile,
                "grant_stale", "Policy, run posture, or execution profile changed; request a new grant.")
        action = effects.request(data["action"])
        require(digest(action) == body["action_digest"], "action_changed", "Exact argv, cwd, or explicit inputs differ from approval.")
        if not self.diagnostic:
            from .backends.linux import workspace_filesystems
            expected = body["effects"]["workspace_filesystems"]
            require(workspace_filesystems([item['path'] for item in expected]) == expected,
                    'workspace_changed', 'Workspace filesystem changed after approval; request a new grant.')
        identified = effects.identify(action, body["effects"], privileged=not self.diagnostic)
        require(digest(identified) == body["inputs_digest"], "inputs_changed", "Executable, input artifact, or directory identity changed after approval.")
        require(simulation == self.diagnostic, "execution_unavailable", "Diagnostic mode can consume a grant for inspection only; it never executes commands. Use a verified execution backend.", "compatibility_block")
        with self.store.transaction():
            cursor = self.store.db.execute("UPDATE grants SET state=? WHERE id=? AND state='issued'", ("simulated" if simulation else "adopted", body["id"]))
            require(cursor.rowcount == 1, "grant_replay", "Grant already consumed.")
            self.store.history(body["run"], "grant_consumed", {"grant": body["id"], "simulation": simulation, "supervised_agent": supervised}, 0)
            self.store.event("grant_simulated" if simulation else "grant_adopted", {"grant": body["id"], "run": body["run"], "executed": False,
                             "effects_digest": body["effects_digest"], "supervised_agent": supervised}, uid)
        return body

    def finish(self, body: dict, result: dict) -> None:
        with self.store.transaction():
            self.store.db.execute("UPDATE grants SET state=? WHERE id=?", ("completed" if result["exit_code"] == 0 else "terminated", body["id"]))
            row = self.admin_run(body["run"])
            run_body = decode(row["body"])
            run_body["actions"] += 1
            self.store.db.execute("UPDATE runs SET body=? WHERE id=?", (canonical(run_body), body["run"]))
            self.store.history(body["run"], "action_finished", {"grant": body["id"], "exit_code": result["exit_code"],
                               "termination": result.get("termination"), "controls_ready": result.get("controls_ready", False)},
                               0 if result["exit_code"] == 0 else 20)
            self.store.event("action_finished", {"run": body["run"], "grant": body["id"],
                             **{k: v for k, v in result.items() if k not in ("stdout", "stderr")},
                             "observed_effects_complete": False}, body["uid"])

    def tighten(self, data: dict, uid: int) -> dict:
        fields(data, {"run", "session", "label"})
        row = self.run(data["run"], data["session"], uid)
        require(isinstance(data["label"], str) and data["label"] in LABELS, "label_unknown", "Unknown untrusted-input label.", "invalid_request")
        return self.trusted_event({"run": data["run"], "session": data["session"], "label": data["label"], "source": "client_report"}, uid)

    def checkpoint(self, data: dict, uid: int, administrative: bool) -> dict:
        self.admin(uid, administrative)
        fields(data, {"run", "mode", "reason"})
        row = self.admin_run(data["run"])
        require(not row["closed"], "run_closed", "Closed runs cannot be reopened.")
        require(isinstance(data["mode"], str) and data["mode"] in MODES and isinstance(data["reason"], str) and 8 <= len(data["reason"]) <= 1000,
                "checkpoint_reason", "Provide a mode and an administrative reason of 8 to 1000 characters.", "invalid_request")
        with self.store.transaction():
            self.store.db.execute("UPDATE runs SET mode=?,revision=revision+1 WHERE id=?", (data["mode"], row["id"]))
            self.store.db.execute("UPDATE grants SET state='revoked_checkpoint' WHERE run=? AND state IN ('issued','pending')", (row["id"],))
            self.store.event("administrator_checkpoint", {"run": row["id"], "from": row["mode"], "to": data["mode"],
                             "reason": data["reason"], "labels_retained": True}, uid)
        return {"run": row["id"], "mode": data["mode"], "terminate_active": True}

    def close_run(self, data: dict, uid: int) -> dict:
        fields(data, {"run", "session"})
        row = self.run(data["run"], data["session"], uid)
        with self.store.transaction():
            self.store.db.execute("UPDATE runs SET closed=1,revision=revision+1 WHERE id=?", (row["id"],))
            self.store.db.execute("UPDATE grants SET state='revoked_session' WHERE run=? AND state IN ('issued','pending')", (row["id"],))
            self.store.event("run_closed", {"run": row["id"]}, uid)
        return {"run": row["id"], "closed": True, "terminate_active": True}

    def import_policy(self, data: dict, uid: int, administrative: bool) -> dict:
        self.admin(uid, administrative)
        fields(data, {"yaml"}, {"expected_version"})
        require(isinstance(data["yaml"], str), "policy_input", "Policy must be YAML text.", "invalid_request")
        candidate = load(data["yaml"], "<import>")
        if "expected_version" in data:
            require(data["expected_version"] == self.policy.version, "policy_conflict", "Active policy changed after review; inspect the new diff before activation.", "operational_error")
        return self.replace_policy(candidate)

    def replace_policy(self, candidate: Policy) -> dict:
        with self.store.transaction():
            self._activate(candidate)
            self.store.db.execute("UPDATE grants SET state='revoked_policy' WHERE state IN ('issued','pending')")
            self.store.db.execute("UPDATE runs SET revision=revision+1")
        self.policy = candidate
        return {"active_policy": candidate.version, "terminate_all_active": True}

    def policy_history(self, data: dict, uid: int, administrative: bool) -> dict:
        self.admin(uid, administrative)
        fields(data, set(), {"after", "limit"})
        after = integer(data.get("after", 0), 0, 50000, "after")
        limit = integer(data.get("limit", 50), 1, 100, "limit")
        rows = self.store.db.execute("SELECT rowid,version,document FROM policies WHERE rowid>? ORDER BY rowid LIMIT ?", (after, limit))
        return {"active": self.policy.version, "versions": [{"index": row[0], "version": row[1], "name": decode(row[2])["name"]} for row in rows]}

    def rollback_policy(self, data: dict, uid: int, administrative: bool) -> dict:
        self.admin(uid, administrative)
        fields(data, {"version", "expected_version", "reason"})
        require(data["expected_version"] == self.policy.version, "policy_conflict", "Active policy changed after review; inspect it before rollback.", "operational_error")
        require(isinstance(data["version"], str) and len(data["version"]) == 64, "policy_version", "Supply a policy digest from policy history.", "invalid_request")
        require(isinstance(data["reason"], str) and 8 <= len(data["reason"]) <= 1000, "policy_reason", "Rollback requires an administrative reason of 8 to 1000 characters.", "invalid_request")
        row = self.store.db.execute("SELECT document FROM policies WHERE version=?", (data["version"],)).fetchone()
        require(row is not None, "policy_missing", "The requested policy is not in local history.", "invalid_request")
        document = validate(decode(row[0]), "<policy-history>")
        require(digest(document) == data["version"], "policy_corrupt", "Historical policy digest mismatch; rollback refused.")
        candidate = Policy(document, data["version"], "<policy-history>")
        with self.store.transaction():
            self.store.event("policy_rollback", {"from": self.policy.version, "to": candidate.version, "reason": data["reason"]}, uid)
            self._activate(candidate)
            self.store.db.execute("UPDATE grants SET state='revoked_policy' WHERE state IN ('issued','pending')")
            self.store.db.execute("UPDATE runs SET revision=revision+1")
        self.policy = candidate
        return {"active_policy": candidate.version, "terminate_all_active": True}

    def expire(self) -> None:
        expired = [key for key, deadline in self.deadlines.items() if time.monotonic() >= deadline]
        if not expired:
            return
        with self.store.transaction():
            for key in expired:
                cursor = self.store.db.execute("UPDATE grants SET state='expired' WHERE id=? AND state IN ('pending','issued')", (key,))
                if cursor.rowcount:
                    self.store.event("grant_expired", {"grant": key}, self.owner)
        for key in expired:
            self.deadlines.pop(key, None)

    def expire_runs(self) -> list[str]:
        now, monotonic = time.time_ns() // 1000000, time.monotonic()
        ended = [run for run, deadline in self.run_deadlines.items() if now >= deadline[0] or monotonic >= deadline[1]]
        for row in self.store.db.execute("SELECT id,body FROM runs WHERE closed=0").fetchall():
            body = decode(row["body"])
            lease = body.get("lease", {})
            if row["id"] not in ended and isinstance(lease, dict) and now >= int(lease.get("expires_ms", 0)):
                ended.append(row["id"])
        terminated = []
        if ended:
            with self.store.transaction():
                for run in ended:
                    changed = self.store.db.execute("UPDATE runs SET closed=1,revision=revision+1 WHERE id=? AND closed=0", (run,))
                    if changed.rowcount:
                        self.store.db.execute("UPDATE grants SET state='revoked_session' WHERE run=? AND state IN ('issued','pending')", (run,))
                        self.store.history(run, "lease_or_run_expired", {"response": "closed and revoked pending grants"}, 100)
                        self.store.event("run_expired", {"run": run, "response": "terminate active action; require new administrator-confirmed contract"}, self.owner)
                        terminated.append(run)
            for run in ended:
                self.run_deadlines.pop(run, None)
        return terminated

    def denied(self, operation: str, error: KechaaError, uid: int) -> None:
        with self.store.transaction():
            self.store.event("request_denied", {"operation": operation, "code": error.code, "category": error.category}, uid)

    def health(self) -> dict:
        return {"ready": True, "profile": self.profile, "policy": self.policy.version,
                "protocol_version": 1, "policy_schema": 1, "state_schema": 1,
                "capabilities": {"execution": "disabled" if self.diagnostic else "experimental",
                                 "network": "offline-only", "observation": "history-and-lifecycle; kernel effect stream incomplete",
                                 "leases": True, "whole_agent_containment": "supervised-boundary-required; not native for arbitrary agents",
                                 "history_aware_policy": True, "quarantine": True,
                                 "policy_history": True, "policy_rollback": True, "expiring_policy_rules": True,
                                 "signed_audit_checkpoints": True, "audit_anchors": True, "offline_backups": True},
                "uptime_ms": int((time.monotonic() - self.started) * 1000), "epoch": self.epoch,
                "audit_sequence": int(self.store.meta("audit_sequence") or 0),
                "execution_available": not self.diagnostic, "production_ready": False,
                "public_key": base64.b64encode(self.store.key.public_key().public_bytes_raw()).decode("ascii")}
