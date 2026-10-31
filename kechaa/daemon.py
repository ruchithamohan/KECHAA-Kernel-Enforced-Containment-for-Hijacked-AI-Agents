"""Bounded local server and execution lifecycle. Never executes in diagnostic mode."""

from __future__ import annotations

import asyncio
import base64
import fcntl
import os
import platform
import secrets
import select
import signal
import stat
import sys
import time
from pathlib import Path

from .backends import preflight
from .common import (MAX_MESSAGE, KechaaError, canonical, decode, fields, integer,
                     read_bounded, require, trusted_path)
from .engine import Engine
from .policy import load
from .protocol import peer_credentials
from .store import Store


async def complete_cleanup(coroutine):
    """Finish bounded cleanup even if its caller is cancelled more than once."""
    task = asyncio.create_task(coroutine)
    interrupted = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            interrupted = True
    result = task.result()
    if interrupted:
        raise asyncio.CancelledError
    return result


class Server:
    def __init__(self, engine: Engine, cgroup_root: str):
        self.engine, self.cgroup_root = engine, cgroup_root
        self.connections = 0
        self.active: dict[str, tuple] = {}
        self.stopping = asyncio.Event()
        self.unhealthy = False
        self.audit_failed = False
        self.execution_reserved = False
        self.handlers: set[asyncio.Task] = set()

    async def terminate_worker(self, process, group) -> list[str]:
        """Attempt both kill paths and a bounded reap, even if one path fails."""
        from .backends.linux import kill_group
        failures = []
        try:
            kill_group(group)
        except FileNotFoundError:
            # Another lifecycle handler may already have reaped and removed it.
            if group.exists() or process is None or process.returncode is None:
                failures.append("cgroup_kill_failed")
        except OSError:
            failures.append("cgroup_kill_failed")
        if process is not None:
            try:
                if process.returncode is None:
                    process.kill()
            except ProcessLookupError:
                pass
            except OSError:
                failures.append("supervisor_kill_failed")
            try:
                async with asyncio.timeout(5):
                    await process.wait()
            except (OSError, TimeoutError):
                failures.append("supervisor_reap_incomplete")
        if failures:
            self.unhealthy = True
        return failures

    async def stop_actions(self, run: str | None = None) -> bool:
        stopped = True
        for body, process, group in list(self.active.values()):
            if run is None or body["run"] == run:
                failures = await self.terminate_worker(process, group)
                if failures:
                    stopped = False
                    print(canonical({"event": "cleanup_incomplete", "grant": body["id"],
                                     "failures": failures, "ready": False}).decode(), file=sys.stderr, flush=True)
        return stopped

    async def stop_required(self, run: str | None = None) -> None:
        require(await self.stop_actions(run), "cleanup_incomplete",
                "Process-tree termination could not be confirmed. Execution is held; an administrator must reconcile the dedicated action cgroup.", "operational_error")

    async def finalize_action(self, body, result, process, group, descriptors, collectors, started) -> None:
        failures = []
        try:
            if group is not None:
                failures.extend(await self.terminate_worker(process, group))
            for task in collectors:
                task.cancel()
            await asyncio.gather(*collectors, return_exceptions=True)
            if group is not None:
                try:
                    from .backends.linux import accounting
                    result['resource_counters'] = accounting(group)
                    group.rmdir()
                except OSError:
                    failures.append("cgroup_removal_incomplete")
        finally:
            for fd in descriptors:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        failures.append("status_descriptor_close_failed")
            self.execution_reserved = False
            if failures:
                self.unhealthy = True
                result.update(cleanup="incomplete; further execution held", cleanup_failures=failures, exit_code=126)
                # Keep the handle for shutdown's independent retry.
            else:
                self.active.pop(body["id"], None)
            result["wall_ms"] = int((time.monotonic() - started) * 1000)
            result["grant"] = body["id"]
            try:
                self.engine.finish(body, result)
            except Exception:
                self.unhealthy = True
                raise

    async def execute(self, data: dict, uid: int) -> dict:
        require(not self.engine.diagnostic, "execution_unavailable", "Diagnostic mode never executes a command. Kernel enforcement is unavailable in this mode.", "compatibility_block")
        require(not self.active and not self.execution_reserved, "execution_busy", "This experimental backend permits one active action at a time; retry after it ends.", "operational_error")
        from .backends.linux import cgroup_create, kill_group
        self.execution_reserved = True
        try:
            body = self.engine.consume(data, uid, simulation=False)
        except BaseException:
            self.execution_reserved = False
            raise
        group = None
        process = None
        read_status = write_status = None
        collectors = []
        started = time.monotonic()
        result = {"exit_code": 126, "termination": "initialization_failed", "controls_ready": False,
                  "stdout": "", "stderr": "", "output_encoding": "base64", "output_bytes": 0,
                  "observed_effects_complete": False}
        try:
            group = cgroup_create(self.cgroup_root, body["id"], body["effects"])
            read_status, write_status = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            worker_path = str(Path(__file__).resolve().with_name("worker.py"))
            config = {"uid": uid, "parent": os.getpid(), "cgroup": str(group), "grant": body, "status_fd": write_status}
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-I", worker_path, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True, pass_fds=(write_status,))
            os.close(write_status)
            write_status = None
            self.active[body["id"]] = (body, process, group)
            current_run = self.engine.run(body["run"], body["session"], uid)
            require(current_run["revision"] == body["revision"] and self.engine.policy.version == body["policy"],
                    "grant_stale", "Authority changed during worker startup; no command may execute.")
            self.engine.valid_time(body)
            with self.engine.store.transaction():
                changed = self.engine.store.db.execute("UPDATE grants SET state='running' WHERE id=? AND state='adopted'", (body["id"],))
                require(changed.rowcount == 1, "grant_stale", "Grant was revoked during worker startup; no command may execute.")
                self.engine.store.event("worker_started", {"grant": body["id"], "run": body["run"], "cgroup": group.name, "action_exec_confirmed": False}, uid)
            process.stdin.write(canonical(config))
            await process.stdin.drain()
            process.stdin.close()
            budget = body["effects"]["limits"]["output_bytes"]
            count = 0

            async def collect(stream):
                nonlocal count
                output = bytearray()
                while True:
                    chunk = await stream.read(16384)
                    if not chunk:
                        return bytes(output)
                    count += len(chunk)
                    if count > budget:
                        kill_group(group)
                        raise KechaaError("output_limit", "Action output exceeded the approved budget; the process tree was terminated.")
                    output.extend(chunk)

            task_out = asyncio.create_task(collect(process.stdout))
            task_err = asyncio.create_task(collect(process.stderr))
            collectors = [task_out, task_err]
            try:
                remaining = min(body["effects"]["limits"]["wall_seconds"],
                                self.engine.deadlines[body["id"]] - time.monotonic())
                async with asyncio.timeout(max(0.001, remaining)):
                    stdout, stderr, exit_code = await asyncio.gather(task_out, task_err, process.wait())
                result.update(exit_code=exit_code, termination="exited", stdout=base64.b64encode(stdout).decode("ascii"),
                              stderr=base64.b64encode(stderr).decode("ascii"), output_bytes=count)
            except (TimeoutError, KechaaError) as exc:
                await self.terminate_worker(process, group)
                result.update(exit_code=124, termination="wall_limit" if isinstance(exc, TimeoutError) else exc.code, output_bytes=count)
            try:
                status_data = os.read(read_status, 4096)
            except BlockingIOError:
                status_data = b""
            result["controls_ready"] = b"controls_ready\n" in status_data
            for line in status_data.splitlines():
                if line.startswith(b'{'):
                    report = decode(line, 4096)
                    fields(report, {"error", "errno", "message"}, where="worker status")
                    result["initialization_error"] = report
            if not result["controls_ready"] or b'"error"' in status_data:
                result["termination"] = "worker_initialization_failed"
                if result["exit_code"] == 0:
                    result["exit_code"] = 126
        except asyncio.CancelledError:
            result.update(exit_code=125, termination="request_cancelled")
            raise
        except (OSError, KechaaError, BrokenPipeError) as exc:
            result["termination"] = exc.code if isinstance(exc, KechaaError) else "worker_initialization_failed"
        finally:
            await complete_cleanup(self.finalize_action(body, result, process, group,
                                   (read_status, write_status), collectors, started))
        return result

    async def dispatch(self, operation: str, data: dict, uid: int, administrative: bool) -> dict:
        engine = self.engine
        if operation == "health":
            fields(data, set())
            return {**engine.health(), "ready": not self.unhealthy and not self.stopping.is_set(),
                    "audit_integrity": "failed" if self.audit_failed else "verified_at_startup",
                    "execution_available": not engine.diagnostic and not self.unhealthy and not self.stopping.is_set(),
                    "active_actions": len(self.active)}
        require(not self.stopping.is_set(), "daemon_stopping", "Daemon shutdown is in progress; no new work is accepted.", "operational_error")
        require(not self.unhealthy or operation in ("audit_verify", "audit_checkpoint", "audit_export", "policy_get", "policy_history", "grant_get", "run_get"),
                "daemon_unhealthy", "Audit or cleanup failure holds all actions. An administrator must reconcile state.", "operational_error")
        if operation == "run_open":
            return engine.open_run(data, uid, administrative)
        if operation == "run_get":
            fields(data, {"run", "session"})
            return engine.public_run(engine.run(data["run"], data["session"], uid))
        if operation == "run_history":
            return engine.history(data, uid)
        if operation == "prepare":
            return engine.prepare(data, uid)
        if operation == "grant_get":
            engine.admin(uid, administrative)
            fields(data, {"grant"})
            row, body = engine.grant(data["grant"])
            return {"state": row["state"], "grant": body, "signature": row["signature"]}
        if operation == "grant_status":
            fields(data, {"grant", "run", "session"})
            run = engine.run(data["run"], data["session"], uid)
            row, body = engine.grant(data["grant"])
            require(body["run"] == run["id"] and body["uid"] == uid, "grant_binding", "Grant belongs to a different run.")
            return {"state": row["state"], "action": body["action"], "profile": body["profile"]}
        if operation == "grant_approve":
            return engine.approve(data, uid, administrative)
        if operation == "grant_revoke":
            engine.admin(uid, administrative)
            fields(data, {"grant"})
            row, body = engine.grant(data["grant"])
            with engine.store.transaction():
                engine.store.db.execute("UPDATE grants SET state='revoked_admin' WHERE id=?", (body["id"],))
                engine.store.event("grant_revoked", {"grant": body["id"], "run": body["run"]}, uid)
            await self.stop_required(body["run"])
            return {"grant": body["id"], "state": "revoked_admin"}
        if operation == "simulate":
            body = engine.consume(data, uid, simulation=True)
            return {"grant": body["id"], "state": "simulated", "executed": False, "profile": engine.profile}
        if operation == "execute":
            return await self.execute(data, uid)
        if operation == "event":
            result = engine.tighten(data, uid)
            if result.get("terminate_active"):
                await self.stop_required(result["run"])
            return result
        if operation == "trusted_event":
            result = engine.trusted_event(data, uid, administrative)
            if result.get("terminate_active"):
                await self.stop_required(result["run"])
            return result
        if operation == "lease_renew":
            result = engine.renew_lease(data, uid, administrative)
            if result.get("terminate_active"):
                await self.stop_required(result["run"])
            return result
        if operation == "run_quarantine":
            result = engine.quarantine(data, uid, administrative)
            await self.stop_required(result["run"])
            return result
        if operation == "run_recover":
            return engine.recover_run(data, uid, administrative)
        if operation == "checkpoint":
            result = engine.checkpoint(data, uid, administrative)
            await self.stop_required(result["run"])
            return result
        if operation == "run_close":
            result = engine.close_run(data, uid)
            await self.stop_required(result["run"])
            return result
        if operation == "policy_get":
            fields(data, set())
            return {"version": engine.policy.version, "policy": engine.policy.document}
        if operation == "policy_import":
            result = engine.import_policy(data, uid, administrative)
            await self.stop_required()
            return result
        if operation == "policy_history":
            return engine.policy_history(data, uid, administrative)
        if operation == "policy_rollback":
            result = engine.rollback_policy(data, uid, administrative)
            await self.stop_required()
            return result
        if operation == "audit_checkpoint":
            engine.admin(uid, administrative)
            fields(data, set())
            try:
                return engine.store.checkpoint(uid)
            except Exception:
                self.unhealthy = self.audit_failed = True
                await self.stop_actions()
                raise
        if operation == "audit_anchor":
            engine.admin(uid, administrative)
            fields(data, set())
            return engine.store.anchor(uid)
        if operation == "audit_anchors":
            engine.admin(uid, administrative)
            fields(data, set(), {"after", "limit"})
            return {"anchors": engine.store.anchors(integer(data.get("after", 0), 0, 50000, "after"), integer(data.get("limit", 20), 1, 100, "limit"))}
        if operation == "audit_verify":
            engine.admin(uid, administrative)
            fields(data, set())
            try:
                return engine.store.verify()
            except Exception:
                self.unhealthy = self.audit_failed = True
                await self.stop_actions()
                raise
        if operation == "audit_export":
            engine.admin(uid, administrative)
            fields(data, set(), {"after", "limit"})
            after = integer(data.get("after", 0), 0, 50000, "after")
            limit = integer(data.get("limit", 50), 1, 100, "limit")
            return {"events": engine.store.export(after, limit), "head": engine.store.meta("audit_head")}
        raise KechaaError("operation_unknown", "Unknown Local API v1 operation.", "invalid_request")

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, administrative: bool) -> None:
        task = asyncio.current_task()
        self.handlers.add(task)
        self.connections += 1
        try:
            await self.respond(reader, writer, administrative)
        finally:
            await complete_cleanup(self.close_connection(writer, task))

    async def close_connection(self, writer, task) -> None:
        try:
            writer.close()
            async with asyncio.timeout(2):
                await writer.wait_closed()
        except (OSError, TimeoutError):
            # The transport is already closed; a peer cannot hold shutdown open.
            pass
        finally:
            self.connections -= 1
            self.handlers.discard(task)

    async def respond(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, administrative: bool) -> None:
        request_id = secrets.token_hex(8)
        uid, operation = -1, "unparsed"
        try:
            require(self.connections <= 32, "backpressure", "Too many client connections; retry shortly.", "operational_error")
            uid, _ = peer_credentials(writer.get_extra_info("socket"))
            async with asyncio.timeout(5):
                try:
                    raw = await reader.readline()
                except ValueError as exc:
                    raise KechaaError("message_size", "Send one JSON line of at most 256 KiB; oversized requests never authorize execution.", "invalid_request") from exc
            require(raw.endswith(b"\n") and len(raw) <= MAX_MESSAGE, "message_size", "Send one JSON line of at most 256 KiB.", "invalid_request")
            message = fields(decode(raw), {"v", "operation", "data"})
            require(type(message["v"]) is int and message["v"] == 1, "protocol_version", "Only Local API v1 is supported.", "invalid_request")
            operation = message["operation"]
            require(isinstance(operation, str) and 1 <= len(operation) <= 32, "operation_invalid", "Invalid operation name.", "invalid_request")
            require(isinstance(message["data"], dict), "data_invalid", "Operation data must be an object.", "invalid_request")
            result = await self.dispatch(operation, message["data"], uid, administrative)
            response = {"v": 1, "ok": True, "request_id": request_id, "result": result}
        except (KechaaError, OSError, TimeoutError, ValueError) as exc:
            error = exc if isinstance(exc, KechaaError) else KechaaError("request_failed", "Request failed before completion. Inspect daemon readiness and retry with a fresh grant.", "operational_error")
            try:
                if not self.audit_failed:
                    self.engine.denied(operation, error, uid)
                else:
                    print(canonical({"event": "audit_failure", "operation": operation, "code": error.code, "ready": False}).decode(), file=sys.stderr, flush=True)
            except Exception:
                self.unhealthy = True
                await self.stop_actions()
            response = {"v": 1, "ok": False, "request_id": request_id, "error": error.as_dict()}
        except Exception:
            self.unhealthy = True
            await self.stop_actions()
            response = {"v": 1, "ok": False, "request_id": request_id,
                        "error": KechaaError("internal_failure", "An internal failure holds all execution; preserve state for investigation.", "operational_error").as_dict()}
        try:
            writer.write(canonical(response) + b"\n")
            async with asyncio.timeout(5):
                await writer.drain()
        except (OSError, TimeoutError):
            # If delivery failed, a consumed grant remains consumed. No automatic retry.
            pass

    async def maintenance(self) -> None:
        while not self.stopping.is_set():
            try:
                if not self.audit_failed:
                    self.engine.expire()
                    for run in self.engine.expire_runs():
                        await self.stop_required(run)
            except Exception:
                self.unhealthy = True
                await self.stop_actions()
            try:
                await asyncio.wait_for(self.stopping.wait(), 1)
            except TimeoutError:
                pass


async def shutdown(server, listeners, maintenance, store, sockets, socket_lock, diagnostic) -> None:
    """Stop admission, finish handler cleanup, and always release state resources."""
    cleanup_complete = True
    try:
        if server:
            server.stopping.set()
        for listener in listeners:
            listener.close()
            await listener.wait_closed()
        if server:
            pending = list(server.handlers)
            for handler in pending:
                handler.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            cleanup_complete = await server.stop_actions()
        if maintenance:
            await maintenance
        if not server or not server.audit_failed:
            with store.transaction():
                store.event("daemon_stopped", {
                    "profile": "diagnostic-no-execution" if diagnostic else "linux-offline-experimental",
                    "cleanup_complete": cleanup_complete, "healthy_at_shutdown": not server or not server.unhealthy,
                }, os.geteuid())
    finally:
        try:
            store.close()
        finally:
            try:
                for path in sockets:
                    try:
                        st = path.lstat()
                    except FileNotFoundError:
                        # Python 3.13+ automatically unlinks Unix listener
                        # paths when the server closes them.
                        continue
                    if stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid():
                        path.unlink()
            finally:
                if socket_lock is not None:
                    os.close(socket_lock)
    require(cleanup_complete, "cleanup_incomplete", "Shutdown could not confirm complete action teardown; preserve state and reconcile the dedicated cgroup before restart.", "operational_error")


async def serve(state: Path, sockets: Path, policy_file: Path | None, diagnostic: bool,
                cgroup_root: str, agent_group: int | None, duration: int) -> None:
    os.umask(0o077)
    if not diagnostic:
        require(platform.system() == "Linux", "backend_unavailable", "Native macOS protected execution is unavailable; use diagnostic mode.", "compatibility_block")
        report = preflight(cgroup_root)
        require(report["execution_available"], "preflight_failed", "Mandatory prerequisites failed: " + "; ".join(report["failures"]), "compatibility_block")
        # Source, interpreter and dependencies must be installed by the administrator.
        for path in (Path(__file__).resolve(), Path(sys.executable).resolve(), sockets.parent, Path(cgroup_root)):
            trusted_path(path, 0)
        for path in Path(__file__).parent.rglob('*.py'):
            trusted_path(path, 0)
        if policy_file is not None:
            trusted_path(policy_file.absolute(), 0)
        require(agent_group is not None and agent_group > 0, "agent_group", "Choose an explicit non-root group for agent socket access.")
    initial = load(read_bounded(policy_file), str(policy_file)) if policy_file else None
    store = Store(state)
    server = None
    listeners = []
    created_sockets = []
    task = None
    socket_lock = None
    try:
        if not diagnostic:
            from .backends.linux import recover
            recovered = recover(cgroup_root)
            with store.transaction():
                store.event("cgroup_recovery", {"terminated": recovered}, os.geteuid())
        engine = Engine(store, initial, diagnostic, os.geteuid())
        server = Server(engine, cgroup_root)
        sockets.mkdir(mode=0o700 if diagnostic else 0o750, parents=False, exist_ok=True)
        st = sockets.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o022,
                "socket_directory", "Socket directory must be daemon-owned and not writable by other users.")
        if not diagnostic:
            os.chown(sockets, 0, agent_group)
            os.chmod(sockets, 0o750)
        socket_lock = os.open(sockets / "socket.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(socket_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise KechaaError("socket_in_use", "Another daemon owns this socket directory.", "operational_error") from exc
        for name, administrative in (("agent.sock", False), ("admin.sock", True)):
            path = sockets / name
            if path.exists() or path.is_symlink():
                st = path.lstat()
                require(stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid(), "socket_path", "Refusing to replace a non-socket or foreign socket path.")
                path.unlink()
            listener = await asyncio.start_unix_server(
                lambda r, w, admin=administrative: server.handle(r, w, admin), str(path), limit=MAX_MESSAGE + 1, backlog=16)
            listeners.append(listener)
            created_sockets.append(path)
            if not diagnostic and not administrative:
                os.chown(path, 0, agent_group)
            os.chmod(path, 0o600 if administrative or diagnostic else 0o660)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, server.stopping.set)
        task = asyncio.create_task(server.maintenance())
        print(canonical({"event": "ready", "profile": engine.profile, "sockets": str(sockets), "policy": engine.policy.version}).decode(), flush=True)
        if duration:
            try:
                await asyncio.wait_for(server.stopping.wait(), duration)
            except TimeoutError:
                server.stopping.set()
        else:
            await server.stopping.wait()
    finally:
        await complete_cleanup(shutdown(server, listeners, task, store, created_sockets, socket_lock, diagnostic))


async def diagnostic_console(state: Path, policy_file: Path | None, administrative: bool, duration: int) -> None:
    """Operator console for non-executing inspection, not an authenticated adapter transport."""
    os.umask(0o077)
    initial = load(read_bounded(policy_file), str(policy_file)) if policy_file else None
    store = Store(state)
    try:
        engine = Engine(store, initial, True, os.geteuid())
        server = Server(engine, "")
        print(canonical({"event": "diagnostic_console_ready", "profile": engine.profile,
                         "administrative": administrative, "peer_authentication": "not_applicable; local operator console",
                         "commands_execute": False}).decode(), flush=True)
        until = time.monotonic() + duration
        buffer = bytearray()
        fd = sys.stdin.fileno()
        while time.monotonic() < until:
            if not server.audit_failed:
                engine.expire()
                engine.expire_runs()
            ready, _, _ = select.select([fd], [], [], min(1, max(0, until - time.monotonic())))
            if not ready:
                continue
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            buffer.extend(chunk)
            require(len(buffer) <= MAX_MESSAGE, "message_size", "Diagnostic input exceeds 256 KiB.", "invalid_request")
            while b"\n" in buffer:
                line, _, rest = buffer.partition(b"\n")
                buffer = bytearray(rest)
                operation = "unparsed"
                try:
                    message = fields(decode(bytes(line)), {"v", "operation", "data"})
                    require(type(message["v"]) is int and message["v"] == 1, "protocol_version", "Only Local API v1 is supported.", "invalid_request")
                    operation = message["operation"]
                    require(isinstance(operation, str) and 1 <= len(operation) <= 32, "operation_invalid", "Invalid operation.", "invalid_request")
                    require(isinstance(message["data"], dict), "data_invalid", "Operation data must be an object.", "invalid_request")
                    result = await server.dispatch(operation, message["data"], os.geteuid(), administrative)
                    response = {"v": 1, "ok": True, "result": result}
                except (KechaaError, OSError, ValueError) as exc:
                    error = exc if isinstance(exc, KechaaError) else KechaaError("request_failed", str(exc), "operational_error")
                    if not server.audit_failed:
                        engine.denied(operation, error, os.geteuid())
                    response = {"v": 1, "ok": False, "error": error.as_dict()}
                print(canonical({"request_id": secrets.token_hex(8), **response}).decode(), flush=True)
    finally:
        try:
            if 'server' not in locals() or not server.audit_failed:
                with store.transaction():
                    store.event("diagnostic_console_stopped", {"executed": False}, os.geteuid())
        finally:
            store.close()
