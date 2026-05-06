"""idalib Pool Manager — manages a pool of idalib_server subprocess instances.

Each instance is an independent idalib_server process communicating over a
local HTTP transport.  On Unix-like platforms the default backend transport is
a Unix domain socket; on Windows it is loopback TCP.  The pool enforces a
1-instance-per-session model: every
instance holds at most one active IDB at a time.  When the pool is full a new
``open`` evicts the least-recently-used session (which becomes "cold" and can
be transparently reactivated later).

Key invariants
--------------
* ``SessionRegistry._open_paths`` prevents the same binary from being opened
  by two instances concurrently (IDA creates working files alongside the IDB).
* ``max_instances == 0`` means *unlimited*: a fresh instance is spawned for
  every ``open`` and destroyed on ``close``.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SessionInfo:
    session_id: str
    binary_path: str
    instance_index: int | None = None  # None = cold (evicted, no instance)
    last_accessed: float = field(default_factory=time.monotonic)

    @property
    def is_hot(self) -> bool:
        return self.instance_index is not None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "input_path": self.binary_path,
            "filename": os.path.basename(self.binary_path),
            "is_active": self.is_hot,
            "last_accessed": self.last_accessed,
            "instance_index": self.instance_index,
        }


@dataclass
class InstanceInfo:
    index: int
    process: subprocess.Popen
    transport: str
    log_path: str
    socket_path: str | None = None
    host: str | None = None
    port: int | None = None
    session_id: str | None = None  # None = idle
    current_operation: str | None = None
    operation_started_at: float | None = None

    @property
    def endpoint(self) -> str:
        if self.transport == "unix":
            return f"unix:{self.socket_path}"
        return f"http://{self.host}:{self.port}"


# ---------------------------------------------------------------------------
# Instance Manager — subprocess lifecycle + HTTP forwarding
# ---------------------------------------------------------------------------

def _supports_unix_sockets() -> bool:
    return hasattr(socket, "AF_UNIX") and sys.platform != "win32"


def _resolve_backend_transport(transport: str) -> str:
    if transport not in {"auto", "unix", "tcp"}:
        raise ValueError("backend_transport must be one of: auto, unix, tcp")
    if transport == "auto":
        return "unix" if _supports_unix_sockets() else "tcp"
    if transport == "unix" and not _supports_unix_sockets():
        raise RuntimeError("Unix domain sockets are not supported on this platform")
    return transport


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _normalize_timeout_seconds(value: float | int | None) -> float | None:
    if value is None:
        return None
    timeout = float(value)
    if timeout <= 0:
        return None
    return timeout


def _operation_name(request: dict) -> str:
    method = str(request.get("method") or "request")
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        if name:
            return f"tools/call:{name}"
    return method


class InstanceManager:
    """Manages idalib_server subprocesses and local HTTP forwarding."""

    def __init__(
        self,
        socket_dir: str,
        idalib_args: list[str] | None = None,
        backend_transport: str = "auto",
    ):
        self.socket_dir = socket_dir
        self.idalib_args = idalib_args or []
        self.backend_transport = _resolve_backend_transport(backend_transport)
        self.instances: list[InstanceInfo] = []
        self._next_index = 0

    def spawn(self) -> InstanceInfo:
        idx = self._next_index
        log_path = os.path.join(self.socket_dir, f"{idx}.log")
        sock_path: str | None = None
        host: str | None = None
        port: int | None = None
        cmd = [sys.executable, "-m", "ida_pro_mcp.idalib_server"]
        if self.backend_transport == "unix":
            sock_path = os.path.join(self.socket_dir, f"{idx}.sock")
            cmd.extend(["--unix-socket", sock_path])
        else:
            host = "127.0.0.1"
            port = _reserve_loopback_port()
            cmd.extend(["--host", host, "--port", str(port), "--single-threaded-http"])
        cmd.extend(self.idalib_args)

        logger.info("Spawning instance %d: %s (log: %s)", idx, " ".join(cmd), log_path)
        log_file = open(log_path, "w", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        inst = InstanceInfo(
            index=idx,
            process=proc,
            transport=self.backend_transport,
            log_path=log_path,
            socket_path=sock_path,
            host=host,
            port=port,
        )
        inst._log_file = log_file  # type: ignore[attr-defined]
        self._next_index += 1
        self.instances.append(inst)
        self._wait_for_ready(inst)
        return inst

    def kill(self, inst: InstanceInfo) -> None:
        logger.info("Killing instance %d (pid %d)", inst.index, inst.process.pid)
        try:
            if sys.platform == "win32":
                inst.process.terminate()
            else:
                inst.process.send_signal(signal.SIGTERM)
            inst.process.wait(timeout=10)
        except Exception:
            inst.process.kill()
            inst.process.wait(timeout=5)
        log_file = getattr(inst, "_log_file", None)
        if log_file:
            log_file.close()
        if inst in self.instances:
            self.instances.remove(inst)

    def kill_all(self) -> None:
        for inst in list(self.instances):
            self.kill(inst)
        self.instances.clear()

    def find(self, index: int) -> InstanceInfo | None:
        for inst in self.instances:
            if inst.index == index:
                return inst
        return None

    def find_idle(self) -> InstanceInfo | None:
        for inst in self.instances:
            if inst.session_id is None:
                return inst
        return None

    def _wait_for_ready(self, inst: InstanceInfo, timeout: float = 120) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if inst.process.poll() is not None:
                raise RuntimeError(
                    f"Instance {inst.index} exited prematurely "
                    f"(code {inst.process.returncode})"
                )
            try:
                sock = self._connect_ready_probe(inst)
                if sock is not None:
                    sock.close()
                    logger.info("Instance %d ready at %s", inst.index, inst.endpoint)
                    return
            except (ConnectionRefusedError, OSError):
                pass
            time.sleep(0.2)
        raise TimeoutError(
            f"Instance {inst.index} did not become ready within {timeout}s"
        )

    def _connect_ready_probe(self, inst: InstanceInfo) -> socket.socket | None:
        if inst.transport == "unix":
            if inst.socket_path is None or not os.path.exists(inst.socket_path):
                return None
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect(inst.socket_path)
            return sock
        if inst.host is None or inst.port is None:
            raise RuntimeError(f"Instance {inst.index} has no TCP endpoint")
        return socket.create_connection((inst.host, inst.port), timeout=1)

    # --- HTTP forwarding ---

    def forward_tool_call(
        self,
        inst: InstanceInfo,
        tool_name: str,
        arguments: dict,
        timeout: float | None = 300,
    ) -> Any:
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": 1,
        }
        resp = self.forward_raw(inst, request, timeout=timeout)
        result = resp.get("result", resp)
        sc = result.get("structuredContent") if isinstance(result, dict) else None
        return sc if sc is not None else result

    def forward_raw(
        self,
        inst: InstanceInfo,
        request: dict,
        timeout: float | None = 300,
    ) -> dict:
        timeout = _normalize_timeout_seconds(timeout)
        if inst.transport == "unix":
            if inst.socket_path is None:
                raise RuntimeError(f"Instance {inst.index} has no Unix socket path")
            conn = http.client.HTTPConnection("localhost", timeout=timeout)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(inst.socket_path)
            conn.sock = sock
        else:
            if inst.host is None or inst.port is None:
                raise RuntimeError(f"Instance {inst.index} has no TCP endpoint")
            conn = http.client.HTTPConnection(inst.host, inst.port, timeout=timeout)
        inst.current_operation = _operation_name(request)
        inst.operation_started_at = time.monotonic()
        try:
            body = json.dumps(request)
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read().decode()
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status}: {data}")
            return json.loads(data)
        finally:
            inst.current_operation = None
            inst.operation_started_at = None
            conn.close()

    def forward_tools_list(self) -> list[dict]:
        candidates = [i for i in self.instances if i.process.poll() is None]
        if not candidates:
            return []
        request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        resp = self.forward_raw(candidates[0], request)
        return resp.get("result", {}).get("tools", [])


# ---------------------------------------------------------------------------
# Session Registry — session state, path dedup, default tracking
# ---------------------------------------------------------------------------

class SessionRegistry:
    """Tracks session metadata, path uniqueness, and the default session."""

    def __init__(self):
        self.sessions: dict[str, SessionInfo] = {}
        self.default_session_id: str | None = None
        # resolved-path → session_id  (prevents concurrent access to same IDB)
        self._open_paths: dict[str, str] = {}

    def create(
        self, session_id: str, binary_path: str, instance_index: int
    ) -> SessionInfo:
        sess = SessionInfo(
            session_id=session_id,
            binary_path=binary_path,
            instance_index=instance_index,
        )
        self.sessions[session_id] = sess
        self._open_paths[binary_path] = session_id
        self.default_session_id = session_id
        return sess

    def remove(self, session_id: str) -> SessionInfo | None:
        """Permanently remove a session (explicit close only)."""
        sess = self.sessions.pop(session_id, None)
        if sess:
            self._open_paths.pop(sess.binary_path, None)
        if self.default_session_id == session_id:
            self.default_session_id = next(iter(self.sessions), None)
        return sess

    def get(self, session_id: str) -> SessionInfo | None:
        return self.sessions.get(session_id)

    def touch(self, session_id: str) -> None:
        sess = self.sessions.get(session_id)
        if sess:
            sess.last_accessed = time.monotonic()

    def make_cold(self, session_id: str) -> None:
        """Mark a session as cold (evicted). Keeps path reservation."""
        sess = self.sessions.get(session_id)
        if sess:
            sess.instance_index = None

    def make_hot(self, session_id: str, instance_index: int) -> None:
        """Bind a (cold) session to an instance."""
        sess = self.sessions.get(session_id)
        if sess:
            sess.instance_index = instance_index

    def find_by_path(self, resolved_path: str) -> str | None:
        """Return session_id if this path is already tracked."""
        return self._open_paths.get(resolved_path)

    def lru_hot_session(self) -> SessionInfo | None:
        """Return the least-recently-used hot session, or None."""
        hot = [s for s in self.sessions.values() if s.is_hot]
        if not hot:
            return None
        return min(hot, key=lambda s: s.last_accessed)

    def generate_id(self) -> str:
        return str(uuid.uuid4())[:8]

    def list_all(self) -> dict:
        return {
            "sessions": [s.to_dict() for s in self.sessions.values()],
            "count": len(self.sessions),
            "default_session_id": self.default_session_id,
        }

    def get_default(self) -> dict:
        if self.default_session_id is None:
            return {"error": "No default session. Use idalib_open to create one."}
        sess = self.sessions.get(self.default_session_id)
        if sess is None:
            return {"error": f"Default session '{self.default_session_id}' not found."}
        return sess.to_dict()


# ---------------------------------------------------------------------------
# Pool Manager — binds instances and sessions together
# ---------------------------------------------------------------------------

class PoolManager:
    def __init__(
        self,
        max_instances: int = 1,
        socket_dir: str | None = None,
        idalib_args: list[str] | None = None,
        backend_transport: str = "auto",
        open_timeout_sec: float | None = None,
    ):
        self.max_instances = max_instances  # 0 = unlimited
        socket_dir = socket_dir or tempfile.mkdtemp(prefix="idalib-pool-")
        os.makedirs(socket_dir, exist_ok=True)

        self.im = InstanceManager(socket_dir, idalib_args, backend_transport)
        self.sr = SessionRegistry()
        if open_timeout_sec is None and self.im.backend_transport == "tcp":
            open_timeout_sec = 110
        self.open_timeout_sec = _normalize_timeout_seconds(open_timeout_sec)
        self._lock = threading.Lock()

    # -- convenience accessors for pool_server --
    @property
    def sessions(self) -> dict[str, SessionInfo]:
        return self.sr.sessions

    @property
    def default_session_id(self) -> str | None:
        return self.sr.default_session_id

    @default_session_id.setter
    def default_session_id(self, value: str | None) -> None:
        self.sr.default_session_id = value

    # ------------------------------------------------------------------
    # High-level operations
    # ------------------------------------------------------------------

    def spawn_instance(self) -> InstanceInfo:
        return self.im.spawn()

    def shutdown_all(self) -> None:
        with self._lock:
            for inst in list(self.im.instances):
                if inst.session_id:
                    try:
                        self.im.forward_tool_call(inst, "idalib_save", {})
                    except Exception:
                        pass
            self.im.kill_all()
            self.sr.sessions.clear()
            self.sr._open_paths.clear()

    def open_session(
        self,
        binary_path: str,
        session_id: str | None = None,
        run_auto_analysis: bool = True,
    ) -> dict:
        resolved = str(Path(binary_path).resolve())

        with self._lock:
            # --- path dedup / conflict ---
            existing_sid = self.sr.find_by_path(resolved)
            if existing_sid is not None:
                if session_id is not None and session_id != existing_sid:
                    return {
                        "error": (
                            f"Binary already open as session '{existing_sid}'. "
                            f"Cannot open with different session_id '{session_id}'."
                        )
                    }
                self.sr.touch(existing_sid)
                self.sr.default_session_id = existing_sid
                sess = self.sr.get(existing_sid)
                return {
                    "success": True,
                    "session": sess.to_dict(),
                    "message": f"Returning existing session: {existing_sid}",
                }

            # --- allocate instance ---
            inst = self._allocate_instance_locked()
            if session_id is None:
                session_id = self.sr.generate_id()

        # --- forward open (outside lock) ---
        try:
            resp = self.im.forward_tool_call(
                inst,
                "idalib_open",
                {
                    "input_path": resolved,
                    "run_auto_analysis": run_auto_analysis,
                    "session_id": session_id,
                },
                timeout=self.open_timeout_sec,
            )
        except Exception as e:
            self._discard_failed_open_instance(inst)
            timeout_msg = (
                f" after {self.open_timeout_sec:.0f}s"
                if self.open_timeout_sec is not None
                else ""
            )
            return {
                "success": False,
                "error": f"Failed to open binary{timeout_msg}: {e}",
                "session_id": session_id,
                "input_path": resolved,
                "instance": {
                    "index": inst.index,
                    "pid": inst.process.pid,
                    "endpoint": inst.endpoint,
                    "log_path": inst.log_path,
                },
            }

        if isinstance(resp, dict) and resp.get("error"):
            return resp

        with self._lock:
            sess = self.sr.create(session_id, resolved, inst.index)
            inst.session_id = session_id

        return {
            "success": True,
            "session": sess.to_dict(),
            "message": f"Session created: {session_id}",
        }

    def close_session(self, session_id: str) -> dict:
        with self._lock:
            sess = self.sr.get(session_id)
            if sess is None:
                return {"success": False, "error": f"Session not found: {session_id}"}

            if sess.is_hot:
                inst = self.im.find(sess.instance_index)
            else:
                inst = None

            if inst is None:
                self.sr.remove(session_id)
                return {"success": True, "message": f"Session cleaned up: {session_id}"}

        # Forward close (outside lock)
        self.im.forward_tool_call(inst, "idalib_close", {"session_id": session_id})

        with self._lock:
            self.sr.remove(session_id)
            inst.session_id = None
            if self.max_instances == 0:
                self.im.kill(inst)

        return {"success": True, "message": f"Session closed: {session_id}"}

    def resolve_session_instance(
        self, session_id: str
    ) -> tuple[SessionInfo, InstanceInfo]:
        """Return (session, instance). Reactivates cold sessions automatically."""
        with self._lock:
            sess = self.sr.get(session_id)
            if sess is None:
                raise KeyError(
                    f"Session '{session_id}' not found. "
                    f"Use idalib_open to create a session first."
                )
            self.sr.touch(session_id)

            # Hot path
            if sess.is_hot:
                inst = self.im.find(sess.instance_index)
                if inst is not None:
                    return sess, inst
                sess.instance_index = None  # instance gone, fall through

            # Cold path — reactivate
            logger.info("Reactivating cold session %s (%s)", session_id, sess.binary_path)
            inst = self._allocate_instance_locked()

        # Forward open (outside lock)
        try:
            resp = self.im.forward_tool_call(
                inst,
                "idalib_open",
                {
                    "input_path": sess.binary_path,
                    "run_auto_analysis": False,
                    "session_id": session_id,
                },
                timeout=self.open_timeout_sec,
            )
        except Exception as e:
            self._discard_failed_open_instance(inst)
            raise RuntimeError(
                f"Failed to reactivate session '{session_id}': {e}"
            ) from e

        if isinstance(resp, dict) and resp.get("error"):
            raise RuntimeError(
                f"Failed to reactivate session '{session_id}': {resp['error']}"
            )

        with self._lock:
            self.sr.make_hot(session_id, inst.index)
            inst.session_id = session_id

        return sess, inst

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_sessions(self) -> dict:
        with self._lock:
            return self.sr.list_all()

    def get_current_session(self) -> dict:
        with self._lock:
            return self.sr.get_default()

    def status(self) -> dict:
        now = time.monotonic()
        with self._lock:
            instances = []
            for inst in self.im.instances:
                returncode = inst.process.poll()
                busy_seconds = None
                if inst.operation_started_at is not None:
                    busy_seconds = round(now - inst.operation_started_at, 3)
                instances.append(
                    {
                        "index": inst.index,
                        "pid": inst.process.pid,
                        "alive": returncode is None,
                        "returncode": returncode,
                        "transport": inst.transport,
                        "endpoint": inst.endpoint,
                        "log_path": inst.log_path,
                        "session_id": inst.session_id,
                        "busy": inst.current_operation is not None,
                        "current_operation": inst.current_operation,
                        "busy_seconds": busy_seconds,
                    }
                )
            return {
                "backend_transport": self.im.backend_transport,
                "socket_dir": self.im.socket_dir,
                "max_instances": self.max_instances,
                "open_timeout_sec": self.open_timeout_sec,
                "default_session_id": self.sr.default_session_id,
                "session_count": len(self.sr.sessions),
                "sessions": [s.to_dict() for s in self.sr.sessions.values()],
                "instance_count": len(instances),
                "instances": instances,
            }

    # ------------------------------------------------------------------
    # Forwarding shortcuts
    # ------------------------------------------------------------------

    def forward_tool_call(self, inst: InstanceInfo, tool_name: str, arguments: dict) -> Any:
        return self.im.forward_tool_call(inst, tool_name, arguments)

    def forward_raw(self, inst: InstanceInfo, request: dict) -> dict:
        return self.im.forward_raw(inst, request)

    def forward_tools_list(self) -> list[dict]:
        with self._lock:
            return self.im.forward_tools_list()

    # ------------------------------------------------------------------
    # Instance allocation & LRU (internal, caller holds _lock)
    # ------------------------------------------------------------------

    def _allocate_instance_locked(self) -> InstanceInfo:
        # 1. Idle instance
        inst = self.im.find_idle()
        if inst is not None:
            return inst

        # 2. Spawn new
        if self.max_instances == 0 or len(self.im.instances) < self.max_instances:
            self._lock.release()
            try:
                return self.im.spawn()
            finally:
                self._lock.acquire()

        # 3. Evict LRU
        return self._evict_lru_locked()

    def _discard_failed_open_instance(self, inst: InstanceInfo) -> None:
        logger.warning(
            "Discarding instance %d after failed open (pid %d)",
            inst.index,
            inst.process.pid,
        )
        try:
            self.im.kill(inst)
        except Exception:
            logger.exception("Failed to kill instance %d after failed open", inst.index)

    def _evict_lru_locked(self) -> InstanceInfo:
        lru_sess = self.sr.lru_hot_session()
        if lru_sess is None:
            raise RuntimeError("Pool is full but has no hot sessions to evict")

        inst = self.im.find(lru_sess.instance_index)
        if inst is None:
            raise RuntimeError(f"Instance for LRU session {lru_sess.session_id} not found")

        logger.info("Evicting LRU session %s from instance %d", lru_sess.session_id, inst.index)

        self._lock.release()
        try:
            try:
                self.im.forward_tool_call(inst, "idalib_save", {})
            except Exception:
                pass
            self.im.forward_tool_call(inst, "idalib_close", {"session_id": lru_sess.session_id})
        finally:
            self._lock.acquire()

        self.sr.make_cold(lru_sess.session_id)
        inst.session_id = None
        return inst
