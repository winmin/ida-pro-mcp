"""
IDA Pro MCP Server with Session Management

This MCP server provides tools for:
1. Opening and managing multiple binary analysis sessions (via idalib)
2. Routing IDA tool calls to the active session
3. Full MCP protocol support (stdio and HTTP/SSE)

Usage:
    # Start the session-aware MCP server
    uv run idalib-session-mcp

    # With SSE transport
    uv run idalib-session-mcp --transport http://127.0.0.1:8744/sse

    # Generate tools cache (run once to enable all tools on startup)
    uv run idalib-session-mcp --generate-tools-cache /path/to/any/binary
"""

import os
import sys
import ast
import json
import time
import uuid
import signal
import socket
import logging
import argparse
import threading
import subprocess
import http.client
import traceback
from pathlib import Path
from typing import Optional, Any, Annotated
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

# Import zeromcp from ida_mcp package
if os.path.exists(os.path.join(os.path.dirname(__file__), "ida_mcp")):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

    sys.path.pop(0)
else:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

logger = logging.getLogger(__name__)

# Port range for idalib sessions
SESSION_PORT_START = 13400
SESSION_PORT_END = 13500

# Tools cache file location
TOOLS_CACHE_FILE = os.path.join(os.path.dirname(__file__), "ida_tools_cache.json")


def load_cached_tools() -> Optional[list[dict]]:
    """Load cached IDA tools from file"""
    if os.path.exists(TOOLS_CACHE_FILE):
        try:
            with open(TOOLS_CACHE_FILE, "r") as f:
                tools = json.load(f)
                logger.info(f"Loaded {len(tools)} cached IDA tools from {TOOLS_CACHE_FILE}")
                return tools
        except Exception as e:
            logger.warning(f"Failed to load tools cache: {e}")
    return None


def save_cached_tools(tools: list[dict]) -> None:
    """Save IDA tools to cache file"""
    try:
        with open(TOOLS_CACHE_FILE, "w") as f:
            json.dump(tools, f, indent=2)
        logger.info(f"Saved {len(tools)} IDA tools to {TOOLS_CACHE_FILE}")
    except Exception as e:
        logger.warning(f"Failed to save tools cache: {e}")


# ============================================================================
# AST-based static tool schema extraction (no IDA required)
# ============================================================================

def _ast_type_to_json_schema(node: ast.expr) -> dict:
    """Convert an AST type annotation node to JSON schema"""
    if node is None:
        return {"type": "object"}

    # Simple name: str, int, bool, dict, list, etc.
    if isinstance(node, ast.Name):
        return {"type": {
            "str": "string", "int": "integer", "float": "number",
            "bool": "boolean", "dict": "object", "list": "array",
        }.get(node.id, "object")}

    # ast.Constant (e.g. None)
    if isinstance(node, ast.Constant) and node.value is None:
        return {"type": "null"}

    # X | Y  (BinOp with BitOr)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _ast_type_to_json_schema(node.left)
        right = _ast_type_to_json_schema(node.right)
        # Flatten nested anyOf
        variants = []
        for s in (left, right):
            if "anyOf" in s:
                variants.extend(s["anyOf"])
            else:
                variants.append(s)
        return {"anyOf": variants}

    # Subscript: Annotated[T, "desc"], Optional[T], list[T], etc.
    if isinstance(node, ast.Subscript):
        base = node.value
        base_name = base.id if isinstance(base, ast.Name) else ""

        # Annotated[T, "description"]
        if base_name == "Annotated":
            if isinstance(node.slice, ast.Tuple):
                elts = node.slice.elts
                schema = _ast_type_to_json_schema(elts[0])
                # Last element is the description string
                if len(elts) >= 2 and isinstance(elts[-1], ast.Constant) and isinstance(elts[-1].value, str):
                    schema["description"] = elts[-1].value
                return schema
            return _ast_type_to_json_schema(node.slice)

        # Optional[T] -> anyOf[T, null]
        if base_name == "Optional":
            inner = node.slice
            return {"anyOf": [_ast_type_to_json_schema(inner), {"type": "null"}]}

        # list[T]
        if base_name == "list":
            inner = node.slice
            return {"type": "array", "items": _ast_type_to_json_schema(inner)}

        # dict[K, V]
        if base_name == "dict":
            if isinstance(node.slice, ast.Tuple) and len(node.slice.elts) == 2:
                return {"type": "object", "additionalProperties": _ast_type_to_json_schema(node.slice.elts[1])}
            return {"type": "object"}

    # Tuple (used in Union-style subscripts)
    if isinstance(node, ast.Tuple):
        return {"anyOf": [_ast_type_to_json_schema(e) for e in node.elts]}

    # Fallback
    return {"type": "object"}


def _has_decorator(decorators: list[ast.expr], name: str) -> bool:
    """Check if a function has a specific decorator"""
    for d in decorators:
        if isinstance(d, ast.Name) and d.id == name:
            return True
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == name:
            return True
    return False


def _extract_tools_from_file(filepath: str) -> list[dict]:
    """Extract @tool decorated function schemas from a Python source file using AST"""
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError:
        logger.warning(f"Failed to parse {filepath}")
        return []

    tools = []
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if not _has_decorator(node.decorator_list, "tool"):
            continue
        # Skip test functions and private functions
        if node.name.startswith("_") or node.name.startswith("test"):
            continue

        # Extract docstring
        docstring = ast.get_docstring(node) or f"Call {node.name}"

        # Extract parameters
        properties = {}
        required = []
        args = node.args

        # Build defaults mapping: last N args have defaults
        num_defaults = len(args.defaults)
        num_args = len(args.args)
        defaults_start = num_args - num_defaults

        for i, arg in enumerate(args.args):
            if arg.arg in ("self", "cls"):
                continue
            if arg.annotation:
                schema = _ast_type_to_json_schema(arg.annotation)
                properties[arg.arg] = schema
            else:
                properties[arg.arg] = {"type": "object"}

            # Check if parameter has a default value
            if i < defaults_start:
                required.append(arg.arg)

        tool_schema = {
            "name": node.name,
            "description": docstring.strip(),
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }
        tools.append(tool_schema)

    return tools


def extract_ida_tools_from_source() -> list[dict]:
    """Extract all IDA tool schemas from api_*.py source files using AST.

    This allows the session MCP server to know about all IDA tools at startup
    without needing a running IDA/idalib instance.
    """
    ida_mcp_dir = os.path.join(os.path.dirname(__file__), "ida_mcp")
    if not os.path.isdir(ida_mcp_dir):
        logger.warning(f"ida_mcp directory not found: {ida_mcp_dir}")
        return []

    all_tools = []
    for filename in sorted(os.listdir(ida_mcp_dir)):
        if not filename.startswith("api_") or not filename.endswith(".py"):
            continue
        filepath = os.path.join(ida_mcp_dir, filename)
        tools = _extract_tools_from_file(filepath)
        logger.debug(f"Extracted {len(tools)} tools from {filename}")
        all_tools.extend(tools)

    logger.info(f"Extracted {len(all_tools)} IDA tools from source via AST")
    return all_tools


@dataclass
class Session:
    """Represents an active IDA session"""

    session_id: str
    binary_path: str
    port: int
    pid: int
    status: str  # "starting", "analyzing", "ready", "error", "closed"
    created_at: float
    error_message: Optional[str] = None
    analysis_time: Optional[float] = None  # Time taken for analysis in seconds

    def to_dict(self) -> dict:
        return asdict(self)


class SessionMcpServer:
    """MCP Server with integrated session management"""

    def __init__(self, unsafe: bool = False, verbose: bool = False):
        self.mcp = McpServer("ida-pro-mcp-session")
        self.sessions: dict[str, Session] = {}
        self.processes: dict[str, subprocess.Popen] = {}
        self.active_session_id: Optional[str] = None
        self.unsafe = unsafe
        self.verbose = verbose
        self._lock = threading.Lock()
        self._port_counter = SESSION_PORT_START

        # Load IDA tools: try cache first, fall back to AST extraction from source
        self._cached_ida_tools: Optional[list[dict]] = load_cached_tools()
        if self._cached_ida_tools is None:
            ast_tools = extract_ida_tools_from_source()
            if ast_tools:
                self._cached_ida_tools = ast_tools

        # Register session management tools
        self._register_session_tools()

        # Patch the dispatch to route IDA tools to active session
        self._patch_dispatch()

    def _register_session_tools(self):
        """Register session management MCP tools"""

        @self.mcp.tool
        def session_open(
            binary_path: Annotated[str, "Path to the binary file to analyze"],
        ) -> dict:
            """Open a new IDA analysis session for a binary file.

            Creates a new idalib session that analyzes the binary.
            The session becomes the active session automatically.
            Returns session info including session_id and port.
            """
            try:
                session = self._create_session(binary_path)
                self.active_session_id = session.session_id
                return {
                    "success": True,
                    "session": session.to_dict(),
                    "message": f"Session {session.session_id} created and activated",
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                }

        @self.mcp.tool
        def session_list() -> dict:
            """List all active IDA analysis sessions.

            Returns information about all sessions including their
            session_id, binary_path, port, status, and whether active.
            """
            with self._lock:
                sessions = []
                for s in self.sessions.values():
                    info = s.to_dict()
                    info["is_active"] = s.session_id == self.active_session_id
                    sessions.append(info)
                return {
                    "sessions": sessions,
                    "active_session_id": self.active_session_id,
                    "total_count": len(sessions),
                }

        @self.mcp.tool
        def session_switch(
            session_id: Annotated[str, "ID of the session to switch to"],
        ) -> dict:
            """Switch to a different IDA analysis session.

            Makes the specified session the active session.
            All subsequent IDA tool calls will be routed to this session.
            """
            with self._lock:
                if session_id not in self.sessions:
                    return {
                        "success": False,
                        "error": f"Session {session_id} not found",
                    }

                session = self.sessions[session_id]
                if session.status != "ready":
                    return {
                        "success": False,
                        "error": f"Session {session_id} is not ready (status: {session.status})",
                    }

                self.active_session_id = session_id
                return {
                    "success": True,
                    "session": session.to_dict(),
                    "message": f"Switched to session {session_id}",
                }

        @self.mcp.tool
        def session_close(
            session_id: Annotated[str, "ID of the session to close"],
        ) -> dict:
            """Close an IDA analysis session.

            Terminates the idalib process and removes the session.
            If the closed session was active, no session will be active.
            """
            success = self._destroy_session(session_id)
            if success:
                return {
                    "success": True,
                    "message": f"Session {session_id} closed",
                }
            else:
                return {
                    "success": False,
                    "error": f"Session {session_id} not found",
                }

        @self.mcp.tool
        def session_info(
            session_id: Annotated[str, "ID of the session to get info for"] = None,
        ) -> dict:
            """Get detailed information about a session.

            If session_id is not provided, returns info about the active session.
            """
            with self._lock:
                if session_id is None:
                    session_id = self.active_session_id

                if session_id is None:
                    return {
                        "error": "No active session. Use session_open to create one.",
                    }

                if session_id not in self.sessions:
                    return {
                        "error": f"Session {session_id} not found",
                    }

                session = self.sessions[session_id]
                info = session.to_dict()
                info["is_active"] = session_id == self.active_session_id
                return info

    def _patch_dispatch(self):
        """Patch MCP dispatch to route IDA tool calls to active session"""
        original_dispatch = self.mcp.registry.dispatch

        def patched_dispatch(
            request: dict | str | bytes | bytearray,
        ) -> JsonRpcResponse | None:
            # Parse request if needed
            if not isinstance(request, dict):
                request_obj: JsonRpcRequest = json.loads(request)
            else:
                request_obj: JsonRpcRequest = request

            method = request_obj.get("method", "")

            # Handle session management and protocol methods locally
            local_methods = [
                "initialize",
                "ping",
                "tools/list",
                "tools/call",
                "resources/list",
                "resources/templates/list",
                "resources/read",
                "prompts/list",
                "prompts/get",
            ]

            # Check if this is a session tool or protocol method
            if method in local_methods:
                # For tools/call, check if it's a session tool
                if method == "tools/call":
                    tool_name = request_obj.get("params", {}).get("name", "")
                    if tool_name.startswith("session_"):
                        return original_dispatch(request)

                    # Extract session_id from arguments (if provided by agent)
                    # and strip it before forwarding to the IDA session
                    arguments = request_obj.get("params", {}).get("arguments", {})
                    target_session_id = arguments.pop("session_id", None)

                    # Route to specified session or fall back to active session
                    return self._route_to_session(request_obj, session_id=target_session_id)

                # For tools/list, merge session tools with IDA tools
                if method == "tools/list":
                    return self._merge_tools_list(original_dispatch(request))

                return original_dispatch(request)

            # Notifications
            if method.startswith("notifications/"):
                return original_dispatch(request)

            # Unknown method - try routing to session
            return self._route_to_session(request_obj)

        self.mcp.registry.dispatch = patched_dispatch

    def _route_to_session(self, request: JsonRpcRequest, session_id: str | None = None) -> JsonRpcResponse | None:
        """Route a request to a specific or active IDA session.

        Args:
            request: The JSON-RPC request to forward.
            session_id: Target session ID. If None, falls back to active_session_id.
        """
        with self._lock:
            target_id = session_id or self.active_session_id
            if target_id is None:
                return self._error_response(
                    request.get("id"),
                    -32001,
                    "No active session. Use session_open to create one, or pass session_id.",
                )

            session = self.sessions.get(target_id)
            if session is None:
                return self._error_response(
                    request.get("id"),
                    -32001,
                    f"Session {target_id} not found.",
                )
            if session.status != "ready":
                return self._error_response(
                    request.get("id"),
                    -32001,
                    f"Session {target_id} is not ready (status: {session.status}).",
                )

            port = session.port

        # Forward request to session's MCP server
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
            body = json.dumps(request)
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read().decode()
            return json.loads(data)
        except Exception as e:
            full_info = traceback.format_exc()
            return self._error_response(
                request.get("id"),
                -32000,
                f"Failed to connect to IDA session: {e}\n{full_info}",
            )
        finally:
            conn.close()

    # Tools from idalib_server.py that conflict with session management tools
    _EXCLUDED_TOOLS = {"idalib_open", "idalib_close", "idalib_switch", "idalib_list", "idalib_current"}

    def _filter_session_tools(self, tools: list[dict]) -> list[dict]:
        """Filter out idalib session tools that conflict with our session_* tools"""
        return [t for t in tools if t.get("name") not in self._EXCLUDED_TOOLS]

    @staticmethod
    def _inject_session_id_param(tools: list[dict]) -> list[dict]:
        """Inject optional session_id parameter into each IDA tool schema.

        This allows multi-agent scenarios where each agent explicitly specifies
        which session to route the tool call to, avoiding global active_session_id conflicts.
        """
        session_id_schema = {
            "type": "string",
            "description": "Session ID to route this call to. If omitted, uses the active session.",
        }
        result = []
        for tool in tools:
            tool = dict(tool)  # shallow copy
            input_schema = dict(tool.get("inputSchema", {}))
            props = dict(input_schema.get("properties", {}))
            props["session_id"] = session_id_schema
            input_schema["properties"] = props
            # session_id is optional, so do NOT add to required
            tool["inputSchema"] = input_schema
            result.append(tool)
        return result

    def _merge_tools_list(self, local_response: JsonRpcResponse) -> JsonRpcResponse:
        """Merge local session tools with IDA tools from active session"""
        if local_response is None:
            return None

        # Start with local tools
        local_tools = local_response.get("result", {}).get("tools", [])

        # If we have cached IDA tools, use them
        if self._cached_ida_tools is not None:
            ida_tools = self._inject_session_id_param(self._filter_session_tools(self._cached_ida_tools))
            return {
                "jsonrpc": "2.0",
                "result": {"tools": local_tools + ida_tools},
                "id": local_response.get("id"),
            }

        # Try to get tools from any ready session (not just active)
        port = None
        with self._lock:
            for session in self.sessions.values():
                if session.status == "ready":
                    port = session.port
                    break

        if port is None:
            return local_response

        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            conn.request(
                "POST", "/mcp", json.dumps(request), {"Content-Type": "application/json"}
            )
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            session_tools = data.get("result", {}).get("tools", [])

            # Filter out idalib session tools that conflict with our session_* tools
            session_tools = self._filter_session_tools(session_tools)

            # Cache the IDA tools for future use (both in memory and to file)
            self._cached_ida_tools = session_tools
            save_cached_tools(session_tools)
            logger.info(f"Cached {len(session_tools)} IDA tools")

            # Merge tools (local first, then session with injected session_id param)
            all_tools = local_tools + self._inject_session_id_param(session_tools)
            return {
                "jsonrpc": "2.0",
                "result": {"tools": all_tools},
                "id": local_response.get("id"),
            }
        except Exception as e:
            logger.warning(f"Failed to get tools from session: {e}")
            return local_response
        finally:
            conn.close()

    def _error_response(
        self, id: Any, code: int, message: str
    ) -> JsonRpcResponse:
        """Create a JSON-RPC error response"""
        if id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": id,
        }

    def _find_available_port(self) -> int:
        """Find an available port for a new session"""
        for port in range(self._port_counter, SESSION_PORT_END):
            in_use = any(s.port == port for s in self.sessions.values())
            if not in_use:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.bind(("127.0.0.1", port))
                        self._port_counter = port + 1
                        return port
                except OSError:
                    continue

        self._port_counter = SESSION_PORT_START
        raise RuntimeError("No available ports for new session")

    def _create_session(self, binary_path: str) -> Session:
        """Create a new IDA session for a binary"""
        binary_path = os.path.abspath(binary_path)

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        session_id = str(uuid.uuid4())[:8]
        port = self._find_available_port()

        # Start idalib subprocess
        cmd = [
            sys.executable,
            "-m",
            "ida_pro_mcp.idalib_server",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--session-id",
            session_id,
            binary_path,
        ]

        if self.unsafe:
            cmd.append("--unsafe")
        if self.verbose:
            cmd.append("--verbose")

        logger.info(f"Starting session {session_id}: {' '.join(cmd)}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to start idalib: {e}")

        session = Session(
            session_id=session_id,
            binary_path=binary_path,
            port=port,
            pid=process.pid,
            status="starting",
            created_at=time.time(),
        )

        with self._lock:
            self.sessions[session_id] = session
            self.processes[session_id] = process

        # Start monitor thread
        thread = threading.Thread(
            target=self._monitor_session, args=(session_id,), daemon=True
        )
        thread.start()

        # Wait for ready
        self._wait_for_session_ready(session_id, timeout=120)

        return self.sessions[session_id]

    def _wait_for_session_ready(self, session_id: str, timeout: float = 120):
        """Wait for session to become ready"""
        start_time = time.time()
        port = self.sessions[session_id].port

        while time.time() - start_time < timeout:
            with self._lock:
                if session_id not in self.sessions:
                    raise RuntimeError("Session was closed")

                session = self.sessions[session_id]
                if session.status == "error":
                    raise RuntimeError(
                        session.error_message or "Session failed to start"
                    )

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect(("127.0.0.1", port))
                    with self._lock:
                        if session_id in self.sessions:
                            self.sessions[session_id].status = "ready"
                    return
            except (socket.error, socket.timeout):
                pass

            time.sleep(0.5)

        raise TimeoutError(f"Session {session_id} did not become ready in {timeout}s")

    def _monitor_session(self, session_id: str):
        """Monitor a session subprocess and parse output"""
        with self._lock:
            if session_id not in self.processes:
                return
            process = self.processes[session_id]

        output_lines = []
        try:
            for line in process.stdout:
                line = line.rstrip()
                output_lines.append(line)
                if self.verbose:
                    logger.debug(f"[{session_id}] {line}")

                # Parse [SESSION_READY] marker to extract analysis time
                if line.startswith("[SESSION_READY]"):
                    # Parse: [SESSION_READY] session_id=xxx port=xxx analysis_time=xxx
                    try:
                        parts = line.split()
                        for part in parts[1:]:
                            if part.startswith("analysis_time="):
                                analysis_time_str = part.split("=")[1]
                                if analysis_time_str != "None":
                                    with self._lock:
                                        if session_id in self.sessions:
                                            self.sessions[session_id].analysis_time = float(analysis_time_str)
                                            logger.info(f"Session {session_id} analysis completed in {analysis_time_str}s")
                    except Exception as e:
                        logger.warning(f"Failed to parse SESSION_READY: {e}")
        except:
            pass

        return_code = process.wait()

        with self._lock:
            if session_id in self.sessions:
                if return_code != 0:
                    self.sessions[session_id].status = "error"
                    self.sessions[session_id].error_message = (
                        f"Process exited with code {return_code}: "
                        + "\n".join(output_lines[-10:])
                    )
                else:
                    self.sessions[session_id].status = "closed"

    def _destroy_session(self, session_id: str) -> bool:
        """Destroy a session, saving the IDB before termination"""
        with self._lock:
            if session_id not in self.sessions:
                return False

            process = self.processes.get(session_id)

            if process and process.poll() is None:
                try:
                    # Send SIGTERM to trigger graceful shutdown with IDB save
                    logger.info(f"Sending SIGTERM to session {session_id} for graceful shutdown with IDB save...")
                    process.terminate()
                    # Wait longer for IDB save to complete (up to 30 seconds)
                    process.wait(timeout=30)
                    logger.info(f"Session {session_id} terminated gracefully with IDB saved")
                except subprocess.TimeoutExpired:
                    logger.warning(f"Session {session_id} did not terminate in time, force killing...")
                    process.kill()
                    process.wait()

            if session_id in self.processes:
                del self.processes[session_id]
            del self.sessions[session_id]

            if self.active_session_id == session_id:
                self.active_session_id = None

            logger.info(f"Destroyed session {session_id}")
            return True

    def cleanup(self):
        """Clean up all sessions, saving IDBs before termination"""
        session_ids = list(self.sessions.keys())
        if session_ids:
            logger.info(f"Saving and closing {len(session_ids)} session(s)...")
        for session_id in session_ids:
            self._destroy_session(session_id)

    def serve(self, host: str, port: int, *, background: bool = True):
        """Start the MCP server"""
        self.mcp.serve(host, port, background=background)

    def stop(self):
        """Stop the MCP server"""
        self.mcp.stop()

    def stdio(self):
        """Run in stdio mode"""
        self.mcp.stdio()


def generate_tools_cache(binary_path: str, unsafe: bool = False, verbose: bool = False):
    """Generate tools cache by opening a temporary session"""
    print(f"Generating tools cache using binary: {binary_path}")

    server = SessionMcpServer(unsafe=unsafe, verbose=verbose)

    try:
        # Open a session to get tools
        session = server._create_session(binary_path)
        print(f"Session created: {session.session_id}")

        # Get tools from session
        port = session.port
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        conn.request("POST", "/mcp", json.dumps(request), {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        tools = data.get("result", {}).get("tools", [])
        conn.close()

        # Save to cache
        save_cached_tools(tools)
        print(f"Cached {len(tools)} tools to {TOOLS_CACHE_FILE}")

    finally:
        server.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="IDA Pro MCP Server with Session Management"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport: stdio (default) or http://host:port/sse",
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "--generate-tools-cache",
        type=str,
        metavar="BINARY",
        help="Generate tools cache using the specified binary, then exit",
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Handle --generate-tools-cache
    if args.generate_tools_cache:
        generate_tools_cache(args.generate_tools_cache, args.unsafe, args.verbose)
        return

    server = SessionMcpServer(unsafe=args.unsafe, verbose=args.verbose)

    def signal_handler(signum, frame):
        logger.info("Shutting down...")
        # Stop the HTTP server from a background thread to avoid deadlock
        # (shutdown() waits for serve_forever() to finish, but serve_forever()
        # is running on this same main thread)
        def _stop():
            server.stop()
        threading.Thread(target=_stop, daemon=True).start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.transport == "stdio":
            server.stdio()
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            server.serve(url.hostname, url.port, background=False)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        server.cleanup()


if __name__ == "__main__":
    main()
