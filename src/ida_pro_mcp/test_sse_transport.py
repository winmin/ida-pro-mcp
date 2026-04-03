"""
SSE Transport Test for idalib-session-mcp

This test verifies that the SSE transport works correctly for the session MCP server.
It tests:
1. SSE connection establishment
2. Session management tools via SSE
3. Proper event streaming
4. Request/response routing

Usage:
    # Test without a binary (session tools only)
    uv run python -m ida_pro_mcp.test_sse_transport

    # Test with a binary (full functionality)
    uv run python -m ida_pro_mcp.test_sse_transport /path/to/binary
"""

import os
import sys
import json
import time
import socket
import threading
import http.client
import subprocess
from typing import Optional


class SSEClient:
    """Simple SSE client for testing using raw sockets"""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.session_id: Optional[str] = None
        self._sock: Optional[socket.socket] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._events: list[tuple[str, str]] = []
        self._lock = threading.Lock()
        self._running = False

    def connect(self, timeout: float = 10.0) -> bool:
        """Establish SSE connection and get session ID"""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(timeout)
        self._sock.connect((self.host, self.port))

        # Send HTTP request
        request = f"GET /sse HTTP/1.1\r\nHost: {self.host}:{self.port}\r\nAccept: text/event-stream\r\n\r\n"
        self._sock.sendall(request.encode())

        # Read headers
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self._sock.recv(1024)
            if not chunk:
                print("[SSE] Connection closed while reading headers")
                return False
            response += chunk

        # Check status
        status_line = response.split(b"\r\n")[0].decode()
        if "200" not in status_line:
            print(f"[SSE] Failed to connect: {status_line}")
            return False

        # Start reader thread with any remaining data after headers
        self._running = True
        header_end = response.index(b"\r\n\r\n") + 4
        initial_data = response[header_end:]
        self._reader_thread = threading.Thread(
            target=self._read_events, args=(initial_data,), daemon=True
        )
        self._reader_thread.start()

        # Wait for endpoint event with session ID
        start = time.time()
        while time.time() - start < timeout:
            with self._lock:
                for event_type, data in self._events:
                    if event_type == "endpoint":
                        # Parse session ID from endpoint URL
                        # Format: /sse?session=xxx
                        if "session=" in data:
                            self.session_id = data.split("session=")[1]
                            return True
            time.sleep(0.1)

        print("[SSE] Timeout waiting for endpoint event")
        return False

    def _read_events(self, initial_data: bytes = b""):
        """Background thread to read SSE events"""
        sock = self._sock
        if sock is None:
            return

        buffer = initial_data.decode("utf-8", errors="replace")
        current_event = None
        current_data: list[str] = []

        try:
            sock.settimeout(1.0)  # Short timeout for polling
            while self._running:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk.decode("utf-8", errors="replace")
                except socket.timeout:
                    continue  # Just check _running flag

                # Process complete lines
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.rstrip("\r")

                    if line.startswith("event:"):
                        current_event = line[6:].strip()
                    elif line.startswith("data:"):
                        current_data.append(line[5:].strip())
                    elif line == "":
                        # Empty line = end of event
                        if current_event is not None and current_data:
                            data_str = "\n".join(current_data)
                            with self._lock:
                                self._events.append((current_event, data_str))
                            current_event = None
                            current_data = []
        except Exception as e:
            if self._running:
                print(f"[SSE] Read error: {e}")

    def send_request(self, method: str, params: Optional[dict] = None, timeout: float = 30.0) -> dict:
        """Send JSON-RPC request via SSE POST and wait for response"""
        if not self.session_id:
            raise RuntimeError("Not connected - call connect() first")

        request_id = int(time.time() * 1000)
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": request_id,
        }

        # Clear old events
        with self._lock:
            self._events = [e for e in self._events if e[0] == "endpoint"]

        # Send POST request
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        body = json.dumps(request)
        conn.request(
            "POST",
            f"/sse?session={self.session_id}",
            body,
            {"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        conn.close()

        if response.status not in (200, 202):
            raise RuntimeError(f"POST failed: {response.status}")

        # Wait for response via SSE
        start = time.time()
        while time.time() - start < timeout:
            with self._lock:
                for event_type, data in self._events:
                    if event_type == "message":
                        try:
                            msg = json.loads(data)
                            if msg.get("id") == request_id:
                                return msg
                        except json.JSONDecodeError:
                            pass
            time.sleep(0.1)

        raise TimeoutError(f"Timeout waiting for response to request {request_id}")

    def close(self):
        """Close SSE connection"""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except:
                pass
        if self._reader_thread:
            self._reader_thread.join(timeout=1)


class StreamableHTTPClient:
    """Simple Streamable HTTP client for testing"""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def send_request(self, method: str, params: Optional[dict] = None, timeout: float = 30.0) -> dict:
        """Send JSON-RPC request via POST /mcp"""
        request_id = int(time.time() * 1000)
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": request_id,
        }

        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        body = json.dumps(request)
        conn.request(
            "POST",
            "/mcp",
            body,
            {"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        data = response.read().decode()
        conn.close()

        if response.status not in (200, 202):
            raise RuntimeError(f"POST failed: {response.status} - {data}")

        return json.loads(data)


def wait_for_server(host: str, port: int, timeout: float = 30.0) -> bool:
    """Wait for server to be ready"""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((host, port))
                return True
        except (socket.error, socket.timeout):
            time.sleep(0.5)
    return False


def test_sse_transport(host: str, port: int) -> bool:
    """Test SSE transport functionality"""
    print("\n=== Testing SSE Transport ===")

    client = SSEClient(host, port)

    try:
        # Test 1: Connect via SSE
        print("\n[Test 1] Connecting via SSE...")
        if not client.connect():
            print("FAILED: Could not establish SSE connection")
            return False
        print(f"PASSED: Connected with session_id={client.session_id}")

        # Test 2: Initialize
        print("\n[Test 2] Sending initialize request...")
        response = client.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"},
        })
        if "error" in response:
            print(f"FAILED: {response['error']}")
            return False
        print(f"PASSED: Server initialized as {response['result']['serverInfo']['name']}")

        # Test 3: List tools
        print("\n[Test 3] Listing tools...")
        response = client.send_request("tools/list")
        if "error" in response:
            print(f"FAILED: {response['error']}")
            return False
        tools = response["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        print(f"PASSED: Found {len(tools)} tools")

        # Test 4: Session tools should be present
        print("\n[Test 4] Checking session management tools...")
        session_tools = ["session_open", "session_list", "session_switch", "session_close", "session_info"]
        missing = [t for t in session_tools if t not in tool_names]
        if missing:
            print(f"FAILED: Missing session tools: {missing}")
            return False
        print(f"PASSED: All session tools present")

        # Test 5: Call session_list (should work without active session)
        print("\n[Test 5] Calling session_list...")
        response = client.send_request("tools/call", {
            "name": "session_list",
            "arguments": {},
        })
        if "error" in response:
            print(f"FAILED: {response['error']}")
            return False
        content = response["result"]["content"][0]["text"]
        result = json.loads(content)
        print(f"PASSED: session_list returned {result['total_count']} sessions")

        # Test 6: Ping
        print("\n[Test 6] Sending ping...")
        response = client.send_request("ping")
        if "error" in response:
            print(f"FAILED: {response['error']}")
            return False
        print("PASSED: Ping successful")

        print("\n=== All SSE Transport Tests Passed ===")
        return True

    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


def test_streamable_http_transport(host: str, port: int) -> bool:
    """Test Streamable HTTP transport functionality"""
    print("\n=== Testing Streamable HTTP Transport ===")

    client = StreamableHTTPClient(host, port)

    try:
        # Test 1: Initialize
        print("\n[Test 1] Sending initialize request...")
        response = client.send_request("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"},
        })
        if "error" in response:
            print(f"FAILED: {response['error']}")
            return False
        print(f"PASSED: Server initialized as {response['result']['serverInfo']['name']}")

        # Test 2: List tools
        print("\n[Test 2] Listing tools...")
        response = client.send_request("tools/list")
        if "error" in response:
            print(f"FAILED: {response['error']}")
            return False
        tools = response["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        print(f"PASSED: Found {len(tools)} tools")

        # Test 3: Session tools should be present
        print("\n[Test 3] Checking session management tools...")
        session_tools = ["session_open", "session_list", "session_switch", "session_close", "session_info"]
        missing = [t for t in session_tools if t not in tool_names]
        if missing:
            print(f"FAILED: Missing session tools: {missing}")
            return False
        print(f"PASSED: All session tools present")

        # Test 4: Call session_list
        print("\n[Test 4] Calling session_list...")
        response = client.send_request("tools/call", {
            "name": "session_list",
            "arguments": {},
        })
        if "error" in response:
            print(f"FAILED: {response['error']}")
            return False
        content = response["result"]["content"][0]["text"]
        result = json.loads(content)
        print(f"PASSED: session_list returned {result['total_count']} sessions")

        # Test 5: Ping
        print("\n[Test 5] Sending ping...")
        response = client.send_request("ping")
        if "error" in response:
            print(f"FAILED: {response['error']}")
            return False
        print("PASSED: Ping successful")

        print("\n=== All Streamable HTTP Transport Tests Passed ===")
        return True

    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_session_with_binary(host: str, port: int, binary_path: str) -> bool:
    """Test session management with an actual binary"""
    print(f"\n=== Testing Session Management with Binary: {binary_path} ===")

    client = StreamableHTTPClient(host, port)

    try:
        # Test 1: Open a session
        print("\n[Test 1] Opening session for binary...")
        response = client.send_request("tools/call", {
            "name": "session_open",
            "arguments": {"binary_path": binary_path},
        }, timeout=120)  # Allow time for analysis
        if "error" in response:
            print(f"FAILED: {response['error']}")
            return False
        if response["result"].get("isError"):
            print(f"FAILED: {response['result']['content'][0]['text']}")
            return False
        content = response["result"]["content"][0]["text"]
        result = json.loads(content)
        if not result.get("success"):
            print(f"FAILED: {result.get('error')}")
            return False
        session_id = result["session"]["session_id"]
        print(f"PASSED: Session {session_id} created")

        # Test 2: List sessions
        print("\n[Test 2] Listing sessions...")
        response = client.send_request("tools/call", {
            "name": "session_list",
            "arguments": {},
        })
        content = response["result"]["content"][0]["text"]
        result = json.loads(content)
        if result["total_count"] < 1:
            print("FAILED: No sessions found")
            return False
        print(f"PASSED: Found {result['total_count']} session(s)")

        # Test 3: Get session info
        print("\n[Test 3] Getting session info...")
        response = client.send_request("tools/call", {
            "name": "session_info",
            "arguments": {},
        })
        content = response["result"]["content"][0]["text"]
        result = json.loads(content)
        if result.get("status") != "ready":
            print(f"FAILED: Session not ready: {result.get('status')}")
            return False
        print(f"PASSED: Session status is ready")

        # Test 4: Call an IDA tool (list_funcs)
        print("\n[Test 4] Calling IDA tool (list_funcs)...")
        response = client.send_request("tools/call", {
            "name": "list_funcs",
            "arguments": {"queries": {"filter": "*", "offset": 0, "count": 5}},
        }, timeout=120)  # IDA tools may take longer
        if response["result"].get("isError"):
            print(f"FAILED: {response['result']['content'][0]['text']}")
            return False
        content = response["result"]["content"][0]["text"]
        result = json.loads(content)
        functions = result if isinstance(result, list) else result.get("items", [])
        print(f"PASSED: Got {len(functions)} function(s)")

        # Test 5: Close session
        print("\n[Test 5] Closing session...")
        response = client.send_request("tools/call", {
            "name": "session_close",
            "arguments": {"session_id": session_id},
        })
        content = response["result"]["content"][0]["text"]
        result = json.loads(content)
        if not result.get("success"):
            print(f"FAILED: {result.get('error')}")
            return False
        print(f"PASSED: Session closed")

        print("\n=== All Session Management Tests Passed ===")
        return True

    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Test SSE transport for idalib-session-mcp")
    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="Server host"
    )
    parser.add_argument(
        "--port", type=int, default=8744, help="Server port"
    )
    parser.add_argument(
        "--start-server", action="store_true",
        help="Start the session MCP server automatically"
    )
    parser.add_argument(
        "binary", nargs="?", type=str,
        help="Optional: Path to binary for full session testing"
    )
    args = parser.parse_args()

    server_process = None

    try:
        if args.start_server:
            # Start the session MCP server
            print(f"Starting idalib-session-mcp on {args.host}:{args.port}...")
            cmd = [
                sys.executable, "-m", "ida_pro_mcp.session_mcp_server",
                "--transport", f"http://{args.host}:{args.port}/sse",
                "--verbose",
            ]
            server_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            # Wait for server to start
            if not wait_for_server(args.host, args.port):
                print("ERROR: Server did not start in time")
                return 1

            print("Server started successfully")

        # Run tests
        success = True

        # Test SSE transport
        if not test_sse_transport(args.host, args.port):
            success = False

        # Test Streamable HTTP transport
        if not test_streamable_http_transport(args.host, args.port):
            success = False

        # Test with binary if provided
        if args.binary:
            if not os.path.exists(args.binary):
                print(f"ERROR: Binary not found: {args.binary}")
                return 1
            if not test_session_with_binary(args.host, args.port, args.binary):
                success = False

        if success:
            print("\n========================================")
            print("ALL TESTS PASSED")
            print("========================================")
            return 0
        else:
            print("\n========================================")
            print("SOME TESTS FAILED")
            print("========================================")
            return 1

    except KeyboardInterrupt:
        print("\nTest interrupted")
        return 1
    finally:
        if server_process:
            print("\nStopping server...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()


if __name__ == "__main__":
    sys.exit(main())
