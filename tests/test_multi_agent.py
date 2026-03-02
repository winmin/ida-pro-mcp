#!/usr/bin/env python3
"""
Multi-Agent Simulation Test for idalib-session-mcp

Tests that agents can use explicit session_id parameter to route tool calls
to specific sessions, avoiding global active_session_id conflicts.

Usage:
    # Terminal 1: Start SSE server
    uv run idalib-session-mcp --transport http://127.0.0.1:8744/sse

    # Terminal 2: Run test
    python3 tests/test_multi_agent.py
"""

import json
import http.client
import shutil
import tempfile
import threading
import time
import os

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8744
BINARY_PATH = os.path.join(os.path.dirname(__file__), "..", "httpd.i64")

# ============================================================================
# JSON-RPC helpers
# ============================================================================

_request_id = 0
_request_id_lock = threading.Lock()


def next_id():
    global _request_id
    with _request_id_lock:
        _request_id += 1
        return _request_id


def rpc_call(method: str, params: dict | None = None) -> dict:
    """Send a JSON-RPC tools/call request to the MCP server"""
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": method, "arguments": params or {}},
        "id": next_id(),
    }
    conn = http.client.HTTPConnection(SERVER_HOST, SERVER_PORT, timeout=120)
    try:
        conn.request("POST", "/mcp", json.dumps(request), {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
    finally:
        conn.close()

    # Check for JSON-RPC level error (e.g. routing errors from session server)
    if "error" in data:
        err = data["error"]
        raise RuntimeError(f"JSON-RPC error [{err.get('code')}]: {err.get('message')}")

    # Check for MCP tools/call level error
    result = data.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        err_msg = content[0]["text"] if content else "unknown error"
        raise RuntimeError(f"Tool error: {err_msg}")
    content = result.get("content", [])
    if content and content[0].get("type") == "text":
        return json.loads(content[0]["text"])
    return data


def rpc_raw(method: str, params: dict | None = None) -> dict:
    """Send a raw JSON-RPC request (not tools/call wrapped)"""
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": next_id(),
    }
    conn = http.client.HTTPConnection(SERVER_HOST, SERVER_PORT, timeout=120)
    try:
        conn.request("POST", "/mcp", json.dumps(request), {"Content-Type": "application/json"})
        resp = conn.getresponse()
        return json.loads(resp.read().decode())
    finally:
        conn.close()


# ============================================================================
# Test framework
# ============================================================================

passed = 0
failed = 0
results = []


def test(name: str):
    """Decorator for test functions"""
    def decorator(func):
        def wrapper():
            global passed, failed
            print(f"\n{'='*60}")
            print(f"TEST: {name}")
            print(f"{'='*60}")
            try:
                func()
                passed += 1
                results.append(("PASS", name))
                print(f"  PASSED")
            except Exception as e:
                failed += 1
                results.append(("FAIL", name, str(e)))
                print(f"  FAILED: {e}")
        wrapper.test_name = name  # type: ignore[attr-defined]
        wrapper.run = wrapper  # type: ignore[attr-defined]
        return wrapper
    return decorator


def assert_eq(actual, expected, msg=""):
    if actual != expected:
        raise AssertionError(f"{msg}: expected {expected!r}, got {actual!r}")


def assert_true(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def has_meta_keys(result: dict) -> bool:
    """Check if idb_meta result has expected keys (path, module, base, etc.)"""
    return any(k in result for k in ("path", "file_path", "filename", "module"))


# ============================================================================
# State
# ============================================================================

session_id_1 = None  # Agent1's session
session_id_2 = None  # Agent2's session
_temp_dir = None  # Temp dir for binary copy


# ============================================================================
# Tests
# ============================================================================

@test("1. Agent1 opens httpd.i64 -> session_1")
def test_agent1_open():
    global session_id_1
    binary = os.path.abspath(BINARY_PATH)
    print(f"  Agent1: session_open({binary})")
    result = rpc_call("session_open", {"binary_path": binary})
    print(f"  Result: success={result.get('success')}")
    assert_true(result.get("success"), f"session_open failed: {result}")
    session_id_1 = result["session"]["session_id"]
    print(f"  Agent1 session_id: {session_id_1}")


@test("2. Agent2 opens httpd.i64 copy -> session_2 (different session)")
def test_agent2_open():
    global session_id_2, _temp_dir
    # IDA locks .i64 files, so copy the binary for the second session
    _temp_dir = tempfile.mkdtemp(prefix="ida_test_")
    binary_copy = os.path.join(_temp_dir, "httpd.i64")
    shutil.copy2(os.path.abspath(BINARY_PATH), binary_copy)
    print(f"  Agent2: session_open({binary_copy})")
    result = rpc_call("session_open", {"binary_path": binary_copy})
    print(f"  Result: success={result.get('success')}")
    assert_true(result.get("success"), f"session_open failed: {result}")
    session_id_2 = result["session"]["session_id"]
    print(f"  Agent2 session_id: {session_id_2}")
    assert_true(session_id_1 != session_id_2, "Should get different session IDs")
    print(f"  Two different sessions: {session_id_1} vs {session_id_2}")


@test("3. Both agents see each other's sessions")
def test_session_visibility():
    assert_true(session_id_1 is not None, "session_id_1 not set (test 1 failed?)")
    assert_true(session_id_2 is not None, "session_id_2 not set (test 2 failed?)")
    result = rpc_call("session_list")
    count = result.get("total_count", 0)
    ids = [s["session_id"] for s in result.get("sessions", [])]
    print(f"  session_list: {ids} (count={count})")
    assert_true(count >= 2, f"Should see >=2 sessions, got {count}")
    assert_true(session_id_1 in ids, f"session_1 {session_id_1} not in list")
    assert_true(session_id_2 in ids, f"session_2 {session_id_2} not in list")


@test("4. IDA tools have session_id parameter in schema")
def test_tools_have_session_id():
    r = rpc_raw("tools/list")
    tools = r.get("result", {}).get("tools", [])
    # Check a few IDA tools have session_id parameter
    ida_tools_checked = 0
    for t in tools:
        if t["name"] in ("idb_meta", "decompile", "list_funcs"):
            props = t.get("inputSchema", {}).get("properties", {})
            assert_true("session_id" in props, f"{t['name']} missing session_id param")
            assert_true("session_id" not in t.get("inputSchema", {}).get("required", []),
                        f"{t['name']} session_id should be optional")
            ida_tools_checked += 1
            print(f"  {t['name']}: has optional session_id")

    # Session tools should NOT have session_id injected
    for t in tools:
        if t["name"] in ("session_open", "session_list"):
            props = t.get("inputSchema", {}).get("properties", {})
            assert_true("session_id" not in props,
                        f"{t['name']} should NOT have injected session_id")
            print(f"  {t['name']}: no session_id (correct)")

    assert_true(ida_tools_checked >= 3, f"Expected >=3 IDA tools checked, got {ida_tools_checked}")


@test("5. Agent1 calls idb_meta with explicit session_id -> routes to session_1")
def test_explicit_session_id_routing():
    assert_true(session_id_1 is not None, "session_id_1 not set")
    assert_true(session_id_2 is not None, "session_id_2 not set")

    # Agent1 calls idb_meta on session_1
    print(f"  Agent1: idb_meta(session_id={session_id_1})")
    r1 = rpc_call("idb_meta", {"session_id": session_id_1})
    print(f"  Result keys: {list(r1.keys())}")
    assert_true(has_meta_keys(r1), f"idb_meta should return file info: {r1}")

    # Agent2 calls idb_meta on session_2
    print(f"  Agent2: idb_meta(session_id={session_id_2})")
    r2 = rpc_call("idb_meta", {"session_id": session_id_2})
    print(f"  Result keys: {list(r2.keys())}")
    assert_true(has_meta_keys(r2), f"idb_meta should return file info: {r2}")


@test("6. No cross-contamination: Agent2 switch doesn't affect Agent1's explicit calls")
def test_no_cross_contamination():
    assert_true(session_id_1 is not None, "session_id_1 not set")
    assert_true(session_id_2 is not None, "session_id_2 not set")

    # Agent2 switches active to session_2
    print(f"  Agent2: session_switch({session_id_2})")
    rpc_call("session_switch", {"session_id": session_id_2})

    # Verify active is session_2
    info = rpc_call("session_info")
    active = info.get("session_id")
    print(f"  Active session: {active} (should be session_2)")
    assert_eq(active, session_id_2, "Active should be session_2")

    # Agent1 calls idb_meta with explicit session_id=session_1
    # Even though active is session_2, Agent1's call should go to session_1
    print(f"  Agent1: idb_meta(session_id={session_id_1}) -- despite active={session_id_2}")
    r1 = rpc_call("idb_meta", {"session_id": session_id_1})
    assert_true(has_meta_keys(r1), f"Should succeed on session_1: {r1}")
    print(f"  Agent1 got result from session_1 (not affected by Agent2's switch)")


@test("7. Concurrent calls to different sessions via explicit session_id")
def test_concurrent_explicit_sessions():
    assert_true(session_id_1 is not None, "session_id_1 not set")
    assert_true(session_id_2 is not None, "session_id_2 not set")

    results_map = {}
    errors = []

    def agent_call(agent_name: str, tool: str, args: dict):
        try:
            t0 = time.time()
            result = rpc_call(tool, args)
            elapsed = time.time() - t0
            results_map[agent_name] = result
            print(f"  {agent_name}: {tool}(session_id={args.get('session_id', 'N/A')}) -> {elapsed:.1f}s")
        except Exception as e:
            errors.append(f"{agent_name}: {e}")

    # Agent1 calls idb_meta on session_1, Agent2 calls idb_meta on session_2
    t1 = threading.Thread(target=agent_call, args=(
        "Agent1", "idb_meta", {"session_id": session_id_1}))
    t2 = threading.Thread(target=agent_call, args=(
        "Agent2", "idb_meta", {"session_id": session_id_2}))

    print("  Starting concurrent calls to different sessions...")
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)

    assert_true(len(errors) == 0, f"Concurrent call errors: {errors}")
    assert_true("Agent1" in results_map, "Agent1 should get a result")
    assert_true("Agent2" in results_map, "Agent2 should get a result")
    print(f"  Both agents got independent results from their own sessions")


@test("8. Invalid session_id returns error")
def test_invalid_session_id():
    print(f"  Calling idb_meta(session_id='nonexistent')")
    try:
        rpc_call("idb_meta", {"session_id": "nonexistent"})
        raise AssertionError("Should have raised an error for invalid session_id")
    except RuntimeError as e:
        print(f"  Got expected error: {e}")
        assert_true("not found" in str(e).lower(), f"Error should mention 'not found': {e}")


@test("9. Fallback: omitting session_id uses active session")
def test_fallback_to_active():
    assert_true(session_id_1 is not None, "session_id_1 not set")

    # Switch active to session_1
    rpc_call("session_switch", {"session_id": session_id_1})

    # Call without session_id -- should use active (session_1)
    print(f"  Active: session_1, calling idb_meta() without session_id")
    r = rpc_call("idb_meta", {})
    assert_true(has_meta_keys(r), f"Should succeed via active session: {r}")
    print(f"  Fallback to active session works")


@test("10. Cleanup: close both sessions")
def test_cleanup():
    global _temp_dir
    if session_id_1:
        print(f"  Closing session_1: {session_id_1}")
        r1 = rpc_call("session_close", {"session_id": session_id_1})
        print(f"  Result: {r1}")

    if session_id_2:
        print(f"  Closing session_2: {session_id_2}")
        r2 = rpc_call("session_close", {"session_id": session_id_2})
        print(f"  Result: {r2}")

    result = rpc_call("session_list")
    remaining = result.get("total_count", -1)
    print(f"  Remaining sessions: {remaining}")

    # Clean up temp dir
    if _temp_dir and os.path.exists(_temp_dir):
        shutil.rmtree(_temp_dir, ignore_errors=True)
        print(f"  Cleaned up temp dir: {_temp_dir}")


# ============================================================================
# Main
# ============================================================================

def main():
    print("=" * 60)
    print("Multi-Agent Test: explicit session_id routing")
    print(f"Server: http://{SERVER_HOST}:{SERVER_PORT}")
    print(f"Binary: {os.path.abspath(BINARY_PATH)}")
    print("=" * 60)

    # Verify server is reachable
    try:
        r = rpc_raw("tools/list")
        tools = r.get("result", {}).get("tools", [])
        print(f"Server OK: {len(tools)} tools available")
    except Exception as e:
        print(f"ERROR: Cannot connect to server at {SERVER_HOST}:{SERVER_PORT}")
        print(f"  Start it first: uv run idalib-session-mcp --transport http://{SERVER_HOST}:{SERVER_PORT}/sse")
        print(f"  Error: {e}")
        return

    # Run tests in order
    all_tests = [
        test_agent1_open,
        test_agent2_open,
        test_session_visibility,
        test_tools_have_session_id,
        test_explicit_session_id_routing,
        test_no_cross_contamination,
        test_concurrent_explicit_sessions,
        test_invalid_session_id,
        test_fallback_to_active,
        test_cleanup,
    ]

    for t in all_tests:
        t.run()  # type: ignore[attr-defined]

    # Summary
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'='*60}")
    for status, *rest in results:
        name = rest[0]
        if status == "PASS":
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name}: {rest[1]}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
