import json
import unittest
from unittest.mock import mock_open, patch

from ida_pro_mcp import idalib_pool_manager


class _FakeProcess:
    pid = 12345
    returncode = None

    def poll(self):
        return None

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class _FakeResponse:
    status = 200

    def read(self):
        return json.dumps({"result": {"ok": True}}).encode("utf-8")


class _FakeHTTPConnection:
    instances = []

    def __init__(self, host, port=None, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.closed = False
        self.requests = []
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def request(self, method, path, body, headers):
        self.requests.append((method, path, body, headers))

    def getresponse(self):
        return _FakeResponse()

    def close(self):
        self.closed = True


class PoolWindowsTransportTests(unittest.TestCase):
    def setUp(self):
        _FakeHTTPConnection.reset()

    def test_auto_backend_uses_tcp_on_windows(self):
        with patch.object(idalib_pool_manager.sys, "platform", "win32"):
            self.assertEqual(idalib_pool_manager._resolve_backend_transport("auto"), "tcp")

    def test_tcp_spawn_uses_loopback_port_instead_of_unix_socket(self):
        popen_calls = []

        def fake_popen(cmd, **kwargs):
            popen_calls.append((cmd, kwargs))
            return _FakeProcess()

        manager = idalib_pool_manager.InstanceManager(
            "backend-dir",
            idalib_args=["--verbose"],
            backend_transport="tcp",
        )
        with patch.object(idalib_pool_manager, "_reserve_loopback_port", return_value=29876):
            with patch.object(idalib_pool_manager.subprocess, "Popen", fake_popen):
                with patch("builtins.open", mock_open()):
                    with patch.object(idalib_pool_manager.InstanceManager, "_wait_for_ready"):
                        inst = manager.spawn()

        self.assertEqual(inst.transport, "tcp")
        self.assertEqual(inst.host, "127.0.0.1")
        self.assertEqual(inst.port, 29876)
        cmd = popen_calls[0][0]
        self.assertIn("--host", cmd)
        self.assertIn("127.0.0.1", cmd)
        self.assertIn("--port", cmd)
        self.assertIn("29876", cmd)
        self.assertIn("--single-threaded-http", cmd)
        self.assertNotIn("--unix-socket", cmd)

    def test_tcp_forward_uses_http_connection_host_and_port(self):
        inst = idalib_pool_manager.InstanceInfo(
            index=0,
            process=_FakeProcess(),
            transport="tcp",
            log_path="backend-dir\\0.log",
            host="127.0.0.1",
            port=29876,
        )
        manager = idalib_pool_manager.InstanceManager("backend-dir", backend_transport="tcp")
        with patch.object(idalib_pool_manager.http.client, "HTTPConnection", _FakeHTTPConnection):
            response = manager.forward_raw(inst, {"jsonrpc": "2.0", "id": 1})

        self.assertEqual(response, {"result": {"ok": True}})
        self.assertEqual(len(_FakeHTTPConnection.instances), 1)
        conn = _FakeHTTPConnection.instances[0]
        self.assertEqual(conn.host, "127.0.0.1")
        self.assertEqual(conn.port, 29876)
        self.assertIsNone(conn.sock)
        self.assertTrue(conn.closed)

    def test_open_timeout_discards_backend_instance(self):
        inst = idalib_pool_manager.InstanceInfo(
            index=0,
            process=_FakeProcess(),
            transport="tcp",
            log_path="backend-dir\\0.log",
            host="127.0.0.1",
            port=29876,
        )
        with patch.object(idalib_pool_manager.os, "makedirs"):
            pool = idalib_pool_manager.PoolManager(
                socket_dir="backend-dir",
                backend_transport="tcp",
                open_timeout_sec=3,
            )
        pool._allocate_instance_locked = lambda: inst

        with patch.object(
            pool.im, "forward_tool_call", side_effect=TimeoutError("read timeout")
        ) as forward:
            with patch.object(pool.im, "kill") as kill:
                result = pool.open_session(
                    "C:\\fake\\sample.exe",
                    session_id="sample",
                    run_auto_analysis=False,
                )

        self.assertFalse(result["success"])
        self.assertIn("Failed to open binary after 3s", result["error"])
        self.assertEqual(pool.sessions, {})
        kill.assert_called_once_with(inst)
        self.assertEqual(forward.call_args.kwargs["timeout"], 3.0)

    def test_auto_open_timeout_depends_on_backend_transport(self):
        with patch.object(idalib_pool_manager.os, "makedirs"):
            tcp_pool = idalib_pool_manager.PoolManager(
                socket_dir="backend-dir",
                backend_transport="tcp",
            )
            with patch.object(idalib_pool_manager, "_supports_unix_sockets", return_value=True):
                unix_pool = idalib_pool_manager.PoolManager(
                    socket_dir="backend-dir",
                    backend_transport="unix",
                )

        self.assertEqual(tcp_pool.open_timeout_sec, 110.0)
        self.assertIsNone(unix_pool.open_timeout_sec)


if __name__ == "__main__":
    unittest.main()
