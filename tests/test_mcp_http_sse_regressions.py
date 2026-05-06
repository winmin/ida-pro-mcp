import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from ida_pro_mcp import idalib_pool_server

mcp_mod = idalib_pool_server._mcp_mod
McpHttpRequestHandler = mcp_mod.McpHttpRequestHandler
McpServer = mcp_mod.McpServer


class _FakeServerBase:
    instances = []

    def __init__(self, server_address, request_handler, bind_and_activate=False):
        self.server_address = server_address
        self.request_handler = request_handler
        self.bind_and_activate = bind_and_activate
        self.allow_reuse_address = False
        self.bound = False
        self.activated = False
        self.closed = False
        self.served = False
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def server_bind(self):
        self.bound = True

    def server_activate(self):
        self.activated = True

    def server_close(self):
        self.closed = True

    def serve_forever(self):
        self.served = True


class _FakeThreadingHTTPServer(_FakeServerBase):
    instances = []


class _FakeHTTPServer(_FakeServerBase):
    instances = []


class McpServeTransportTests(unittest.TestCase):
    def setUp(self):
        _FakeThreadingHTTPServer.reset()
        _FakeHTTPServer.reset()

    def test_foreground_tcp_server_is_threaded_for_sse(self):
        server = McpServer("ida-pro-mcp")
        with patch.object(mcp_mod, "ThreadingHTTPServer", _FakeThreadingHTTPServer):
            with patch.object(mcp_mod, "HTTPServer", _FakeHTTPServer):
                server.serve(
                    host="127.0.0.1",
                    port=27144,
                    background=False,
                    request_handler=McpHttpRequestHandler,
                )

        self.assertEqual(len(_FakeThreadingHTTPServer.instances), 1)
        self.assertEqual(len(_FakeHTTPServer.instances), 0)
        self.assertTrue(_FakeThreadingHTTPServer.instances[0].bound)
        self.assertTrue(_FakeThreadingHTTPServer.instances[0].activated)
        self.assertTrue(_FakeThreadingHTTPServer.instances[0].served)

    def test_foreground_tcp_server_can_be_single_threaded_for_idalib(self):
        server = McpServer("ida-pro-mcp")
        with patch.object(mcp_mod, "ThreadingHTTPServer", _FakeThreadingHTTPServer):
            with patch.object(mcp_mod, "HTTPServer", _FakeHTTPServer):
                server.serve(
                    host="127.0.0.1",
                    port=27145,
                    background=False,
                    request_handler=McpHttpRequestHandler,
                    threaded=False,
                )

        self.assertEqual(len(_FakeThreadingHTTPServer.instances), 0)
        self.assertEqual(len(_FakeHTTPServer.instances), 1)
        self.assertTrue(_FakeHTTPServer.instances[0].bound)
        self.assertTrue(_FakeHTTPServer.instances[0].activated)
        self.assertTrue(_FakeHTTPServer.instances[0].served)


class McpProtocolNotificationTests(unittest.TestCase):
    def test_initialized_notification_is_accepted(self):
        server = McpServer("ida-pro-mcp")
        request = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": None,
        }

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            response = server.registry.dispatch(request)

        self.assertIsNone(response)
        self.assertNotIn(
            "Method 'notifications/initialized' not found",
            stdout.getvalue(),
        )


class PoolProxyToolSchemaTests(unittest.TestCase):
    def test_prepare_tools_adds_local_pool_status_tool(self):
        tools = idalib_pool_server._prepare_tools(
            [
                {
                    "name": "decompile",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )

        by_name = {tool["name"]: tool for tool in tools}
        self.assertIn("idalib_pool_status", by_name)
        self.assertIn("session_id", by_name["decompile"]["inputSchema"]["properties"])
        self.assertNotIn(
            "session_id",
            by_name["idalib_pool_status"]["inputSchema"]["properties"],
        )

    def test_invalid_open_timeout_env_falls_back_to_default(self):
        with patch.dict(idalib_pool_server.os.environ, {"IDA_MCP_OPEN_TIMEOUT_SEC": "bad"}):
            self.assertIsNone(idalib_pool_server._default_open_timeout_sec())


if __name__ == "__main__":
    unittest.main()
