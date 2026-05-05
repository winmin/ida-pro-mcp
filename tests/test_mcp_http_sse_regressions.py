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


if __name__ == "__main__":
    unittest.main()
