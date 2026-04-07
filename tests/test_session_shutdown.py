import unittest
import os
import sys
from unittest.mock import Mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_pro_mcp.headless_web import HeadlessWebBackend
from ida_pro_mcp.session_mcp_server import SessionMcpServer


class SessionShutdownTests(unittest.TestCase):
    def test_cleanup_destroys_each_known_session(self):
        server = object.__new__(SessionMcpServer)
        server.sessions = {
            "sess-1": object(),
            "sess-2": object(),
            "sess-3": object(),
        }

        destroyed = []

        def fake_destroy(session_id):
            destroyed.append(session_id)
            server.sessions.pop(session_id, None)
            return True

        server._destroy_session = fake_destroy  # type: ignore[attr-defined]

        SessionMcpServer.cleanup(server)

        self.assertEqual(destroyed, ["sess-1", "sess-2", "sess-3"])
        self.assertEqual(server.sessions, {})

    def test_headless_backend_shutdown_cleans_sessions_and_notifier(self):
        backend = object.__new__(HeadlessWebBackend)
        backend.sessions = Mock()
        backend.notifier = Mock()

        HeadlessWebBackend.shutdown(backend)

        backend.sessions.cleanup.assert_called_once_with()
        backend.notifier.stop.assert_called_once_with()

    def test_headless_backend_shutdown_tolerates_missing_notifier(self):
        backend = object.__new__(HeadlessWebBackend)
        backend.sessions = Mock()
        backend.notifier = None

        HeadlessWebBackend.shutdown(backend)

        backend.sessions.cleanup.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
