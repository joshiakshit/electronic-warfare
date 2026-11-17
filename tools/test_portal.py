"""Exercise the lab portal JSON API without opening sockets or starting radio tools."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


class PortalTest(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parents[1] / "src/main/resources/portal/portal_server.py"
        spec = importlib.util.spec_from_file_location("portal_server", source)
        self.portal = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.portal)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.log = Path(self.directory.name) / "submissions.txt"
        with patch.object(sys, "argv", ["portal", "--creds", str(self.log)]):
            with patch.object(self.portal, "ThreadingHTTPServer") as server:
                self.portal.main()
                self.handler_class = server.call_args.args[1]

    def request(self, method, path, body=b""):
        handler = self.handler_class.__new__(self.handler_class)
        handler.path = path
        handler.headers = {"Content-Length": str(len(body))}
        handler.client_address = ("127.0.0.1", 12345)
        handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        with patch.object(handler, "send_response") as response:
            with patch.object(handler, "send_header") as headers:
                with patch.object(handler, "end_headers"):
                    getattr(handler, "do_" + method)()
        headers.assert_any_call("Content-Type", "application/json; charset=utf-8")
        return response.call_args.args[0], json.loads(handler.wfile.getvalue())

    def test_get_returns_service_status_without_html(self):
        status, data = self.request("GET", "/")
        self.assertEqual(200, status)
        self.assertEqual("running", data["status"])
        self.assertEqual("", self.log.read_text())

    def test_submission_keeps_existing_form_contract_and_records_dummy_data(self):
        status, data = self.request("POST", "/submit", b"username=fixture&password=dummy")
        self.assertEqual((200, {"status": "recorded"}), (status, data))
        self.assertIn("\t127.0.0.1\tfixture\tdummy\n", self.log.read_text())
        self.assertEqual(0o600, self.log.stat().st_mode & 0o777)

    def test_unknown_submission_returns_json_error_without_recording(self):
        status, data = self.request("POST", "/missing", b"username=fixture")
        self.assertEqual(404, status)
        self.assertIn("error", data)
        self.assertEqual("", self.log.read_text())


if __name__ == "__main__":
    unittest.main()
