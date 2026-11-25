"""Exercise the lab portal JSON API without opening sockets or starting radio tools."""
import importlib.util
import io
import json
import os
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
        self.log.touch(mode=0o600)
        self.backend_inode = self.log.stat().st_ino
        self.backend_owner = self.log.stat().st_uid
        self.start_portal()

    def start_portal(self):
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

    def test_existing_backend_log_is_reused_without_create_flags(self):
        real_open = os.open
        calls = []

        def protected_open(path, flags, *args, **kwargs):
            if not flags & os.O_DIRECTORY:
                calls.append(flags)
            if Path(path).exists() and flags & os.O_CREAT:
                raise PermissionError("simulated protected_regular denial for elevated O_CREAT")
            return real_open(path, flags, *args, **kwargs)

        self.log.write_text("stale credentials\n")
        with patch.object(self.portal.os, "open", side_effect=protected_open):
            self.start_portal()
            self.assertEqual("", self.log.read_text())
            status, data = self.request("POST", "/submit", b"username=lab&password=dummy")
        self.assertEqual((200, {"status": "recorded"}), (status, data))
        self.assertTrue(all(not flags & os.O_CREAT for flags in calls))
        self.assertEqual(self.backend_inode, self.log.stat().st_ino)
        self.assertEqual(self.backend_owner, self.log.stat().st_uid)
        self.assertEqual(0o600, self.log.stat().st_mode & 0o777)

    def test_standalone_helper_can_create_a_private_log(self):
        self.log.unlink()
        self.start_portal()
        self.assertTrue(self.log.is_file())
        self.assertEqual(0o600, self.log.stat().st_mode & 0o777)

    def test_log_initialization_failure_is_reported_before_serving(self):
        with patch.object(self.portal.os, "open", side_effect=PermissionError("unreadable log")):
            with patch.object(self.portal, "ThreadingHTTPServer") as server:
                with self.assertRaises(PermissionError):
                    self.start_portal()
                server.assert_not_called()

    def test_symlink_log_does_not_truncate_another_file(self):
        victim = self.log.with_name("other.txt")
        victim.write_text("keep this data")
        self.log.unlink()
        self.log.symlink_to(victim)
        with self.assertRaises(OSError):
            self.start_portal()
        self.assertEqual("keep this data", victim.read_text())

    def test_hardlinked_log_is_rejected_before_truncation(self):
        self.log.write_text("keep this data")
        os.link(self.log, self.log.with_name("hardlink"))
        with self.assertRaises(PermissionError):
            self.start_portal()
        self.assertEqual("keep this data", self.log.read_text())

    def test_shared_directory_and_wrong_owner_are_rejected(self):
        self.log.write_text("keep this data")
        os.chmod(self.directory.name, 0o777)
        try:
            with self.assertRaises(PermissionError):
                self.start_portal()
        finally:
            os.chmod(self.directory.name, 0o700)
        with patch.object(self.portal.os, "geteuid", return_value=self.backend_owner + 1):
            with patch.dict(os.environ, {"SUDO_UID": str(self.backend_owner + 1)}):
                with self.assertRaises(PermissionError):
                    self.start_portal()
        self.assertEqual("keep this data", self.log.read_text())

    def test_replaced_log_is_rejected_during_submission(self):
        self.log.rename(self.log.with_name("original"))
        self.log.touch(mode=0o600)
        with self.assertRaises(PermissionError):
            self.request("POST", "/submit", b"username=dummy")
        self.assertEqual("", self.log.read_text())

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
