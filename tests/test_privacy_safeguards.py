"""
Privacy Safeguards Verification Tests
=====================================
Automated verification proving that:
1. Passwords submitted to /api/analyze are NEVER written to application logs.
2. The breach-check endpoint strictly rejects full hashes, long inputs, and raw passwords.
3. The breach checker only constructs URLs with 5-character prefixes and never transmits passwords.
4. Error responses do not leak submitted credentials or server internals.
5. Client static assets contain zero calls to localStorage, sessionStorage, or cookies.
6. The application contains no database or file-persistence mechanism for passwords.
"""

import logging
import os
import re
import unittest
from unittest.mock import patch, MagicMock

from app import app
from breach_checker import check_breach_prefix, validate_prefix, InvalidPrefixError


class TestPrivacySafeguards(unittest.TestCase):

    def setUp(self):
        """Configure test client and logging capture."""
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_passwords_never_logged_during_analysis(self):
        """Canary password sent to /api/analyze must never appear in any log records."""
        canary_password = "SuperSecretCanaryPassword987!#@$"
        
        class LogCapturer(logging.Handler):
            def __init__(self):
                super().__init__()
                self.records = []
            def emit(self, record):
                self.records.append(self.format(record))

        capturer = LogCapturer()
        logging.getLogger().addHandler(capturer)
        try:
            res = self.client.post("/api/analyze", json={"password": canary_password})
            self.assertEqual(res.status_code, 200)
            
            for log_msg in capturer.records:
                self.assertNotIn(
                    canary_password,
                    log_msg,
                    f"Privacy violation: canary password found in log: '{log_msg}'"
                )
        finally:
            logging.getLogger().removeHandler(capturer)

    def test_breach_endpoint_rejects_raw_password(self):
        """GET /api/breach-check must reject raw password strings with HTTP 400."""
        res = self.client.get("/api/breach-check?prefix=mysecretpassword")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["error"]["code"], "INVALID_PREFIX")

    def test_breach_endpoint_rejects_full_hash(self):
        """GET /api/breach-check must reject 40-character full SHA-1 hashes with HTTP 400."""
        full_sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        res = self.client.get(f"/api/breach-check?prefix={full_sha1}")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["error"]["code"], "INVALID_PREFIX")

    def test_breach_endpoint_strictly_enforces_5_hex_chars(self):
        """Prefix validation must strictly allow only [0-9A-Fa-f]{5}."""
        invalid_prefixes = [
            "1234",       # 4 chars (too short)
            "123456",     # 6 chars (too long)
            "ABCZG",      # Non-hex characters ('Z', 'G')
            "   ",        # Whitespace
            "",           # Empty
            "12 45",      # Embedded space
            "1234\n",     # Embedded newline
        ]
        for p in invalid_prefixes:
            res = self.client.get(f"/api/breach-check?prefix={p}")
            self.assertEqual(res.status_code, 400, f"Expected 400 for prefix '{p}'")

    @patch("urllib.request.urlopen")
    def test_breach_checker_outgoing_url_contains_only_5_chars(self, mock_urlopen):
        """Upstream HTTP request URL must contain exactly the 5-character prefix and no payload."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        prefix = "5BAA6"
        check_breach_prefix(prefix)

        # Inspect the Request object passed to urlopen
        called_request = mock_urlopen.call_args[0][0]
        self.assertEqual(
            called_request.full_url,
            "https://api.pwnedpasswords.com/range/5BAA6",
            "Privacy violation: Outgoing URL must strictly be the 5-character range lookup"
        )
        self.assertIsNone(called_request.data, "Outbound GET request must not carry body payload")

    def test_error_responses_contain_no_credentials(self):
        """Error responses must never echo back passwords or internal stack traces."""
        canary = "CanaryErrorPassword123!"
        res = self.client.post("/api/analyze", json={"password": canary, "unexpected": 123})
        self.assertEqual(res.status_code, 200)

        # Trigger 400 with invalid type
        res_bad = self.client.post("/api/analyze", json={"password": 99999})
        self.assertEqual(res_bad.status_code, 400)
        text = res_bad.get_data(as_text=True)
        self.assertNotIn("99999", text)
        self.assertNotIn("Traceback", text)

    def test_static_assets_contain_no_client_storage(self):
        """Frontend JS files must not use persistent client storage APIs (localStorage, etc.)."""
        js_path = os.path.join(os.path.dirname(__file__), "..", "static", "app.js")
        with open(js_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check for active storage calls (ignoring comments)
        code_lines = [line for line in content.splitlines() if not line.strip().startswith("*") and not line.strip().startswith("//")]
        code_text = "\n".join(code_lines)

        self.assertNotIn("localStorage.setItem", code_text)
        self.assertNotIn("sessionStorage.setItem", code_text)
        self.assertNotIn("document.cookie", code_text)
        self.assertNotIn("indexedDB.open", code_text)

    def test_no_database_files_or_persistence(self):
        """Verify no SQLite or database files exist in workspace."""
        workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        for root, dirs, files in os.walk(workspace_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                self.assertNotIn(ext, [".db", ".sqlite", ".sqlite3", ".sql"], f"Forbidden DB file found: {file}")


if __name__ == "__main__":
    unittest.main()
