"""
End-to-End Verification Test Script
===================================
Simulates the complete frontend-to-backend user flow against the live server:
- Health check
- Security headers
- Strength analysis across weak, patterned, and strong credentials
- HIBP breach check using 5-character prefix (k-Anonymity)
- Verify suffix matching for known breached password
- Verify suffix non-matching for unbreached password
"""

import hashlib
import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from werkzeug.serving import make_server

from app import app

BASE_URL = "http://127.0.0.1:5000"


class TestLiveIntegration(unittest.TestCase):
    _server = None
    _server_thread = None

    @classmethod
    def setUpClass(cls):
        """Ensure the test server is responding before running live tests."""
        try:
            with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=0.5):
                return
        except Exception:
            pass

        cls._server = make_server("127.0.0.1", 5000, app)
        cls._server_thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._server_thread.start()

        for _ in range(50):
            try:
                with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=0.2):
                    break
            except Exception:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        """Shut down the background test server if started by this class."""
        if cls._server:
            cls._server.shutdown()
            cls._server = None

    def test_live_health_endpoint(self):
        """Live server responds to /api/health with status ok."""
        req = urllib.request.Request(f"{BASE_URL}/api/health")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data.get("status"), "ok")

    def test_live_security_headers(self):
        """Live server returns strict security headers."""
        req = urllib.request.Request(BASE_URL)
        with urllib.request.urlopen(req) as resp:
            headers = dict(resp.headers)
            self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(headers.get("X-Frame-Options"), "DENY")
            self.assertIn("Content-Security-Policy", headers)

    def test_live_analyze_weak_password(self):
        """Analyze common weak password 'password123'."""
        payload = json.dumps({"password": "password123"}).encode()
        req = urllib.request.Request(
            f"{BASE_URL}/api/analyze",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertLessEqual(data["score"], 25)
            self.assertIn(data["rating"], ["Very Weak", "Weak"])
            self.assertEqual(len(data["checks"]), 5)
            self.assertGreater(len(data["suggestions"]), 0)

    def test_live_analyze_strong_passphrase(self):
        """Analyze high-strength passphrase."""
        payload = json.dumps({"password": "Correct-Horse-Battery-Staple-2026!"}).encode()
        req = urllib.request.Request(
            f"{BASE_URL}/api/analyze",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertGreaterEqual(data["score"], 80)
            self.assertIn(data["rating"], ["Strong", "Very Strong"])
            # All 5 checklist items must be passed
            self.assertTrue(all(c["passed"] for c in data["checks"]))

    def test_live_breach_check_known_password(self):
        """Verify k-Anonymity flow for known breached password 'password'."""
        pwd = "password"
        sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        req = urllib.request.Request(f"{BASE_URL}/api/breach-check?prefix={prefix}")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["prefix"], prefix)
            matches = [h for h in data["hashes"] if h["suffix"] == suffix]
            self.assertEqual(len(matches), 1)
            self.assertGreater(matches[0]["count"], 10_000_000)

    def test_live_breach_check_unbreached_password(self):
        """Verify k-Anonymity flow for an unbreached high-entropy password."""
        pwd = "zX9#qL!2pM$7wK@vSecure2026Unbreached"
        sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        req = urllib.request.Request(f"{BASE_URL}/api/breach-check?prefix={prefix}")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            matches = [h for h in data["hashes"] if h["suffix"] == suffix]
            self.assertEqual(len(matches), 0)

    def test_live_breach_invalid_prefix(self):
        """Live server rejects invalid prefix with 400."""
        req = urllib.request.Request(f"{BASE_URL}/api/breach-check?prefix=123")
        try:
            urllib.request.urlopen(req)
            self.fail("Expected HTTP 400 for invalid prefix")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            data = json.loads(e.read().decode())
            self.assertEqual(data["error"]["code"], "INVALID_PREFIX")


if __name__ == "__main__":
    unittest.main()
