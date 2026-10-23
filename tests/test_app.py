"""
Integration Tests for SecurePass Flask Application
==================================================
Tests API endpoints, request validation, error responses, security headers,
CORS preflight, and mock integration with breach checking and strength engines.
"""

import json
import unittest
from unittest.mock import patch

from app import app
from breach_checker import BreachServiceUnavailableError


class TestFlaskApp(unittest.TestCase):

    def setUp(self):
        """Configure test client."""
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_security_headers(self):
        """Verify presence of modern security headers on responses."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("X-Content-Type-Options", res.headers)
        self.assertEqual(res.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("X-Frame-Options", res.headers)
        self.assertEqual(res.headers["X-Frame-Options"], "DENY")
        self.assertIn("Content-Security-Policy", res.headers)
        self.assertIn("Access-Control-Allow-Origin", res.headers)

    def test_cors_options_preflight(self):
        """OPTIONS preflight requests to API routes must return 204 No Content with CORS headers."""
        res = self.client.open("/api/analyze", method="OPTIONS")
        self.assertEqual(res.status_code, 204)
        self.assertEqual(res.headers.get("Access-Control-Allow-Origin"), "*")
        self.assertIn("POST", res.headers.get("Access-Control-Allow-Methods", ""))

    def test_health_check(self):
        """GET /api/health should return 200 with status ok."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "ok")

    def test_analyze_valid_password(self):
        """POST /api/analyze with valid string should return 200 and analysis results."""
        payload = {"password": "SuperSecurePassphrase2026!@#"}
        res = self.client.post("/api/analyze", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("score", data)
        self.assertIn("rating", data)
        self.assertIn("checks", data)
        self.assertIn("suggestions", data)
        self.assertIsInstance(data["score"], int)
        self.assertEqual(len(data["checks"]), 5)

    def test_analyze_missing_password_field(self):
        """POST /api/analyze missing 'password' key should return 400."""
        payload = {"other_field": "test"}
        res = self.client.post("/api/analyze", json=payload)
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["error"]["code"], "MISSING_FIELD")

    def test_analyze_invalid_json(self):
        """POST /api/analyze with invalid Content-Type or non-JSON body should return 400."""
        res = self.client.post("/api/analyze", data="plain text data", content_type="text/plain")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_analyze_invalid_password_type(self):
        """POST /api/analyze with non-string password should return 400."""
        payload = {"password": 123456}
        res = self.client.post("/api/analyze", json=payload)
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["error"]["code"], "INVALID_PASSWORD_TYPE")

    @patch("app.check_breach_prefix")
    def test_breach_check_valid_prefix(self, mock_check):
        """GET /api/breach-check with valid 5-char hex prefix should return 200."""
        mock_check.return_value = {
            "prefix": "21BD1",
            "hashes": [{"suffix": "CB04040F83E7... ", "count": 10}],
            "is_demo": False
        }
        res = self.client.get("/api/breach-check?prefix=21BD1")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["prefix"], "21BD1")
        self.assertIsInstance(data["hashes"], list)

    def test_breach_check_demo_param(self):
        """GET /api/breach-check?prefix=5BAA6&demo=1 returns labeled mock demo dataset."""
        res = self.client.get("/api/breach-check?prefix=5BAA6&demo=1")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("is_demo"))
        self.assertIn("DEMO DATA", data.get("demo_label", ""))

    def test_breach_check_missing_prefix(self):
        """GET /api/breach-check without prefix parameter should return 400."""
        res = self.client.get("/api/breach-check")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["error"]["code"], "MISSING_PREFIX")

    def test_breach_check_invalid_prefix(self):
        """GET /api/breach-check with invalid prefix should return 400."""
        res = self.client.get("/api/breach-check?prefix=xyz")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["error"]["code"], "INVALID_PREFIX")

    @patch("app.check_breach_prefix")
    def test_breach_check_upstream_error(self, mock_check):
        """GET /api/breach-check when upstream fails should return 503 error JSON."""
        mock_check.side_effect = BreachServiceUnavailableError("Service unavailable.")
        res = self.client.get("/api/breach-check?prefix=ABCDE")
        self.assertEqual(res.status_code, 503)
        data = res.get_json()
        self.assertEqual(data["error"]["code"], "BREACH_CHECK_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
