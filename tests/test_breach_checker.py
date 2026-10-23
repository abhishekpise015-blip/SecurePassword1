"""
Unit Tests for SecurePass Breach Checker
========================================
Tests prefix validation, response parsing, error handling, timeouts,
mocked upstream communication with the HIBP range API, and labeled demo dataset.
"""

import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from breach_checker import (
    BreachServiceTimeoutError,
    BreachServiceUnavailableError,
    InvalidPrefixError,
    check_breach_prefix,
    parse_hibp_response,
    validate_prefix,
)


class TestBreachChecker(unittest.TestCase):

    def test_validate_prefix_valid(self):
        """Valid 5-character hex strings should normalize to uppercase."""
        self.assertEqual(validate_prefix("abcde"), "ABCDE")
        self.assertEqual(validate_prefix("12345"), "12345")
        self.assertEqual(validate_prefix("0A1B2"), "0A1B2")
        self.assertEqual(validate_prefix("fffff"), "FFFFF")

    def test_validate_prefix_invalid(self):
        """Invalid prefixes should raise InvalidPrefixError."""
        invalid_cases = [
            "", "1234", "123456", "ABCDE1", "GHIJK", "1234Z",
            None, 12345, ["ABCDE"], "ABC DE"
        ]
        for invalid in invalid_cases:
            with self.assertRaises(InvalidPrefixError):
                validate_prefix(invalid)

    def test_validate_prefix_rejects_full_hash_and_raw_passwords(self):
        """Reject full 40-char SHA-1 hashes and raw passwords from reaching range query."""
        full_hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        raw_password = "MySecretPassword123!"
        with self.assertRaises(InvalidPrefixError):
            validate_prefix(full_hash)
        with self.assertRaises(InvalidPrefixError):
            validate_prefix(raw_password)

    def test_parse_hibp_response_valid(self):
        """Correctly parse lines of SUFFIX:COUNT format."""
        raw_data = (
            "0018A45C4D6372E66E0B14AE9E7F64F1429:2\r\n"
            "00D4F6E8FA6ECC35023F4EE41D3D7D105E3:1\r\n"
            "0123456789ABCDEF0123456789ABCDEF012:42\r\n"
        )
        parsed = parse_hibp_response(raw_data)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0]["suffix"], "0018A45C4D6372E66E0B14AE9E7F64F1429")
        self.assertEqual(parsed[0]["count"], 2)
        self.assertEqual(parsed[2]["count"], 42)

    def test_parse_hibp_response_malformed(self):
        """Malformed lines should be handled gracefully without crashing."""
        raw_data = "GARBAGE_LINE\r\nSUFFIX_ONLY:\r\n:COUNT_ONLY\r\nVALID_SUFFIX:10\r\n"
        parsed = parse_hibp_response(raw_data)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[-1]["count"], 10)

    @patch("urllib.request.urlopen")
    def test_check_breach_prefix_success_matching_suffix(self, mock_urlopen):
        """Simulate successful upstream HIBP range response containing a matching suffix."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = (
            b"0018A45C4D6372E66E0B14AE9E7F64F1429:5\r\n"
            b"FEEDBEEFFEEDBEEFFEEDBEEFFEEDBEEFFEE:100\r\n"
        )
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = check_breach_prefix("ABCDE")
        self.assertEqual(res["prefix"], "ABCDE")
        self.assertEqual(len(res["hashes"]), 2)
        self.assertFalse(res.get("is_demo", False))
        self.assertEqual(res["hashes"][0]["suffix"], "0018A45C4D6372E66E0B14AE9E7F64F1429")
        self.assertEqual(res["hashes"][0]["count"], 5)

    @patch("urllib.request.urlopen")
    def test_check_breach_prefix_no_match(self, mock_urlopen):
        """Simulate upstream response where the specific target suffix is not present."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"AAAAAA4D6372E66E0B14AE9E7F64F1429:1\r\n"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = check_breach_prefix("12345")
        # Target suffix is not in returned list
        matching = [h for h in res["hashes"] if h["suffix"] == "NONEXISTENT_SUFFIX_12345"]
        self.assertEqual(len(matching), 0)

    @patch("urllib.request.urlopen")
    def test_check_breach_prefix_timeout(self, mock_urlopen):
        """Simulate network timeout when connecting to HIBP."""
        mock_urlopen.side_effect = TimeoutError("Connection timed out")
        with self.assertRaises(BreachServiceTimeoutError):
            check_breach_prefix("ABCDE")

    @patch("urllib.request.urlopen")
    def test_check_breach_prefix_http_error(self, mock_urlopen):
        """Simulate HTTP 503 or 429 upstream error."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.pwnedpasswords.com/range/ABCDE",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=None
        )
        with self.assertRaises(BreachServiceUnavailableError):
            check_breach_prefix("ABCDE")

    def test_demo_mode_dataset_labeling(self):
        """Demo mode returns local mock fixture explicitly labeled with disclaimer."""
        res = check_breach_prefix("5BAA6", demo_mode=True)
        self.assertTrue(res["is_demo"])
        self.assertIn("DEMO DATA", res["demo_label"])
        self.assertGreater(len(res["hashes"]), 0)


if __name__ == "__main__":
    unittest.main()
