"""
SecurePass — Breach Risk Checker
================================
Queries the official Have I Been Pwned (HIBP) Pwned Passwords range API
using k-Anonymity privacy architecture.

Security & Privacy Guarantees:
- Only a 5-character hexadecimal SHA-1 prefix is ever processed by this module.
- Full passwords or full hashes are NEVER transmitted, logged, or persisted.
- SHA-1 is utilized strictly for protocol compatibility with the HIBP range API,
  not for password storage.
- Never fabricates results or claims a password is safe upon network failure.
- If an offline mock dataset is requested for isolated demonstrations, it is
  explicitly labeled as "DEMO DATA — NOT A REAL BREACH CHECK".
"""

import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "SecurePass-Hackathon-Project/1.0 (Cybersecurity Education; +https://github.com/SecurePass)"
TIMEOUT_SECONDS = 5.0
PREFIX_REGEX = re.compile(r"^[0-9A-Fa-f]{5}$")

# Static demo fixture dataset strictly isolated for offline/airplane-mode demonstrations
DEMO_MOCK_DATASET: Dict[str, List[Dict[str, Any]]] = {
    "5BAA6": [
        {"suffix": "1E4C9B93F3F0682250B6CF8331B7EE68FD8", "count": 52372427},  # 'password'
        {"suffix": "0018A45C4D6372E66E0B14AE9E7F64F1429", "count": 14},
        {"suffix": "0123456789ABCDEF0123456789ABCDEF012", "count": 42}
    ],
    "7C4A8": [
        {"suffix": "D09CA3762AF61E59520943DC26494F8941B", "count": 18234091},  # '123456'
        {"suffix": "00D4F6E8FA6ECC35023F4EE41D3D7D105E3", "count": 8}
    ],
    "B1B37": [
        {"suffix": "73A467DEE1EC01140F0BEF279ACCFE241EE", "count": 4812392},   # 'qwerty'
        {"suffix": "FAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAF", "count": 1}
    ]
}


class BreachCheckerError(Exception):
    """Base exception for breach checking errors."""
    def __init__(self, code: str, message: str, status_code: int = 500):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class InvalidPrefixError(BreachCheckerError):
    """Raised when the prefix is not a valid 5-character hex string."""
    def __init__(self, message: str = "Invalid prefix. Expected 5 hexadecimal characters."):
        super().__init__(code="INVALID_PREFIX", message=message, status_code=400)


class BreachServiceUnavailableError(BreachCheckerError):
    """Raised when the upstream HIBP API cannot be reached or returns an error."""
    def __init__(self, message: str = "The breach checking service is temporarily unavailable."):
        super().__init__(code="BREACH_CHECK_UNAVAILABLE", message=message, status_code=503)


class BreachServiceTimeoutError(BreachCheckerError):
    """Raised when the upstream HIBP API times out."""
    def __init__(self, message: str = "Breach check request timed out."):
        super().__init__(code="BREACH_CHECK_TIMEOUT", message=message, status_code=504)


def validate_prefix(prefix: Any) -> str:
    """
    Validate that the provided prefix is exactly 5 hexadecimal characters.
    Returns normalized uppercase prefix.
    """
    if not isinstance(prefix, str) or not PREFIX_REGEX.match(prefix):
        raise InvalidPrefixError()
    return prefix.upper()


def parse_hibp_response(response_text: str) -> List[Dict[str, Any]]:
    """
    Parse the HIBP range text response into structured hash records.
    HIBP response format:
    0018A45C4D6372E66E0B14AE9E7F64F1429:2
    00D4F6E8FA6ECC35023F4EE41D3D7D105E3:1
    """
    results: List[Dict[str, Any]] = []
    for line in response_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) == 2:
            suffix = parts[0].strip().upper()
            try:
                count = int(parts[1].strip())
            except ValueError:
                count = 0
            results.append({"suffix": suffix, "count": count})
    return results


def check_breach_prefix(prefix: str, timeout: float = TIMEOUT_SECONDS, demo_mode: bool = False) -> Dict[str, Any]:
    """
    Query HIBP range API for the given 5-character prefix and return the list
    of matching suffixes and their breach counts.

    If demo_mode is True (or env SECUREPASS_DEMO_MODE=1), returns an explicitly
    labeled mock dataset for offline demonstrations without contacting external APIs.

    Returns:
    {
        "prefix": "ABCDE",
        "hashes": [{"suffix": "...", "count": 42}, ...],
        "is_demo": bool,
        "demo_label": str (only present if is_demo is True)
    }
    """
    normalized_prefix = validate_prefix(prefix)

    # Check if explicit demo mode is requested
    is_env_demo = os.environ.get("SECUREPASS_DEMO_MODE", "").strip().lower() in ("1", "true", "yes")
    if demo_mode or is_env_demo:
        mock_hashes = DEMO_MOCK_DATASET.get(normalized_prefix, [])
        return {
            "prefix": normalized_prefix,
            "hashes": mock_hashes,
            "is_demo": True,
            "demo_label": "DEMO DATA — NOT A REAL BREACH CHECK"
        }

    # Live HIBP Pwned Passwords range API request
    url = HIBP_RANGE_URL.format(prefix=normalized_prefix)
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain",
            "Add-Padding": "true"  # Privacy protection recommended by Troy Hunt
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise BreachServiceUnavailableError(
                    f"Upstream breach service returned status {response.status}."
                )
            content = response.read().decode("utf-8", errors="ignore")
            hashes = parse_hibp_response(content)
            return {
                "prefix": normalized_prefix,
                "hashes": hashes,
                "is_demo": False
            }

    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise BreachServiceUnavailableError("Breach check rate limit exceeded. Please try again shortly.")
        raise BreachServiceUnavailableError(f"Breach check service error (HTTP {e.code}).")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        if "timed out" in str(e).lower():
            raise BreachServiceTimeoutError()
        raise BreachServiceUnavailableError("Could not connect to the breach intelligence network.")
    except Exception as e:
        if isinstance(e, BreachCheckerError):
            raise
        raise BreachServiceUnavailableError("Unexpected error during breach verification.")
