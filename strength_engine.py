"""
SecurePass — Password Strength Engine
=====================================
A heuristic password evaluation module for analyzing password strength,
character entropy, predictable sequences, repetition, and common weak patterns.

DISCLAIMER:
This scoring engine relies on rule-based heuristics and mathematical entropy
estimates. A high score does not guarantee that a password cannot be cracked,
compromised via phishing, intercepted by malware, or discovered through targeted
social engineering.

BLOCKLIST LIMITATIONS & SCOPE:
The curated offline blocklist contains high-frequency leaked passwords, default
credentials, and common root words (~75 entries). While it immediately catches
trivial and notorious passwords locally with zero network delay, an offline list
cannot encompass all 10+ billion historically exposed passwords. For exhaustive
breach detection, SecurePass couples this engine with the k-Anonymity HIBP range API.
"""

import math
import re
from typing import Any, Dict, List

# Common passwords blocklist (top leaked/trivial passwords, default credentials & common roots)
COMMON_WEAK_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "12345", "1234", "qwerty", "qwerty123", "qwertyuiop", "abc123", "football",
    "monkey", "letmein", "welcome", "welcome123", "dragon", "baseball", "sunshine",
    "iloveyou", "trustno1", "superman", "batman", "starwars", "princess", "shadow",
    "master", "michael", "jordan", "killer", "hunter2", "admin", "admin123",
    "administrator", "root", "guest", "default", "pass1234", "passcode", "access",
    "login", "secret", "mustang", "ninja", "charlie", "freedom", "whatever",
    "cookie", "testing", "securepass", "secure123", "asdfghjk", "zxcvbnm"
}

# Common keyboard sequences (QWERTY layout walks)
KEYBOARD_SEQUENCES = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "0987654321",
    "poiuytrewq",
    "lkjhgfdsa",
    "mnbvcxz",
    "1qaz2wsx3edc",
    "qazwsxedcrfv",
    "zaq1xsw2cde3",
    "plmoknijbuhvygctfxrdzeswaq",
]

# Character sets
LOWERCASE_CHARS = set("abcdefghijklmnopqrstuvwxyz")
UPPERCASE_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
DIGIT_CHARS = set("0123456789")
SPECIAL_CHARS = set("!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~\\")

# L33t substitutions for normalization
L33T_MAP = {
    "@": "a", "4": "a", "8": "b", "(": "c", "3": "e", "9": "g",
    "1": "i", "!": "i", "|": "l", "0": "o", "5": "s", "$": "s",
    "7": "t", "+": "t"
}


def _normalize_l33t(text: str) -> str:
    """Normalize common l33tspeak characters to lowercase Latin letters."""
    lowered = text.lower()
    return "".join(L33T_MAP.get(c, c) for c in lowered)


def _check_predictable_sequences(text: str) -> List[str]:
    """Check for alphabetical, numerical, or keyboard walk sequences."""
    lowered = text.lower()
    found = []

    # 1. Alphabetical sequences of length >= 3 (e.g., 'abc', 'cba', 'xyz')
    for i in range(len(lowered) - 2):
        chunk = lowered[i:i + 3]
        if len(chunk) == 3 and chunk.isalpha():
            diff1 = ord(chunk[1]) - ord(chunk[0])
            diff2 = ord(chunk[2]) - ord(chunk[1])
            if diff1 == 1 and diff2 == 1:
                found.append(f"Ascending alphabetical sequence detected ('{chunk}').")
                break
            elif diff1 == -1 and diff2 == -1:
                found.append(f"Descending alphabetical sequence detected ('{chunk}').")
                break

    # 2. Numerical sequences of length >= 3 (e.g., '123', '321', '789')
    for i in range(len(lowered) - 2):
        chunk = lowered[i:i + 3]
        if len(chunk) == 3 and chunk.isdigit():
            diff1 = ord(chunk[1]) - ord(chunk[0])
            diff2 = ord(chunk[2]) - ord(chunk[1])
            if diff1 == 1 and diff2 == 1:
                found.append(f"Ascending numerical sequence detected ('{chunk}').")
                break
            elif diff1 == -1 and diff2 == -1:
                found.append(f"Descending numerical sequence detected ('{chunk}').")
                break

    # 3. Keyboard walk sequences
    for seq in KEYBOARD_SEQUENCES:
        for i in range(len(seq) - 2):
            pattern = seq[i:i + 3]
            if pattern in lowered:
                found.append(f"Predictable keyboard walk pattern detected ('{pattern}').")
                break
        if found:
            break

    return found


def _check_repetitions(text: str) -> List[str]:
    """Check for identical repeated characters (e.g. 'AAAAAA') or short repeating cycles."""
    found = []
    # 3+ identical consecutive characters (e.g., 'AAAAAA', '1111')
    match = re.search(r"(.)\1{2,}", text)
    if match:
        repeated_char = match.group(1)
        found.append(f"Excessive repeated characters detected ('{repeated_char * len(match.group(0))}').")

    # Simple repeating 2-3 char blocks like 'ababab' or '121212'
    if len(text) >= 4 and re.search(r"(.{2,3})\1{2,}", text.lower()):
        found.append("Repeating cyclic character pattern detected.")

    return found


def _format_seconds(seconds: float) -> str:
    """Format duration in seconds into human-readable cybersecurity time-to-crack."""
    if seconds < 0.001:
        return "Instant (< 1 ms)"
    elif seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        mins = seconds / 60
        return f"{mins:.1f} minutes"
    elif seconds < 86400:
        hrs = seconds / 3600
        return f"{hrs:.1f} hours"
    elif seconds < 365.25 * 86400:
        days = seconds / 86400
        return f"{days:.0f} days"
    elif seconds < 1000 * 365.25 * 86400:
        years = seconds / (365.25 * 86400)
        return f"{years:.1f} years"
    elif seconds < 1_000_000 * 365.25 * 86400:
        ky = seconds / (1000 * 365.25 * 86400)
        return f"{ky:.0f} thousand years"
    elif seconds < 1_000_000_000 * 365.25 * 86400:
        my = seconds / (1_000_000 * 365.25 * 86400)
        return f"{my:.0f} million years"
    else:
        return "> 1 billion years (Immune)"


def _calculate_pool_size(password: str) -> int:
    """Calculate the active character keyspace pool size."""
    pool_size = 0
    if any(c in LOWERCASE_CHARS for c in password):
        pool_size += 26
    if any(c in UPPERCASE_CHARS for c in password):
        pool_size += 26
    if any(c in DIGIT_CHARS for c in password):
        pool_size += 10
    if any(c in SPECIAL_CHARS for c in password):
        pool_size += 33
    return pool_size or 1


def _calculate_entropy(password: str) -> float:
    """Calculate approximate keyspace entropy bits: L * log2(PoolSize)."""
    if not password:
        return 0.0

    pool_size = _calculate_pool_size(password)
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 1)


def analyze_password(password: Any) -> Dict[str, Any]:
    """
    Analyze password strength, evaluate security criteria, detect patterns,
    and return an actionable score, rating, checklist, suggestions, and cyber telemetry.
    """
    default_stats = {
        "uppercase": 0, "lowercase": 0, "digits": 0, "special": 0, "unique": 0, "unique_ratio": 0.0
    }
    default_cracks = {
        "online_throttled": "Instant (< 1 ms)",
        "offline_cpu": "Instant (< 1 ms)",
        "single_gpu": "Instant (< 1 ms)",
        "gpu_cluster": "Instant (< 1 ms)"
    }
    default_nist = {
        "min_length_passed": False,
        "recommended_length_passed": False,
        "no_common_dictionary": False,
        "no_repetitive_pattern": True,
        "no_sequential_walk": True,
        "overall_compliant": False
    }

    # 1. Input validation & type safety
    if password is None or not isinstance(password, str):
        return {
            "score": 0,
            "rating": "Very Weak",
            "checks": [
                {"name": "At least 12 characters", "passed": False, "message": "Password is empty."},
                {"name": "Uppercase letter (A–Z)", "passed": False, "message": "Missing uppercase letters."},
                {"name": "Lowercase letter (a–z)", "passed": False, "message": "Missing lowercase letters."},
                {"name": "Number (0–9)", "passed": False, "message": "Missing numerical digits."},
                {"name": "Special character (!@#$...)", "passed": False, "message": "Missing special symbols."}
            ],
            "suggestions": ["Enter a valid text password to analyze."],
            "entropy_bits": 0.0,
            "length": 0,
            "pool_size": 0,
            "combinations_display": "0",
            "crack_times": default_cracks,
            "char_stats": default_stats,
            "defcon_level": 1,
            "nist_audit": default_nist
        }

    pwd_len = len(password)

    # Empty string case
    if pwd_len == 0:
        return {
            "score": 0,
            "rating": "Very Weak",
            "checks": [
                {"name": "At least 12 characters", "passed": False, "message": "Password is empty."},
                {"name": "Uppercase letter (A–Z)", "passed": False, "message": "Missing uppercase letters."},
                {"name": "Lowercase letter (a–z)", "passed": False, "message": "Missing lowercase letters."},
                {"name": "Number (0–9)", "passed": False, "message": "Missing numerical digits."},
                {"name": "Special character (!@#$...)", "passed": False, "message": "Missing special symbols."}
            ],
            "suggestions": [
                "Enter a password with at least 12-16 characters.",
                "Combine uppercase, lowercase, numbers, and special symbols."
            ],
            "entropy_bits": 0.0,
            "length": 0,
            "pool_size": 0,
            "combinations_display": "0",
            "crack_times": default_cracks,
            "char_stats": default_stats,
            "defcon_level": 1,
            "nist_audit": default_nist
        }

    # 2. Evaluate requirements checklist
    has_min_len = pwd_len >= 12
    has_upper = any(c in UPPERCASE_CHARS for c in password)
    has_lower = any(c in LOWERCASE_CHARS for c in password)
    has_digit = any(c in DIGIT_CHARS for c in password)
    has_special = any(c in SPECIAL_CHARS for c in password)

    checks = [
        {
            "name": "At least 12 characters",
            "passed": has_min_len,
            "message": f"Length requirement met ({pwd_len} characters)." if has_min_len
            else f"Currently {pwd_len}/12 characters. Longer passwords offer higher resistance to cracking."
        },
        {
            "name": "Uppercase letter (A–Z)",
            "passed": has_upper,
            "message": "Includes uppercase character(s)." if has_upper
            else "Add at least one uppercase letter (A–Z) to broaden character space."
        },
        {
            "name": "Lowercase letter (a–z)",
            "passed": has_lower,
            "message": "Includes lowercase character(s)." if has_lower
            else "Add at least one lowercase letter (a–z)."
        },
        {
            "name": "Number (0–9)",
            "passed": has_digit,
            "message": "Includes numerical digit(s)." if has_digit
            else "Add at least one number (0–9) to resist dictionary attacks."
        },
        {
            "name": "Special character (!@#$...)",
            "passed": has_special,
            "message": "Includes special symbol(s)." if has_special
            else "Add special characters (e.g. !@#$%^&*) for maximum complexity."
        }
    ]

    # 3. Base scoring calculation
    base_score = 0
    suggestions: List[str] = []

    # Length scoring (up to 40 points)
    if pwd_len >= 20:
        base_score += 40
    elif pwd_len >= 16:
        base_score += 35
    elif pwd_len >= 12:
        base_score += 25
    elif pwd_len >= 8:
        base_score += 15
    elif pwd_len >= 5:
        base_score += 5
    else:
        base_score += 2

    # Character variety scoring (up to 35 points)
    variety_count = sum([has_lower, has_upper, has_digit, has_special])
    if variety_count == 4:
        base_score += 35
    elif variety_count == 3:
        base_score += 25
    elif variety_count == 2:
        base_score += 15
    elif variety_count == 1:
        base_score += 5

    # Unique character ratio bonus (up to 15 points)
    unique_ratio = len(set(password)) / pwd_len
    if unique_ratio > 0.8 and pwd_len >= 10:
        base_score += 15
    elif unique_ratio > 0.6 and pwd_len >= 8:
        base_score += 10
    elif unique_ratio > 0.4:
        base_score += 5

    # Entropy calculation bonus
    entropy = _calculate_entropy(password)
    if entropy >= 75:
        base_score += 10
    elif entropy >= 50:
        base_score += 5

    # 4. Pattern detection & penalties
    penalties = 0

    # Common weak passwords check (exact and substring matches, plus l33t speak normalization)
    norm_pwd = password.lower().strip()
    l33t_pwd = _normalize_l33t(password)

    is_common = False
    if norm_pwd in COMMON_WEAK_PASSWORDS or l33t_pwd in COMMON_WEAK_PASSWORDS:
        is_common = True
        suggestions.append("Critical: This password matches a well-known common weak password.")
    else:
        for common in COMMON_WEAK_PASSWORDS:
            if len(common) >= 5 and (common in norm_pwd or common in l33t_pwd):
                is_common = True
                suggestions.append(f"Warning: Contains common password pattern ('{common}').")
                break

    # Repetition penalties
    repetition_issues = _check_repetitions(password)
    if repetition_issues:
        penalties += 20
        suggestions.extend(repetition_issues)
        suggestions.append("Remediation: Break up consecutive repeated characters; replace them with distinct symbols or words.")

    # Predictable sequence penalties
    sequence_issues = _check_predictable_sequences(password)
    if sequence_issues:
        penalties += 20
        suggestions.extend(sequence_issues)
        suggestions.append("Remediation: Remove predictable sequences (e.g. '123', 'abc', 'qwerty'); cracking dictionaries test these first.")

    # Calculate final score with penalties
    final_score = base_score - penalties

    # If it is a known common weak password, cap score strictly at 18
    if is_common:
        final_score = min(final_score, 18)
        suggestions.append("Actionable tip: Replace common dictionary roots with a multi-word passphrase (e.g. 'Falcon-Sunset-Orbit-42!').")

    # Length and variety constraints
    if pwd_len < 6:
        final_score = min(final_score, 15)
    elif pwd_len < 8:
        final_score = min(final_score, 30)
    elif pwd_len < 12 and final_score > 65:
        final_score = 65

    # If only 1 character variety exists, cap at 25 regardless of length
    if variety_count <= 1:
        final_score = min(final_score, 25)

    # Guarantee score boundaries [0, 100]
    final_score = max(0, min(100, int(round(final_score))))

    # 5. Determine Rating
    if final_score >= 85:
        rating = "Very Strong"
    elif final_score >= 70:
        rating = "Strong"
    elif final_score >= 50:
        rating = "Moderate"
    elif final_score >= 25:
        rating = "Weak"
    else:
        rating = "Very Weak"

    # 6. Actionable suggestions corresponding to detected deficiencies
    if not has_min_len:
        needed = 12 - pwd_len
        suggestions.insert(0, f"Increase length by at least {needed} character{'s' if needed > 1 else ''} (target 12-16+ chars). Passphrases offer superior length with high memorability.")
    if variety_count < 3:
        missing_classes = []
        if not has_upper: missing_classes.append("uppercase (A-Z)")
        if not has_lower: missing_classes.append("lowercase (a-z)")
        if not has_digit: missing_classes.append("numbers (0-9)")
        if not has_special: missing_classes.append("special symbols")
        suggestions.append(f"Add missing character types: {', '.join(missing_classes)} to expand brute-force search space.")
    if pwd_len >= 14 and final_score >= 80 and not suggestions:
        suggestions.append("Excellent password composition. Ensure you do not reuse it across multiple accounts.")
    elif not suggestions:
        suggestions.append("Actionable tip: Consider turning your password into a memorable multi-word passphrase.")

    # Deduplicate suggestions while preserving order
    deduped_suggestions = []
    seen = set()
    for s in suggestions:
        if s not in seen:
            seen.add(s)
            deduped_suggestions.append(s)

    # 7. Cyber Field Telemetry & Crack Time Estimation
    pool_size = _calculate_pool_size(password)

    # Keyspace combinations: pool_size ^ pwd_len
    combinations = pool_size ** pwd_len
    if combinations >= 1e12:
        combinations_display = f"{combinations:.2e}".replace("+", "")
    else:
        combinations_display = f"{combinations:,}"

    # Attack simulation times
    if is_common:
        crack_times = {
            "online_throttled": "Instant (< 1 ms) — Leaked dictionary root",
            "offline_cpu": "Instant (< 1 ms) — Leaked dictionary root",
            "single_gpu": "Instant (< 1 ms) — Leaked dictionary root",
            "gpu_cluster": "Instant (< 1 ms) — Leaked dictionary root"
        }
    else:
        avg_guesses = max(1, combinations // 2)
        crack_times = {
            "online_throttled": _format_seconds(avg_guesses / 100),
            "offline_cpu": _format_seconds(avg_guesses / 100_000),
            "single_gpu": _format_seconds(avg_guesses / 10_000_000_000),
            "gpu_cluster": _format_seconds(avg_guesses / 100_000_000_000_000)
        }

    # Character distribution statistics
    char_stats = {
        "uppercase": sum(1 for c in password if c in UPPERCASE_CHARS),
        "lowercase": sum(1 for c in password if c in LOWERCASE_CHARS),
        "digits": sum(1 for c in password if c in DIGIT_CHARS),
        "special": sum(1 for c in password if c in SPECIAL_CHARS),
        "unique": len(set(password)),
        "unique_ratio": round(len(set(password)) / pwd_len, 2) if pwd_len > 0 else 0.0
    }

    # DEFCON threat condition: 1 (Critical) to 5 (Maximum)
    if final_score <= 20 or is_common:
        defcon_level = 1
    elif final_score <= 45:
        defcon_level = 2
    elif final_score <= 65:
        defcon_level = 3
    elif final_score <= 84:
        defcon_level = 4
    else:
        defcon_level = 5

    # NIST SP 800-63B Compliance Verification
    nist_audit = {
        "min_length_passed": pwd_len >= 8,
        "recommended_length_passed": pwd_len >= 12,
        "no_common_dictionary": not is_common,
        "no_repetitive_pattern": len(repetition_issues) == 0,
        "no_sequential_walk": len(sequence_issues) == 0,
        "overall_compliant": (pwd_len >= 8 and not is_common and len(repetition_issues) == 0 and len(sequence_issues) == 0)
    }

    return {
        "score": final_score,
        "rating": rating,
        "checks": checks,
        "suggestions": deduped_suggestions,
        "entropy_bits": entropy,
        "length": pwd_len,
        "pool_size": pool_size,
        "combinations_display": combinations_display,
        "crack_times": crack_times,
        "char_stats": char_stats,
        "defcon_level": defcon_level,
        "nist_audit": nist_audit
    }
