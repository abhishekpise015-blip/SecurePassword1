"""
Unit Tests for SecurePass Strength Engine
=========================================
Tests scoring heuristics, sequence detection, repetition checks,
common password detection, boundaries, and type safety according
to hackathon specification requirements.
"""

import unittest
from strength_engine import analyze_password


class TestStrengthEngine(unittest.TestCase):

    def test_empty_input(self):
        """Empty string should yield score 0, rating 'Very Weak', and failed checks."""
        res = analyze_password("")
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["rating"], "Very Weak")
        self.assertEqual(res["length"], 0)
        self.assertEqual(res["entropy_bits"], 0.0)
        self.assertTrue(all(not c["passed"] for c in res["checks"]))
        self.assertGreater(len(res["suggestions"]), 0)

    def test_invalid_input_types(self):
        """Non-string or None inputs should be handled safely without exceptions."""
        for invalid in [None, 12345, ["password"], {"key": "val"}, True]:
            res = analyze_password(invalid)
            self.assertEqual(res["score"], 0)
            self.assertEqual(res["rating"], "Very Weak")
            self.assertEqual(res["length"], 0)
            self.assertTrue(isinstance(res["checks"], list))
            self.assertTrue(isinstance(res["suggestions"], list))

    def test_output_schema_keys_and_types(self):
        """Output dictionary must always have the exact required schema keys and valid types."""
        res = analyze_password("SamplePass123!@#")
        required_keys = {"score", "rating", "checks", "suggestions", "entropy_bits", "length"}
        self.assertTrue(required_keys.issubset(res.keys()))
        self.assertIsInstance(res["score"], int)
        self.assertIsInstance(res["rating"], str)
        self.assertIsInstance(res["checks"], list)
        self.assertIsInstance(res["suggestions"], list)
        self.assertIsInstance(res["entropy_bits"], (int, float))
        self.assertIsInstance(res["length"], int)

        for check in res["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("message", check)
            self.assertIsInstance(check["passed"], bool)

    def test_very_short_password(self):
        """Very short passwords (<6 chars) must receive a heavily capped score and 'Very Weak'."""
        for pwd in ["a", "12", "aB!", "1a#", "short"]:
            res = analyze_password(pwd)
            self.assertLessEqual(res["score"], 25)
            self.assertIn(res["rating"], ["Very Weak", "Weak"])

    def test_common_weak_password_123456(self):
        """Specific check: '123456' must be recognized as common weak password and heavily penalized."""
        res = analyze_password("123456")
        self.assertLessEqual(res["score"], 18)
        self.assertEqual(res["rating"], "Very Weak")
        has_common = any("common" in s.lower() or "critical" in s.lower() for s in res["suggestions"])
        self.assertTrue(has_common, "Expected suggestion warning for common password '123456'")

    def test_common_weak_password_password123(self):
        """Specific check: 'password123' must be penalized as a common weak password pattern."""
        res = analyze_password("password123")
        self.assertLessEqual(res["score"], 25)
        self.assertIn(res["rating"], ["Very Weak", "Weak"])
        has_warning = any("common" in s.lower() or "password" in s.lower() for s in res["suggestions"])
        self.assertTrue(has_warning, "Expected suggestion warning for 'password123'")

    def test_predictable_sequence_qwerty(self):
        """Specific check: 'qwerty' must be detected as a predictable keyboard walk."""
        res = analyze_password("qwerty")
        self.assertLessEqual(res["score"], 18)
        self.assertEqual(res["rating"], "Very Weak")
        has_kb = any("keyboard" in s.lower() or "qwerty" in s.lower() for s in res["suggestions"])
        self.assertTrue(has_kb, "Expected keyboard pattern suggestion for 'qwerty'")

    def test_predictable_sequence_12345678(self):
        """Specific check: '12345678' must be detected as a predictable sequence."""
        res = analyze_password("12345678")
        self.assertLessEqual(res["score"], 18)
        self.assertEqual(res["rating"], "Very Weak")
        has_seq = any("sequence" in s.lower() or "common" in s.lower() for s in res["suggestions"])
        self.assertTrue(has_seq, "Expected sequence/common warning for '12345678'")

    def test_repeated_characters_AAAAAA(self):
        """Specific check: 'AAAAAA' must trigger repetition penalty and dedicated suggestion."""
        res = analyze_password("AAAAAA")
        self.assertLessEqual(res["score"], 20)
        self.assertEqual(res["rating"], "Very Weak")
        has_rep = any("repeated" in s.lower() for s in res["suggestions"])
        self.assertTrue(has_rep, "Expected repeated character warning for 'AAAAAA'")

    def test_longer_strong_passphrase(self):
        """Long, diverse passphrases should receive high scores and 'Strong' or 'Very Strong'."""
        res = analyze_password("Correct-Horse-Battery-Staple-2026!")
        self.assertGreaterEqual(res["score"], 80)
        self.assertIn(res["rating"], ["Strong", "Very Strong"])
        self.assertTrue(res["checks"][0]["passed"])  # Length check passed

    def test_mixed_character_checklist(self):
        """Verify that all 5 checklist items reflect accurate character classes."""
        res = analyze_password("SuperSecret99!")
        checks_by_name = {c["name"]: c["passed"] for c in res["checks"]}
        self.assertTrue(checks_by_name["At least 12 characters"])
        self.assertTrue(checks_by_name["Uppercase letter (A–Z)"])
        self.assertTrue(checks_by_name["Lowercase letter (a–z)"])
        self.assertTrue(checks_by_name["Number (0–9)"])
        self.assertTrue(checks_by_name["Special character (!@#$...)" ])

    def test_suggestions_correspond_to_weaknesses(self):
        """Verify suggestions directly map to the weaknesses detected in the password."""
        # Short password lacking variety
        res_short = analyze_password("abc")
        self.assertTrue(any("length" in s.lower() for s in res_short["suggestions"]))
        self.assertTrue(any("missing" in s.lower() or "mix" in s.lower() or "add" in s.lower() for s in res_short["suggestions"]))

        # Password with sequence
        res_seq = analyze_password("MySecurePass123!")
        self.assertTrue(any("sequence" in s.lower() for s in res_seq["suggestions"]))

    def test_score_boundaries(self):
        """Score must never exceed 100 or drop below 0."""
        passwords = [
            "", "a", "123", "password", "A1!a",
            "ThisIsAnExtremelyLongComplexPassphraseWithManyUniqueCharactersAndSymbols!@#$%^&*()_+2026",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ]
        for pwd in passwords:
            res = analyze_password(pwd)
            self.assertGreaterEqual(res["score"], 0)
            self.assertLessEqual(res["score"], 100)

    def test_common_weak_examples_battery(self):
        """Test battery of common weak passwords: must receive low scores, Very Weak ratings, and actionable remediation."""
        weak_samples = [
            ("123456", "sequence"),
            ("password", "common"),
            ("password123", "common"),
            ("qwerty", "walk"),
            ("12345678", "sequence"),
            ("AAAAAA", "repeat"),
            ("admin2026!", "common"),
            ("iloveyou", "common")
        ]
        for pwd, expected_issue in weak_samples:
            res = analyze_password(pwd)
            self.assertLessEqual(res["score"], 25, f"Weak password '{pwd}' scored too high: {res['score']}")
            self.assertIn(res["rating"], ["Very Weak", "Weak"], f"Weak password '{pwd}' rating unexpected: {res['rating']}")
            # Must contain actionable suggestions
            self.assertGreater(len(res["suggestions"]), 0, f"No suggestions for '{pwd}'")
            # Verify specific weakness diagnoses
            all_sugg_text = " ".join(res["suggestions"]).lower()
            if expected_issue == "sequence":
                self.assertTrue("sequence" in all_sugg_text or "123" in all_sugg_text)
            elif expected_issue == "repeat":
                self.assertTrue("repeat" in all_sugg_text)
            elif expected_issue == "walk":
                self.assertTrue("walk" in all_sugg_text or "predictable" in all_sugg_text)

    def test_moderate_examples_battery(self):
        """Test battery of moderate passwords."""
        moderate_samples = ["BlueSky99!", "Coffee#Cup2026"]
        for pwd in moderate_samples:
            res = analyze_password(pwd)
            self.assertGreaterEqual(res["score"], 50, f"Moderate password '{pwd}' scored too low: {res['score']}")
            self.assertIn(res["rating"], ["Moderate", "Strong"])
            self.assertGreaterEqual(sum(1 for c in res["checks"] if c["passed"]), 4)

    def test_strong_examples_battery(self):
        """Test battery of strong passwords and passphrases."""
        strong_samples = [
            "Solar#Flare$Cascade88",
            "Correct-Horse-Battery-Staple-2026!",
            "W!nter_P1ne#Forest99"
        ]
        for pwd in strong_samples:
            res = analyze_password(pwd)
            self.assertGreaterEqual(res["score"], 80, f"Strong password '{pwd}' scored too low: {res['score']}")
            self.assertIn(res["rating"], ["Strong", "Very Strong"])
            # All 5 checklist items must be passed
            self.assertEqual(sum(1 for c in res["checks"] if c["passed"]), 5)
            self.assertGreaterEqual(res["entropy_bits"], 75.0)


if __name__ == "__main__":
    unittest.main()
