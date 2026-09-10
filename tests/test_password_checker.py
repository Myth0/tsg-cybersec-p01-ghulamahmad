"""
Unit tests for password_checker.py
Covers the edge cases TSG explicitly grades under Tool Functionality:
empty input, very long input, and additionally unicode, whitespace-only,
and each individual scoring signal in isolation.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import password_checker as pc


class TestLengthCheck(unittest.TestCase):
    def test_empty_password(self):
        points, reason = pc.check_length("")
        self.assertEqual(points, 0)
        self.assertIn("empty", reason.lower())

    def test_very_long_password_does_not_crash(self):
        huge = "a" * 100_000
        points, reason = pc.check_length(huge)
        self.assertEqual(points, 70)

    def test_short_password(self):
        points, _ = pc.check_length("abc")
        self.assertEqual(points, 10)


class TestDiversityCheck(unittest.TestCase):
    def test_all_four_classes(self):
        points, reason = pc.check_diversity("Aa1!")
        self.assertEqual(points, 20)
        self.assertIn("4/4", reason)

    def test_space_not_counted_as_symbol(self):
        points, reason = pc.check_diversity("word word")
        self.assertEqual(points, 5)

    def test_unicode_letters(self):
        points, reason = pc.check_diversity("пароль密码🔒")
        self.assertIsInstance(points, int)


class TestCommonPasswordCheck(unittest.TestCase):
    def setUp(self):
        self.common = {"password", "123456", "qwerty"}

    def test_exact_match(self):
        penalty, reason = pc.check_common_password("password", self.common)
        self.assertEqual(penalty, -60)
        self.assertIsNotNone(reason)

    def test_common_word_plus_digits(self):
        penalty, reason = pc.check_common_password("password123", self.common)
        self.assertEqual(penalty, -45)

    def test_no_match(self):
        penalty, reason = pc.check_common_password("xk9mQ2vLp", self.common)
        self.assertEqual(penalty, 0)
        self.assertIsNone(reason)


class TestPatternCheck(unittest.TestCase):
    def setUp(self):
        self.common = {"password", "123456", "qwerty"}

    def test_repeated_characters(self):
        penalty, reasons = pc.check_patterns("aaabbbccc", self.common)
        self.assertLess(penalty, 0)

    def test_sequence(self):
        penalty, reasons = pc.check_patterns("abcd1234", self.common)
        self.assertLess(penalty, 0)

    def test_keyboard_walk(self):
        penalty, reasons = pc.check_patterns("qwerty99", self.common)
        self.assertLess(penalty, 0)

    def test_leetspeak_of_known_word_flagged(self):
        penalty, reasons = pc.check_patterns("p@ssw0rd", self.common)
        self.assertTrue(any("substitution" in r for r in reasons))

    def test_leetspeak_of_unknown_word_not_flagged(self):
        penalty, reasons = pc.check_patterns("xK9mQ2vLp7Rz", self.common)
        self.assertFalse(any("substitution" in r for r in reasons))

    def test_clean_password_no_penalty(self):
        penalty, reasons = pc.check_patterns("xk9mQpvLzR", self.common)
        self.assertEqual(penalty, 0)
        self.assertEqual(reasons, [])


class TestCalculateScore(unittest.TestCase):
    def setUp(self):
        self.common = pc.load_common_passwords()

    def test_empty_password_returns_invalid(self):
        result = pc.calculate_score("", self.common)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["rating"], "Invalid")

    def test_score_never_negative(self):
        result = pc.calculate_score("aaa111", self.common)
        self.assertGreaterEqual(result["score"], 0)

    def test_score_never_exceeds_100(self):
        result = pc.calculate_score("x" * 200, self.common)
        self.assertLessEqual(result["score"], 100)

    def test_very_long_password_does_not_crash(self):
        huge = "correct horse battery staple " * 50
        result = pc.calculate_score(huge, self.common)
        self.assertIsInstance(result["score"], int)

    def test_unicode_password_does_not_crash(self):
        result = pc.calculate_score("пароль密码🔒テスト", self.common)
        self.assertIsInstance(result["score"], int)

    def test_whitespace_only_password(self):
        result = pc.calculate_score("        ", self.common)
        self.assertIsInstance(result["score"], int)

    def test_strong_passphrase_rated_strong(self):
        result = pc.calculate_score("correct horse battery staple purple", self.common)
        self.assertEqual(result["rating"], "Strong")

    def test_known_weak_password_rated_very_weak_or_weak(self):
        result = pc.calculate_score("password123", self.common)
        self.assertIn(result["rating"], ["Very Weak", "Weak"])


class TestFeedback(unittest.TestCase):
    def setUp(self):
        self.common = pc.load_common_passwords()

    def test_short_password_gets_length_feedback(self):
        result = pc.calculate_score("abc123", self.common)
        feedback = pc.get_feedback("abc123", result)
        self.assertTrue(any("length" in f.lower() for f in feedback))

    def test_strong_password_gets_positive_feedback(self):
        result = pc.calculate_score("correct horse battery staple purple", self.common)
        feedback = pc.get_feedback("correct horse battery staple purple", result)
        self.assertTrue(len(feedback) >= 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
