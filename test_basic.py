"""
Basic tests and edge-case checks for the Password Safety & Data-Breach Checker.

Owner: Great-Cyril Agbaegbu (feature/password-generator-testing)

Run with: python -m pytest tests/
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from password_generator import generate_password, generate_strong_password
from password_strength import analyze_password


def test_empty_password_is_weak():
    result = analyze_password("")
    assert result.category == "Weak"
    assert result.score == 0


def test_very_short_password_is_weak():
    result = analyze_password("ab1")
    assert result.category == "Weak"


def test_strong_password_scores_high():
    result = analyze_password("Tr0ub4dor&Correct-Horse!")
    assert result.category in ("Medium", "Strong")


def test_repeated_characters_detected():
    result = analyze_password("aaaaaaaa1A!")
    assert any("repeated" in reason.lower() for reason in result.reasons)


def test_generate_password_default_length():
    pw = generate_password()
    assert len(pw) == 16


def test_generate_password_invalid_length_raises():
    try:
        generate_password(length=2)
        assert False, "Expected ValueError for too-short length"
    except ValueError:
        pass


def test_generate_password_no_charsets_raises():
    try:
        generate_password(use_upper=False, use_lower=False, use_digits=False, use_symbols=False)
        assert False, "Expected ValueError for no character sets"
    except ValueError:
        pass


def test_generate_strong_password_is_strong():
    pw = generate_strong_password(length=16)
    result = analyze_password(pw)
    assert result.category == "Strong"


if __name__ == "__main__":
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    passed = 0
    for test in tests:
        test()
        passed += 1
        print(f"PASSED: {test.__name__}")
    print(f"\n{passed}/{len(tests)} tests passed.")
