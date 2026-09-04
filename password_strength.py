"""
Password strength analysis using rule-based checks and regular expressions.

Owner: Gospel Morris (feature/password-strength)
"""

import re
from typing import List, Tuple

from models.password_analysis import PasswordAnalysis

# --- Regex patterns -------------------------------------------------------
UPPER_RE = re.compile(r"[A-Z]")
LOWER_RE = re.compile(r"[a-z]")
DIGIT_RE = re.compile(r"\d")
SYMBOL_RE = re.compile(r"[^\w\s]")
REPEATED_CHAR_RE = re.compile(r"(.)\1{2,}")          # e.g. "aaa", "111"
SIMPLE_SEQUENCE_RE = re.compile(
    r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf)",
    re.IGNORECASE,
)

MIN_RECOMMENDED_LENGTH = 12


def _length_score(length: int) -> int:
    """Score contribution from password length (max 40 points)."""
    if length >= 16:
        return 40
    if length >= MIN_RECOMMENDED_LENGTH:
        return 30
    if length >= 8:
        return 15
    return 0


def _variety_score(has_upper: bool, has_lower: bool, has_digit: bool, has_symbol: bool) -> int:
    """Score contribution from character variety (max 40 points, 10 each)."""
    return 10 * sum([has_upper, has_lower, has_digit, has_symbol])


def _pattern_penalty(password: str) -> Tuple[int, List[str]]:
    """Detect weak patterns and return a penalty plus explanations."""
    penalty = 0
    reasons: List[str] = []

    if REPEATED_CHAR_RE.search(password):
        penalty += 15
        reasons.append("Contains a repeated character run (e.g. 'aaa').")

    if SIMPLE_SEQUENCE_RE.search(password):
        penalty += 15
        reasons.append("Contains a common simple sequence (e.g. '1234', 'qwer').")

    return penalty, reasons


def analyze_password(password: str) -> PasswordAnalysis:
    """Analyze a password's strength and return a PasswordAnalysis.

    This function only reads the password in memory to compute a score;
    it never writes the raw password anywhere.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)
    has_upper = bool(UPPER_RE.search(password))
    has_lower = bool(LOWER_RE.search(password))
    has_digit = bool(DIGIT_RE.search(password))
    has_symbol = bool(SYMBOL_RE.search(password))

    reasons: List[str] = []

    if length == 0:
        return PasswordAnalysis(
            length=0, has_upper=False, has_lower=False, has_digit=False,
            has_symbol=False, score=0, category="Weak",
            reasons=["Password is empty."],
        )

    score = _length_score(length) + _variety_score(has_upper, has_lower, has_digit, has_symbol)
    penalty, pattern_reasons = _pattern_penalty(password)
    score = max(0, min(100, score - penalty))
    reasons.extend(pattern_reasons)

    if length < 8:
        reasons.append("Password is shorter than 8 characters.")
    elif length < MIN_RECOMMENDED_LENGTH:
        reasons.append(f"Consider using at least {MIN_RECOMMENDED_LENGTH} characters.")

    if not has_upper:
        reasons.append("Missing uppercase letters.")
    if not has_lower:
        reasons.append("Missing lowercase letters.")
    if not has_digit:
        reasons.append("Missing digits.")
    if not has_symbol:
        reasons.append("Missing symbols/punctuation.")

    if score >= 75:
        category = "Strong"
    elif score >= 45:
        category = "Medium"
    else:
        category = "Weak"

    if not reasons:
        reasons.append("Meets all basic strength checks.")

    return PasswordAnalysis(
        length=length,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_symbol=has_symbol,
        score=score,
        category=category,
        reasons=reasons,
    )
