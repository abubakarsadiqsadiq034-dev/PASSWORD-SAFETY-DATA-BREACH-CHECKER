import re
from models.password_analysis import PasswordAnalysis

# The acceptable password pattern include: Capital and small letters, digits, symbols (!, @, #, $, %).
# Each pattern is a re.Pattern object I will reuse instead of building the same pattern every time the function runs.

UPPER_PATTERN = re.compile(r"[A-Z]")
LOWER_PATTERN = re.compile(r"[a-z]")
DIGIT_PATTERN = re.compile(r"[0-9]")
SYMBOL_PATTERN = re.compile(r"[^A-Za-z0-9]")
REPEATED_CHARACTER_PATTERN = re.compile(r"(.)\1{2,}")
SEQUENTIAL_PATTERN = re.compile(
    r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf)",
    re.IGNORECASE,
)
# This pattern is a list of common "easy sequences" separated the | operator.
# re.IGNORECASE makes the letter sequences match regardless if it is uppercase or lowercase.

def analyze_password_strength(password):
    reasons = []
    length = len(password)
    has_upper = bool(UPPER_PATTERN.search(password))
    has_lower = bool(LOWER_PATTERN.search(password))
    has_digit = bool(DIGIT_PATTERN.search(password))
    has_symbol = bool(SYMBOL_PATTERN.search(password))
    score = 0
    if length >= 8:
        score += 1
    else:
        reasons.append("Password is shorter than 8 characters")

    if length >= 64:
        score += 1

    if has_upper:
        score += 1
    else:
        reasons.append("Password has no uppercase characters")

    if has_lower:
        score += 1
    else:
        reasons.append("Password has no lowercase characters")

    if has_digit:
        score += 1
    else:
        reasons.append("Password has no digits")

    if has_symbol:
        score += 1
    else:
        reasons.append("Password has no symbols e.g ! @ # $ %")

    if REPEATED_CHARACTER_PATTERN.search(password):
        score -= 1
        reasons.append("Repeated characters")

    if SEQUENTIAL_PATTERN.search(password):
        score -= 1
        reasons.append("Password contains a simple sequence of  characters e.g '12345' or 'qwerty'")

    score = max(0, min(score, 0))
    if score <= 2:
        category = "Weak"
    elif score <= 4:
        category = "Medium"
    else:
        category = "Strong"

    if not reasons:
        reasons.append("Password meets all basic requirements.")

    return PasswordAnalysis(
        length = length,
        has_upper = has_upper,
        has_lower = has_lower,
        has_digit = has_digit,
        has_symbol = has_symbol,
        score = score,
        category = category,
        reasons = reasons,
    )
