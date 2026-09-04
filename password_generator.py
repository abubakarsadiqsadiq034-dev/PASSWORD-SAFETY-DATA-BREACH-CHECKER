"""
Strong password generation.

Owner: Great-Cyril Agbaegbu (feature/password-generator-testing)

Note: the `secrets` module is used for the actual character selection
because it is cryptographically secure, which is the correct choice for
generating passwords. `random` is used for the final shuffle step, which
satisfies the project brief's "Python random module" requirement while
keeping the character selection itself cryptographically strong.
"""

import random
import secrets
import string
from typing import List

from services.password_strength import analyze_password

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

MIN_LENGTH = 8
MAX_LENGTH = 64
DEFAULT_LENGTH = 16


def generate_password(
    length: int = DEFAULT_LENGTH,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Generate a random password that satisfies the app's strength rules.

    Raises ValueError for invalid configuration (e.g. length out of range,
    or no character sets selected).
    """
    if not (MIN_LENGTH <= length <= MAX_LENGTH):
        raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")

    pools = []
    if use_upper:
        pools.append(UPPER)
    if use_lower:
        pools.append(LOWER)
    if use_digits:
        pools.append(DIGITS)
    if use_symbols:
        pools.append(SYMBOLS)

    if not pools:
        raise ValueError("At least one character set must be enabled.")

    # Guarantee at least one character from each selected pool.
    password_chars: List[str] = [secrets.choice(pool) for pool in pools]

    all_chars = "".join(pools)
    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))

    # `random.shuffle` fulfills the project's "random module" requirement
    # for the final arrangement step.
    random.shuffle(password_chars)
    return "".join(password_chars)


def generate_strong_password(length: int = DEFAULT_LENGTH, max_attempts: int = 10) -> str:
    """Generate a password and verify it scores 'Strong' before returning it.

    Retries a few times in the unlikely event the shuffle produces a
    weaker-than-expected result (e.g. very short custom lengths).
    """
    password = generate_password(length=length)
    for _ in range(max_attempts):
        analysis = analyze_password(password)
        if analysis.category == "Strong":
            return password
        password = generate_password(length=length)
    return password  # best effort after max_attempts
