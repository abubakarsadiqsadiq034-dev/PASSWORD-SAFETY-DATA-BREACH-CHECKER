"""
Privacy-safe data-breach checking using the k-anonymity model
popularized by the "Have I Been Pwned" Pwned Passwords API.

Owner: Richard Odey (feature/breach-checker)

How it stays privacy-safe:
    1. The password is hashed locally with SHA-1 (never sent as plaintext).
    2. Only the FIRST 5 characters of the hash ("prefix") are sent to the
       breach-checking service.
    3. The service returns all known hash SUFFIXES that share that prefix.
    4. We check locally whether our password's suffix is in that list.
The full password and full hash never leave this machine.
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

import requests

PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT_SECONDS = 6


@dataclass
class BreachResult:
    """Outcome of a privacy-safe breach check."""
    checked: bool           # whether the check completed successfully
    breached: bool = False  # whether the password was found in a breach
    times_seen: int = 0     # how many times it appeared, if known
    error: Optional[str] = None


def _sha1_hex(password: str) -> str:
    """Return the uppercase SHA-1 hex digest of the password."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password_breach(password: str) -> BreachResult:
    """Check whether a password appears in known data breaches.

    Only a 5-character hash prefix is ever transmitted over the network.
    """
    if not password:
        return BreachResult(checked=False, error="No password provided.")

    sha1 = _sha1_hex(password)
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            PWNED_PASSWORDS_API.format(prefix=prefix),
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers={"Add-Padding": "true"},  # asks the API to pad the response
        )
        response.raise_for_status()
    except requests.exceptions.Timeout:
        return BreachResult(checked=False, error="Breach-checking service timed out.")
    except requests.exceptions.ConnectionError:
        return BreachResult(checked=False, error="Could not reach breach-checking service.")
    except requests.exceptions.RequestException as exc:
        return BreachResult(checked=False, error=f"Breach-checking request failed: {exc}")

    try:
        for line in response.text.splitlines():
            if ":" not in line:
                continue
            returned_suffix, count_str = line.split(":", 1)
            if returned_suffix.strip() == suffix:
                return BreachResult(checked=True, breached=True, times_seen=int(count_str.strip()))
    except (ValueError, AttributeError) as exc:
        return BreachResult(checked=False, error=f"Could not parse breach service response: {exc}")

    return BreachResult(checked=True, breached=False, times_seen=0)
