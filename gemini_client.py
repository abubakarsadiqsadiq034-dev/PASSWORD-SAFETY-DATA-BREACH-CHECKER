"""
Gemini AI integration for beginner-friendly password risk explanations
and security recommendations.

Owner: Ikedichi Anozie (feature/gemini-ai)

Only SAFE SUMMARY DATA (strength category, score, breach status) is ever
sent to the AI - never the raw password.
"""

import os
import re
from typing import List, Optional

try:
    import google.generativeai as genai
except ImportError:  # library not installed yet - handled gracefully
    genai = None

MODEL_NAME = "gemini-1.5-flash"

_CLEANUP_RE = re.compile(r"[*_`]{1,3}")  # strips stray markdown emphasis chars


class GeminiClientError(Exception):
    """Raised when the Gemini client cannot be used or a call fails."""


def _get_model():
    """Configure and return a Gemini GenerativeModel instance.

    Reads the API key from the GEMINI_API_KEY environment variable.
    Raises GeminiClientError if the SDK isn't installed or the key is missing.
    """
    if genai is None:
        raise GeminiClientError(
            "google-generativeai is not installed. Run: pip install google-generativeai"
        )

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise GeminiClientError("GEMINI_API_KEY environment variable is not set.")

    genai.configure(api_key=api_key)
    return genai.GenerativeModel(MODEL_NAME)


def _clean_text(text: str) -> str:
    """Remove stray markdown characters from generated text."""
    return _CLEANUP_RE.sub("", text).strip()


def explain_password_risk(
    category: str,
    score: int,
    reasons: List[str],
    breached: Optional[bool] = None,
) -> str:
    """Ask Gemini to explain, in simple language, why a password scored
    the way it did. Only the score/category/reasons/breach flag are sent -
    never the password itself.
    """
    prompt = (
        "You are a friendly security assistant. Explain the following "
        "password strength result to a beginner in 2-3 short sentences, "
        "in plain, non-technical language. Do not ask for or reference "
        "the actual password.\n\n"
        f"Strength category: {category}\n"
        f"Score: {score}/100\n"
        f"Reasons: {'; '.join(reasons) if reasons else 'None given'}\n"
        f"Found in a known breach: {breached if breached is not None else 'unknown'}\n"
    )

    try:
        model = _get_model()
        response = model.generate_content(prompt)
        return _clean_text(response.text or "")
    except GeminiClientError:
        raise
    except Exception as exc:  # network/API errors from the SDK
        raise GeminiClientError(f"Gemini request failed: {exc}") from exc


def suggest_stronger_password_advice(category: str, score: int) -> str:
    """Ask Gemini for general, non-specific advice on building stronger,
    memorable passwords (not a literal password suggestion tied to theirs).
    """
    prompt = (
        "Give a beginner 2-3 short, practical tips for creating a strong "
        "but memorable password, written simply. The user's current "
        f"password strength category is '{category}' with score {score}/100. "
        "Do not invent or guess their actual password."
    )

    try:
        model = _get_model()
        response = model.generate_content(prompt)
        return _clean_text(response.text or "")
    except GeminiClientError:
        raise
    except Exception as exc:
        raise GeminiClientError(f"Gemini request failed: {exc}") from exc


def general_security_advice() -> str:
    """Ask Gemini for general advice about password reuse and account safety."""
    prompt = (
        "Give 3 short, beginner-friendly bullet points of general advice "
        "about avoiding password reuse and keeping online accounts safe."
    )

    try:
        model = _get_model()
        response = model.generate_content(prompt)
        return _clean_text(response.text or "")
    except GeminiClientError:
        raise
    except Exception as exc:
        raise GeminiClientError(f"Gemini request failed: {exc}") from exc
