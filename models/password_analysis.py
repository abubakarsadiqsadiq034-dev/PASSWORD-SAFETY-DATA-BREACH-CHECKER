from dataclasses import dataclass, field
from typing import List


@dataclass
class PasswordAnalysis:
    """Structured result of a password-strength analysis.

    The raw password is never stored in this model.
    """

    length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool
    score: int
    category: str
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert the analysis into a JSON-safe dictionary."""
        return {
            "length": self.length,
            "has_upper": self.has_upper,
            "has_lower": self.has_lower,
            "has_digit": self.has_digit,
            "has_symbol": self.has_symbol,
            "score": self.score,
            "category": self.category,
            "reasons": list(self.reasons),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordAnalysis":
        """Rebuild a PasswordAnalysis from a dictionary."""
        return cls(
            length=data.get("length", 0),
            has_upper=data.get("has_upper", False),
            has_lower=data.get("has_lower", False),
            has_digit=data.get("has_digit", False),
            has_symbol=data.get("has_symbol", False),
            score=data.get("score", 0),
            category=data.get("category", "Unknown"),
            reasons=data.get("reasons", []),
        )

    def is_strong(self) -> bool:
        """Return True when the password is classified as Strong."""
        return self.category.lower() == "strong"