from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from .password_analysis import PasswordAnalysis


@dataclass
class SecurityReport:
    """Structured security report for an analyzed password.

    The raw password is never stored in this model.
    """

    account_label: str
    analysis: PasswordAnalysis
    breached: Optional[bool] = None
    breach_count: Optional[int] = None
    ai_summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict:
        """Convert the report into a JSON-safe dictionary."""
        return {
            "account_label": self.account_label,
            "analysis": self.analysis.to_dict(),
            "breached": self.breached,
            "breach_count": self.breach_count,
            "ai_summary": self.ai_summary,
            "recommendations": list(self.recommendations),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SecurityReport":
        """Rebuild a SecurityReport from a dictionary."""
        return cls(
            account_label=data.get("account_label", "Unlabeled account"),
            analysis=PasswordAnalysis.from_dict(data.get("analysis", {})),
            breached=data.get("breached"),
            breach_count=data.get("breach_count"),
            ai_summary=data.get("ai_summary", ""),
            recommendations=data.get("recommendations", []),
            timestamp=data.get(
                "timestamp",
                datetime.now().isoformat(timespec="seconds"),
            ),
        )