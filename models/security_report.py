from datetime import datetime


class SecurityReport:
    def __init__(
        self,
        analysis,
        breach_found=False,
        account_label="Unknown",
        created_at=None
    ):
        self.analysis = analysis
        self.breach_found = breach_found
        self.account_label = account_label
        self.created_at = created_at or datetime.now().isoformat()

    def to_dict(self):
        return {
            "account_label": self.account_label,
            "analysis": self.analysis.to_dict(),
            "breach_found": self.breach_found,
            "created_at": self.created_at
        }

    def get_summary(self):
        if self.breach_found:
            breach_status = "Password may have appeared in a known data breach."
        else:
            breach_status = "No matching breach was found."

        return (
            f"Password strength: {self.analysis.strength}. "
            f"Score: {self.analysis.score}. "
            f"{breach_status}"
        )