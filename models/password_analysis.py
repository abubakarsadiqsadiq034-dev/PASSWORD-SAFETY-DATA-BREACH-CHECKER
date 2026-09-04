class PasswordAnalysis:
    def __init__(
        self,
        score=0,
        strength="Unknown",
        findings=None,
        recommendations=None
    ):
        self.score = score
        self.strength = strength
        self.findings = findings or []
        self.recommendations = recommendations or []

    def to_dict(self):
        return {
            "score": self.score,
            "strength": self.strength,
            "findings": self.findings,
            "recommendations": self.recommendations
        }

    def is_strong(self):
        return self.strength.lower() == "strong"