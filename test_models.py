from models.password_analysis import PasswordAnalysis
from models.security_report import SecurityReport


def test_password_analysis_model():
    analysis = PasswordAnalysis(
        length=16,
        has_upper=True,
        has_lower=True,
        has_digit=True,
        has_symbol=True,
        score=100,
        category="Strong",
        reasons=["Meets all basic strength checks."],
    )

    data = analysis.to_dict()

    assert data["length"] == 16
    assert data["score"] == 100
    assert data["category"] == "Strong"
    assert analysis.is_strong() is True


def test_security_report_model():
    analysis = PasswordAnalysis(
        length=16,
        has_upper=True,
        has_lower=True,
        has_digit=True,
        has_symbol=True,
        score=100,
        category="Strong",
        reasons=[],
    )

    report = SecurityReport(
        account_label="Test Account",
        analysis=analysis,
        breached=False,
        breach_count=0,
        ai_summary="Password appears strong.",
        recommendations=["Do not reuse passwords."],
    )

    data = report.to_dict()

    assert data["account_label"] == "Test Account"
    assert data["breached"] is False
    assert data["breach_count"] == 0
    assert data["analysis"]["category"] == "Strong"
    assert "timestamp" in data


def test_security_report_round_trip():
    analysis = PasswordAnalysis(
        length=12,
        has_upper=True,
        has_lower=True,
        has_digit=True,
        has_symbol=True,
        score=80,
        category="Strong",
        reasons=[],
    )

    report = SecurityReport(
        account_label="Example Account",
        analysis=analysis,
        breached=True,
        breach_count=5,
    )

    restored = SecurityReport.from_dict(report.to_dict())

    assert restored.account_label == "Example Account"
    assert restored.analysis.score == 80
    assert restored.analysis.category == "Strong"
    assert restored.breached is True
    assert restored.breach_count == 5