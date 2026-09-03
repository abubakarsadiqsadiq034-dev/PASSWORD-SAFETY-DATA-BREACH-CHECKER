from models.password_analysis import PasswordAnalysis
from models.security_report import SecurityReport


analysis = PasswordAnalysis(
    score=5,
    strength="Strong",
    findings=[
        "Password has uppercase letters",
        "Password has lowercase letters",
        "Password contains numbers",
        "Password contains symbols"
    ],
    recommendations=[
        "Avoid reusing this password on other accounts."
    ]
)

print("PASSWORD ANALYSIS")
print(analysis.to_dict())
print("Is strong:", analysis.is_strong())


report = SecurityReport(
    analysis=analysis,
    breach_found=False,
    account_label="Test Account"
)

print("\nSECURITY REPORT")
print(report.to_dict())

print("\nSUMMARY")
print(report.get_summary())