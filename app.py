"""
Streamlit user interface for the Password Safety & Data-Breach Checker.

UI integration:
- Home
- Password Check
- Password Generator
- Security Report

This version is integrated with the current repository's root-level modules.
"""

import streamlit as st

from models.security_report import SecurityReport
from breach_checker import check_password_breach
from gemini_client import (
    GeminiClientError,
    explain_password_risk,
    general_security_advice,
)
from password_generator import generate_strong_password
from password_strength import analyze_password
from file_manager import append_report, load_reports


st.set_page_config(
    page_title="Password Safety & Data-Breach Checker",
    page_icon="🔒",
)


def render_home() -> None:
    st.title("🔒 Password Safety & Data-Breach Checker")
    st.write(
        "This tool helps you understand how strong a password is and "
        "whether it may have appeared in a known data breach — without "
        "ever sending or storing your full password."
    )

    st.subheader("How your privacy is protected")
    st.markdown(
        "- Breach checking uses a k-anonymity method: only a 5-character "
        "hash prefix is ever sent over the network.\n"
        "- Raw passwords are never written to disk or sent to the AI.\n"
        "- Only safe summaries (strength score, category, breach status) "
        "are stored or shared with the AI assistant."
    )


def render_password_check() -> None:
    st.title("Password Check")
    account_label = st.text_input(
        "Account label (e.g. 'Gmail') — optional"
    )
    password = st.text_input(
        "Enter a password to analyze",
        type="password",
    )

    if st.button("Analyze password") and password:
        analysis = analyze_password(password)
        st.metric("Strength", analysis.category, f"{analysis.score}/100")

        for reason in analysis.reasons:
            st.write(f"- {reason}")

        with st.spinner("Checking against known breaches..."):
            breach_result = check_password_breach(password)

        if breach_result.checked:
            if breach_result.breached:
                st.error(
                    f"⚠️ Found in known breaches "
                    f"({breach_result.times_seen:,} times)."
                )
            else:
                st.success("✅ Not found in known breaches.")
        else:
            st.warning(
                f"Could not complete breach check: {breach_result.error}"
            )

        ai_summary = ""

        try:
            ai_summary = explain_password_risk(
                category=analysis.category,
                score=analysis.score,
                reasons=analysis.reasons,
                breached=(
                    breach_result.breached
                    if breach_result.checked
                    else None
                ),
            )
            st.info(ai_summary)
        except GeminiClientError as exc:
            st.caption(f"AI explanation unavailable: {exc}")

        report = SecurityReport(
            account_label=account_label or "Unlabeled account",
            analysis=analysis,
            breached=(
                breach_result.breached
                if breach_result.checked
                else None
            ),
            breach_count=(
                breach_result.times_seen
                if breach_result.checked
                else None
            ),
            ai_summary=ai_summary,
        )

        append_report(report.to_dict())
        st.caption(
            "A safe summary of this check was saved to your "
            "Security Report page."
        )


def render_password_generator() -> None:
    st.title("Password Generator")
    length = st.slider(
        "Password length",
        min_value=8,
        max_value=64,
        value=16,
    )

    if st.button("Generate strong password"):
        new_password = generate_strong_password(length=length)
        st.code(new_password)
        st.caption(
            "Copy this password and store it in a password manager."
        )


def render_security_report() -> None:
    st.title("Security Report")
    reports = load_reports()

    if not reports:
        st.write("No reports yet — run a password check first.")
        return

    for entry in reversed(reports[-20:]):
        with st.expander(
            f"{entry.get('account_label', 'Account')} — "
            f"{entry.get('timestamp', '')}"
        ):
            analysis = entry.get("analysis", {})
            st.write(
                f"Strength: {analysis.get('category')} "
                f"({analysis.get('score')}/100)"
            )
            st.write(f"Breached: {entry.get('breached')}")

            if entry.get("ai_summary"):
                st.write(entry["ai_summary"])

    st.divider()

    if st.button("Show general security tips"):
        try:
            st.write(general_security_advice())
        except GeminiClientError as exc:
            st.caption(f"AI tips unavailable: {exc}")


def main() -> None:
    page = st.sidebar.radio(
        "Navigate",
        [
            "Home",
            "Password Check",
            "Password Generator",
            "Security Report",
        ],
    )

    if page == "Home":
        render_home()
    elif page == "Password Check":
        render_password_check()
    elif page == "Password Generator":
        render_password_generator()
    elif page == "Security Report":
        render_security_report()


if __name__ == "__main__":
    main()
