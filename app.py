
import re
import streamlit as st
import pandas as pd
from datetime import datetime

st.set_page_config(
    page_title="AgentShield | Cyber Defense",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;700;800&display=swap');

.stApp {
    background: radial-gradient(ellipse at top left, #142747, #080d18 55%);
    color: #edf4ff;
    font-family: 'Manrope', sans-serif;
}
section[data-testid="stSidebar"] {
    background: #09111f;
    border-right: 1px solid #20304a;
}
.block-container {
    max-width: 1400px;
    padding-top: 2rem;
}
.hero {
    padding: 28px;
    border: 1px solid #294467;
    border-radius: 18px;
    background: linear-gradient(120deg, #172f52, #0d192b);
    margin-bottom: 24px;
}
.hero h1 {
    font-size: 36px;
    font-weight: 800;
    color: #f4f8ff;
}
.hero p { color: #b7c8e2; }
.metric {
    background: #101b2d;
    border: 1px solid #253956;
    padding: 20px;
    border-radius: 14px;
}
.metric-label {
    color: #93a9c7;
    font-size: 12px;
    letter-spacing: 1px;
}
.metric-value {
    color: #58a6ff;
    font-size: 30px;
    font-weight: 800;
}
.stButton button {
    background: #1767bb;
    color: white;
    border: 1px solid #3989df;
    border-radius: 9px;
    font-weight: 700;
}
.stTextArea textarea, .stTextInput input {
    background: #0b1525;
    color: white;
    border: 1px solid #29405f;
}
</style>
""", unsafe_allow_html=True)

st.sidebar.markdown("# 🛡️ AgentShield")
st.sidebar.caption("AI × CYBERSECURITY")
st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    ["Overview", "Data Shield", "Threat Analyzer", "Log Inspector"]
)

st.sidebar.divider()
st.sidebar.caption("CHAKRAVYUH 1.0")
st.sidebar.caption("Team Hacksmiths · HK26-0049")

st.markdown("""
<div class="hero">
    <p>CHAKRAVYUH 1.0 / HACKSMITHS</p>
    <h1>Intelligence meets cyber defense.</h1>
    <p>Inspect sensitive data, analyze suspicious URLs, and investigate
    security indicators from one unified workspace.</p>
</div>
""", unsafe_allow_html=True)

if page == "Overview":
    st.subheader("Security Overview")

    cols = st.columns(3)
    metrics = [
        ("TOTAL SCANS", "0"),
        ("HIGH-RISK FLAGS", "0"),
        ("SYSTEM STATUS", "READY"),
    ]

    for col, (label, value) in zip(cols, metrics):
        with col:
            st.markdown(
                f'<div class="metric">'
                f'<div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.write("")
    st.info(
        "Select a security tool from the sidebar to run your first analysis."
    )

elif page == "Data Shield":
    st.subheader("🔐 Sensitive Data Scanner")
    st.caption("Detect common secret patterns before sharing text.")

    content = st.text_area(
        "Content to inspect",
        height=220,
        placeholder="Paste sample code or text here..."
    )

    if st.button("Scan Content", use_container_width=True):
        if not content.strip():
            st.warning("Enter some text first.")
        else:
            patterns = {
                "Possible AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
                "Possible GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
                "Private key marker": r"-----BEGIN .*PRIVATE KEY-----",
                "Possible password assignment":
                    r"(?i)\b(password|passwd)\s*[:=]\s*\S+",
                "Email address":
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            }

            findings = []
            for name, pattern in patterns.items():
                count = len(re.findall(pattern, content))
                if count:
                    findings.append({
                        "Finding": name,
                        "Matches": count,
                    })

            if findings:
                st.error("Potential sensitive information detected.")
                st.dataframe(
                    pd.DataFrame(findings),
                    use_container_width=True,
                    hide_index=True,
                )
                st.subheader("Redacted preview")
                redacted = content

                for name, pattern in patterns.items():
                    redacted = re.sub(
                        pattern,
                        "[REDACTED]",
                        redacted,
                    )

                st.code(redacted, language="text")
            else:
                st.success("No configured patterns were detected.")
                st.caption(
                    "This does not guarantee that the content is safe."
                )

elif page == "Threat Analyzer":
    st.subheader("🌐 URL Threat Analyzer")
    st.caption("Check URL characteristics using local heuristic rules.")

    url = st.text_input(
        "URL to analyze",
        placeholder="https://example.com/account"
    )

    if st.button("Analyze URL", use_container_width=True):
        if not url.strip():
            st.warning("Enter a URL first.")
        else:
            score = 0
            reasons = []
            lowered = url.lower()

            if not lowered.startswith("https://"):
                score += 20
                reasons.append("URL does not use HTTPS.")

            if "@" in url:
                score += 35
                reasons.append("URL contains an @ symbol.")

            suspicious_terms = [
                "verify", "login", "password", "wallet",
                "free-gift", "account-confirm"
            ]

            matched = [x for x in suspicious_terms if x in lowered]
            if matched:
                score += min(15 * len(matched), 45)
                reasons.append(
                    "Potential social-engineering terms: "
                    + ", ".join(matched)
                )

            score = min(score, 100)

            st.metric("Heuristic Risk Score", f"{score}/100")

            if score >= 50:
                st.error("HIGHER RISK — investigate before interacting.")
            elif score >= 20:
                st.warning("CAUTION — review the URL carefully.")
            else:
                st.success("No configured warning indicators detected.")

            if reasons:
                st.write("#### Findings")
                for reason in reasons:
                    st.write(f"- {reason}")

            st.caption(
                "This is not a live reputation check and does not "
                "visit the URL or verify whether it is malicious."
            )

elif page == "Log Inspector":
    st.subheader("📋 Security Log Inspector")
    st.caption("Search supplied logs for basic suspicious activity patterns.")

    logs = st.text_area(
        "Paste sample logs",
        height=220,
        placeholder="Paste authorized log samples here..."
    )

    if st.button("Inspect Logs", use_container_width=True):
        if not logs.strip():
            st.warning("Enter log text first.")
        else:
            rules = {
                "Failed login": r"(?i)failed password|login failed",
                "SQL injection indicator": r"(?i)sql injection",
                "Possible port scan": r"(?i)port scan|nmap scan",
                "Possible malware activity":
                    r"(?i)ransomware|reverse shell|webshell",
            }

            found = []
            for label, pattern in rules.items():
                count = len(re.findall(pattern, logs))
                if count:
                    found.append({
                        "Indicator": label,
                        "Occurrences": count,
                    })

            if found:
                st.warning("Review the following log indicators.")
                st.dataframe(
                    pd.DataFrame(found),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.success("No configured indicators matched.")

            st.caption(
                "Pattern matching is limited and does not replace "
                "professional log analysis."
            )

st.divider()
st.caption(
    f"AgentShield · Chakravyuh 1.0 · Hacksmiths · "
    f"Prototype · {datetime.now().strftime('%Y-%m-%d')}"
)
