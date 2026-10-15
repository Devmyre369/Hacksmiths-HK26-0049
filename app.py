import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

# ---------------------------------------------------------
# CONFIGURATION + PERSISTENT SQLITE STORAGE
# ---------------------------------------------------------
st.set_page_config(
    page_title="AgentShield | Cyber Defense",
    page_icon="🛡️",
    layout="wide",
)
DB_PATH = Path(__file__).resolve().parent / "agentshield.db"


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                details TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                tool TEXT NOT NULL,
                description TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                reviewed_at TEXT,
                reviewer_note TEXT
            )
        """)


def save_audit(event_type, subject, decision, risk_score, details):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO audit_events
                (created_at, event_type, subject, decision, risk_score, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            now_iso(), str(event_type), str(subject)[:500], str(decision),
            max(0, min(100, int(risk_score))),
            json.dumps(details, ensure_ascii=False, default=str),
        ))


def get_metrics():
    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        high_risk = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE risk_score >= 70"
        ).fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE decision = 'BLOCK'"
        ).fetchone()[0]
        pending = conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE status = 'PENDING'"
        ).fetchone()[0]
    return total, high_risk, blocked, pending


init_db()

# ---------------------------------------------------------
# AGENTGUARD-INSPIRED LOCAL POLICY ENGINE
# This evaluates simulated actions; it does not execute tools.
# ---------------------------------------------------------
TOOL_POLICIES = {
    "read": ("ALLOW", 10),
    "search": ("ALLOW", 10),
    "summarize": ("ALLOW", 10),
    "email": ("APPROVAL_REQUIRED", 55),
    "message": ("APPROVAL_REQUIRED", 55),
    "upload": ("APPROVAL_REQUIRED", 60),
    "delete": ("BLOCK", 95),
    "shell": ("BLOCK", 95),
    "database": ("BLOCK", 90),
    "money_transfer": ("BLOCK", 95),
}
DANGEROUS_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"reveal (the )?(system prompt|secrets|credentials)",
    r"send .*?(api key|password|secret|token)",
    r"exfiltrat",
    r"bypass (security|authentication|authorization)",
]


def inspect_action(tool_name, description, contains_sensitive_data=False):
    tool = (tool_name or "").strip().lower()
    text = (description or "").strip().lower()
    policy, risk = TOOL_POLICIES.get(tool, ("APPROVAL_REQUIRED", 50))
    reasons = []

    if tool not in TOOL_POLICIES:
        reasons.append("Unknown tool: review its permissions.")
    if contains_sensitive_data:
        risk = max(risk, 85)
        reasons.append("Sensitive data may be exposed.")
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text):
            risk = max(risk, 90)
            reasons.append("Suspicious instruction pattern detected.")

    if risk >= 85 or policy == "BLOCK":
        decision = "BLOCK"
    elif policy == "APPROVAL_REQUIRED":
        decision = "APPROVAL_REQUIRED"
    else:
        decision = "ALLOW"
    if not reasons:
        reasons.append("No additional suspicious pattern matched.")
    return {
        "tool": tool or "unknown",
        "risk_score": min(risk, 100),
        "decision": decision,
        "reasons": reasons,
    }


def inspect_prompt(prompt):
    text = (prompt or "").lower()
    findings = []
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text):
            findings.append("Potential prompt-injection indicator detected.")
    if re.search(r"\b(password|api[_ -]?key|secret|access[_ -]?token)\s*[:=]", text):
        findings.append("Possible credential disclosure.")
    findings = list(dict.fromkeys(findings))
    score = min(100, len(findings) * 35)
    return {
        "risk_score": score,
        "findings": findings,
        "decision": "REVIEW" if findings else "NO_INDICATOR_DETECTED",
    }

# ---------------------------------------------------------
# LOCAL SCANNERS
# ---------------------------------------------------------
SECRET_PATTERNS = {
    "Possible AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
    "Possible GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    "Private key marker": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "Possible password assignment": r"(?i)\b(password|passwd)\s*[:=]\s*['\"]?[^\s'\"]+",
    "Email address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
}
LOG_PATTERNS = {
    "Failed login": r"(?i)failed password|login failed|failed login",
    "SQL injection indicator": r"(?i)sql injection|union\s+select|or\s+1=1",
    "Possible port scan": r"(?i)port scan|nmap scan",
    "Possible malware activity": r"(?i)ransomware|reverse shell|webshell",
}
SUSPICIOUS_URL_TERMS = [
    "verify", "login", "password", "wallet", "free-gift", "account-confirm"
]


def scan_secrets(content):
    findings = []
    redacted = content
    for name, pattern in SECRET_PATTERNS.items():
        matches = list(re.finditer(pattern, content))
        if matches:
            findings.append({"Finding": name, "Matches": len(matches)})
            redacted = re.sub(pattern, "[REDACTED]", redacted)
    return findings, redacted


def analyze_url(url):
    score, reasons = 0, []
    lowered = url.lower().strip()
    if not lowered.startswith("https://"):
        score += 20
        reasons.append("URL does not use HTTPS.")
    if "@" in url:
        score += 35
        reasons.append("URL contains an @ symbol.")
    matched = [term for term in SUSPICIOUS_URL_TERMS if term in lowered]
    if matched:
        score += min(15 * len(matched), 45)
        reasons.append("Potential social-engineering terms: " + ", ".join(matched))
    if not re.match(r"^https?://[^/\s]+\.[^/\s]+", lowered):
        score += 20
        reasons.append("URL format appears unusual or incomplete.")
    return min(score, 100), reasons


def inspect_logs(logs):
    found = []
    for label, pattern in LOG_PATTERNS.items():
        count = len(re.findall(pattern, logs))
        if count:
            found.append({"Indicator": label, "Occurrences": count})
    return found

# ---------------------------------------------------------
# VISUAL DESIGN
# ---------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;700;800&display=swap');
.stApp {
    background: radial-gradient(ellipse at top left, #142747, #080d18 55%);
    color: #edf4ff; font-family: 'Manrope', sans-serif;
}
section[data-testid="stSidebar"] { background: #09111f; border-right: 1px solid #20304a; }
.block-container { max-width: 1400px; padding-top: 2rem; }
.hero { padding: 28px; border: 1px solid #294467; border-radius: 18px;
    background: linear-gradient(120deg, #172f52, #0d192b); margin-bottom: 24px; }
.hero h1 { font-size: 36px; font-weight: 800; color: #f4f8ff; }
.hero p { color: #b7c8e2; }
.metric { background: #101b2d; border: 1px solid #253956; padding: 20px; border-radius: 14px; }
.metric-label { color: #93a9c7; font-size: 12px; letter-spacing: 1px; }
.metric-value { color: #58a6ff; font-size: 30px; font-weight: 800; }
.stButton button { background: #1767bb; color: white; border: 1px solid #3989df;
    border-radius: 9px; font-weight: 700; }
.stTextArea textarea, .stTextInput input { background: #0b1525; color: white; border: 1px solid #29405f; }
div[data-testid="stMetric"] { background: #101b2d; border: 1px solid #253956; padding: 12px; border-radius: 12px; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# NAVIGATION + HEADER
# ---------------------------------------------------------
st.sidebar.markdown("# 🛡️ AgentShield")
st.sidebar.caption("AI × CYBERSECURITY")
st.sidebar.divider()
page = st.sidebar.radio("Navigation", [
    "Overview", "Data Shield", "Threat Analyzer", "Log Inspector",
    "Agent Firewall", "Prompt Security", "Approval Center", "Audit Center",
])
st.sidebar.divider()
st.sidebar.caption("CHAKRAVYUH 1.0")
st.sidebar.caption("Team Hacksmiths · HK26-0049")
st.sidebar.caption("Local prototype · simulated actions only")

st.markdown("""
<div class="hero">
    <p>CHAKRAVYUH 1.0 / HACKSMITHS</p>
    <h1>Intelligence meets cyber defense.</h1>
    <p>Inspect sensitive data, analyze suspicious URLs, investigate security
    indicators, and evaluate AI-agent actions in one unified workspace.</p>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# OVERVIEW
# ---------------------------------------------------------
if page == "Overview":
    st.subheader("Security Overview")
    total, high_risk, blocked, pending = get_metrics()
    cols = st.columns(4)
    for col, (label, value) in zip(cols, [
        ("AUDIT EVENTS", str(total)), ("HIGH-RISK EVENTS", str(high_risk)),
        ("BLOCKED ACTIONS", str(blocked)), ("PENDING APPROVALS", str(pending)),
    ]):
        with col:
            st.markdown(
                f'<div class="metric"><div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div></div>',
                unsafe_allow_html=True,
            )
    st.write("")
    st.info("Choose a security tool from the sidebar to run an analysis.")
    with sqlite3.connect(DB_PATH) as conn:
        recent = pd.read_sql_query("""
            SELECT created_at AS Time, event_type AS Event, subject AS Subject,
                   decision AS Decision, risk_score AS Risk
            FROM audit_events ORDER BY id DESC LIMIT 10
        """, conn)
    st.subheader("Recent security activity")
    if recent.empty:
        st.caption("No activity recorded yet.")
    else:
        st.dataframe(recent, use_container_width=True, hide_index=True)

# ---------------------------------------------------------
# DATA SHIELD
# ---------------------------------------------------------
elif page == "Data Shield":
    st.subheader("🔐 Sensitive Data Scanner")
    st.caption("Detect common secret patterns before sharing text. Use synthetic samples only.")
    content = st.text_area("Content to inspect", height=220,
                            placeholder="Paste synthetic sample code or text here...")
    if st.button("Scan Content", use_container_width=True):
        if not content.strip():
            st.warning("Enter some text first.")
        else:
            findings, redacted = scan_secrets(content)
            matches = sum(item["Matches"] for item in findings)
            risk = min(100, matches * 25)
            decision = "FLAGGED" if findings else "NO_INDICATOR_DETECTED"
            if findings:
                st.error("Potential sensitive information detected.")
                st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)
                st.subheader("Redacted preview")
                st.code(redacted, language="text")
            else:
                st.success("No configured patterns were detected.")
                st.caption("This does not guarantee that the content is safe.")
            save_audit("DATA_SCAN", "Sensitive data scan", decision, risk,
                       {"findings": findings, "matches": matches})

# ---------------------------------------------------------
# URL THREAT ANALYZER
# ---------------------------------------------------------
elif page == "Threat Analyzer":
    st.subheader("🌐 URL Threat Analyzer")
    st.caption("Check URL characteristics using local heuristic rules.")
    url = st.text_input("URL to analyze", placeholder="https://example.com/account")
    if st.button("Analyze URL", use_container_width=True):
        if not url.strip():
            st.warning("Enter a URL first.")
        else:
            score, reasons = analyze_url(url)
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
            decision = "FLAGGED" if score >= 50 else "REVIEW" if score >= 20 else "NO_INDICATOR_DETECTED"
            save_audit("URL_SCAN", url[:250], decision, score, {"reasons": reasons})
            st.caption("This is not a live reputation check. The app does not visit the URL or verify whether it is malicious.")

# ---------------------------------------------------------
# LOG INSPECTOR
# ---------------------------------------------------------
elif page == "Log Inspector":
    st.subheader("📋 Security Log Inspector")
    st.caption("Search supplied logs for basic suspicious activity patterns.")
    logs = st.text_area("Paste sample logs", height=220,
                        placeholder="Paste authorized log samples here...")
    if st.button("Inspect Logs", use_container_width=True):
        if not logs.strip():
            st.warning("Enter log text first.")
        else:
            found = inspect_logs(logs)
            risk = min(100, sum(item["Occurrences"] for item in found) * 25)
            decision = "FLAGGED" if found else "NO_INDICATOR_DETECTED"
            if found:
                st.warning("Review the following log indicators.")
                st.dataframe(pd.DataFrame(found), use_container_width=True, hide_index=True)
            else:
                st.success("No configured indicators matched.")
            save_audit("LOG_SCAN", "Security log inspection", decision, risk, {"findings": found})
            st.caption("Pattern matching is limited and does not replace professional log analysis.")

# ---------------------------------------------------------
# AGENT FIREWALL
# ---------------------------------------------------------
elif page == "Agent Firewall":
    st.subheader("🧱 Agent Firewall")
    st.caption("AgentGuard-inspired policy checks for simulated AI-agent actions.")
    with st.form("agent_firewall_form"):
        tool = st.selectbox("Requested tool", [
            "read", "search", "summarize", "email", "message", "upload",
            "delete", "shell", "database", "money_transfer", "unknown_tool",
        ])
        description = st.text_area("Describe the requested action",
                                   placeholder="Example: Send a project report to the team")
        sensitive = st.checkbox("The action may expose sensitive information")
        submitted = st.form_submit_button("Inspect action", type="primary", use_container_width=True)
    if submitted:
        if not description.strip():
            st.warning("Describe the requested action first.")
        else:
            result = inspect_action(tool, description, contains_sensitive_data=sensitive)
            decision, risk = result["decision"], result["risk_score"]
            if decision == "ALLOW":
                st.success("ALLOW — permitted by the current prototype policy.")
            elif decision == "APPROVAL_REQUIRED":
                st.warning("APPROVAL REQUIRED — reviewer action needed.")
            else:
                st.error("BLOCK — denied by the current prototype policy.")
            st.metric("Risk score", f"{risk}/100")
            st.write("**Reasons for this decision**")
            for reason in result["reasons"]:
                st.write(f"- {reason}")
            save_audit("AGENT_ACTION", f"{tool}: {description[:150]}", decision, risk, result)
            if decision == "APPROVAL_REQUIRED":
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("""
                        INSERT INTO approvals (created_at, tool, description, risk_score, reasons)
                        VALUES (?, ?, ?, ?, ?)
                    """, (now_iso(), tool, description[:2000], risk,
                          json.dumps(result["reasons"], ensure_ascii=False)))
                st.info("This request was added to the Approval Center.")
            st.caption("Prototype mode: no external tool or real-world action was executed.")

# ---------------------------------------------------------
# PROMPT SECURITY
# ---------------------------------------------------------
elif page == "Prompt Security":
    st.subheader("🧠 Prompt Security")
    st.caption("Inspect text for potential prompt-injection indicators.")
    prompt = st.text_area("Prompt or agent response", height=200,
                          placeholder="Paste synthetic test text here...")
    if st.button("Analyze Prompt", type="primary", use_container_width=True):
        if not prompt.strip():
            st.warning("Enter text to analyze first.")
        else:
            result = inspect_prompt(prompt)
            st.metric("Heuristic risk score", f"{result['risk_score']}/100")
            if result["findings"]:
                st.warning("Potential security indicators found.")
                for finding in result["findings"]:
                    st.write(f"- {finding}")
            else:
                st.success("No configured indicators detected.")
            save_audit("PROMPT_SCAN", "Prompt security scan", result["decision"],
                       result["risk_score"], result)
            st.caption("Heuristic analysis only; this is not a guarantee that a prompt is safe.")

# ---------------------------------------------------------
# APPROVAL CENTER
# ---------------------------------------------------------
elif page == "Approval Center":
    st.subheader("🧑‍⚖️ Approval Center")
    st.caption("Review simulated agent actions that require human approval.")
    with sqlite3.connect(DB_PATH) as conn:
        pending_rows = conn.execute("""
            SELECT id, created_at, tool, description, risk_score, reasons
            FROM approvals WHERE status = 'PENDING' ORDER BY id DESC
        """).fetchall()
        reviewed_rows = conn.execute("""
            SELECT id, tool, description, risk_score, status, reviewed_at, reviewer_note
            FROM approvals WHERE status != 'PENDING' ORDER BY id DESC LIMIT 50
        """).fetchall()
    st.metric("Pending approvals", len(pending_rows))
    if not pending_rows:
        st.info("No pending approvals. Run an email or upload action in Agent Firewall to create one.")
    else:
        for row in pending_rows:
            approval_id, created_at, tool, description, risk, reasons_json = row
            with st.container(border=True):
                st.markdown(f"**Request #{approval_id} · {tool}**")
                st.caption(f"Submitted: {created_at}")
                st.write(description)
                st.write(f"**Risk score:** {risk}/100")
                try:
                    reasons = json.loads(reasons_json)
                except (ValueError, TypeError):
                    reasons = [str(reasons_json)]
                for reason in reasons:
                    st.write(f"- {reason}")
                reviewer_note = st.text_input("Reviewer note (optional)", key=f"review_note_{approval_id}")
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Approve", key=f"approve_{approval_id}", use_container_width=True):
                        with sqlite3.connect(DB_PATH) as conn:
                            updated = conn.execute("""
                                UPDATE approvals SET status='APPROVED', reviewed_at=?, reviewer_note=?
                                WHERE id=? AND status='PENDING'
                            """, (now_iso(), reviewer_note[:500], approval_id)).rowcount
                        if updated:
                            save_audit("APPROVAL_REVIEW", f"Request #{approval_id}", "APPROVED", risk,
                                       {"tool": tool, "reviewer_note": reviewer_note[:500]})
                        st.rerun()
                with col2:
                    if st.button("Reject", key=f"reject_{approval_id}", use_container_width=True):
                        with sqlite3.connect(DB_PATH) as conn:
                            updated = conn.execute("""
                                UPDATE approvals SET status='REJECTED', reviewed_at=?, reviewer_note=?
                                WHERE id=? AND status='PENDING'
                            """, (now_iso(), reviewer_note[:500], approval_id)).rowcount
                        if updated:
                            save_audit("APPROVAL_REVIEW", f"Request #{approval_id}", "REJECTED", risk,
                                       {"tool": tool, "reviewer_note": reviewer_note[:500]})
                        st.rerun()
    if reviewed_rows:
        st.subheader("Recently reviewed")
        reviewed_df = pd.DataFrame(reviewed_rows, columns=[
            "ID", "Tool", "Description", "Risk", "Status", "Reviewed at", "Reviewer note"
        ])
        st.dataframe(reviewed_df, use_container_width=True, hide_index=True)
    st.caption("Approval records a reviewer decision only. It does not execute the requested action.")

# ---------------------------------------------------------
# AUDIT CENTER
# ---------------------------------------------------------
elif page == "Audit Center":
    st.subheader("🧾 Audit Center")
    st.caption("Persistent record of security scans and policy decisions.")
    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM audit_events WHERE decision='BLOCK'").fetchone()[0]
        high_risk = conn.execute("SELECT COUNT(*) FROM audit_events WHERE risk_score >= 70").fetchone()[0]
        events = pd.read_sql_query("""
            SELECT id AS ID, created_at AS Time, event_type AS Event, subject AS Subject,
                   decision AS Decision, risk_score AS Risk, details AS Details
            FROM audit_events ORDER BY id DESC LIMIT 500
        """, conn)
    c1, c2, c3 = st.columns(3)
    c1.metric("Recorded events", total)
    c2.metric("Blocked actions", blocked)
    c3.metric("High-risk events", high_risk)
    if events.empty:
        st.info("No audit events yet. Run a scan or firewall check first.")
    else:
        decisions = sorted(events["Decision"].dropna().unique().tolist())
        decision_filter = st.multiselect("Filter by decision", options=decisions, default=[])
        visible = events[events["Decision"].isin(decision_filter)] if decision_filter else events
        st.dataframe(visible.drop(columns=["Details"]), use_container_width=True, hide_index=True)
        st.download_button("Export visible audit events as CSV",
                           data=visible.to_csv(index=False).encode("utf-8"),
                           file_name="agentshield_audit.csv", mime="text/csv",
                           use_container_width=True)
        with st.expander("View event details"):
            event_ids = visible["ID"].tolist()
            if event_ids:
                selected_id = st.selectbox("Choose event ID", event_ids)
                details = visible.loc[visible["ID"] == selected_id, "Details"].iloc[0]
                try:
                    st.json(json.loads(details))
                except (ValueError, TypeError):
                    st.code(str(details))

# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------
st.divider()
st.caption(
    f"AgentShield · Chakravyuh 1.0 · Hacksmiths · Prototype · {datetime.now().strftime('%Y-%m-%d')}"
)
st.caption("Security checks are heuristic and intended for demonstration. Do not paste real secrets into this prototype.")
