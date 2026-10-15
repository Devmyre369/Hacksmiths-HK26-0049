import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from security_engine import (
    scan_sensitive_data, evaluate_outbound, SensitiveDataScanner, DataCategory,
    Decision, inspect_action, inspect_prompt,
)
from action_gateway import ActionRequest, AgentActionGateway, demo_echo_handler
from policy_manager import PolicyManager

# ---------------------------------------------------------
# CONFIGURATION + PERSISTENT SQLITE STORAGE
# ---------------------------------------------------------
st.set_page_config(
    page_title="AgentShield | Cyber Defense",
    page_icon="🛡️",
    layout="wide",
)
DB_PATH = Path(__file__).resolve().parent / "agentshield.db"
POLICY_PATH = Path(__file__).resolve().parent / "security_policies.json"


def load_policy_manager():
    try:
        return PolicyManager.load(POLICY_PATH)
    except (OSError, ValueError, KeyError, TypeError):
        return PolicyManager()


POLICY_MANAGER = load_policy_manager()
ACTION_GATEWAY = AgentActionGateway(policy_manager=POLICY_MANAGER)
# Local-only demo handlers: they return a preview and never contact a network.
for _tool_name in ("send_message", "upload_preview", "summarize_preview"):
    ACTION_GATEWAY.register_tool(_tool_name, demo_echo_handler)


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
    """Compatibility wrapper around the central security engine."""
    result = scan_sensitive_data(content)
    counts = {}
    for finding in result.findings:
        label = f"{finding.category.value} — {finding.description}"
        counts[label] = counts.get(label, 0) + 1
    findings = [
        {"Finding": label, "Matches": count}
        for label, count in counts.items()
    ]
    return findings, result.redacted_text


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
    background: radial-gradient(ellipse at top left, #260d14, #080709 55%);
    color: #fff0f2; font-family: 'Manrope', sans-serif;
}
section[data-testid="stSidebar"] { background: #10090d; border-right: 1px solid #48202b; }
.block-container { max-width: 1400px; padding-top: 2rem; }
.hero { padding: 28px; border: 1px solid #652536; border-radius: 18px;
    background: linear-gradient(120deg, #4a1422, #180b10); margin-bottom: 24px; }
.hero h1 { font-size: 36px; font-weight: 800; color: #fff7f8; }
.hero p { color: #e0bfc7; }
.metric { background: #1b0e13; border: 1px solid #4b202c; padding: 20px; border-radius: 14px; }
.metric-label { color: #c7a0aa; font-size: 12px; letter-spacing: 1px; }
.metric-value { color: #ff5268; font-size: 30px; font-weight: 800; }
.stButton button { background: #a81432; color: white; border: 1px solid #ed3553;
    border-radius: 9px; font-weight: 700; }
.stTextArea textarea, .stTextInput input { background: #130a0e; color: white; border: 1px solid #612536; }
div[data-testid="stMetric"] { background: linear-gradient(145deg, #1b0e13, #160a10); border: 1px solid #4b202c; padding: 14px; border-radius: 14px; box-shadow: 0 8px 22px rgba(0,0,0,.12); }
/* Enhanced visual system */
:root { --as-blue: #ff4d67; --as-cyan: #ff6578; --as-violet: #ff9aaa; }
.hero { position: relative; overflow: hidden; min-height: 205px; display: flex; align-items: center; }
.hero:after { content: ""; position: absolute; width: 270px; height: 270px; border: 1px solid rgba(255,65,95,.28); border-radius: 50%; right: 5%; top: -38px; box-shadow: 0 0 0 24px rgba(255,65,95,.06), 0 0 0 52px rgba(255,65,95,.035); pointer-events: none; }
.hero-copy { position: relative; z-index: 2; max-width: 72%; }
.hero-eyebrow { display: inline-block; padding: 6px 10px; border: 1px solid #7a2a3e; border-radius: 999px; color: #ff9aaa !important; background: rgba(170,20,50,.22); font-size: 11px; letter-spacing: 1.5px; font-weight: 800; }
.hero h1 { margin: 12px 0 8px 0; line-height: 1.12; }
.hero-graphic { position: absolute; right: 6%; top: 28px; width: 155px; height: 155px; z-index: 1; filter: drop-shadow(0 0 24px rgba(255,45,80,.24)); }
.section-kicker { color: #ff8b9c; font-size: 11px; letter-spacing: 1.6px; font-weight: 800; text-transform: uppercase; margin-bottom: 5px; }
.panel { background: linear-gradient(145deg, rgba(35,13,20,.98), rgba(17,8,12,.98)); border: 1px solid #4b202c; border-radius: 16px; padding: 18px; }
.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #ff6578; margin-right: 8px; box-shadow: 0 0 12px rgba(255,75,105,.65); }
.visual-label { color: #d6aab5; font-size: 12px; }
.visual-value { color: #fff0f3; font-size: 24px; font-weight: 800; }
div[data-testid="stVerticalBlockBorderWrapper"] { border-color: #4b202c !important; }
.stTabs [data-baseweb="tab-list"] { gap: 8px; }
.stTabs [data-baseweb="tab"] { background: #1b0e13; border-radius: 9px 9px 0 0; padding: 10px 16px; }
.stProgress > div > div > div > div { background-image: linear-gradient(90deg, #ff294f, #ff6578); }
[data-testid="stSidebar"] .stRadio label { padding: 6px 4px; }
.stButton button:hover { background: linear-gradient(110deg, #d91f43, #ff5268); border-color: #ff8797; box-shadow: 0 0 18px rgba(255,55,85,.22); }
.stButton button:focus { border-color: #ff6578 !important; box-shadow: 0 0 0 2px rgba(255,65,95,.25) !important; }
.stTabs [aria-selected="true"] { color: #ff8193 !important; border-bottom-color: #ff405f !important; }
[data-testid="stSidebar"] [aria-checked="true"] { color: #ff8193 !important; }
.stAlert { border-color: #652536 !important; }
[data-testid="stDownloadButton"] button { background: linear-gradient(110deg, #75142a, #bd1f3e); border: 1px solid #ed526c; color: #fff; }
@media (max-width: 800px) { .hero { min-height: 180px; } .hero-copy { max-width: 100%; } .hero-graphic { opacity: .18; right: -8px; } .hero:after { right: -100px; } }
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
    "Agent Firewall", "Policy Manager", "Prompt Security", "Approval Center", "Audit Center",
])
st.sidebar.divider()
st.sidebar.caption("CHAKRAVYUH 1.0")
st.sidebar.caption("Team Hacksmiths · HK26-0049")
st.sidebar.caption("Local prototype · gateway-enforced simulated actions")

st.markdown("""
<div class="hero">
  <div class="hero-copy">
    <span class="hero-eyebrow">CHAKRAVYUH 1.0 · HACKSMITHS</span>
    <h1>Intelligence meets<br>cyber defense.</h1>
    <p>Protect sensitive information with risk-aware scanning, explainable decisions,<br>and a unified security operations workspace.</p>
  </div>
  <svg class="hero-graphic" viewBox="0 0 180 180" role="img" aria-label="AgentShield security shield graphic">
    <defs>
      <linearGradient id="shieldGradient" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ff9cac"/><stop offset="1" stop-color="#d51c43"/></linearGradient>
      <radialGradient id="orbGlow"><stop offset="0" stop-color="#ff3459" stop-opacity=".3"/><stop offset="1" stop-color="#ff3459" stop-opacity="0"/></radialGradient>
    </defs>
    <circle cx="90" cy="90" r="84" fill="url(#orbGlow)"/>
    <circle cx="90" cy="90" r="69" fill="none" stroke="#ff405f" stroke-opacity=".35" stroke-width="1.4" stroke-dasharray="3 7"/>
    <circle cx="90" cy="90" r="54" fill="none" stroke="#ff6578" stroke-opacity=".28" stroke-width="1.4"/>
    <path d="M90 34 L132 50 V83 C132 111 115 132 90 145 C65 132 48 111 48 83 V50 Z" fill="#2c0c16" stroke="url(#shieldGradient)" stroke-width="3"/>
    <path d="M90 45 L121 57 V83 C121 105 108 121 90 132 C72 121 59 105 59 83 V57 Z" fill="#4a1021" stroke="#ff6578" stroke-opacity=".8" stroke-width="1.2"/>
    <path d="M73 88 L85 100 L108 74" fill="none" stroke="#ffd0d7" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="35" cy="83" r="4" fill="#ff6578"/><circle cx="142" cy="112" r="3" fill="#ff8b9c"/><circle cx="121" cy="27" r="3" fill="#ff6578"/>
  </svg>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# OVERVIEW
# ---------------------------------------------------------
if page == "Overview":
    st.subheader("Security Overview")
    st.caption("A live snapshot of the activity recorded by this AgentShield instance.")
    total, high_risk, blocked, pending = get_metrics()
    cols = st.columns(4)
    metric_icons = ["◈", "⚠", "⛨", "◷"]
    for col, (label, value), glyph in zip(cols, [
        ("AUDIT EVENTS", str(total)), ("HIGH-RISK EVENTS", str(high_risk)),
        ("BLOCKED ACTIONS", str(blocked)), ("PENDING APPROVALS", str(pending)),
    ], metric_icons):
        with col:
            st.markdown(
                f'<div class="metric"><div style="color:#ff6578;font-size:20px;margin-bottom:8px">{glyph}</div>'
                f'<div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div></div>',
                unsafe_allow_html=True,
            )
    st.write("")
    with sqlite3.connect(DB_PATH) as conn:
        recent = pd.read_sql_query("""
            SELECT created_at AS Time, event_type AS Event, subject AS Subject,
                   decision AS Decision, risk_score AS Risk
            FROM audit_events ORDER BY id DESC LIMIT 100
        """, conn)

    # Visual threat posture: computed from recorded events, not external telemetry.
    posture_score = 0 if recent.empty else min(100, round(recent["Risk"].head(20).mean()))
    posture_label = "QUIET" if recent.empty else "ELEVATED" if posture_score >= 60 else "GUARDED" if posture_score >= 25 else "STABLE"
    left, right = st.columns([1.35, 1])
    with left:
        st.markdown('<div class="panel"><div class="section-kicker">Threat posture</div>', unsafe_allow_html=True)
        st.markdown(f'<div style="display:flex;align-items:center;gap:10px;margin:4px 0 12px"><span class="status-dot"></span><span style="font-size:23px;font-weight:800;color:#fff0f2">{posture_label}</span><span style="margin-left:auto;color:#cda0ac;font-size:12px">LOCAL EVENT BASED</span></div>', unsafe_allow_html=True)
        st.progress(posture_score / 100, text=f"Recent-event risk index · {posture_score}/100")
        st.caption("Calculated from recent recorded event scores. This is not a live network threat feed.")
        st.markdown('</div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div class="panel"><div class="section-kicker">Security controls</div><div style="font-size:19px;font-weight:800;margin:6px 0 10px">Protection workspace</div><div style="color:#d6aab5;font-size:13px;line-height:1.7">Sensitive data scan<br>Outbound policy evaluation<br>Agent action review<br>Persistent audit history</div></div>', unsafe_allow_html=True)

    st.write("")
    st.markdown("### Activity analytics")
    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.markdown('<div class="section-kicker">Event timeline</div>', unsafe_allow_html=True)
        if recent.empty:
            st.info("Run a scan to populate the activity timeline.")
        else:
            timeline = recent.copy()
            timeline["Day"] = pd.to_datetime(
                timeline["Time"], format="mixed", errors="coerce", utc=True
            ).dt.strftime("%m-%d")
            timeline = timeline.dropna(subset=["Day"]).groupby("Day", as_index=False).size().rename(columns={"size": "Events"}).tail(10)
            if not timeline.empty:
                st.bar_chart(timeline.set_index("Day"), width="stretch", height=245)
            else:
                st.caption("Not enough timestamp data to draw the timeline.")
    with chart_right:
        st.markdown('<div class="section-kicker">Decision distribution</div>', unsafe_allow_html=True)
        if recent.empty:
            st.info("Decision distribution appears after the first security event.")
        else:
            distribution = recent["Decision"].fillna("UNKNOWN").value_counts().rename_axis("Decision").reset_index(name="Count")
            st.bar_chart(distribution.set_index("Decision"), width="stretch", height=245)
            st.caption("Based on the latest 100 recorded events.")

    st.markdown("### Recent security activity")
    if recent.empty:
        st.caption("No activity recorded yet. Choose a security tool from the sidebar to begin.")
    else:
        display_recent = recent.head(10).copy()
        display_recent["Subject"] = display_recent["Subject"].astype(str).str.slice(0, 100)
        st.dataframe(display_recent, width="stretch", hide_index=True)
        st.caption("Open Audit Center for filtering and exporting the recorded history.")

# ---------------------------------------------------------
# DATA SHIELD
# ---------------------------------------------------------
elif page == "Data Shield":
    st.subheader("🔐 Sensitive Data Protection Center")
    st.caption("Inspect text locally, understand each finding, redact risky values, and evaluate a proposed transfer before it leaves the app.")

    with st.expander("What this scanner checks", expanded=False):
        st.write("Credentials and tokens, private-key markers, email addresses, phone-like values, payment-card candidates, bank identifiers, government-ID-like patterns, IP addresses, and confidential-document markers.")
        st.caption("Use synthetic samples only. Rule matches can produce false positives and do not prove that unmatched content is safe.")

    content = st.text_area(
        "Content to inspect",
        height=230,
        placeholder="Paste synthetic text, code, a message, or a document excerpt here...",
        help="The current prototype scans only the content you submit on this page. It does not monitor other apps or files automatically.",
    )

    left, right = st.columns([1, 1])
    with left:
        redaction_strategy = st.selectbox(
            "Redaction strategy",
            ["Replace with category labels", "Partially mask values", "Remove matched values"],
        )
    with right:
        st.write("")
        st.write("")
        run_scan = st.button("🔎 Analyze sensitive data", type="primary", width="stretch")

    if run_scan:
        if not content.strip():
            st.warning("Enter some text first.")
        else:
            scanner = SensitiveDataScanner()
            scan_result = scan_sensitive_data(content)
            strategy_map = {
                "Replace with category labels": "replace",
                "Partially mask values": "partial",
                "Remove matched values": "remove",
            }
            safe_preview = scanner.mask(content, strategy_map[redaction_strategy])
            findings_count = len(scan_result.findings)
            critical_count = sum(f.severity.value == "CRITICAL" for f in scan_result.findings)
            high_count = sum(f.severity.value == "HIGH" for f in scan_result.findings)
            medium_count = sum(f.severity.value == "MEDIUM" for f in scan_result.findings)
            low_count = sum(f.severity.value == "LOW" for f in scan_result.findings)

            # Show a content-based scan report. Transfer decision is evaluated
            # separately below because destination authorization is contextual.
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Risk score", f"{scan_result.risk_score}/100")
            m2.metric("Findings", findings_count)
            m3.metric("High / critical", high_count + critical_count)
            m4.metric("Data categories", len(scan_result.categories))

            if critical_count:
                st.error("Critical credential material detected. Do not send the original content.")
            elif high_count:
                st.warning("High-severity sensitive information detected. Review the destination and purpose before sharing.")
            elif findings_count:
                st.warning("Potential sensitive information detected. Review each finding before sharing.")
            else:
                st.success("No configured sensitive-data patterns were detected.")
                st.caption("This is not proof that the content is safe; unsupported formats and unknown secret types may be missed.")

            st.markdown("#### Risk composition")
            risk_cols = st.columns(4)
            for col, (label, count, color) in zip(risk_cols, [
                ("CRITICAL", critical_count, "#ff5263"),
                ("HIGH", high_count, "#ff9d4d"),
                ("MEDIUM", medium_count, "#ffd166"),
                ("LOW", low_count, "#ff6578"),
            ]):
                with col:
                    st.markdown(
                        f'<div class="panel"><div style="color:{color};font-size:11px;letter-spacing:1px;font-weight:800">{label}</div>'
                        f'<div style="font-size:27px;font-weight:800;margin-top:5px">{count}</div>'
                        f'<div style="height:4px;background:#3c1b25;border-radius:8px;margin-top:10px"><div style="height:4px;width:{min(100, count * 25)}%;background:{color};border-radius:8px"></div></div></div>',
                        unsafe_allow_html=True,
                    )

            if scan_result.risk_factors:
                with st.expander("Why this score was assigned", expanded=True):
                    for factor in scan_result.risk_factors:
                        st.write(f"• {factor}")

            if scan_result.findings:
                st.markdown("#### Finding-by-finding analysis")
                rows = []
                for f in scan_result.findings:
                    rows.append({
                        "Category": f.category.value,
                        "Severity": f.severity.value,
                        "Rule confidence": f"{f.confidence}% (heuristic)",
                        "Finding": f.description,
                        "Masked example": f.matched_preview,
                        "Recommended action": f.recommendation,
                    })
                st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

            st.markdown("#### Safe preview")
            st.caption(f"Strategy: {redaction_strategy}. The original content is not included in the audit event.")
            st.code(safe_preview, language="text")
            st.download_button(
                "Download redacted content",
                data=safe_preview,
                file_name="agentshield_redacted.txt",
                mime="text/plain",
                width="stretch",
            )

            st.markdown("#### Outbound transfer policy check")
            st.caption("This evaluates a proposed transfer only. It does not send data or verify the destination's reputation.")
            destination = st.text_input(
                "Destination URL",
                key="dlp_destination",
                placeholder="https://approved.example.com/upload",
            )
            approved = st.checkbox(
                "I explicitly approve this sensitive-data transfer after reviewing the findings",
                key="dlp_user_approved",
            )
            if st.button("Evaluate transfer", key="evaluate_dlp_transfer", width="stretch"):
                transfer = POLICY_MANAGER.evaluate(
                    content,
                    destination.strip(),
                    user_approved=approved,
                    purpose="Data Shield outbound transfer evaluation",
                )
                st.markdown(f"**Decision: `{transfer.decision.value}`**")
                st.progress(min(transfer.risk_score, 100) / 100, text=f"Transfer risk: {transfer.risk_score}/100")
                for reason in transfer.reasons:
                    st.write(f"• {reason}")
                if transfer.decision.value == "BLOCK":
                    st.error("Do not proceed with this transfer. Remove the sensitive material or use an approved secure workflow.")
                elif transfer.decision.value == "REVIEW":
                    st.warning("Transfer requires review. Verify necessity, recipient, and applicable policy before proceeding.")
                else:
                    st.success("No configured rule blocked this proposed transfer. This is not a guarantee of safety.")
                save_audit(
                    "DLP_TRANSFER_EVALUATION",
                    "Outbound transfer evaluation",
                    transfer.decision.value,
                    transfer.risk_score,
                    {
                        "finding_count": len(transfer.scan.findings),
                        "categories": transfer.scan.categories,
                        "destination_scheme_https": destination.strip().lower().startswith("https://"),
                        "destination_host": transfer.destination_host,
                        "trusted_destination": transfer.trusted_destination,
                        "user_approved": approved,
                        "reasons": list(transfer.reasons),
                        "raw_content_saved": False,
                    },
                )

            # Keep audit details limited to categories/counts and never persist raw content.
            scan_decision = "BLOCK" if critical_count or scan_result.risk_score >= 70 else "REVIEW" if findings_count else "ALLOW"
            save_audit(
                "DATA_SCAN",
                "Sensitive data scan",
                scan_decision,
                scan_result.risk_score,
                {
                    "findings_count": findings_count,
                    "categories": scan_result.categories,
                    "severity_counts": {
                        "critical": critical_count,
                        "high": high_count,
                        "medium": medium_count,
                        "low": low_count,
                    },
                    "redaction_strategy": redaction_strategy,
                },
            )

# ---------------------------------------------------------
# URL THREAT ANALYZER
# ---------------------------------------------------------
elif page == "Threat Analyzer":
    st.subheader("🌐 URL Threat Analyzer")
    st.caption("Check URL characteristics using local heuristic rules.")
    url = st.text_input("URL to analyze", placeholder="https://example.com/account")
    if st.button("Analyze URL", width="stretch"):
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
    if st.button("Inspect Logs", width="stretch"):
        if not logs.strip():
            st.warning("Enter log text first.")
        else:
            found = inspect_logs(logs)
            risk = min(100, sum(item["Occurrences"] for item in found) * 25)
            decision = "FLAGGED" if found else "NO_INDICATOR_DETECTED"
            if found:
                st.warning("Review the following log indicators.")
                st.dataframe(pd.DataFrame(found), width="stretch", hide_index=True)
            else:
                st.success("No configured indicators matched.")
            save_audit("LOG_SCAN", "Security log inspection", decision, risk, {"findings": found})
            st.caption("Pattern matching is limited and does not replace professional log analysis.")

# ---------------------------------------------------------
# AGENT FIREWALL — POLICY-INTEGRATED ACTION GATEWAY
# ---------------------------------------------------------
elif page == "Agent Firewall":
    st.subheader("🧱 Agent Firewall")
    st.caption("The Action Gateway evaluates destination trust and sensitive-data policy before a registered handler can execute.")
    st.warning("Safe demo mode: handlers return a local preview only. No real email, upload, shell command, network request, or external action is performed.")

    with st.form("agent_firewall_form"):
        tool = st.selectbox("Requested action", [
            "send_message", "upload_preview", "summarize_preview",
            "delete", "shell", "database", "money_transfer", "unknown_tool",
        ], format_func=lambda value: {
            "send_message": "Send message (simulated)",
            "upload_preview": "Upload preview (simulated)",
            "summarize_preview": "Summarize content (simulated)",
            "delete": "Delete (unregistered / blocked)",
            "shell": "Shell command (unregistered / blocked)",
            "database": "Database action (unregistered / blocked)",
            "money_transfer": "Money transfer (unregistered / blocked)",
            "unknown_tool": "Unknown tool (unregistered / blocked)",
        }.get(value, value))
        destination = st.text_input("Destination URL (HTTPS required)", placeholder="https://example.com/api")
        description = st.text_area("Content the action would use", height=150,
                                   placeholder="Use synthetic test text; never paste real credentials.")
        purpose = st.text_input("Purpose (optional)", placeholder="Why is this action needed?")
        submitted = st.form_submit_button("Evaluate action", type="primary", width="stretch")

    def record_gateway_result(request, result):
        evaluation = result.policy_evaluation
        reasons = list(evaluation.reasons) if evaluation else list(result.security_result.reasons)
        host = evaluation.destination_host if evaluation else None
        # Persist metadata only, never the original request content.
        save_audit("GATEWAY_ACTION", f"{request.tool_name} → {host or 'invalid destination'}",
                   result.decision.value, result.risk_score, {
                       "tool": request.tool_name,
                       "destination_host": host,
                       "trusted_destination": bool(evaluation and evaluation.trusted_destination),
                       "executed": result.executed,
                       "categories": result.security_result.scan.categories,
                       "finding_count": len(result.security_result.scan.findings),
                       "reasons": reasons,
                       "raw_content_saved": False,
                   })

    if submitted:
        if not description.strip():
            st.warning("Enter the content or action description first.")
        else:
            request = ActionRequest(tool_name=tool, content=description,
                                    destination=destination.strip(), purpose=purpose.strip())
            result = ACTION_GATEWAY.execute(request)
            record_gateway_result(request, result)
            st.session_state["gateway_last_result"] = {
                "decision": result.decision.value,
                "risk_score": result.risk_score,
                "message": result.message,
                "reasons": list(result.policy_evaluation.reasons) if result.policy_evaluation else list(result.security_result.reasons),
                "redacted": result.security_result.scan.redacted_text,
                "categories": result.security_result.scan.categories,
                "executed": result.executed,
                "output": result.output,
            }
            if result.decision == Decision.REVIEW:
                st.session_state["gateway_pending_action"] = {
                    "tool_name": tool, "content": description,
                    "destination": destination.strip(), "purpose": purpose.strip(),
                }
            else:
                st.session_state.pop("gateway_pending_action", None)

    last = st.session_state.get("gateway_last_result")
    if last:
        st.divider()
        st.subheader("Gateway decision")
        metric_cols = st.columns(2)
        metric_cols[0].metric("Decision", last["decision"])
        metric_cols[1].metric("Risk score", f"{last['risk_score']}/100")
        if last["decision"] == "ALLOW":
            st.success(last["message"])
        elif last["decision"] == "REVIEW":
            st.warning("REVIEW — action paused. Inspect the redacted preview before approving.")
        else:
            st.error("BLOCK — the registered handler was not executed.")
        st.write("**Policy reasons**")
        for reason in last["reasons"]:
            st.write(f"- {reason}")
        if last["categories"]:
            st.write("**Detected categories:** " + ", ".join(last["categories"]))
        if last["redacted"]:
            st.write("**Redacted content preview**")
            st.code(last["redacted"], language="text")
        if last["executed"]:
            st.success("Local demo handler executed. Returned preview:")
            st.json(last["output"])

    pending = st.session_state.get("gateway_pending_action")
    if pending:
        st.info("This action is paused for explicit approval. Approval passes only the redacted preview to the local demo handler.")
        if st.button("Approve redacted action", type="primary", width="stretch"):
            approved_request = ActionRequest(
                tool_name=pending["tool_name"], content=pending["content"],
                destination=pending["destination"], user_approved=True,
                purpose=pending["purpose"],
            )
            approved_result = ACTION_GATEWAY.execute(approved_request)
            record_gateway_result(approved_request, approved_result)
            st.session_state["gateway_last_result"] = {
                "decision": approved_result.decision.value,
                "risk_score": approved_result.risk_score,
                "message": approved_result.message,
                "reasons": list(approved_result.policy_evaluation.reasons) if approved_result.policy_evaluation else list(approved_result.security_result.reasons),
                "redacted": approved_result.security_result.scan.redacted_text,
                "categories": approved_result.security_result.scan.categories,
                "executed": approved_result.executed,
                "output": approved_result.output,
            }
            st.session_state.pop("gateway_pending_action", None)
            st.rerun()
        if st.button("Cancel pending action", width="stretch"):
            st.session_state.pop("gateway_pending_action", None)
            st.session_state.pop("gateway_last_result", None)
            st.rerun()

# ---------------------------------------------------------
# POLICY MANAGER
# ---------------------------------------------------------
elif page == "Policy Manager":
    st.subheader("🛡️ Trusted Destinations & Policies")
    st.caption("The gateway trusts exact HTTPS hostnames by default. Adding a host does not establish its reputation; add only destinations you control or have independently verified.")
    with st.form("add_trusted_destination_form"):
        host = st.text_input("Hostname only", placeholder="example.com")
        allow_subdomains = st.checkbox("Also trust subdomains (for example, api.example.com)", value=False)
        allowed_categories = st.multiselect(
            "Categories this host may receive without per-action approval (critical credentials are always blocked)",
            options=[category.value for category in DataCategory], default=[],
        )
        note = st.text_input("Note (optional)", placeholder="Why is this destination trusted?")
        add_host = st.form_submit_button("Add trusted destination", type="primary", width="stretch")
    if add_host:
        try:
            POLICY_MANAGER.add_trusted_destination(host, allow_subdomains=allow_subdomains,
                                                   allowed_categories=allowed_categories, note=note)
            POLICY_MANAGER.save(POLICY_PATH)
            st.success(f"Trusted destination saved: {host.strip().lower()}")
            st.rerun()
        except (ValueError, OSError) as exc:
            st.error(f"Could not add destination: {exc}")

    st.subheader("Current trusted destinations")
    destinations = POLICY_MANAGER.policy.trusted_destinations
    if not destinations:
        st.warning("No destinations are trusted yet. Gateway actions will be blocked until you add a host.")
    for destination_entry in destinations:
        with st.container(border=True):
            col1, col2 = st.columns([4, 1])
            with col1:
                st.markdown(f"**{destination_entry.host}**")
                st.caption("Subdomains allowed" if destination_entry.allow_subdomains else "Exact hostname only")
                if destination_entry.allowed_categories:
                    st.write("Approval-exempt categories: " + ", ".join(destination_entry.allowed_categories))
                if destination_entry.note:
                    st.write(destination_entry.note)
            with col2:
                if st.button("Remove", key=f"remove_host_{destination_entry.host}", width="stretch"):
                    POLICY_MANAGER.remove_trusted_destination(destination_entry.host)
                    POLICY_MANAGER.save(POLICY_PATH)
                    st.rerun()
    st.caption(f"Policy file: {POLICY_PATH.name}. Critical credentials remain blocked regardless of trust or approval.")

# ---------------------------------------------------------
# PROMPT SECURITY
# ---------------------------------------------------------
elif page == "Prompt Security":
    st.subheader("🧠 Prompt Security")
    st.caption("Inspect text for potential prompt-injection indicators.")
    prompt = st.text_area("Prompt or agent response", height=200,
                          placeholder="Paste synthetic test text here...")
    if st.button("Analyze Prompt", type="primary", width="stretch"):
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
                    if st.button("Approve", key=f"approve_{approval_id}", width="stretch"):
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
                    if st.button("Reject", key=f"reject_{approval_id}", width="stretch"):
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
        st.dataframe(reviewed_df, width="stretch", hide_index=True)
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
        st.dataframe(visible.drop(columns=["Details"]), width="stretch", hide_index=True)
        st.download_button("Export visible audit events as CSV",
                           data=visible.to_csv(index=False).encode("utf-8"),
                           file_name="agentshield_audit.csv", mime="text/csv",
                           width="stretch")
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
