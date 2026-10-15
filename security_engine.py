
import re

# AgentShield / AgentGuard policy engine.
# This evaluates simulated actions; it does not execute tools.

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

    policy, risk = TOOL_POLICIES.get(
        tool, ("APPROVAL_REQUIRED", 50)
    )

    reasons = []

    if tool not in TOOL_POLICIES:
        reasons.append("Unknown tool: review its permissions.")

    if contains_sensitive_data:
        risk = max(risk, 85)
        reasons.append("Sensitive data may be exposed.")

    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text):
            risk = max(risk, 90)
            reasons.append(
                f"Suspicious instruction matched: {pattern}"
            )

    # High-risk actions cannot be approved automatically.
    if risk >= 85:
        decision = "BLOCK"
    elif policy == "BLOCK":
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
            findings.append(
                f"Potential prompt-injection indicator: {pattern}"
            )

    if re.search(
        r"(password|api[_ -]?key|secret|access[_ -]?token)\s*[:=]",
        text,
    ):
        findings.append("Possible credential disclosure.")

    return {
        "risk_score": min(100, len(findings) * 35),
        "findings": findings,
        "decision": "REVIEW" if findings else "NO INDICATOR DETECTED",
    }
