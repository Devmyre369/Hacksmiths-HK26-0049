"""AgentShield advanced local sensitive-data protection engine.

Rule-based prototype: detects common sensitive-data patterns, provides
explainable findings, creates redacted previews, and evaluates outbound
transfers. It does not inspect traffic outside the application or verify
remote destination reputation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class DataCategory(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    PAYMENT_CARD = "PAYMENT_CARD"
    PASSWORD = "PASSWORD"
    API_KEY = "API_KEY"
    ACCESS_TOKEN = "ACCESS_TOKEN"
    PRIVATE_KEY = "PRIVATE_KEY"
    BANK_IDENTIFIER = "BANK_IDENTIFIER"
    GOVERNMENT_ID = "GOVERNMENT_ID"
    IP_ADDRESS = "IP_ADDRESS"
    CONFIDENTIAL_MARKER = "CONFIDENTIAL_MARKER"


@dataclass(frozen=True)
class Finding:
    category: DataCategory
    severity: Severity
    start: int
    end: int
    description: str
    confidence: int = 80
    recommendation: str = "Review this value before sharing."
    matched_preview: str = "[VALUE HIDDEN]"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str = ""
    risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)

    @property
    def has_sensitive_data(self) -> bool:
        return bool(self.findings)

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                 Severity.HIGH: 3, Severity.CRITICAL: 4}
        return max((f.severity for f in self.findings), key=lambda s: order[s])

    @property
    def categories(self) -> list[str]:
        return sorted({f.category.value for f in self.findings})


@dataclass(frozen=True)
class SecurityResult:
    decision: Decision
    risk_score: int
    reasons: tuple[str, ...]
    scan: ScanResult
    recommended_action: str = "Review the result before proceeding."


# Pattern order matters: more specific patterns are evaluated before broad ones.
# Recommendations are intentionally actionable and do not include the matched secret.
PATTERNS = [
    (DataCategory.PRIVATE_KEY, Severity.CRITICAL, 99, "Private-key material",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", re.I),
     "Remove the key from the content, rotate it if it may have been exposed, and store it in a secrets manager."),
    (DataCategory.API_KEY, Severity.CRITICAL, 96, "AWS access-key identifier",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "Do not transmit this key. If real, disable or rotate it and review cloud audit logs."),
    (DataCategory.API_KEY, Severity.CRITICAL, 94, "GitHub personal-access-token pattern",
     re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
     "Remove the token and revoke or rotate it if real. Use a narrowly scoped token stored in a secret manager."),
    (DataCategory.API_KEY, Severity.CRITICAL, 92, "Google API-key-like pattern",
     re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
     "Remove the key, check its restrictions, and rotate it if it is a real credential."),
    (DataCategory.ACCESS_TOKEN, Severity.HIGH, 90, "Bearer authentication token",
     re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
     "Do not share the token. Revoke or rotate it if exposed and use a short-lived credential where possible."),
    (DataCategory.PASSWORD, Severity.CRITICAL, 94, "Password or secret assignment",
     re.compile(r'''(?i)\b(?:password|passwd|pwd|client_secret|secret_key|api_secret)\b\s*[:=]\s*(?:"[^"\r\n]{1,200}"|'[^'\r\n]{1,200}'|[^\s,;]{6,200})'''),
     "Replace the value with a placeholder. If it is real and has been shared, change it immediately."),
    (DataCategory.BANK_IDENTIFIER, Severity.HIGH, 88, "Possible bank account identifier",
     re.compile(r"(?i)\b(?:account\s*(?:number|no\.?)|bank\s*account)\s*[:#-]?\s*\d{9,18}\b"),
     "Share only with a verified recipient and only when necessary; mask most digits in general documents."),
    (DataCategory.GOVERNMENT_ID, Severity.HIGH, 82, "Possible Aadhaar-format identifier",
     re.compile(r"(?<!\d)(?:\d{4}[ -]){2}\d{4}(?!\d)"),
     "Verify the context before classifying this as an ID. Mask it and avoid sharing it unless required."),
    (DataCategory.PAYMENT_CARD, Severity.HIGH, 90, "Possible payment-card number",
     re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
     "Use a payment processor or tokenized reference instead of sending the full card number."),
    (DataCategory.EMAIL, Severity.MEDIUM, 96, "Email address",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "Share only with the intended recipient. Mask it in public examples or reports if identity is not needed."),
    (DataCategory.PHONE, Severity.MEDIUM, 75, "Possible phone number",
     re.compile(r"(?<!\w)(?:\+\d{1,3}[-.\s]?)?(?:\(?\d{2,5}\)?[-.\s]?)\d{3,5}[-.\s]?\d{3,5}(?!\w)"),
     "Confirm this is a phone number, then mask it unless the recipient needs the full value."),
    (DataCategory.IP_ADDRESS, Severity.LOW, 96, "IPv4 address",
     re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
     "Check whether this is an internal address before publishing logs or infrastructure details."),
    (DataCategory.CONFIDENTIAL_MARKER, Severity.HIGH, 90, "Confidentiality marker",
     re.compile(r"(?i)\b(?:strictly confidential|confidential|internal use only|do not distribute)\b"),
     "Confirm the document's sharing policy and recipient authorization before sharing."),
]

SEVERITY_SCORES = {Severity.INFO: 0, Severity.LOW: 10, Severity.MEDIUM: 25,
                   Severity.HIGH: 45, Severity.CRITICAL: 70}

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


def inspect_action(
    tool_name: str,
    description: str,
    contains_sensitive_data: bool = False,
) -> dict[str, object]:
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


def inspect_prompt(prompt: str) -> dict[str, object]:
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


def _luhn_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, char in enumerate(digits[::-1]):
        n = int(char)
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def calculate_risk(findings: list[Finding]) -> int:
    if not findings:
        return 0
    scores = sorted((SEVERITY_SCORES[f.severity] for f in findings), reverse=True)
    return min(100, scores[0] + sum(min(s // 4, 10) for s in scores[1:]))


def _safe_preview(value: str) -> str:
    """Return a non-secret preview suitable for display/logging."""
    if len(value) <= 4:
        return "[VALUE HIDDEN]"
    return value[:2] + "••••" + value[-2:]


class SensitiveDataScanner:
    def scan(self, text: str) -> ScanResult:
        if not isinstance(text, str):
            raise TypeError("Text to scan must be a string.")
        if not text:
            return ScanResult(redacted_text="", risk_score=0)

        findings: list[Finding] = []
        occupied: list[tuple[int, int]] = []
        risk_factors: list[str] = []

        for category, severity, confidence, description, pattern, recommendation in PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span()
                value = match.group()
                if any(start < b and end > a for a, b in occupied):
                    continue
                if category == DataCategory.PAYMENT_CARD and not _luhn_valid(value):
                    continue
                if category == DataCategory.PHONE:
                    digit_count = sum(c.isdigit() for c in value)
                    if not 10 <= digit_count <= 15:
                        continue
                # Aadhaar-like numeric format is weak evidence without nearby context.
                if category == DataCategory.GOVERNMENT_ID:
                    context = text[max(0, start - 35):min(len(text), end + 35)].lower()
                    if not any(word in context for word in ("aadhaar", "aadhar", "uid", "government id")):
                        confidence = 55
                        severity = Severity.MEDIUM
                        recommendation = "This number only matches an ID-like format. Confirm its meaning before taking action."
                finding = Finding(
                    category=category, severity=severity, start=start, end=end,
                    description=description, confidence=confidence,
                    recommendation=recommendation, matched_preview=_safe_preview(value),
                )
                findings.append(finding)
                occupied.append((start, end))
                risk_factors.append(f"{category.value}: {severity.value} severity ({confidence}% rule confidence)")

        redacted = text
        for finding in sorted(findings, key=lambda item: item.start, reverse=True):
            redacted = redacted[:finding.start] + f"[REDACTED_{finding.category.value}]" + redacted[finding.end:]

        return ScanResult(
            findings=sorted(findings, key=lambda item: item.start),
            redacted_text=redacted,
            risk_score=calculate_risk(findings),
            risk_factors=list(dict.fromkeys(risk_factors)),
        )

    def mask(self, text: str, strategy: str = "replace") -> str:
        """Redact matches. Strategies: replace, partial, remove."""
        result = self.scan(text)
        if strategy == "replace":
            return result.redacted_text
        output = text
        for finding in sorted(result.findings, key=lambda item: item.start, reverse=True):
            original = text[finding.start:finding.end]
            if strategy == "remove":
                replacement = ""
            elif strategy == "partial":
                digits = re.sub(r"\D", "", original)
                if len(digits) >= 8:
                    replacement = "•" * (len(digits) - 4) + digits[-4:]
                else:
                    replacement = "[PARTIALLY_MASKED]"
            else:
                raise ValueError("strategy must be 'replace', 'partial', or 'remove'")
            output = output[:finding.start] + replacement + output[finding.end:]
        return output


DEFAULT_SCANNER = SensitiveDataScanner()


def scan_sensitive_data(text: str) -> ScanResult:
    return DEFAULT_SCANNER.scan(text)


def is_https_destination(destination: str) -> bool:
    try:
        parsed = urlparse(destination)
        return parsed.scheme.lower() == "https" and bool(parsed.hostname) and parsed.username is None and parsed.password is None
    except (ValueError, AttributeError):
        return False


class SensitiveDataProtectionEngine:
    """Evaluate an outgoing transfer. Caller must enforce the result."""
    def __init__(self) -> None:
        self.scanner = SensitiveDataScanner()

    def evaluate_outbound(
        self, content: str, destination: str, *,
        destination_authorized: bool = False, user_approved: bool = False,
        allow_sensitive_categories: Optional[set[DataCategory]] = None,
    ) -> SecurityResult:
        scan = self.scanner.scan(content)
        reasons: list[str] = []
        score = scan.risk_score
        decision = Decision.ALLOW
        allowed_categories = allow_sensitive_categories or set()

        if not destination:
            decision = Decision.REVIEW
            score = max(score, 35)
            reasons.append("Destination is missing; verify where the data will go.")
        elif not is_https_destination(destination):
            decision = Decision.BLOCK
            score = max(score, 90)
            reasons.append("Destination is not a valid HTTPS URL.")

        critical = [f for f in scan.findings if f.severity == Severity.CRITICAL]
        disallowed = [f for f in scan.findings if f.category not in allowed_categories]
        if critical:
            decision = Decision.BLOCK
            score = max(score, 90)
            reasons.append("Critical credential material detected; remove it before transfer.")
        elif disallowed and not destination_authorized:
            decision = Decision.BLOCK
            score = max(score, 75)
            reasons.append("Sensitive data is present and the destination is not authorized.")
        elif disallowed and not user_approved:
            if decision != Decision.BLOCK:
                decision = Decision.REVIEW
            score = max(score, 55)
            reasons.append("Sensitive-data transfer requires explicit user approval.")

        if not scan.findings and decision == Decision.ALLOW:
            reasons.append("No configured sensitive-data pattern was detected; this is not proof of safety.")
        elif scan.findings:
            reasons.append("Detected categories: " + ", ".join(scan.categories))

        if decision == Decision.BLOCK:
            action = "Do not send. Remove the sensitive value or use an approved secure workflow."
        elif decision == Decision.REVIEW:
            action = "Pause the transfer, inspect the redacted preview, and confirm recipient and purpose."
        else:
            action = "Proceed only if the destination and purpose are expected; continue monitoring."

        return SecurityResult(decision, min(score, 100), tuple(dict.fromkeys(reasons)), scan, action)


DEFAULT_ENGINE = SensitiveDataProtectionEngine()


def evaluate_outbound(content: str, destination: str, *, destination_authorized: bool = False,
                      user_approved: bool = False,
                      allow_sensitive_categories: Optional[set[DataCategory]] = None) -> SecurityResult:
    return DEFAULT_ENGINE.evaluate_outbound(
        content, destination, destination_authorized=destination_authorized,
        user_approved=user_approved, allow_sensitive_categories=allow_sensitive_categories,
    )
