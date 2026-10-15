
"""
AgentShield — Sensitive Data Protection Engine
Version: 1.0

Purpose:
- Detect sensitive information in text.
- Classify findings by severity.
- Assess outgoing data-transfer risk.
- Redact sensitive values.
- Return ALLOW, REVIEW, or BLOCK decisions.

This is a local, rule-based prototype. It does not replace a
production DLP gateway, antivirus, or endpoint security product.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


# ============================================================
# 1. SECURITY ENUMS
# ============================================================

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


# ============================================================
# 2. DATA MODELS
# ============================================================

@dataclass(frozen=True)
class Finding:
    """A detected sensitive-data finding.

    Never put the matched secret itself in this object.
    Store only its location, category, severity and safe metadata.
    """

    category: DataCategory
    severity: Severity
    start: int
    end: int
    description: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str = ""
    risk_score: int = 0

    @property
    def has_sensitive_data(self) -> bool:
        return bool(self.findings)

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None

        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }

        return max(
            (finding.severity for finding in self.findings),
            key=lambda severity: order[severity],
        )


@dataclass(frozen=True)
class SecurityResult:
    decision: Decision
    risk_score: int
    reasons: tuple[str, ...]
    scan: ScanResult


# ============================================================
# 3. DETECTION RULES
# ============================================================

# Each rule contains a category, severity, description and regex.
# Patterns are deliberately conservative: regex matches need
# context and validation before being treated as confirmed secrets.

PATTERNS = [
    (
        DataCategory.PRIVATE_KEY,
        Severity.CRITICAL,
        "Private-key material",
        re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?"
            r"PRIVATE KEY-----",
            re.IGNORECASE,
        ),
    ),
    (
        DataCategory.API_KEY,
        Severity.CRITICAL,
        "AWS access-key identifier",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        DataCategory.API_KEY,
        Severity.CRITICAL,
        "GitHub personal-access-token pattern",
        re.compile(
            r"\b(?:ghp_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,})\b"
        ),
    ),
    (
        DataCategory.API_KEY,
        Severity.CRITICAL,
        "Common cloud API-key pattern",
        re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    ),
    (
        DataCategory.ACCESS_TOKEN,
        Severity.HIGH,
        "Bearer authentication token",
        re.compile(
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"
        ),
    ),
    (
        DataCategory.PASSWORD,
        Severity.CRITICAL,
        "Password or secret assignment",
        re.compile(
            r"""(?i)\b(?:password|passwd|pwd|client_secret|"""
            r"""secret_key|api_secret)\b\s*[:=]\s*"""
            r"""(?:"[^"\r\n]{1,200}"|'[^'\r\n]{1,200}'|"""
            r"""[^\s,;]{6,200})"""
        ),
    ),
    (
        DataCategory.PAYMENT_CARD,
        Severity.HIGH,
        "Possible payment-card number",
        re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    ),
    (
        DataCategory.EMAIL,
        Severity.MEDIUM,
        "Email address",
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@"
            r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
    ),
    (
        DataCategory.PHONE,
        Severity.MEDIUM,
        "Possible international phone number",
        re.compile(
            r"(?<!\w)(?:\+\d{1,3}[-.\s]?)?"
            r"(?:\(?\d{2,5}\)?[-.\s]?)"
            r"\d{3,5}[-.\s]?\d{3,5}(?!\w)"
        ),
    ),
    (
        DataCategory.BANK_IDENTIFIER,
        Severity.HIGH,
        "Possible Indian bank account number",
        re.compile(
            r"(?i)\b(?:account\s*(?:number|no\.?)|"
            r"bank\s*account)\s*[:#-]?\s*\d{9,18}\b"
        ),
    ),
    (
        DataCategory.GOVERNMENT_ID,
        Severity.HIGH,
        "Possible Aadhaar number",
        re.compile(
            r"(?<!\d)(?:\d{4}[ -]){2}\d{4}(?!\d)"
        ),
    ),
    (
        DataCategory.IP_ADDRESS,
        Severity.LOW,
        "IPv4 address",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|"
            r"1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
    ),
    (
        DataCategory.CONFIDENTIAL_MARKER,
        Severity.HIGH,
        "Confidential document marker",
        re.compile(
            r"(?i)\b(?:"
            r"confidential|strictly confidential|"
            r"internal use only|do not distribute"
            r")\b"
        ),
    ),
]


# ============================================================
# 4. RISK SCORING
# ============================================================

SEVERITY_SCORES = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 45,
    Severity.CRITICAL: 70,
}


def calculate_risk(findings: list[Finding]) -> int:
    """Calculate a bounded score, avoiding duplicate overcounting."""

    if not findings:
        return 0

    # Combine the strongest finding with a modest additional
    # contribution for distinct findings.
    scores = sorted(
        (SEVERITY_SCORES[item.severity] for item in findings),
        reverse=True,
    )

    score = scores[0]

    for extra_score in scores[1:]:
        score += min(extra_score // 4, 10)

    return min(score, 100)


# ============================================================
# 5. SENSITIVE DATA SCANNER
# ============================================================

class SensitiveDataScanner:
    """Scans text locally and produces redacted output."""

    def __init__(self) -> None:
        self.patterns = PATTERNS

    @staticmethod
    def _is_valid_luhn(number: str) -> bool:
        """Validate a candidate card number using the Luhn check."""

        digits = re.sub(r"\D", "", number)

        if not 13 <= len(digits) <= 19:
            return False

        total = 0
        reverse_digits = digits[::-1]

        for index, char in enumerate(reverse_digits):
            value = int(char)

            if index % 2 == 1:
                value *= 2
                if value > 9:
                    value -= 9

            total += value

        return total % 10 == 0

    def scan(self, text: str) -> ScanResult:
        if not isinstance(text, str):
            raise TypeError("Text to scan must be a string.")

        if not text:
            return ScanResult(redacted_text="", risk_score=0)

        findings: list[Finding] = []
        occupied_spans: list[tuple[int, int]] = []

        # Run high-priority patterns first. Overlapping matches
        # are skipped to prevent repeated masking of the same span.
        for category, severity, description, pattern in self.patterns:
            for match in pattern.finditer(text):
                start, end = match.span()
                matched_value = match.group()

                if any(
                    start < previous_end and end > previous_start
                    for previous_start, previous_end in occupied_spans
                ):
                    continue

                if category == DataCategory.PAYMENT_CARD:
                    if not self._is_valid_luhn(matched_value):
                        continue

                # Avoid treating short, common phone-like numeric
                # fragments as personal information.
                if category == DataCategory.PHONE:
                    digit_count = sum(c.isdigit() for c in matched_value)
                    if not 10 <= digit_count <= 15:
                        continue

                findings.append(
                    Finding(
                        category=category,
                        severity=severity,
                        start=start,
                        end=end,
                        description=description,
                    )
                )
                occupied_spans.append((start, end))

        # Redact from right to left so offsets remain valid.
        redacted = text

        for finding in sorted(
            findings,
            key=lambda item: item.start,
            reverse=True,
        ):
            replacement = f"[REDACTED_{finding.category.value}]"
            redacted = (
                redacted[:finding.start]
                + replacement
                + redacted[finding.end:]
            )

        return ScanResult(
            findings=sorted(findings, key=lambda item: item.start),
            redacted_text=redacted,
            risk_score=calculate_risk(findings),
        )


# ============================================================
# 6. OUTBOUND DESTINATION CHECKS
# ============================================================

def is_https_destination(destination: str) -> bool:
    """Check basic URL syntax and require HTTPS.

    This does not establish that a destination is trustworthy.
    """

    try:
        parsed = urlparse(destination)
        return (
            parsed.scheme.lower() == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
        )
    except (ValueError, AttributeError):
        return False


# ============================================================
# 7. CENTRAL PROTECTION ENGINE
# ============================================================

class SensitiveDataProtectionEngine:
    """Evaluates whether an outgoing action should proceed.

    Important:
    This method makes a decision only. The caller must enforce
    that decision before performing any real network or tool action.
    """

    def __init__(self) -> None:
        self.scanner = SensitiveDataScanner()

    def evaluate_outbound(
        self,
        content: str,
        destination: str,
        *,
        destination_authorized: bool = False,
        user_approved: bool = False,
    ) -> SecurityResult:

        scan = self.scanner.scan(content)
        reasons: list[str] = []

        score = scan.risk_score
        decision = Decision.ALLOW

        if not destination:
            reasons.append("No destination was provided.")
            decision = Decision.REVIEW
            score = max(score, 30)

        elif not is_https_destination(destination):
            reasons.append(
                "Destination is not a valid HTTPS URL."
            )
            decision = Decision.BLOCK
            score = max(score, 85)

        if scan.has_sensitive_data:
            categories = sorted(
                {finding.category.value for finding in scan.findings}
            )
            reasons.append(
                "Sensitive data detected: " + ", ".join(categories)
            )

        if any(
            finding.severity == Severity.CRITICAL
            for finding in scan.findings
        ):
            decision = Decision.BLOCK
            score = max(score, 90)
            reasons.append(
                "Critical credential material must not be sent "
                "through this generic outbound path."
            )

        elif scan.has_sensitive_data:
            if not destination_authorized:
                decision = Decision.BLOCK
                score = max(score, 75)
                reasons.append(
                    "Sensitive information cannot be sent to an "
                    "unauthorized destination."
                )
            elif not user_approved:
                decision = Decision.REVIEW
                score = max(score, 50)
                reasons.append(
                    "User approval is required for this sensitive transfer."
                )

        if not reasons:
            reasons.append(
                "No configured sensitive-data rule was triggered."
            )

        return SecurityResult(
            decision=decision,
            risk_score=min(score, 100),
            reasons=tuple(reasons),
            scan=scan,
        )


# ============================================================
# 8. CONVENIENCE FUNCTIONS
# ============================================================

_default_scanner = SensitiveDataScanner()
_default_engine = SensitiveDataProtectionEngine()


def scan_sensitive_data(text: str) -> ScanResult:
    """Scan text and return findings plus a redacted preview."""

    return _default_scanner.scan(text)


def evaluate_outbound(
    content: str,
    destination: str,
    *,
    destination_authorized: bool = False,
    user_approved: bool = False,
) -> SecurityResult:
    """Evaluate an outgoing transfer without executing it."""

    return _default_engine.evaluate_outbound(
        content,
        destination,
        destination_authorized=destination_authorized,
        user_approved=user_approved,
    )
