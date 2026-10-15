"""AgentShield trusted-destination and user-policy manager.

This is an application-level policy layer. It does not intercept traffic outside
AgentShield, verify a site's reputation, or guarantee that a remote service is safe.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlsplit

from security_engine import (
    DataCategory,
    Decision,
    SecurityResult,
    Severity,
    SensitiveDataProtectionEngine,
)


@dataclass(frozen=True)
class TrustedDestination:
    host: str
    allow_subdomains: bool = False
    allowed_categories: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class UserSecurityPolicy:
    """User-configurable guardrails. Defaults intentionally fail closed."""
    require_https: bool = True
    require_trusted_destination: bool = True
    block_critical_credentials: bool = True
    require_approval_for_sensitive_data: bool = True
    trusted_destinations: tuple[TrustedDestination, ...] = ()


@dataclass(frozen=True)
class PolicyEvaluation:
    decision: Decision
    risk_score: int
    reasons: tuple[str, ...]
    destination_host: Optional[str]
    trusted_destination: bool
    security_result: SecurityResult
    recommended_action: str


class PolicyManager:
    def __init__(
        self,
        policy: Optional[UserSecurityPolicy] = None,
        engine: Optional[SensitiveDataProtectionEngine] = None,
    ) -> None:
        self.policy = policy or UserSecurityPolicy()
        self.engine = engine or SensitiveDataProtectionEngine()

    @staticmethod
    def _normalize_host(host: str) -> str:
        value = host.strip().rstrip(".").lower()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("A valid hostname is required.")
        try:
            return value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Hostname is invalid.") from exc

    @classmethod
    def _parse_destination(cls, destination: str, require_https: bool = True) -> tuple[Optional[str], Optional[str]]:
        """Return (host, error). Reject credentials, malformed URLs and IP literals."""
        try:
            parsed = urlsplit(destination.strip())
            if parsed.scheme.lower() not in ({"https"} if require_https else {"https", "http"}):
                return None, "Destination must use HTTPS."
            if not parsed.netloc or parsed.hostname is None:
                return None, "Destination URL is malformed or has no hostname."
            if parsed.username is not None or parsed.password is not None:
                return None, "URLs containing embedded credentials are not allowed."
            # Accessing port catches malformed values such as example.com:abc.
            _ = parsed.port
            host = cls._normalize_host(parsed.hostname)
            try:
                ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                pass
            else:
                return None, "IP-literal destinations require a separately reviewed policy and are blocked by default."
            if "." not in host or host.startswith(".") or host.endswith("."):
                return None, "A fully qualified hostname is required."
            return host, None
        except (ValueError, AttributeError):
            return None, "Destination URL is malformed."

    def add_trusted_destination(
        self,
        host: str,
        *,
        allow_subdomains: bool = False,
        allowed_categories: Iterable[DataCategory | str] = (),
        note: str = "",
    ) -> None:
        normalized = self._normalize_host(host)
        try:
            ipaddress.ip_address(normalized.strip("[]"))
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses cannot be added as trusted hosts in this version.")
        if "/" in normalized or ":" in normalized or "@" in normalized:
            raise ValueError("Enter a hostname only, not a URL, path, port, or credentials.")
        categories = tuple(sorted({c.value if isinstance(c, DataCategory) else DataCategory(str(c).upper()).value for c in allowed_categories}))
        existing = [d for d in self.policy.trusted_destinations if d.host != normalized]
        existing.append(TrustedDestination(normalized, bool(allow_subdomains), categories, note.strip()))
        self.policy = UserSecurityPolicy(
            require_https=self.policy.require_https,
            require_trusted_destination=self.policy.require_trusted_destination,
            block_critical_credentials=self.policy.block_critical_credentials,
            require_approval_for_sensitive_data=self.policy.require_approval_for_sensitive_data,
            trusted_destinations=tuple(sorted(existing, key=lambda d: d.host)),
        )

    def remove_trusted_destination(self, host: str) -> bool:
        normalized = self._normalize_host(host)
        remaining = tuple(d for d in self.policy.trusted_destinations if d.host != normalized)
        changed = len(remaining) != len(self.policy.trusted_destinations)
        if changed:
            self.policy = UserSecurityPolicy(
                require_https=self.policy.require_https,
                require_trusted_destination=self.policy.require_trusted_destination,
                block_critical_credentials=self.policy.block_critical_credentials,
                require_approval_for_sensitive_data=self.policy.require_approval_for_sensitive_data,
                trusted_destinations=remaining,
            )
        return changed

    def _find_trusted(self, host: Optional[str]) -> Optional[TrustedDestination]:
        if host is None:
            return None
        for item in self.policy.trusted_destinations:
            if host == item.host or (item.allow_subdomains and host.endswith("." + item.host)):
                return item
        return None

    def evaluate(
        self,
        content: str,
        destination: str,
        *,
        user_approved: bool = False,
        purpose: str = "",
    ) -> PolicyEvaluation:
        host, parse_error = self._parse_destination(destination, self.policy.require_https)
        trusted = self._find_trusted(host)
        base = self.engine.evaluate_outbound(
            content,
            destination,
            destination_authorized=trusted is not None,
            user_approved=(user_approved or not self.policy.require_approval_for_sensitive_data),
            allow_sensitive_categories={DataCategory(c) for c in trusted.allowed_categories} if trusted else set(),
        )
        reasons = list(base.reasons)
        decision = base.decision
        score = base.risk_score

        if parse_error:
            decision = Decision.BLOCK
            score = max(score, 90)
            reasons.append(parse_error)
        elif self.policy.require_trusted_destination and trusted is None:
            decision = Decision.BLOCK
            score = max(score, 80)
            reasons.append("Destination host is not on the user's exact trusted-destination allowlist.")

        critical_present = any(f.severity == Severity.CRITICAL for f in base.scan.findings)
        if self.policy.block_critical_credentials and critical_present:
            decision = Decision.BLOCK
            score = max(score, 95)
            reasons.append("User policy blocks critical credentials regardless of destination trust or approval.")

        if purpose.strip():
            reasons.append("Declared purpose: " + " ".join(purpose.split())[:160])

        if decision == Decision.BLOCK:
            recommended = "Do not execute. Correct the destination or remove prohibited data."
        elif decision == Decision.REVIEW:
            recommended = "Pause and review the redacted preview, recipient, and purpose before approval."
        else:
            recommended = "Policy checks passed; the caller must still execute only the redacted content."

        return PolicyEvaluation(
            decision=decision,
            risk_score=min(score, 100),
            reasons=tuple(dict.fromkeys(reasons)),
            destination_host=host,
            trusted_destination=trusted is not None,
            security_result=base,
            recommended_action=recommended,
        )

    def save(self, path: str | Path) -> None:
        data = {
            "require_https": self.policy.require_https,
            "require_trusted_destination": self.policy.require_trusted_destination,
            "block_critical_credentials": self.policy.block_critical_credentials,
            "require_approval_for_sensitive_data": self.policy.require_approval_for_sensitive_data,
            "trusted_destinations": [
                {"host": d.host, "allow_subdomains": d.allow_subdomains,
                 "allowed_categories": list(d.allowed_categories), "note": d.note}
                for d in self.policy.trusted_destinations
            ],
        }
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path, engine: Optional[SensitiveDataProtectionEngine] = None) -> "PolicyManager":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        destinations = []
        for raw in data.get("trusted_destinations", []):
            host = cls._normalize_host(str(raw["host"]))
            categories = tuple(sorted({DataCategory(str(c).upper()).value for c in raw.get("allowed_categories", [])}))
            destinations.append(TrustedDestination(host, bool(raw.get("allow_subdomains", False)), categories, str(raw.get("note", ""))))
        policy = UserSecurityPolicy(
            require_https=bool(data.get("require_https", True)),
            require_trusted_destination=bool(data.get("require_trusted_destination", True)),
            block_critical_credentials=bool(data.get("block_critical_credentials", True)),
            require_approval_for_sensitive_data=bool(data.get("require_approval_for_sensitive_data", True)),
            trusted_destinations=tuple(destinations),
        )
        return cls(policy=policy, engine=engine)
