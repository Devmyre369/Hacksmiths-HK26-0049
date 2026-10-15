"""AgentShield Action Gateway with trusted-destination policy enforcement.

This is an application-level prototype. It gates only actions routed through
registered handlers; it is not a system-wide network interceptor.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from policy_manager import PolicyEvaluation, PolicyManager
from security_engine import Decision, SecurityResult, SensitiveDataProtectionEngine


@dataclass(frozen=True)
class ActionRequest:
    tool_name: str
    content: str
    destination: str = ""
    # Kept for backward compatibility. Trusted status is determined by PolicyManager,
    # not by this caller-supplied flag.
    destination_authorized: bool = False
    user_approved: bool = False
    purpose: str = ""


@dataclass(frozen=True)
class ActionExecutionResult:
    decision: Decision
    risk_score: int
    executed: bool
    message: str
    security_result: SecurityResult
    output: Any = None
    policy_evaluation: Optional[PolicyEvaluation] = None


ToolHandler = Callable[[str, str, str], Any]


class AgentActionGateway:
    """Check policy before executing any explicitly registered tool."""

    def __init__(
        self,
        engine: Optional[SensitiveDataProtectionEngine] = None,
        policy_manager: Optional[PolicyManager] = None,
    ) -> None:
        if policy_manager is not None and engine is not None and policy_manager.engine is not engine:
            raise ValueError("Pass either a shared engine or a policy manager; their engines must match.")
        self.policy_manager = policy_manager or PolicyManager(engine=engine)
        self.engine = self.policy_manager.engine
        self._handlers: dict[str, ToolHandler] = {}

    def register_tool(self, name: str, handler: ToolHandler) -> None:
        normalized = name.strip().lower()
        if not normalized or not normalized.replace("_", "").isalnum():
            raise ValueError("Tool names may contain only letters, numbers, and underscores.")
        if not callable(handler):
            raise TypeError("Tool handler must be callable.")
        self._handlers[normalized] = handler

    def available_tools(self) -> list[str]:
        return sorted(self._handlers)

    def execute(self, request: ActionRequest) -> ActionExecutionResult:
        """Evaluate allowlist + data policy; execute only ALLOW actions.

        Registered handlers receive only redacted text, never the original input.
        Caller-supplied destination_authorized is intentionally not used as proof
        of trust; the policy manager's exact-host allowlist is authoritative.
        """
        tool_name = request.tool_name.strip().lower()
        handler = self._handlers.get(tool_name)

        if handler is None:
            evaluation = self.policy_manager.evaluate(
                request.content, request.destination,
                user_approved=False, purpose=request.purpose,
            )
            return ActionExecutionResult(
                decision=Decision.BLOCK,
                risk_score=max(85, evaluation.risk_score),
                executed=False,
                message=f"Tool '{tool_name or '[empty]'}' is not registered; action blocked.",
                security_result=evaluation.security_result,
                policy_evaluation=evaluation,
            )

        evaluation = self.policy_manager.evaluate(
            request.content,
            request.destination,
            user_approved=request.user_approved,
            purpose=request.purpose,
        )
        security_result = evaluation.security_result
        if evaluation.decision != Decision.ALLOW:
            return ActionExecutionResult(
                decision=evaluation.decision,
                risk_score=evaluation.risk_score,
                executed=False,
                message="Action was not executed because the policy did not return ALLOW.",
                security_result=security_result,
                policy_evaluation=evaluation,
            )

        try:
            output = handler(tool_name, request.destination, security_result.scan.redacted_text)
        except Exception as exc:
            return ActionExecutionResult(
                decision=Decision.BLOCK,
                risk_score=evaluation.risk_score,
                executed=False,
                message=f"Registered tool failed safely: {type(exc).__name__}.",
                security_result=security_result,
                policy_evaluation=evaluation,
            )

        return ActionExecutionResult(
            decision=Decision.ALLOW,
            risk_score=evaluation.risk_score,
            executed=True,
            message="Action passed destination and data policies; registered handler executed.",
            security_result=security_result,
            output=output,
            policy_evaluation=evaluation,
        )


def demo_echo_handler(tool_name: str, destination: str, safe_content: str) -> dict[str, str]:
    """Safe local demonstration handler; performs no network operations."""
    return {
        "tool": tool_name,
        "destination": destination,
        "content_received_by_handler": safe_content,
    }
