"""AgentShield Action Gateway.

All supported tool actions should pass through this gateway before execution.
The gateway is deliberately fail-closed: missing policy context or a BLOCK/REVIEW
result prevents the registered handler from running.

This is an application-level prototype, not a system-wide network interceptor.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from security_engine import (
    Decision,
    SecurityResult,
    SensitiveDataProtectionEngine,
)


@dataclass(frozen=True)
class ActionRequest:
    tool_name: str
    content: str
    destination: str = ""
    destination_authorized: bool = False
    user_approved: bool = False


@dataclass(frozen=True)
class ActionExecutionResult:
    decision: Decision
    risk_score: int
    executed: bool
    message: str
    security_result: SecurityResult
    output: Any = None


ToolHandler = Callable[[str, str, str], Any]


class AgentActionGateway:
    """Policy-check and gate execution of explicitly registered tools."""

    def __init__(self, engine: Optional[SensitiveDataProtectionEngine] = None) -> None:
        self.engine = engine or SensitiveDataProtectionEngine()
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
        """Evaluate first; execute the handler only if policy returns ALLOW.

        The handler receives only the tool name, destination, and redacted content.
        The original content is deliberately not passed to handlers.
        """
        tool_name = request.tool_name.strip().lower()
        handler = self._handlers.get(tool_name)
        if handler is None:
            # No unregistered tool can be executed through this gateway.
            security_result = self.engine.evaluate_outbound(
                request.content,
                request.destination,
                destination_authorized=False,
                user_approved=False,
            )
            return ActionExecutionResult(
                decision=Decision.BLOCK,
                risk_score=max(85, security_result.risk_score),
                executed=False,
                message=f"Tool '{tool_name or '[empty]'}' is not registered; action blocked.",
                security_result=security_result,
            )

        security_result = self.engine.evaluate_outbound(
            request.content,
            request.destination,
            destination_authorized=request.destination_authorized,
            user_approved=request.user_approved,
        )

        if security_result.decision != Decision.ALLOW:
            return ActionExecutionResult(
                decision=security_result.decision,
                risk_score=security_result.risk_score,
                executed=False,
                message="Action was not executed because security policy did not return ALLOW.",
                security_result=security_result,
            )

        # Only redacted content is passed to the handler. The original request
        # remains available as metadata, so handlers must not transmit its content.
        try:
            output = handler(tool_name, request.destination, security_result.scan.redacted_text)
        except Exception as exc:  # prevent tool errors from being mistaken for success
            return ActionExecutionResult(
                decision=Decision.BLOCK,
                risk_score=security_result.risk_score,
                executed=False,
                message=f"Registered tool failed safely: {type(exc).__name__}.",
                security_result=security_result,
            )

        return ActionExecutionResult(
            decision=Decision.ALLOW,
            risk_score=security_result.risk_score,
            executed=True,
            message="Action passed policy and the registered handler executed.",
            security_result=security_result,
            output=output,
        )


def demo_echo_handler(tool_name: str, destination: str, safe_content: str) -> dict[str, str]:
    """Safe local demonstration handler; performs no network operations."""
    return {
        "tool": tool_name,
        "destination": destination,
        "content_received_by_handler": safe_content,
    }
