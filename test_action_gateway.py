"""Regression tests for the policy-integrated AgentShield Action Gateway."""
import unittest

from action_gateway import ActionRequest, AgentActionGateway
from policy_manager import PolicyManager
from security_engine import Decision


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyManager()
        self.policy.add_trusted_destination("example.com")
        self.gateway = AgentActionGateway(policy_manager=self.policy)
        self.calls = []

        def recording_handler(tool_name, destination, safe_content):
            self.calls.append(safe_content)
            return {"received": safe_content}

        self.gateway.register_tool("send_message", recording_handler)

    def test_critical_secret_is_blocked_before_handler(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message", content='password="SuperSecretPassword123!"',
            destination="https://example.com/send", user_approved=True,
        ))
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertFalse(result.executed)
        self.assertEqual(self.calls, [])

    def test_unregistered_tool_is_blocked(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="unknown_tool", content="hello", destination="https://example.com/send",
        ))
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertFalse(result.executed)
        self.assertEqual(self.calls, [])

    def test_http_destination_is_blocked(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message", content="hello world", destination="http://example.com/send",
        ))
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertFalse(result.executed)
        self.assertEqual(self.calls, [])

    def test_safe_content_executes_only_at_trusted_destination(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message", content="Hello team, meeting starts at 3 PM.",
            destination="https://example.com/send",
        ))
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertTrue(result.executed)
        self.assertEqual(len(self.calls), 1)

    def test_untrusted_host_cannot_be_overridden_by_request_flag(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message", content="hello world",
            destination="https://attacker.test/collect", destination_authorized=True,
        ))
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertFalse(result.executed)
        self.assertEqual(self.calls, [])

    def test_sensitive_data_requires_approval(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message", content="Contact dev@example.com about the meeting.",
            destination="https://example.com/send", user_approved=False,
        ))
        self.assertEqual(result.decision, Decision.REVIEW)
        self.assertFalse(result.executed)
        self.assertEqual(self.calls, [])

    def test_approved_sensitive_content_is_redacted_before_handler(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message", content="Contact dev@example.com about the meeting.",
            destination="https://example.com/send", user_approved=True,
        ))
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertTrue(result.executed)
        self.assertNotIn("dev@example.com", self.calls[0])

    def test_gateway_exposes_policy_reasons(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message", content="hello", destination="https://not-trusted.test/send",
        ))
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertIsNotNone(result.policy_evaluation)
        self.assertTrue(result.policy_evaluation.reasons)


if __name__ == "__main__":
    unittest.main(verbosity=2)
