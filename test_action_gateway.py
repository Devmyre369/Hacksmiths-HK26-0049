"""Quick regression tests for AgentShield's application-level action gateway."""
import unittest

from action_gateway import ActionRequest, AgentActionGateway, demo_echo_handler
from security_engine import Decision


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.gateway = AgentActionGateway()
        self.calls = []

        def recording_handler(tool_name, destination, safe_content):
            self.calls.append(safe_content)
            return {"received": safe_content}

        self.gateway.register_tool("send_message", recording_handler)

    def test_critical_secret_is_blocked_before_handler(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message",
            content="password=DemoPassword123!",
            destination="https://example.com/send",
            destination_authorized=True,
            user_approved=True,
        ))
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertFalse(result.executed)
        self.assertEqual(self.calls, [])

    def test_unregistered_tool_is_blocked(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="unknown_tool",
            content="hello",
            destination="https://example.com",
        ))
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertFalse(result.executed)
        self.assertEqual(self.calls, [])

    def test_invalid_http_destination_is_blocked(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message",
            content="hello world",
            destination="http://example.com/send",
        ))
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertFalse(result.executed)
        self.assertEqual(self.calls, [])

    def test_safe_authorized_action_executes(self):
        result = self.gateway.execute(ActionRequest(
            tool_name="send_message",
            content="Hello team, the meeting starts at 3 PM.",
            destination="https://example.com/send",
            destination_authorized=True,
        ))
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertTrue(result.executed)
        self.assertEqual(len(self.calls), 1)

    def test_medium_sensitive_data_requires_approval(self):
        request = ActionRequest(
            tool_name="send_message",
            content="Contact dev@example.com about the meeting.",
            destination="https://example.com/send",
            destination_authorized=True,
            user_approved=False,
        )
        result = self.gateway.execute(request)
        self.assertEqual(result.decision, Decision.REVIEW)
        self.assertFalse(result.executed)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
