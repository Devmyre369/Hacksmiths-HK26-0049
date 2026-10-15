import tempfile
import unittest
from pathlib import Path

from policy_manager import PolicyManager
from security_engine import DataCategory, Decision


class PolicyManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = PolicyManager()
        self.manager.add_trusted_destination("example.com")

    def test_trusted_https_destination_allows_non_sensitive_content(self):
        result = self.manager.evaluate("hello world", "https://example.com/api")
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertTrue(result.trusted_destination)

    def test_untrusted_destination_blocked_even_without_sensitive_data(self):
        result = self.manager.evaluate("hello world", "https://other.example/api")
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertFalse(result.trusted_destination)

    def test_deceptive_host_does_not_match_exact_allowlist(self):
        result = self.manager.evaluate("hello", "https://example.com.attacker.test/collect")
        self.assertEqual(result.decision, Decision.BLOCK)

    def test_http_url_blocked(self):
        result = self.manager.evaluate("hello", "http://example.com/api")
        self.assertEqual(result.decision, Decision.BLOCK)

    def test_url_embedded_credentials_blocked(self):
        result = self.manager.evaluate("hello", "https://user:pass@example.com/api")
        self.assertEqual(result.decision, Decision.BLOCK)

    def test_subdomains_require_explicit_opt_in(self):
        self.assertEqual(self.manager.evaluate("hello", "https://api.example.com").decision, Decision.BLOCK)
        self.manager.add_trusted_destination("example.com", allow_subdomains=True)
        self.assertEqual(self.manager.evaluate("hello", "https://api.example.com").decision, Decision.ALLOW)

    def test_sensitive_data_needs_approval_even_at_trusted_destination(self):
        result = self.manager.evaluate("Contact me at dev@example.org", "https://example.com/api")
        self.assertEqual(result.decision, Decision.REVIEW)
        approved = self.manager.evaluate("Contact me at dev@example.org", "https://example.com/api", user_approved=True)
        self.assertEqual(approved.decision, Decision.ALLOW)

    def test_critical_secret_blocked_even_if_approved(self):
        result = self.manager.evaluate('password="SuperSecretPassword123!"', "https://example.com/api", user_approved=True)
        self.assertEqual(result.decision, Decision.BLOCK)

    def test_category_allowlist_still_never_overrides_critical_block(self):
        self.manager.add_trusted_destination("example.com", allowed_categories=[DataCategory.EMAIL])
        email = self.manager.evaluate("dev@example.org", "https://example.com/api")
        self.assertEqual(email.decision, Decision.ALLOW)
        secret = self.manager.evaluate('password="SuperSecretPassword123!"', "https://example.com/api")
        self.assertEqual(secret.decision, Decision.BLOCK)

    def test_save_and_load_policy(self):
        self.manager.add_trusted_destination("sub.example.org", allow_subdomains=True, note="demo")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            self.manager.save(path)
            restored = PolicyManager.load(path)
            self.assertEqual(restored.evaluate("hello", "https://example.com").decision, Decision.ALLOW)
            self.assertEqual(restored.evaluate("hello", "https://api.sub.example.org").decision, Decision.ALLOW)

    def test_remove_trusted_destination(self):
        self.assertTrue(self.manager.remove_trusted_destination("example.com"))
        self.assertEqual(self.manager.evaluate("hello", "https://example.com").decision, Decision.BLOCK)


if __name__ == "__main__":
    unittest.main(verbosity=2)
