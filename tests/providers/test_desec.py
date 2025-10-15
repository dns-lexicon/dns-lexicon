"""Integration tests for deSEC"""
from unittest import TestCase
from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTestsV2
class DesecProviderTests(TestCase, IntegrationTestsV2):
    """Integration tests for deSEC provider"""

    provider_name = "desec"
    domain = "example.xxx"

    def _filter_headers(self):
        return ["Authorization"]

    def _test_fallback_fn(self):
        # Prevent conflict between login credentials and token
        return lambda x: None if x in ("auth_username", "auth_password") else f"placeholder_{x}"

    def _filter_response(self, response):
        # Remove retry requests/responses
        # Otherwise the test rerun might sleep for the "retry-after" header's value
        if response["status"]["code"] == 429:
            return None

        # Filter dnssec keys / tokens
        content = response["body"]["string"]
        if (b"dnskey" in content) or (b"token" in content):
            response["body"]["string"] = b"{}"
            return response

        return response
