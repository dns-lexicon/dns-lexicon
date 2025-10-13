"""Integration tests for deSEC"""
from unittest import TestCase
from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTestsV2
class DesecProviderTests(TestCase, IntegrationTestsV2):
    """Integration tests for deSEC provider"""

    provider_name = "desec"
    domain = "example.online"

    def _filter_headers(self):
        return ["Authorization"]

    def _test_fallback_fn(self):
        # Prevent conflict between login credentials and token
        return lambda x: None if x in ("auth_username", "auth_password") else f"placeholder_{x}"
