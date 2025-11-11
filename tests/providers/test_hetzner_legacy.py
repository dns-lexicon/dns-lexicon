"""Integration tests for Hetzner Legacy"""

from unittest import TestCase

from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class HetznerProviderTests(TestCase, IntegrationTestsV2):
    """TestCase for Hetzner Legacy"""

    provider_name = "hetzner_legacy"
    domain = "hetzner-api-test.de"

    def _filter_headers(self):
        return ["Auth-API-Token"]
