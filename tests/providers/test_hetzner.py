"""Integration tests for Hetzner"""

from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestHetznerProvider(IntegrationTestsV2):
    """TestCase for Hetzner"""

    provider_name = "hetzner"
    domain = "hetzner-api-test.de"

    def _filter_headers(self):
        return ["Auth-API-Token"]
