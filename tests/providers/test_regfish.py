"""Integration tests for Regfish"""

from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from define_tests.TheTests
class TestRegfishProvider(IntegrationTestsV2):
    """TestCase for Regfish"""

    provider_name = "regfish"
    domain = "regfish-dev.de"

    def _filter_headers(self):
        return ["x-api-key", "set-cookie"]
