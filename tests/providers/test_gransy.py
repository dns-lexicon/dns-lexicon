"""Integration tests for Gransy"""

from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestGransySOAPProvider(IntegrationTestsV2):
    """TestCase for Gransy on SOAP API at subreg.cz"""

    provider_name = "gransy"
    domain = "oldium.xyz"
    provider_variant = "SOAP"
