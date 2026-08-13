"""Integration tests for OVH"""

import os

from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestOvhProvider(IntegrationTestsV2):
    """TestCase for OVH"""

    provider_name = "ovh"
    # Default domain matches the recorded cassettes. Override with the
    # LEXICON_OVH_DOMAIN environment variable to run live tests
    # (LEXICON_LIVE_TESTS=true) against a domain you actually own.
    domain = os.environ.get("LEXICON_OVH_DOMAIN", "example.com")

    def _filter_headers(self):
        return ["X-Ovh-Application", "X-Ovh-Consumer", "X-Ovh-Signature"]

    def _test_parameters_overrides(self):
        return {"auth_entrypoint": "ovh-eu"}
