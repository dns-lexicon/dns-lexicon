"""Integration tests for DevNomads"""

import pytest
from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestDevNomadsProvider(IntegrationTestsV2):
    """TestCase for DevNomads"""

    provider_name = "devnomads"
    domain = "example.nl"

    def _filter_headers(self):
        return ["Authorization"]

    @pytest.mark.skip(reason="new test, missing recording")
    def test_provider_when_calling_update_record_should_modify_record_name_specified(
        self,
    ):
        return
