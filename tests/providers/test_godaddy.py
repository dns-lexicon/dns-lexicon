"""Integration tests for Goddady"""

from unittest import TestCase

import pytest

from integration_tests import IntegrationTestsV2


# TODO: Refresh these cassettes do re-enable the tests.
@pytest.mark.skip("Cassettes need to be refreshed")
class GoDaddyProviderTests(TestCase, IntegrationTestsV2):
    """TestCase for Godaddy"""

    provider_name = "godaddy"
    domain = "fullm3tal.online"

    def _filter_headers(self):
        return ["Authorization"]
