"""Integration tests for Goddady"""

from unittest import TestCase

from integration_tests import IntegrationTestsV2

class GoDaddyProviderTests(TestCase, IntegrationTestsV2):
    """TestCase for Godaddy"""

    provider_name = "godaddy"
    domain = "fullm3tal.online"

    def _filter_headers(self):
        return ["Authorization"]
