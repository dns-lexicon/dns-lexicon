from unittest import TestCase

from integration_tests import IntegrationTestsV2


class HetznerProviderTests(TestCase, IntegrationTestsV2):
    provider_name = "hetzner"
    domain = "devcoop.de"

    def _filter_headers(self):
        return ["Authorization"]
