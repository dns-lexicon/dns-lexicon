"""Integration tests for Dynu.com"""

from unittest.mock import patch

from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestDynuProvider(IntegrationTestsV2):
    """TestCase for Dynu.com"""

    provider_name = "dynu"
    domain = "example.com"

    def _filter_headers(self):
        return ["API-Key"]

    def _filter_response(self, response):
        if response["status"]["code"] not in [200, 503]:
            return None
        return response

    # Dynu returns the domain name in the case it was registered with.
    def test_provider_when_root_domain_has_mixed_case_should_resolve_names(self):
        provider = self.provider_module.Provider(self._test_config())
        with patch.object(provider, "_get", return_value={"domainName": "ExAmple.com"}):
            assert (
                provider._relative_name("_acme-challenge.example.com.")
                == "_acme-challenge"
            )
            assert (
                provider._full_name("_acme-challenge") == "_acme-challenge.example.com"
            )
            assert (
                provider._full_name("_acme-challenge.Example.com")
                == "_acme-challenge.example.com"
            )
