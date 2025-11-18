"""Integration tests for the Scaleway API provider"""

from integration_tests import IntegrationTestsV2, vcr_integration_test


class TestScalewayProvider(IntegrationTestsV2):
    """Integration tests for Scaleway provider"""

    provider_name = "scaleway"
    domain = "example.com"

    def _filter_headers(self):
        return ["X-Auth-Token"]

    @vcr_integration_test
    def test_provider_when_calling_list_records_should_return_empty_list_if_no_records_found(
        self,
    ):
        provider = self._construct_authenticated_provider()
        assert isinstance(provider.list_records(), list)

    @vcr_integration_test
    def test_provider_when_calling_list_records_with_arguments_should_filter_list(self):
        provider = self._construct_authenticated_provider()
        assert isinstance(provider.list_records(), list)
