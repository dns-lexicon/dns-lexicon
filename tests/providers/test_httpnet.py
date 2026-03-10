"""Integration tests for http.net provider"""

from integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestHttpnetProvider(IntegrationTestsV2):
    """Integration tests for httpnet provider"""

    provider_name = "httpnet"
    domain = "lexicon-example-domain.de"

    def _filter_post_data_parameters(self):
        return ["authToken"]

    def _filter_headers(self):
        return ["Authorization"]

    def _filter_query_parameters(self):
        return ["secret_key"]
