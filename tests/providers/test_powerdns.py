"""Integration tests for PowerDNS"""

import pytest
from integration_tests import IntegrationTestsV2

from lexicon._private.providers.powerdns import Provider
from lexicon.config import ConfigResolver


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestPowerdnsProvider(IntegrationTestsV2):
    """TestCase for PowerDNS"""

    provider_name = "powerdns"
    domain = "sometestdomain.com"

    def _filter_headers(self):
        return ["X-API-Key"]

    def _test_parameters_overrides(self):
        return {"pdns_server": "http://127.0.0.1:8081", "pdns_server_id": "localhost"}

    # TODO: enable the skipped tests
    @pytest.mark.skip(reason="new test, missing recording")
    def test_provider_when_calling_update_record_should_modify_record_name_specified(
        self,
    ):
        return

    def test_identifier_keeps_a_content_that_holds_a_slash(self):
        """The base64 of a DKIM key holds slashes and equals signs."""
        provider = Provider(
            ConfigResolver().with_dict(
                {
                    "provider_name": "powerdns",
                    "domain": "sometestdomain.com",
                    "powerdns": {
                        "auth_token": "placeholder",
                        "pdns_server": "http://127.0.0.1:8081",
                    },
                }
            )
        )
        content = "v=DKIM1; k=rsa; p=MIIBIjAN/BgkqhkiG9w0B+AQEFAAOCAQ8A/MIIBCgKCAQEA=="
        identifier = provider._make_identifier(
            "TXT", "default._domainkey.sometestdomain.com.", content
        )
        assert provider._parse_identifier(identifier) == (
            "TXT",
            "default._domainkey.sometestdomain.com.",
            content,
        )

    def test_provider_when_writing_a_cname_keeps_an_absolute_target(self):
        provider = self.provider_module.Provider(self._test_config())
        assert (
            provider._clean_content("CNAME", "other.example.com.")
            == "other.example.com."
        )
        assert provider._clean_content("CNAME", "docs") == "docs.sometestdomain.com."

    def test_provider_when_reading_a_cname_keeps_a_target_outside_the_zone(self):
        provider = self.provider_module.Provider(self._test_config())
        assert (
            provider._unclean_content("CNAME", "other.example.com.")
            == "other.example.com"
        )
        assert (
            provider._unclean_content("CNAME", "docs.sometestdomain.com.")
            == "docs.sometestdomain.com"
        )
