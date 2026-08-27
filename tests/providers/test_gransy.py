"""Integration tests for Gransy"""

import os
import re

import pytest
import requests
from integration_tests import IntegrationTestsV2, vcr_integration_test

from lexicon._private.providers.gransy import SOAP_WSDL, SOAP_WSDL_URL


class GransyApexTests:
    """Apex records: the SOAP API names them None, the REST API ""."""

    @vcr_integration_test
    def test_provider_when_calling_create_record_for_TXT_with_apex_name_and_content(
        self,
    ):
        provider = self._construct_authenticated_provider()
        assert provider.create_record("TXT", self.domain, "apexchallengetoken")

    @vcr_integration_test
    def test_provider_when_calling_list_records_with_apex_name_filter_should_return_record(
        self,
    ):
        provider = self._construct_authenticated_provider()
        provider.create_record("TXT", self.domain, "apexlisttoken")
        records = provider.list_records("TXT", self.domain, "apexlisttoken")
        assert len(records) == 1
        assert records[0]["name"] == self.domain
        assert records[0]["content"] == "apexlisttoken"
        assert records[0]["type"] == "TXT"

    @vcr_integration_test
    def test_provider_when_calling_list_records_with_apex_fqdn_name_filter_should_return_record(
        self,
    ):
        provider = self._construct_authenticated_provider()
        provider.create_record("TXT", f"{self.domain}.", "apexfqdntoken")
        records = provider.list_records("TXT", f"{self.domain}.", "apexfqdntoken")
        assert len(records) == 1
        assert records[0]["name"] == self.domain

    @vcr_integration_test
    def test_provider_when_calling_update_record_to_apex_name_should_modify_record(
        self,
    ):
        provider = self._construct_authenticated_provider()
        assert provider.create_record("TXT", "orig.apextest", "apexrenametoken")
        records = provider.list_records("TXT", "orig.apextest", "apexrenametoken")
        assert provider.update_record(
            records[0].get("id", None), "TXT", self.domain, "apexrenametoken"
        )
        records = provider.list_records("TXT", self.domain, "apexrenametoken")
        assert len(records) == 1
        assert not provider.list_records("TXT", "orig.apextest", "apexrenametoken")

    @vcr_integration_test
    def test_provider_when_calling_update_record_with_apex_name_should_modify_record(
        self,
    ):
        provider = self._construct_authenticated_provider()
        assert provider.create_record("TXT", self.domain, "apexorigtoken")
        records = provider.list_records("TXT", self.domain, "apexorigtoken")
        assert provider.update_record(
            records[0].get("id", None), "TXT", self.domain, "apexupdatedtoken"
        )
        records = provider.list_records("TXT", self.domain, "apexupdatedtoken")
        assert len(records) == 1
        assert not provider.list_records("TXT", self.domain, "apexorigtoken")

    @vcr_integration_test
    def test_provider_when_calling_delete_record_by_filter_with_apex_name_should_remove_record(
        self,
    ):
        provider = self._construct_authenticated_provider()
        assert provider.create_record("TXT", self.domain, "apexdeletetoken")
        assert provider.delete_record(None, "TXT", self.domain, "apexdeletetoken")
        records = provider.list_records("TXT", self.domain, "apexdeletetoken")
        assert not records


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestGransySOAPProvider(GransyApexTests, IntegrationTestsV2):
    """TestCase for Gransy on SOAP API at subreg.cz"""

    provider_name = "gransy"
    domain = "oldium.xyz"
    provider_variant = "SOAP"

    def _test_fallback_fn(self):
        # A placeholder remote_api_definition would be truthy and go online
        return lambda x: None if x == "remote_api_definition" else f"placeholder_{x}"

    @staticmethod
    def _redact_soap(body: str) -> str:
        body = re.sub(
            r"<login>[^<]*</login>", "<login>placeholder_auth_username</login>", body
        )
        body = re.sub(
            r"<password>[^<]*</password>",
            "<password>placeholder_auth_password</password>",
            body,
        )
        return re.sub(r"<ssid>[^<]*</ssid>", "<ssid>placeholder_ssid</ssid>", body)

    def _filter_request(self, request):
        # Credentials and the session id travel in the SOAP body
        if request.body:
            request.body = self._redact_soap(request.body.decode())
        return request

    def _filter_response(self, response):
        # Login returns the session id; Domains_List lists the whole account
        body = self._redact_soap(response["body"]["string"].decode())
        if "<domains>" in body:
            body = re.sub(
                r"<domains>.*?</domains>",
                lambda m: (
                    m.group(0) if f"<name>{self.domain}</name>" in m.group(0) else ""
                ),
                body,
            )
            body = re.sub(
                r"<count>\d+</count>", f"<count>{body.count('<domains>')}</count>", body
            )
            body = re.sub(
                r"<expire>[^<]*</expire>", "<expire>2199-12-31</expire>", body
            )
        response["body"]["string"] = body.encode()
        return response


@pytest.mark.skipif(
    os.environ.get("LEXICON_LIVE_TESTS") != "true", reason="compares with the live WSDL"
)
def test_vendored_wsdl_matches_live():
    live = requests.get(SOAP_WSDL_URL, timeout=30).content
    assert live.splitlines() == SOAP_WSDL.read_bytes().splitlines(), (
        f"gransy.wsdl is outdated, refresh it from {SOAP_WSDL_URL}"
    )
