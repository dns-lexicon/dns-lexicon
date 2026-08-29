"""Integration tests for Gransy"""

import json
import os
import re

import pytest
import requests
from integration_tests import IntegrationTestsV2, vcr_integration_test

import lexicon.client
from lexicon._private.providers.gransy import SOAP_WSDL, SOAP_WSDL_URL
from lexicon.config import ConfigResolver


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
        # Placeholders would route to REST (auth_token) or go online
        return lambda x: (
            None if x in ("auth_token", "remote_api_definition") else f"placeholder_{x}"
        )

    @pytest.fixture(autouse=True)
    def _drop_rest_env(self, monkeypatch):
        # A REST token in the environment would select the REST backend
        for var in ("LEXICON_GRANSY_AUTH_TOKEN", "LEXICON_GRANSY_TOKEN"):
            monkeypatch.delenv(var, raising=False)

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


class TestGransyRESTProvider(GransyApexTests, IntegrationTestsV2):
    """TestCase for Gransy on REST API at api.subreg.cz"""

    provider_name = "gransy"
    domain = "oldium.top"
    provider_variant = "REST"

    def _filter_headers(self):
        return ["Authorization"]

    def _filter_response(self, response):
        # GET /domains lists the whole account
        try:
            data = json.loads(response["body"]["string"])
        except ValueError:
            return response
        if isinstance(data, dict) and "domains" in data:
            data["domains"] = [
                {**d, "expire": "2199-12-31"}
                for d in data["domains"]
                if d["name"] == self.domain
            ]
            data["count"] = len(data["domains"])
            response["body"]["string"] = json.dumps(
                data, separators=(",", ":")
            ).encode()
        return response

    def _test_fallback_fn(self):
        # Prevent SOAP credentials conflict with the Bearer token.
        return lambda x: (
            None if x in ("auth_username", "auth_password") else f"placeholder_{x}"
        )

    @pytest.fixture(autouse=True)
    def _drop_soap_env(self, monkeypatch):
        # Keep the SOAP credentials out of the REST variant
        for var in (
            "LEXICON_GRANSY_AUTH_USERNAME",
            "LEXICON_GRANSY_USERNAME",
            "LEXICON_GRANSY_AUTH_PASSWORD",
            "LEXICON_GRANSY_PASSWORD",
        ):
            monkeypatch.delenv(var, raising=False)


def test_client_init_without_zeep_and_without_token_raises(monkeypatch):
    from lexicon import client as client_module
    from lexicon.exceptions import ProviderNotAvailableError

    monkeypatch.setattr(client_module, "_is_installed", lambda pkg: pkg != "zeep")
    options = {
        "provider_name": "gransy",
        "action": "list",
        "domain": "example.com",
        "type": "TXT",
    }
    with pytest.raises(ProviderNotAvailableError) as exc_info:
        lexicon.client.Client(ConfigResolver().with_dict(options))
    assert "--auth-token" in str(exc_info.value)


def test_client_init_without_zeep_with_token_does_not_raise(monkeypatch):
    from lexicon import client as client_module

    monkeypatch.setattr(client_module, "_is_installed", lambda pkg: pkg != "zeep")
    options = {
        "provider_name": "gransy",
        "action": "list",
        "domain": "example.com",
        "type": "TXT",
        "gransy": {"auth_token": "fake-token"},
    }
    lexicon.client.Client(ConfigResolver().with_dict(options))


@pytest.mark.skipif(
    os.environ.get("LEXICON_LIVE_TESTS") != "true", reason="compares with the live WSDL"
)
def test_vendored_wsdl_matches_live():
    live = requests.get(SOAP_WSDL_URL, timeout=30).content
    assert live.splitlines() == SOAP_WSDL.read_bytes().splitlines(), (
        f"gransy.wsdl is outdated, refresh it from {SOAP_WSDL_URL}"
    )
