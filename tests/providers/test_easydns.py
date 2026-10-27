"""Integration tests for EasyDNS

To record against the easyDNS sandbox, set LEXICON_EASYDNS_DOMAIN to a domain of
the sandbox account, beside its LEXICON_EASYDNS_AUTH_USERNAME and
LEXICON_EASYDNS_AUTH_TOKEN, and LEXICON_EASYDNS_API_ENDPOINT to
https://sandbox.rest.easydns.net.  The recordings name easydnstemp.com and the
endpoint below in their place.
"""

import os

import pytest
from integration_tests import IntegrationTestsV1, vcr_integration_test

from lexicon.config import DictConfigSource

RECORDED_DOMAIN = "easydnstemp.com"
RECORDED_ENDPOINT = "http://sandbox.rest.easydns.net"


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from define_tests.TheTests
# TODO: migrate to IntegrationTestsV2 and its extended test suite
class TestEasyDnsProvider(IntegrationTestsV1):
    """TestCase for EasyDNS"""

    provider_name = "easydns"

    @property
    def domain(self):
        return os.environ.get("LEXICON_EASYDNS_DOMAIN") or RECORDED_DOMAIN

    @property
    def endpoint(self):
        return os.environ.get("LEXICON_EASYDNS_API_ENDPOINT") or RECORDED_ENDPOINT

    def _test_parameters_overrides(self):
        return {"api_endpoint": self.endpoint}

    def _filter_headers(self):
        return ["Authorization"]

    def _filter_query_parameters(self):
        return ["_key", "_user"]

    def _filter_request(self, request):
        uri = request.uri.replace(self.endpoint, RECORDED_ENDPOINT)
        request.uri = uri.replace(self.domain, RECORDED_DOMAIN)
        if isinstance(request.body, bytes):
            request.body = request.body.replace(
                self.domain.encode(), RECORDED_DOMAIN.encode()
            )
        elif isinstance(request.body, str):
            request.body = request.body.replace(self.domain, RECORDED_DOMAIN)
        return request

    def _filter_response(self, response):
        body = response["body"]["string"]
        response["body"]["string"] = body.replace(
            self.domain.encode(), RECORDED_DOMAIN.encode()
        )
        return response

    def _listed(self, provider, rtype, name):
        return [record["content"] for record in provider.list_records(rtype, name)]

    @vcr_integration_test
    def test_provider_when_calling_create_record_for_MX_with_priority_in_content(
        self,
    ):
        provider = self._construct_authenticated_provider()
        content = f"10 mail.{self.domain}."
        assert provider.create_record("MX", "mx.inline", content)
        assert self._listed(provider, "MX", "mx.inline") == [content]
        assert provider.delete_record(None, "MX", "mx.inline", content)

    @vcr_integration_test
    def test_provider_when_calling_create_record_for_MX_with_priority_option(
        self,
    ):
        config = self._test_config()
        config.add_config_source(DictConfigSource({"priority": "20"}), 0)
        provider = self.provider_module.Provider(config)
        provider.authenticate()
        assert provider.create_record("MX", "mx.option", f"mail.{self.domain}.")
        assert self._listed(provider, "MX", "mx.option") == [f"20 mail.{self.domain}."]
        assert provider.delete_record(None, "MX", "mx.option")

    @vcr_integration_test
    def test_provider_when_calling_create_record_for_SRV_with_priority_in_content(
        self,
    ):
        provider = self._construct_authenticated_provider()
        content = f"0 5 993 mail.{self.domain}."
        assert provider.create_record("SRV", "_imaps._tcp.srv", content)
        assert self._listed(provider, "SRV", "_imaps._tcp.srv") == [content]
        assert provider.delete_record(None, "SRV", "_imaps._tcp.srv", content)

    @vcr_integration_test
    def test_provider_when_calling_update_record_should_modify_MX_priority(self):
        provider = self._construct_authenticated_provider()
        assert provider.create_record("MX", "mx.update", f"10 mail.{self.domain}.")
        (record,) = provider.list_records("MX", "mx.update")
        content = f"30 mail.{self.domain}."
        assert provider.update_record(record["id"], "MX", "mx.update", content)
        assert self._listed(provider, "MX", "mx.update") == [content]
        assert provider.delete_record(record["id"])

    @pytest.mark.skip(reason="new test, missing recording")
    def test_provider_when_calling_update_record_should_modify_record_name_specified(
        self,
    ):
        return
