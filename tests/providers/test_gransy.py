"""Integration tests for Gransy"""

import os
import re

import pytest
import requests
from integration_tests import IntegrationTestsV2

from lexicon._private.providers.gransy import SOAP_WSDL, SOAP_WSDL_URL


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestGransySOAPProvider(IntegrationTestsV2):
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
