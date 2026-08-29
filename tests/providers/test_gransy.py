"""Integration tests for Gransy"""

import os

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


@pytest.mark.skipif(
    os.environ.get("LEXICON_LIVE_TESTS") != "true", reason="compares with the live WSDL"
)
def test_vendored_wsdl_matches_live():
    live = requests.get(SOAP_WSDL_URL, timeout=30).content
    assert live.splitlines() == SOAP_WSDL.read_bytes().splitlines(), (
        f"gransy.wsdl is outdated, refresh it from {SOAP_WSDL_URL}"
    )
