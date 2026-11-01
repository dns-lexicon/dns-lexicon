"""Integration tests for DNSSimple"""

from unittest import mock

from integration_tests import IntegrationTestsV2

from lexicon._private.providers.dnsimple import Provider
from lexicon.config import ConfigResolver


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from define_tests.TheTests
class TestDnsimpleProvider(IntegrationTestsV2):
    """TestCase for DNSSimple"""

    provider_name = "dnsimple"
    domain = "lexicontest.us"

    def _test_parameters_overrides(self):
        return {
            "api_endpoint": "https://api.sandbox.dnsimple.com/v2",
            "region": "global",
        }

    def _filter_headers(self):
        return ["Authorization", "set-cookie", "X-Dnsimple-OTP"]


# DNSimple returns TXT content wrapped in double quotes. The recorded cassettes
# above predate that behaviour, so these tests feed the provider such a payload.
QUOTED_TXT_PAYLOAD = [
    {
        "id": 1,
        "type": "TXT",
        "name": "_acme-challenge",
        "ttl": 3600,
        "content": '"challengetoken"',
        "priority": None,
    },
    {
        "id": 2,
        "type": "TXT",
        "name": "_acme-challenge",
        "ttl": 3600,
        "content": '"othertoken"',
        "priority": None,
    },
]


def _provider():
    config = ConfigResolver().with_dict(
        {
            "provider_name": "dnsimple",
            "domain": "lexicontest.us",
            "dnsimple": {"auth_token": "fake"},
        }
    )
    provider = Provider(config)
    provider.account_id = "1"
    return provider


def test_list_records_strips_quotes_from_txt_content():
    provider = _provider()
    with mock.patch.object(Provider, "_get", return_value=QUOTED_TXT_PAYLOAD):
        records = provider.list_records("TXT", "_acme-challenge")

    assert [record["content"] for record in records] == [
        "challengetoken",
        "othertoken",
    ]


def test_list_records_filters_quoted_txt_by_unquoted_content():
    provider = _provider()
    with mock.patch.object(Provider, "_get", return_value=QUOTED_TXT_PAYLOAD):
        records = provider.list_records("TXT", "_acme-challenge", "challengetoken")

    assert [record["id"] for record in records] == [1]


def test_delete_record_by_content_removes_quoted_txt_record():
    provider = _provider()
    with (
        mock.patch.object(Provider, "_get", return_value=QUOTED_TXT_PAYLOAD),
        mock.patch.object(Provider, "_delete") as delete,
    ):
        assert provider.delete_record(None, "TXT", "_acme-challenge", "challengetoken")

    delete.assert_called_once_with("/1/zones/lexicontest.us/records/1")
