"""Unit tests for the record types that a provider takes"""

import pytest

from lexicon._private.discovery import load_provider_module
from lexicon.config import ConfigResolver


def _provider(name, rtype):
    config = ConfigResolver().with_dict(
        {
            "provider_name": name,
            "domain": "example.com",
            "type": rtype,
            # powerdns refuses to start without its API and a key for it.
            "powerdns": {
                "pdns_server": "http://127.0.0.1:8081",
                "auth_token": "placeholder",
            },
        }
    )
    return load_provider_module(name).Provider(config)


def test_a_provider_refuses_a_type_outside_its_list():
    with pytest.raises(ValueError, match="TLSA records are not supported"):
        _provider("cloudflare", "TLSA")


def test_a_provider_takes_a_type_in_its_list():
    assert _provider("cloudflare", "TXT")


def test_an_empty_list_takes_any_type():
    assert _provider("powerdns", "TLSA")


def test_a_provider_with_an_empty_list_does_not_open_the_others():
    load_provider_module("powerdns")
    with pytest.raises(ValueError, match="TLSA records are not supported"):
        _provider("cloudflare", "TLSA")


def test_an_action_without_a_type_is_not_refused():
    assert _provider("cloudflare", None)
