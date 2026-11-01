"""Unit tests for the OAuth2 (service account) authentication of the OVH provider"""

from unittest import mock

import pytest

from lexicon._private.providers import ovh
from lexicon.config import ConfigResolver
from lexicon.exceptions import AuthenticationError


def _config(**options):
    return ConfigResolver().with_dict(
        {"provider_name": "ovh", "domain": "example.com", "ovh": options}
    )


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise ovh.requests.HTTPError(f"{self.status_code} Client Error")


class FakeSession:
    """Answers the token endpoint and the zone API; the first API token can be expired."""

    def __init__(self, expired_first_token=False, token_status=200):
        self.tokens = 0
        self.token_status = token_status
        self.expired_first_token = expired_first_token
        self.calls = []

    def post(self, url, data=None):
        self.calls.append(("POST", url, data))
        self.tokens += 1
        return FakeResponse(
            self.token_status,
            {"access_token": f"token{self.tokens}", "expires_in": 3599},
        )

    def get(self, url):
        self.calls.append(("GET", url, None))
        raise AssertionError("OAuth2 must not ask for the server time")

    def request(self, method, url, params=None, data=None, headers=None):
        self.calls.append((method, url, dict(headers)))
        if self.expired_first_token and headers["Authorization"] == "Bearer token1":
            return FakeResponse(401, {"message": "token expired"})
        if url.endswith("/domain/zone/"):
            return FakeResponse(200, ["example.com"])
        if url.endswith("/status"):
            return FakeResponse(200, {"isDeployed": True})
        return FakeResponse(200, [])


def _provider(session, **options):
    options = {"auth_entrypoint": "ovh-eu", **options}
    provider = ovh.Provider(_config(**options))
    with mock.patch.object(ovh.requests, "Session", return_value=session):
        provider.authenticate()
    return provider


def test_oauth2_uses_bearer_token_and_no_signature():
    session = FakeSession()
    provider = _provider(session, auth_client_id="id", auth_client_secret="secret")
    assert provider.list_records("TXT") == []
    method, url, data = session.calls[0]
    assert (method, url) == ("POST", "https://www.ovh.com/auth/oauth2/token")
    assert data == {
        "grant_type": "client_credentials",
        "client_id": "id",
        "client_secret": "secret",
        "scope": "all",
    }
    api_calls = [c for c in session.calls if c[0] != "POST"]
    assert api_calls[0][1] == "https://eu.api.ovh.com/1.0/domain/zone/example.com/status"
    for _, _, headers in api_calls:
        assert headers["Authorization"] == "Bearer token1"
        assert "X-Ovh-Signature" not in headers


def test_oauth2_token_endpoint_follows_entrypoint():
    session = FakeSession()
    _provider(
        session,
        auth_entrypoint="ovh-ca",
        auth_client_id="id",
        auth_client_secret="secret",
    )
    assert session.calls[0][1] == "https://ca.ovh.com/auth/oauth2/token"


def test_oauth2_expired_token_is_renewed_once():
    session = FakeSession(expired_first_token=True)
    provider = _provider(session, auth_client_id="id", auth_client_secret="secret")
    assert provider.domain_id == "example.com"
    assert session.tokens == 2


def test_oauth2_bad_credentials():
    session = FakeSession(token_status=401)
    with pytest.raises(AuthenticationError):
        _provider(session, auth_client_id="id", auth_client_secret="wrong")


def test_oauth2_not_available_for_kimsufi():
    with pytest.raises(Exception, match="not available for kimsufi-eu"):
        ovh.Provider(
            _config(
                auth_entrypoint="kimsufi-eu",
                auth_client_id="id",
                auth_client_secret="secret",
            )
        )


def test_oauth2_requires_both_parts():
    with pytest.raises(Exception, match="client secret is not defined"):
        ovh.Provider(_config(auth_entrypoint="ovh-eu", auth_client_id="id"))


def test_application_key_still_required_without_oauth2():
    with pytest.raises(Exception, match="application key is not defined"):
        ovh.Provider(_config(auth_entrypoint="ovh-eu"))


def test_application_key_wins_when_both_are_given():
    provider = ovh.Provider(
        _config(
            auth_entrypoint="ovh-eu",
            auth_application_key="ak",
            auth_application_secret="as",
            auth_consumer_key="ck",
            auth_client_id="id",
            auth_client_secret="secret",
        )
    )
    assert not provider.oauth2
