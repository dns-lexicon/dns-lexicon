# coding: utf-8
# Copyright (c) 2016, Jason Kulatunga
# Copyright (c) 2021, Oracle and/or its affiliates.
import os
import re

import pytest
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

try:
    from oci.auth.signers import InstancePrincipalsSecurityTokenSigner  # type: ignore
except ImportError:
    pass

from integration_tests import IntegrationTestsV2


class MockSigner(requests.auth.AuthBase):
    """Mock client-side no-op signer."""

    def __init__(self):
        self.region = "us-ashburn-1"

    def __call__(self, r):
        return r


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class TestOciProvider(IntegrationTestsV2):
    """Integration tests for OCI provider using API key authentication."""

    provider_name = "oci"
    domain = "lexicon-test.com"

    @pytest.fixture(autouse=True)
    def test_mock_signer(self, monkeypatch):
        """Enable the mock signer when not testing live."""

        if os.environ.get("LEXICON_LIVE_TESTS", "false") == "false":
            monkeypatch.setattr(
                InstancePrincipalsSecurityTokenSigner, "__init__", MockSigner.__init__
            )
            monkeypatch.setattr(
                InstancePrincipalsSecurityTokenSigner, "__call__", MockSigner.__call__
            )

    @pytest.fixture(autouse=True)
    def test_key_file(self, tmp_path):
        """Create a valid private key to test provider validation."""
        key_file = tmp_path / "oci_api_key.pem"
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        key_file.write_text(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8"),
            encoding="utf-8",
        )
        self.key_file = str(key_file)

    # Provide credentials that conform to requirements to test validation
    def _test_parameters_overrides(self):
        return {
            "auth_type": "api_key",
            "auth_user": "ocid1.user.oc1..0a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c",
            "auth_tenancy": "ocid1.tenancy.oc1..0d1d2d3d4d5d6d7d8d9d0e1e2e3e4e5e6e7e8e9e0f1f2f3f4f5f6f7f8f9f",
            "auth_fingerprint": "aa:00:bb:11:cc:22:dd:33:ee:44:ff:55:00:66:77:88",
            "auth_key_file": self.key_file,
        }

    def _test_fallback_fn(self):
        return lambda _: None

    def _filter_headers(self):
        return ["authorization", "x-content-sha256"]

    def _filter_response(self, response):
        response["body"]["string"] = re.sub(
            rb'"compartmentId":"[\w.-]+"',
            b'"compartmentId":"OCI-COMPARTMENT-ID"',
            response["body"]["string"],
        )
        response["body"]["string"] = re.sub(
            rb'"id":"[\w.-]+"',
            b'"id":"DNS-ZONE-ID"',
            response["body"]["string"],
        )
        response["body"]["string"] = re.sub(
            rb'"CreatedBy":"[\w.-\/@]+"',
            b'"CreatedBy":"USER-ID"',
            response["body"]["string"],
        )

        return response


class TestOciInstancePrincipalProvider(TestOciProvider):
    """Integration tests for OCI Provider using instance principal authentication."""

    provider_variant = "instance_principal"

    def _test_parameters_overrides(self):
        return {"auth_type": "instance_principal"}
