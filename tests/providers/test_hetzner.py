from unittest import TestCase

"""Integration tests for Hetzner"""

import pytest
from integration_tests import IntegrationTestsV2


class HetznerProviderTests(TestCase, IntegrationTestsV2):
    """TestCase for Hetzner"""

    provider_name = "hetzner"
    domain = "devcoop.de"

    def _filter_headers(self):
        return ["Authorization"]

    def _test_parameters_overrides(self):
        return {"retry_wait_time": 1}

    @pytest.mark.skip(reason="manipulating records by id is not supported")
    def test_provider_when_calling_delete_record_by_identifier_should_remove_record(
        self,
    ):
        return

    @pytest.mark.skip(reason="manipulating records by id is not supported")
    def test_provider_when_calling_update_record_should_modify_record(self):
        return

    @pytest.mark.skip(reason="manipulating records by id is not supported")
    def test_provider_when_calling_update_record_with_fqdn_name_should_modify_record(
        self,
    ):
        return

    @pytest.mark.skip(reason="manipulating records by id is not supported")
    def test_provider_when_calling_update_record_with_full_name_should_modify_record(
        self,
    ):
        return
