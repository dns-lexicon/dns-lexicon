"""Module provider for Scaleway
Documentation about Domains and DNS APIs for Scaleway can be found in
https://www.scaleway.com/en/developers/api/domains-and-dns
Documentation to obtain an API key can be found in
https://www.scaleway.com/en/developers/api/
"""

import json
from argparse import ArgumentParser
from typing import List

import requests

from lexicon.interfaces import Provider as BaseProvider


class Provider(BaseProvider):
    """
    Provide Scaleway Domains and DNS API Implementation for lexicon.
    """

    @staticmethod
    def get_nameservers() -> List[str]:
        return ["scw.cloud"]

    @staticmethod
    def configure_parser(parser: ArgumentParser) -> None:
        parser.add_argument(
            "--auth-secret-key",
            help="specify Scaleway API key",
        )

    def __init__(self, config):
        super(Provider, self).__init__(config)
        self.default_ttl = 3600
        self.endpoint = "https://api.scaleway.com/domain/v2beta1"

    def authenticate(self):
        self.domain_id = self.domain.lower()
        self._get(self._records_url())

    def create_record(self, rtype, name, content):
        records = self.list_records(rtype, name, content)
        if records:
            return True
        patch = {
            "changes": [
                {
                    "add": {
                        "records": [
                            {
                                "name": name,
                                "data": content,
                                "type": rtype,
                                "ttl": self._get_lexicon_option("ttl")
                                or self.default_ttl,
                            },
                        ],
                    },
                },
            ],
        }
        self._patch(self._records_url(), patch)
        return True

    def list_records(self, rtype=None, name=None, content=None):
        # Up to 20 records are listed with default page-size, we need to request all pages.
        page = 1
        total = 0
        records = []
        while page == 1 or len(records) < total:
            results = self._get(self._records_url() + f"?page={page}")
            for result in results["records"]:
                record = {
                    "id": result["id"],
                    "type": result["type"],
                    "name": self._full_name(result["name"]),
                    "ttl": result["ttl"],
                    "content": self._decode_content(result["type"], result["data"]),
                }
                records.append(record)

            total = results["total_count"]
            page += 1
        return self._filter_records(records, rtype, name, content)

    @staticmethod
    def _decode_content(rtype, data):
        if not data or rtype != "TXT":
            return data
        if data[0] == '"' and data[len(data) - 1] == '"':
            return (
                data[1:-1].replace('" "', "").replace('\\"', '"').replace("\\\\", "\\")
            )
        return data

    def _filter_records(self, records, rtype=None, name=None, content=None):
        if not rtype and not name and not content:
            return records

        filtered = []
        for record in records:
            if rtype and record["type"] != rtype:
                continue
            if name and record["name"] != self._full_name(name):
                continue
            if content and record["content"] != content:
                continue
            filtered.append(record)
        return filtered

    def delete_record(self, identifier=None, rtype=None, name=None, content=None):
        changes = []
        if identifier:
            changes.append(
                {
                    "delete": {
                        "id": identifier,
                    },
                }
            )
        else:
            records = self.list_records(rtype, name, content)
            if not records:
                return True
            for record in records:
                changes.append(
                    {
                        "delete": {
                            "id": record["id"],
                        },
                    }
                )
        patch = {
            "changes": changes,
        }
        self._patch(self._records_url(), patch)
        return True

    def update_record(self, identifier=None, rtype=None, name=None, content=None):
        if not identifier:
            records = self.list_records(None, name)
            if not records:
                raise Exception(f"Record {name} not found with type {rtype}")
            if len(records) > 1:
                raise Exception(f"More than one {rtype} record found for {name}")
            identifier = records[0]["id"]
        patch = {
            "changes": [
                {
                    "set": {
                        "id": identifier,
                        "records": [
                            {
                                "name": name,
                                "data": content,
                                "type": rtype,
                                "ttl": self._get_lexicon_option("ttl")
                                or self.default_ttl,
                            },
                        ],
                    },
                },
            ],
        }
        print(patch)
        self._patch(self._records_url(), patch)
        return True

    def _request(self, action="GET", url="/", data=None, query_params=None):
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Auth-Token": self._get_provider_option("auth_secret_key"),
        }
        response = requests.request(
            action,
            self.endpoint + url,
            params=query_params,
            data=json.dumps(data),
            headers=headers,
        )
        response.raise_for_status()
        return response.json()

    def _records_url(self):
        return f"/dns-zones/{self.domain_id}/records"
