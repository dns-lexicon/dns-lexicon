"""
Lexicon DevNomads Provider

Author: Loek Geleijn, 2025

API Docs: https://api.devnomads.nl/api/documentation#/Dns

Implementation notes:
The DevNomads API basically implements the PowerDNS API but applies client
specific authentication and filtering.
"""

import json
import logging
from argparse import ArgumentParser
from typing import List

import requests

from lexicon.interfaces import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)


class DevNomadsProviderError(Exception):
    """Generic DevNomads exception"""


class Provider(BaseProvider):
    """Provider class for DevNomads"""

    @staticmethod
    def get_nameservers() -> List[str]:
        return []

    @staticmethod
    def configure_parser(parser: ArgumentParser) -> None:
        parser.add_argument("--auth-token", help="Specify token for authentication.")

    def __init__(self, config):
        super(Provider, self).__init__(config)

        self.api_endpoint = "https://api.devnomads.nl/services/dns"

        if self.api_endpoint.endswith("/"):
            self.api_endpoint = self.api_endpoint[:-1]

        self.auth_token = self._get_provider_option("auth_token")
        if not self.auth_token:
            raise DevNomadsProviderError(
                "DevNomads auth token not defined (auth_token)"
            )

        self._zone_data = None

    def zone_data(self):
        """Get zone data"""
        if self._zone_data is None:
            self._zone_data = self._get(
                "/zones/" + self._ensure_dot(self.domain)
            ).json()
        return self._zone_data

    def authenticate(self):
        self.zone_data()
        self.domain_id = self.domain

    def cleanup(self) -> None:
        pass

    def _make_identifier(self, rtype, name, content):
        return f"{rtype}/{name}={content}"

    def _parse_identifier(self, identifier):
        parts = identifier.split("/")
        rtype = parts[0]
        parts = parts[1].split("=")
        name = parts[0]
        content = "=".join(parts[1:])
        return rtype, name, content

    def list_records(self, rtype=None, name=None, content=None):
        records = []
        for rrset in self.zone_data()["rrsets"]:
            if (
                name is None or self._fqdn_name(rrset["name"]) == self._fqdn_name(name)
            ) and (rtype is None or rrset["type"] == rtype):
                for record in rrset["records"]:
                    if content is None or record["content"] == self._clean_content(
                        rtype, content
                    ):
                        records.append(
                            {
                                "type": rrset["type"],
                                "name": self._full_name(rrset["name"]),
                                "ttl": rrset["ttl"],
                                "content": self._unclean_content(
                                    rrset["type"], record["content"]
                                ),
                                "id": self._make_identifier(
                                    rrset["type"], rrset["name"], record["content"]
                                ),
                            }
                        )
        LOGGER.debug(f"list_records: {records}")
        return records

    def _clean_content(self, rtype, content):
        if rtype in ("TXT", "LOC"):
            if content[0] != '"':
                content = '"' + content
            if content[-1] != '"':
                content += '"'
        elif rtype == "CNAME":
            content = self._fqdn_name(content)
        return content

    def _unclean_content(self, rtype, content):
        if rtype in ("TXT", "LOC"):
            content = content.strip('"')
        elif rtype == "CNAME":
            content = self._full_name(content)
        return content

    def create_record(self, rtype, name, content):
        rname = self._fqdn_name(name)
        newcontent = self._clean_content(rtype, content)

        updated_data = {
            "name": rname,
            "type": rtype,
            "records": [],
            "ttl": self._get_lexicon_option("ttl") or 600,
            "changetype": "REPLACE",
        }

        updated_data["records"].append({"content": newcontent, "disabled": False})

        for rrset in self.zone_data()["rrsets"]:
            if rrset["name"] == rname and rrset["type"] == rtype:
                updated_data["ttl"] = rrset["ttl"]

                for record in rrset["records"]:
                    if record["content"] != newcontent:
                        updated_data["records"].append(
                            {
                                "content": record["content"],
                                "disabled": record["disabled"],
                            }
                        )
                break

        request = {"rrsets": [updated_data]}
        LOGGER.debug(f"request: {requests}")

        self._patch("/zones/" + self._ensure_dot(self.domain), data=request)
        self._zone_data = None
        return True

    def delete_record(self, identifier=None, rtype=None, name=None, content=None):
        if identifier is not None:
            rtype, name, content = self._parse_identifier(identifier)

        LOGGER.debug(f"delete {rtype} {name} {content}")
        if rtype is None or name is None:
            raise Exception("Must specify at least both rtype and name")

        update_data = None
        for rrset in self.zone_data()["rrsets"]:
            if rrset["type"] == rtype and self._fqdn_name(
                rrset["name"]
            ) == self._fqdn_name(name):
                update_data = rrset

                if "comments" in update_data:
                    del update_data["comments"]

                if content is None:
                    update_data["records"] = []
                    update_data["changetype"] = "DELETE"
                else:
                    new_record_list = []
                    for record in update_data["records"]:
                        if (
                            self._clean_content(rrset["type"], content)
                            != record["content"]
                        ):
                            new_record_list.append(record)

                    update_data["records"] = new_record_list
                    update_data["changetype"] = "REPLACE"
                break

        request = {"rrsets": [update_data]}
        LOGGER.debug(f"request: {request}")

        self._patch("/zones/" + self._ensure_dot(self.domain), data=request)

        self._zone_data = None
        return True

    def update_record(self, identifier, rtype=None, name=None, content=None):
        self.delete_record(identifier)
        return self.create_record(rtype, name, content)

    def _patch(self, url="/", data=None, query_params=None):
        return self._request("PATCH", url, data=data, query_params=query_params)

    def _request(self, action="GET", url="/", data=None, query_params=None):
        if data is None:
            data = {}
        if query_params is None:
            query_params = {}
        response = requests.request(
            action,
            self.api_endpoint + url,
            params=query_params,
            data=json.dumps(data),
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
        )
        LOGGER.debug(f"response: {response.text}")
        response.raise_for_status()
        return response

    @classmethod
    def _ensure_dot(cls, text):
        """
        This function makes sure a string contains a dot at the end
        """
        if text.endswith("."):
            return text
        return text + "."
