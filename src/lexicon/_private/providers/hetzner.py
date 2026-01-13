"""Module provider for Hetzner"""

import json
import logging
import requests
from argparse import ArgumentParser
from typing import List, Any, TypedDict, Union, Optional
from time import sleep
from lexicon.config import ConfigResolver
from lexicon.exceptions import AuthenticationError, LexiconError
from lexicon.interfaces import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)


class Provider(BaseProvider):
    """
    Provider for Hetzner Cloud DNS at https://console.hetzner.com or
    https://api.hetzner.cloud; and Hetzner DNS at https://dns.hetzner.com for backwards-compatibility.

    Does not work for konsoleH or Domain Robot.

    If you're still using dns.hetzner.com, migration to Hetzner Cloud is recommended. See the [official migration guide](https://docs.hetzner.com/networking/dns/migration-to-hetzner-console/process).
    """

    def __init__(self, config):
        super(Provider, self).__init__(config)
        self.domain_id = None
        self._hetzner_impl = self._decide_provider()

    @staticmethod
    def get_nameservers() -> list[str]:
        return ["ns.hetzner.com"]

    @staticmethod
    def configure_parser(parser: ArgumentParser) -> None:
        parser.add_argument(
            "--auth-token", help="Specify Hetzner DNS or Cloud API token"
        )

    def authenticate(self) -> None:
        self._hetzner_impl.authenticate()
        self.domain_id = self._hetzner_impl.domain_id

    def create_record(self, rtype, name, content):
        return self._hetzner_impl.create_record(rtype, name, content)

    def list_records(
        self,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        return self._hetzner_impl.list_records(rtype, name, content)

    def update_record(
        self,
        identifier: Optional[str] = None,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ) -> bool:
        return self._hetzner_impl.update_record(identifier, rtype, name, content)

    def delete_record(
        self,
        identifier: Optional[str] = None,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ) -> bool:
        return self._hetzner_impl.delete_record(identifier, rtype, name, content)

    def _decide_provider(self) -> BaseProvider:
        """
        To provide backwards-compatibilty, implementation for Hetzner DNS (old API) is kept. When the old API is completely shut down, this can be removed and HetznerCloud can be made the only provider in this file.
        """
        token = self._get_provider_option("auth_token")
        if token is None:
            raise LexiconError("auth-token must be passed.")
        if len(token) == 32:
            return HetznerDns(self.config)
        return HetznerCloud(self.config)


class HetznerDns(BaseProvider):

    @staticmethod
    def get_nameservers() -> List[str]:
        return ["ns.hetzner.com"]

    @staticmethod
    def configure_parser(parser: ArgumentParser) -> None:
        parser.add_argument("--auth-token", help="Specify Hetzner DNS API token")

    def __init__(self, config):
        super(HetznerDns, self).__init__(config)
        self.domain_id = None
        self.api_endpoint = "https://dns.hetzner.com/api/v1"

    def authenticate(self):
        provider = self._get_zone_by_domain(self.domain)
        self.domain_id = provider["id"]

    def create_record(self, rtype, name, content):
        data = {
            # hetzner needs the FQDN name if it does not belong to the managed domain itself
            "name": self._get_record_name(self.domain, name),
            "type": rtype,
            "value": content,
            "zone_id": self.domain_id,
        }
        if self._get_lexicon_option("ttl"):
            data["ttl"] = self._get_lexicon_option("ttl")

        records = self.list_records(rtype=rtype, name=name, content=content)
        if len(records) >= 1:
            for record in records:
                LOGGER.warning(
                    "Duplicate record %s %s %s with id %s",
                    rtype,
                    name,
                    content,
                    record["id"],
                )
            return True
        self._post("/records", data)
        return True

    def list_records(self, rtype=None, name=None, content=None):
        filter_obj = {"zone_id": self.domain_id}
        payload = self._get("/records", filter_obj)
        records = map(self._hetzner_record_to_lexicon_record, payload["records"])
        filtered_records = self._filter_records(
            records, rtype, name if name is not None else None, content
        )

        return filtered_records

    def _filter_records(self, records, rtype=None, name=None, content=None):
        return [
            record
            for record in records
            if (rtype is None or record["type"] == rtype)
            and (name is None or record["name"] == self._full_name(name))
            and (content is None or record["content"] == content)
        ]

    def update_record(self, identifier, rtype=None, name=None, content=None):
        data = {
            "type": rtype,
            "name": self._get_record_name(self.domain, name),
            "value": content,
            "zone_id": self.domain_id,
        }
        if self._get_lexicon_option("ttl"):
            data["ttl"] = self._get_lexicon_option("ttl")
        update_identifier = identifier
        if update_identifier is None:
            records = self.list_records(rtype, name)
            if len(records) == 1:
                update_identifier = records[0]["id"]
            elif len(records) < 1:
                raise Exception(
                    "No records found matching type, name and content - won't update"
                )
            else:
                raise Exception(
                    "Multiple records found matching type, name and content - won't update"
                )
        self._put(f"/records/{update_identifier}", data)
        return True

    def delete_record(self, identifier=None, rtype=None, name=None, content=None):
        delete_record_ids = []
        if identifier is None:
            records = self.list_records(rtype, name, content)
            delete_record_ids = [record["id"] for record in records]
        else:
            delete_record_ids.append(identifier)

        for record_id in delete_record_ids:
            self._delete(f"/records/{record_id}")
        return True

    # Helpers
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
                "Auth-API-Token": self._get_provider_option("auth_token"),
                "Content-Type": "application/json",
            },
        )
        # if the request fails for any reason, throw an error.
        response.raise_for_status()
        return response.json()

    def _get_zone_by_domain(self, domain):
        """
        Requests all dns zones from your Hetzner account and searches for a specific
        one to determine the ID of it
        :param domain: Name of domain for which dns zone should be searched
        :rtype: dict
        :return: The dictionary of the zone with ``domain`` in the 'name' key
        :raises Exception: If no zone was found
        :raises KeyError, ValueError: If the response is malformed
        :raises urllib.error.HttpError: If request to /zones did not return 200
        """
        filter_obj = {"name": domain}
        payload = self._get("/zones", filter_obj)
        zones = payload["zones"]
        for zone in zones:
            if zone["name"] == domain:
                return zone
        raise AuthenticationError(f"No zone was found in account matching {domain}")

    def _get_record_name(self, domain, record_name):
        """
        Get the name attribute appropriate for hetzner api. This means it's the name
        without domain name if record name ends with managed domain name else a fqdn
        :param domain: Name of domain for which dns zone should be searched
        :param record_name: The record name to convert
        :rtype: str
        :return: The record name in an appropriate format for hetzner api
        """
        if record_name.rstrip(".").endswith(domain):
            record_name = self._relative_name(record_name)
        return record_name

    @staticmethod
    def _pretty_json(data):
        return json.dumps(data, sort_keys=True, indent=4, separators=(",", ": "))

    def _hetzner_record_to_lexicon_record(self, hetzner_record):
        lexicon_record = {
            "id": hetzner_record["id"],
            "name": self._full_name(hetzner_record["name"]),
            "content": hetzner_record["value"],
            "type": hetzner_record["type"],
        }
        if "ttl" in hetzner_record:
            lexicon_record["ttl"] = hetzner_record["ttl"]
        return lexicon_record


Record = TypedDict("Record", {"value": str})
RecordSet = TypedDict(
    "RecordSet",
    {
        "name": str,
        "type": str,
        "ttl": int,
        "records": list[Record],
    },
)
CreateRecordSetRequest = TypedDict(
    "CreateRecordSetRequest",
    {
        "name": str,
        "type": str,
        "ttl": Optional[int],
        "records": list[Record],
    },
)
SetTtlRequest = TypedDict("SetTtlRequest", {"ttl": int})


class HetznerCloud(BaseProvider):
    API_ENDPOINT = "https://api.hetzner.cloud/v1/zones"

    @staticmethod
    def get_nameservers() -> list[str]:
        return ["hydrogen.ns.hetzner.com", "oxygen.ns.hetzner.com", "helium.ns.hetzner.de"]

    @staticmethod
    def configure_parser(parser: ArgumentParser) -> None:
        parser.add_argument("--auth-token", help="Specify Hetzner DNS API token")

    def __init__(self, config: Union[ConfigResolver, dict[str, Any]]):
        super(HetznerCloud, self).__init__(config)
        self.domain_id = None

    def authenticate(self) -> None:
        self.domain_id = self._fetch_zone(self.domain)["id"]

    def create_record(self, rtype: str, name: str, content: str) -> bool:
        duplicate_records = self.list_records(rtype, name, content)
        if len(duplicate_records) > 0:
            LOGGER.info(f"Record {rtype} {name} {content} already exists")
            return True

        action = self._post(
            f"{self._rrset_url(name, rtype)}/actions/add_records",
            {'ttl': self._get_ttl(), 'records': self._records_from(rtype, content)}
        )['action']

        return self._wait_for_action(action)

    def list_records(
        self,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        record_sets = self._get_record_sets(rtype, name)

        name = self._full_name(name) if name else None
        return [
            record
            for record_set in record_sets
            for record in self._rrset_to_records(record_set)
            if (rtype is None or record["type"] == rtype)
            and (name is None or record["name"] == name)
            and (content is None or record["content"] == content)
        ]

    def update_record(
        self,
        identifier: Optional[str] = None,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ) -> bool:
        if rtype is None or name is None or content is None:
            raise LexiconError("rtype, name and content need to be set in order to update a record.")

        if identifier:
            raise LexiconError("Hetzner API does not provide ids per record")

        records = self.list_records(rtype, name)
        if len(records) < 1:
            raise Exception("No records found matching type and name - won't update")
        elif len(records) > 1:
            raise Exception("Multiple records found matching type and name - won't update")

        action = self._post(
            f"{self._rrset_url(name, rtype)}/actions/set_records",
            {'records': self._records_from(rtype, content)}
        )['action']
        if not self._wait_for_action(action):
            return False

        # verify the ttl is correctly set
        ttl = self._get_ttl()
        if ttl and records[0]["ttl"] is not ttl:
            return self._wait_for_action(
                self._post(
                    f"{self._rrset_url(name, rtype)}/actions/change_ttl",
                    {'ttl': ttl}
                )['action']
            )
        return True

    def delete_record(
        self,
        identifier: Optional[str] = None,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ) -> bool:
        if rtype is None or name is None:
            raise LexiconError("both rtype and name need to be passed.")

        if identifier:
            raise LexiconError("Hetzner API does not provide ids per record")

        if content is None:
            # Entire record set should be deleted
            action = self._delete(self._rrset_url(name, rtype))['action']
            return self._wait_for_action(action)
        else:
            # Record should be taken out of set
            action = self._post(
                f"{self._rrset_url(name, rtype)}/actions/remove_records",
                {"records": self._records_from(rtype, content)}
            )['action']

            return self._wait_for_action(action)

    # Helpers
    def _request(
        self,
        action: str = "GET",
        url: str = "/",
        data: Optional[dict[str, Any]] = None,
        query_params: Optional[dict[str, Any]] = None,
    ):
        query_params = query_params or {}

        headers = {
            "Authorization": f"Bearer {self._get_provider_option('auth_token')}",
            "Accept": "application/json",
        }
        json_data = None
        if data:
            headers["Content-Type"] = "application/json"
            json_data = json.dumps(data)

        response = requests.request(
            action,
            self.API_ENDPOINT + url,
            params=query_params,
            data=json_data,
            headers=headers,
        )
        # if the request fails for any reason, throw an error.
        response.raise_for_status()
        return response.json()

    def _get_action(self, action_id):
        return self._get(
            f"/actions/{action_id}"
        )['action']

    def _is_action_running(self, action):
        return action['status'] == "running"

    def _was_action_successful(self, action):
        return action['status'] == "success"

    def _wait_for_action(self, action):
        if not self._is_action_running(action):
            return self._was_action_successful(action)

        while self._is_action_running(action):
            sleep(0.5)
            action = self._get_action(action['id'])

        return self._was_action_successful(action)

    def _fetch_zone(self, domain: str) -> dict[str, Any]:
        try:
            return self._get(f"/{domain}")["zone"]
        except requests.HTTPError as err:
            if err.response.status_code == 401:
                raise AuthenticationError() from err
            elif err.response.status_code == 404:
                raise LexiconError(f"There is no zone for {domain}.") from err
            else:
                raise LexiconError(err) from err

    def _get_ttl(self) -> Optional[int]:
        ttl_str = self._get_lexicon_option("ttl")
        if not ttl_str:
            return None
        ttl = int(ttl_str)
        if not ttl:
            return None
        if ttl < 60 or ttl > 2147483647:
            raise LexiconError("TTL has to be between 60 and 2147483647")
        return ttl

    def _zone_url(self) -> str:
        return f"/{self.domain_id}"

    def _rrset_url(self, name: str, rtype: str) -> str:
        rrset_name = self._relative_name(name)
        return f"{self._zone_url()}/rrsets/{rrset_name}/{rtype}"

    def _rrset_to_records(self, rrset: RecordSet) -> list[dict[str, Any]]:
        return [
            {
                "id": None,
                "name": self._full_name(rrset["name"]),
                "content": self._get_content_from_record(rrset['type'], record['value']),
                "type": rrset["type"],
                "ttl": rrset["ttl"],
            }
            for record in rrset["records"]
        ]

    def _get_content_from_record(self, rtype: str, content: str):
        if rtype == "TXT":
            return content.removeprefix('"')\
                .removesuffix('"')\
                .replace('" "', '')\
                .replace('\\"', '"')
        return content

    def _records_from(self, rtype: str, content: str) -> list[Record]:
        if rtype == 'TXT':
            escaped_content = content.replace("\"", "\\\"")

            parts = []
            for start in range(0, len(escaped_content), 255):
                end = min(start + 255, len(escaped_content))
                parts.append('"' + escaped_content[start:end] + '"')
            content = " ".join(parts)

        return [{"value": content}]

    def _get_record_sets(self, rtype, name):
        response = self._get(f"{self._zone_url()}/rrsets", {'type': rtype, 'name': self._relative_name(name) if name else None})
        record_sets: list[RecordSet] = response["rrsets"]

        # get paged rrsets
        while response['meta']['pagination']['page'] < response['meta']['pagination']['last_page']:
            response = self._get(f"{self._zone_url()}/rrsets", {'type': rtype , 'name': name,  'page': response['meta']['pagination']['next_page']})
            record_sets += response["rrsets"]

        return record_sets
