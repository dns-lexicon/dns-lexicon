"""Module provider for deSEC"""

import hashlib
import logging
import re
from argparse import ArgumentParser
from typing import Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError
from urllib3.util.retry import Retry

from lexicon._private.discovery import lexicon_version
from lexicon.config import ConfigResolver
from lexicon.exceptions import AuthenticationError
from lexicon.interfaces import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)

# Type aliases
RecordType = Tuple[dict, int]
RecordList = dict[str, RecordType]
StrDict = dict[str, str]
StrDictList = list[StrDict]
OptStr = Optional[str]
OptStrDict = Optional[StrDict]
SanitizedResponseType = Tuple[str, str, dict]


class Provider(BaseProvider):
    """Provider class for deSEC"""

    @staticmethod
    def get_nameservers() -> list[str]:
        return ["ns1.desec.io", "ns2.desec.org"]

    @staticmethod
    def configure_parser(parser: ArgumentParser) -> None:
        parser.add_argument("--auth-token", help="specify api token for authentication")
        parser.add_argument(
            "--auth-username", help="specify email address for authentication"
        )
        parser.add_argument(
            "--auth-password", help="specify password for authentication"
        )

    def __init__(self, config: ConfigResolver):
        super(Provider, self).__init__(config)
        self.api_endpoint = "https://desec.io/api/v1"
        self._lexicon_version = lexicon_version()
        self._token = self._get_provider_option("auth_token")
        self._priority = self._get_lexicon_option("priority")
        if self._priority and not self._priority.isnumeric():
            raise ValueError(f"Priority argument '{self._priority}' is not numeric.")

        # RegEx patterns, priority optional
        self._re = {
            "MX": re.compile(r"((?P<priority>\d+)\s+)?(?P<target>.+)"),
            "SRV": re.compile(
                r"((?P<priority>\d+)\s+)?(?P<weight>\d+)\s+(?P<port>\d+)\s+(?P<target>.+)"
            ),
        }

        # deSEC enforces rate limits, which are hit by rapid successive requests,
        # like by the automated tests via pytest. The API responses with status 429
        # and a retry-after header, which we want to use for retries.

        # https://desec.readthedocs.io/en/latest/rate-limits.html
        # dns_api_per_domain_expensive: 2/s - 15/min - 100/h - 300/day
        self._session = requests.Session()
        self._session.mount(
            "https://",
            HTTPAdapter(
                max_retries=Retry(
                    allowed_methods=None,  # Allow all methods
                    respect_retry_after_header=True,
                )
            ),
        )

    def authenticate(self):
        # Handle authentication
        username = self._get_provider_option("auth_username")
        password = self._get_provider_option("auth_password")
        if self._token and (username or password):
            raise AuthenticationError("Multiple authentication mechanisms specified.")
        if username and password and not self._token:
            self._login(username, password)
        if not self._token:
            raise AuthenticationError("No valid authentication mechanism specified.")

        # Check if domain exists
        try:
            self._get("..")
            self.domain_id = self.domain
            LOGGER.debug(f"authenticate: domain '{self.domain}' found.")
        except HTTPError as err:
            raise AuthenticationError(
                f"Domain '{self.domain}' not found ({err.response.status_code})."
            )

    def cleanup(self) -> None:
        pass

    def list_records(
        self, rtype: OptStr = None, name: OptStr = None, content: OptStr = None
    ) -> list[dict]:
        rec_sets = self._fetch_record_sets(rtype, name, content)
        records = [
            {
                "type": rec_set["type"],
                "ttl": rec_set["ttl"],
                "name": self._format_name(rec_set),
                "id": identifier,
                "content": sanitized,
            }
            | options
            for identifier, (rec_set, index) in rec_sets.items()
            for sanitized, dirty, options in [
                self._sanitize_response_content(rec_set, index)
            ]
        ]
        LOGGER.debug("list_records: %s", records)
        return records

    # Create record. If record already exists with the same content, do nothing
    def create_record(self, rtype: str, name: str, content: str) -> bool:
        (desec_rec, index) = self._get_record_set(rtype, name)
        desec_content = self._sanitize_request_content(content, rtype)
        subname = self._relative_name(name) if name else ""
        if not desec_rec or index == -1:
            # Create new record set, as it doesn't exist yet
            LOGGER.debug("_create_record: Creating new record set")
            self._post(
                "",
                {
                    "records": [desec_content],
                    "type": rtype,
                    "subname": subname,
                },
            )
            return True

        # Check if record is in record set
        desec_records: list[str] = desec_rec["records"]
        if content in desec_records or desec_content in desec_records:
            LOGGER.debug("_create_record: The record already exists. Ignore.")
            return True

        # Patch existing record set
        desec_records.append(desec_content)
        self._patch(f"{subname}/{rtype}", desec_rec)
        return True

    # Update a record.
    def update_record(
        self,
        identifier: OptStr = None,
        rtype: OptStr = None,
        name: OptStr = None,
        content: OptStr = None,
    ) -> bool:
        if identifier and name:
            # We can only filter for record type, as the subname could differ
            rec_sets = self._fetch_record_sets(rtype)
            if identifier not in rec_sets:
                LOGGER.warning(
                    f"update_record: No match for identifier '{identifier}'. Abort."
                )
                return False
            (desec_rec, index) = rec_sets[identifier]
        else:
            # We can't filter for content, as it likely changed
            (desec_rec, index) = self._get_record_set(rtype, name, None, identifier)

        if not desec_rec or index == -1:
            LOGGER.warning("update_record: No matching record found. Abort.")
            return False

        desec_records: list[str] = desec_rec["records"]
        rtype = rtype or desec_rec["type"]
        content = content or desec_records[index]

        # The subname is immutable and can't be modified.
        # We need to delete the old record and create a new one.
        old_subname = desec_rec["subname"]
        new_subname = self._relative_name(name) if name else ""
        if old_subname != new_subname:
            LOGGER.debug(
                f"update_record: new subname '{new_subname}' differs from old '{old_subname}'. Delete and recreate record."
            )
            return self._delete_record(
                desec_rec, index, rtype, old_subname
            ) and self.create_record(rtype, new_subname, content)

        # Patch the content
        new_content = self._sanitize_request_content(content or "", rtype or "")
        desec_records[index] = new_content
        self._patch(f"{new_subname or '@'}/{rtype}", desec_rec)
        return True

    # Delete an existing record.
    # If record does not exist, do nothing.
    def delete_record(
        self,
        identifier: OptStr = None,
        rtype: OptStr = None,
        name: OptStr = None,
        content: OptStr = None,
    ) -> bool:
        # Get first item
        (desec_rec, index) = self._get_record_set(rtype, name, content, identifier)
        if not desec_rec or index == -1:
            LOGGER.debug("delete_record: Record not found. Ignore.")
            return True
        subname = desec_rec["subname"]
        rtype = rtype or desec_rec["type"]
        if rtype and name and not (content or identifier):
            LOGGER.debug(
                f"delete_record: remove whole '{rtype}' record set '{subname}'"
            )
            self._delete(f"{subname}/{rtype}/")
            return True
        return self._delete_record(desec_rec, index, rtype, subname)

    def _delete_record(
        self, desec_rec: dict, index: int, rtype: str, subname: str
    ) -> bool:
        # Delete specific record
        desec_records: list[str] = desec_rec["records"]
        removed = desec_records.pop(index)
        self._patch(f"{subname}/{rtype}", desec_rec)
        LOGGER.debug(
            f"_delete_record: removed '{rtype}' item from '{subname}' record set, with content '{removed}'"
        )
        return True

    # Helpers

    def _request(
        self,
        action: str = "GET",
        url: str = "/",
        data: OptStrDict = None,
        query_params: OptStrDict = None,
    ):
        # TTL is required for all deSEC record sets
        if data:
            if ttl := self._get_lexicon_option("ttl"):
                data["ttl"] = ttl
            if not data["ttl"]:
                data["ttl"] = "3600"

        response = self._session.request(
            action,
            f"{self.api_endpoint}/domains/{self.domain}/rrsets/{url}/",
            params=query_params,
            json=data,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": f"lexicon/{self._lexicon_version} desec",
                "Authorization": f"Token {self._token}",
            },
        )

        # if the request fails for any reason, throw an error.
        response.raise_for_status()
        # DELETE responses without a body
        if response.status_code == 204:
            return {}
        return response.json()

    def _login(self, username: str, password: str) -> None:
        LOGGER.debug("_login: logging in with username / password")
        auth_res = requests.post(
            self.api_endpoint + "/auth/login/",
            None,
            {"email": username, "password": password},
        )
        auth_res.raise_for_status()

        json_res = auth_res.json()
        if json_res.get("mfa"):
            raise AuthenticationError("Login with enabled MFA/2FA is not supported.")

        self._token = json_res.get("token")
        if not self._token:
            raise AuthenticationError("Login successful, but no token was acquired.")

    def _fetch_record_sets(
        self, rtype: OptStr = None, name: OptStr = None, content: OptStr = None
    ) -> RecordList:
        desec_content = self._sanitize_request_content(content or "", rtype or "")
        response = self._get(
            "",
            {
                "type": rtype or None,
                "subname": self._relative_name(name) if name else None,
            },
        )

        # Generates a dict with the identifier as key
        # and a tuple of the record set and the index of related record
        # {id: (rec_set, index)}
        id_sets = {
            self._identifier(rec_set, rec): (rec_set, i)
            for rec_set in response
            for i, rec in enumerate(rec_set["records"])
            if (not content or content == rec)
            or (not desec_content or desec_content == rec)
        }
        LOGGER.debug("_fetch_record_sets: %s", id_sets)
        return id_sets

    def _get_record_set(
        self,
        rtype: OptStr = None,
        name: OptStr = None,
        content: OptStr = None,
        identifier: OptStr = None,
    ) -> RecordType:
        rec_sets = self._fetch_record_sets(rtype, name, content)
        if not len(rec_sets):
            # No record set found
            LOGGER.debug("_get_record_set: No match.")
            return ({}, -1)

        rec_set, *_ = rec_sets.values()
        if identifier and identifier in rec_sets:
            # Return specified record set
            return rec_sets[identifier]

        # Return first result
        return rec_set

    # Override, handle apex
    def _relative_name(self, record_name: str) -> str:
        subname = super()._relative_name(record_name or "@")
        return subname if subname != "@" else ""

    # Override, allow foreign domains
    def _fqdn_name(self, record_name: str) -> str:
        return (
            record_name
            if record_name.endswith(".")
            else super()._fqdn_name(record_name)
        )

    @staticmethod
    def _format_name(match: StrDict) -> str:
        sub = match["subname"]
        return f"{'@.' if not sub else ''}{match['name']}".strip(".")

    @staticmethod
    def _identifier(match: StrDict, record: str) -> str:
        sha256 = hashlib.sha256()
        sha256.update(f"{match['name']} => {match['type']} => '{record}'".encode())
        return sha256.hexdigest()[0:7]

    def _sanitize_request_content(self, content: str, rtype: str) -> str:
        if rtype == "TXT":
            content = content.strip('"')
            return f'"{content}"' if content else ""
        if rtype == "CNAME":
            return self._fqdn_name(content)
        if rtype in ("MX", "SRV"):
            # The priority is only relevant for MX and SRV types.
            # deSEC does not support this property, it is part of the record's content.
            parsed = self._parse_priority_record(content, rtype)
            priority = parsed.get("priority") or str(self._priority)
            parsed["priority"] = priority  # Ensure fallback for join operation
            if not priority:
                raise ValueError("Priority value is not defined.")
            if self._priority and self._priority != priority:
                raise ValueError(
                    f"The priority was specified as an argument ({self._priority}) "
                    f"and in the content ({priority}), but it doesn't match."
                )
            return " ".join(parsed.values())
        return content

    def _sanitize_response_content(
        self, rec_set: dict, index: int
    ) -> SanitizedResponseType:
        rtype = rec_set["type"]
        content = rec_set["records"][index]
        if rtype in ("MX", "SRV"):
            parsed = self._parse_priority_record(content, rtype)
            if not (priority := parsed.get("priority")) or not priority.isnumeric():
                raise Exception("Priority value is not present in content.")
            # Convert numeric options to int, see `technical_workbook.rst`
            options: dict = {
                k: (int(v) if v.isnumeric() else v) for k, v in parsed.items()
            }
            return " ".join(parsed.values()), content, {rtype.lower(): options}
        return content.strip('"'), content, {}

    def _parse_priority_record(self, content: str, rtype: str) -> StrDict:
        if not (match := self._re[rtype].match(content)):
            raise Exception(f"Content '{content}' is not valid for type '{rtype}'.")

        groups = match.groupdict()
        groups["target"] = self._fqdn_name(groups["target"])
        return groups
