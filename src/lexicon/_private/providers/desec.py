"""Module provider for deSEC"""

import re
import logging
import hashlib
import requests

from argparse import ArgumentParser
from typing import Literal, Tuple
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


from lexicon.exceptions import AuthenticationError
from lexicon.interfaces import Provider as BaseProvider
from lexicon._private.discovery import lexicon_version

LOGGER = logging.getLogger(__name__)


class Provider(BaseProvider):
    """Provider class for deSEC"""

    StrDict = dict[str, str]
    OptStr = str | None
    OptStrDict = StrDict | None
    OptStrDictList = list[StrDict] | None
    ActionType = Literal["update", "delete", "create"]
    SanitizedResponseType = Tuple[str, str, dict | None]

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

    def __init__(self, config):
        super(Provider, self).__init__(config)
        self.domain_id = self.domain
        self.api_endpoint = "https://desec.io/api/v1"
        self._lexicon_version = lexicon_version()
        self._token = self._get_provider_option("auth_token")
        self._priority = self._get_lexicon_option("priority")
        if self._priority and not self._priority.isnumeric():
            raise ValueError(f"Priority argument '{self._priority}' is not numeric.")

        # RegEx patterns, priority optional
        self._re = {
            "MX": re.compile(r"((?P<priority>\d+)\s+)?(?P<target>.+)"),
            "SRV": re.compile(r"((?P<priority>\d+)\s+)?(?P<weight>\d+)\s+(?P<port>\d+)\s+(?P<target>.+)"),
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
                    allowed_methods=None,   # Allow all methods
                    respect_retry_after_header=True,
                )
            )
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

        domains = self._get("/domains")
        for domain in domains:
            if domain.get("name") == self.domain:
                LOGGER.debug(f"authenticate: domain '{self.domain}' found.")
                break
        else:
            raise AuthenticationError(f"Domain '{self.domain}' not found.")

    def cleanup(self) -> None:
        pass

    # List all records. Return an empty list if no records found
    # type, name and content are used to filter records.
    # If possible filter during the query, otherwise filter after response is received.
    def list_records(self, rtype=None, name=None, content=None) -> list[dict]:
        filter_query = {}
        if rtype:
            filter_query["type"] = rtype
        if name:
            filter_query["subname"] = self._relative_name(name)

        payload = self._get(f"/domains/{self.domain}/rrsets/", filter_query)
        records = [
            {
                "type": match["type"],
                "ttl": match["ttl"],
                "name": self._format_name(match),
                "id": self._identifier(match, record),
                "content": record,
                "options": options,
                "_internal_record": match,   # used internally
                "_internal_content": dirty,  # used internally
            }
            for match in payload
            for record, dirty, options in [
                self._sanitize_response_content(dirty, match["type"])
                for dirty in match["records"]
            ]
            if not content or content == record or content == dirty
        ]
        LOGGER.debug("list_records: %s", records)
        return records

    # Create record. If record already exists with the same content, do nothing
    def create_record(self, rtype: str, name: str, content: str) -> bool:
        # "create" can't have an identifier and we can't filter for content
        # it would filter out the type and subname combination
        # if this content isn't present yet, which is likely while creating a record
        records = self.list_records(rtype, name) or [
            # Create a stub for non-existent records
            {
                "content": "",
                "_internal_content": "",
                "_internal_record": {
                    "records": [],
                    "type": rtype,
                    "subname": self._relative_name(name or ""),
                },
            },
        ]
        matches = self._dedup_matches(records)
        return self._record_action("create", None, rtype, name, content, matches)

    # Create or update (or delete) a record.
    def update_record(self, identifier: OptStr = None, rtype: OptStr = None, name: OptStr = None, content: OptStr = None) -> bool:
        matches = []
        if content and not identifier:
            records = self.list_records(rtype, name)
            matches = [record for record in records if record["content"] == content]
        return self._record_action('update', identifier, rtype, name, content, matches)

    # Delete an existing record.
    # If record does not exist, do nothing.
    def delete_record(self, identifier=None, rtype=None, name=None, content=None) -> bool:
        # We can only delete all records of an type and (sub)domain combination via the API.
        # We can update the combination though and remove said record.
        # If the records are empty, the whole combination will be removed.
        matches = []
        if rtype and name and not (content or identifier):
            LOGGER.debug(f"delete_record: remove whole '{rtype}' record set for '{name}'")
            records = self.list_records(rtype, name)
            if not records:
                return True
            matches = self._dedup_matches(records)

        return self._record_action("delete", identifier, rtype, name, content, matches)

    # Helpers

    # Create / update / delete a record.
    # As multiple records might be associated with a type / subname combo, we use the put method, which allows all operations.
    def _record_action(self, _action: ActionType, identifier: OptStr = None, rtype: OptStr = None, name: OptStr = None, content: OptStr = None, matches: OptStrDictList = None) -> bool:
        # Allow matches override, prevent unnecessary API calls.
        if not matches:
            # Find lexicon record
            if identifier:
                # Identifier takes precedence over filter options
                records = self.list_records(rtype)
                matches = [record for record in records if record["id"] == identifier]
            elif _action == "update":
                # Update without identifier can't filter for content
                matches = self.list_records(rtype, name)
            else:
                matches = self.list_records(rtype, name, content)

        if len(matches) != 1:
            LOGGER.debug("%s_record: found %d matches, expected 1", _action, len(matches))
            return False

        # Shorthands / types
        lexicon_rec: dict = matches[0]
        desec_rec: dict = lexicon_rec["_internal_record"]
        old_content: str = lexicon_rec["_internal_content"]
        desec_records: list[str] = desec_rec["records"]

        # Determine and update (or delete) the target record
        new_content = self._sanitize_request_content(content or "", rtype or "")
        match _action:
            case "create":
                if new_content in desec_records:
                    LOGGER.debug("The record already exists. Ignore.")
                    return True
                desec_records.append(new_content)
            case "delete":
                if old_content and (content or identifier):
                    # Specific record
                    desec_records.remove(old_content)
                else:
                    # Whole record set
                    desec_records.clear()
            case "update" | _:
                if old_content not in desec_records:
                    raise Exception("The record does not exist, so it can't be updated!")

                # The subname can't be changed.
                # We need to delete the old record and create a new one.
                old_subname = desec_rec["subname"]
                new_subname = self._relative_name(name or "")
                if old_subname != new_subname:
                    LOGGER.debug("%s_record: new subname '%s' differs from old '%s'. Delete and recreate record.", _action, new_subname, old_subname)
                    return self._record_action("delete", identifier, matches=matches) and \
                        self.create_record(lexicon_rec["type"], new_subname, content or lexicon_rec["content"])

                index = desec_records.index(old_content)
                desec_records[index] = new_content

        # TTL is valid for all deSEC records of this type and subname combination
        if ttl := self._get_lexicon_option("ttl"):
            desec_rec["ttl"] = ttl

        # The PATCH call can manage create, delete and update at once, on multiple records.
        # For this reason, it only takes an array, which MyPy doesn't like. Ignore.
        # See: https://desec.readthedocs.io/en/latest/endpoint-reference.html
        self._patch(f"/domains/{self.domain}/rrsets/", [desec_rec])     # type: ignore[arg-type]
        LOGGER.debug("%s_record: %s", _action, True)
        return True

    def _request(self, action: str = "GET", url: str = "/", data: OptStrDict = None, query_params: OptStrDict = None):
        response = self._session.request(
            action,
            self.api_endpoint + url,
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
        return response.json()

    def _login(self, username: str, password: str) -> None:
        LOGGER.debug("_login: logging in with username / password")
        auth_res = requests.post(
            self.api_endpoint + "/auth/login/",
            None,
            {
                "email": username,
                "password": password
            }
        )
        auth_res.raise_for_status()

        json_res = auth_res.json()
        if json_res.get("mfa"):
            raise AuthenticationError("Login with enabled MFA/2FA is not supported.")

        self._token = json_res.get("token")
        if not self._token:
            raise AuthenticationError("Login successful, but no token was acquired.")

    # Override, handle apex
    def _relative_name(self, record_name: str) -> str:
        subname = super()._relative_name(record_name or "@")
        return subname if subname != "@" else ""

    # Override, allow foreign domains
    def _fqdn_name(self, record_name: str) -> str:
        return record_name if record_name.endswith(".") else super()._fqdn_name(record_name)

    @staticmethod
    def _format_name(match: StrDict) -> str:
        sub = match['subname']
        return f"{'@.' if not sub else ''}{match['name']}".strip(".")

    @staticmethod
    def _identifier(match: StrDict, record: str) -> str:
        sha256 = hashlib.sha256()
        sha256.update(f"{match['created']} => '{record}'".encode())
        return sha256.hexdigest()[0:7]

    @staticmethod
    def _dedup_matches(records: list[dict]) -> list[dict]:
        assert records
        # The list_records() call splits the "records" list into multiple entries.
        # Filtered against the first entry, the list should be empty. Append first entry.
        first_record = records[0]
        first_internal = first_record["_internal_record"]
        matches = [record for record in records if record["_internal_record"] != first_internal]
        matches.append(first_record)
        return matches

    def _sanitize_request_content(self, content: str, rtype: str) -> str:
        match rtype:
            case "TXT":
                return f"\"{content}\"" if content else ""
            case "CNAME":
                return self._fqdn_name(content)
            case "MX" | "SRV":
                # The priority is only relevant for MX and SRV types.
                # deSEC does not support this property, it is part of the record's content.
                parsed = self._parse_priority_record(content, rtype)
                priority = parsed.get("priority") or str(self._priority)
                parsed["priority"] = priority   # Ensure fallback for join operation
                if not priority:
                    raise ValueError("Priority value is not defined.")
                if self._priority and self._priority != priority:
                    raise ValueError(f"The priority was specified as an argument ({self._priority}) "
                                     f"and in the content ({priority}), but it doesn't match.")
                return " ".join(parsed.values())
            case _:
                return content

    def _sanitize_response_content(self, content: str, rtype: str) -> SanitizedResponseType:
        match rtype:
            case "MX" | "SRV":
                parsed = self._parse_priority_record(content, rtype)
                if not (priority := parsed.get("priority")) or not priority.isnumeric():
                    raise Exception("Priority value is not present in content.")
                # Convert numeric options to int, see `technical_workbook.rst`
                options: dict = {k: (int(v) if v.isnumeric() else v) for k, v in parsed.items()}
                return " ".join(parsed.values()), content, {rtype.lower(): options}
            case _:
                return content.strip("\""), content, None

    def _parse_priority_record(self, content: str, rtype: str) -> StrDict:
        if not (match := self._re[rtype].match(content)):
            raise Exception(f"Content '{content}' is not valid for type '{rtype}'.")

        groups = match.groupdict()
        groups["target"] = self._fqdn_name(groups["target"])

        return groups
