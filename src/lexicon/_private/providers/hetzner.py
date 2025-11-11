import json
import logging
from argparse import ArgumentParser
from typing import Any, Optional, TypedDict, Union, cast

import requests

from lexicon.config import ConfigResolver
from lexicon.exceptions import AuthenticationError, LexiconError
from lexicon.interfaces import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)

Record = TypedDict("Record", {"value": str})
RecordSet = TypedDict(
    "RecordSet",
    {
        "id": str,
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
AddRecordsRequest = TypedDict(
    "AddRecordsRequest", {"ttl": Optional[int], "records": list[Record]}
)
SetRecordsRequest = TypedDict("SetRecordsRequest", {"records": list[Record]})
RemoveRecordsRequest = TypedDict("RemoveRecordsRequest", {"records": list[Record]})
SetTtlRequest = TypedDict("SetTtlRequest", {"ttl": int})


class Provider(BaseProvider):
    """
    Provider for Hetzner Cloud DNS at https://console.hetzner.com or
    https://api.hetzner.cloud.
    Does not work for konsoleH, Domain Robot, or dns.hetzner.com.
    If you're still using dns.hetzner.com, see the [official migration guide](\
    https://docs.hetzner.com/networking/dns/migration-to-hetzner-console\
    /process), or use the `hetzner_legacy` provider.
    """

    API_ENDPOINT = "https://api.hetzner.cloud/v1/zones"

    @staticmethod
    def get_nameservers() -> list[str]:
        return ["ns.hetzner.com"]

    @staticmethod
    def configure_parser(parser: ArgumentParser) -> None:
        parser.add_argument("--auth-token", help="Specify Hetzner DNS API token")

    def __init__(self, config: Union[ConfigResolver, dict[str, Any]]):
        super(Provider, self).__init__(config)

    def authenticate(self) -> None:
        self.domain_id = self._fetch_zone(self.domain)["id"]

    def create_record(self, rtype: str, name: str, content: str) -> bool:
        duplicate_records = self.list_records(rtype, name, content)
        if len(duplicate_records) > 0:
            LOGGER.info(f"Record {rtype} {name} {content} already exists")
            return True

        self._post(
            f"{self._rrset_url(name, rtype)}/actions/add_records",
            cast(
                dict[str, Any],
                AddRecordsRequest(
                    ttl=self._get_ttl(), records=[self._record_from(rtype, content)]
                ),
            ),
        )
        return True

    def list_records(
        self,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        record_sets: list[RecordSet] = self._get(f"{self._zone_url()}/rrsets")["rrsets"]
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
        if identifier is None and (rtype is None or name is None):
            raise LexiconError(
                "Either identifier or both rtype and name need to be set in order to match a record."
            )
        if identifier is not None and content is not None:
            self._move_record(identifier, content, to_rtype=rtype, to_name=name)
            return True
        elif rtype is not None and name is not None and content is not None:
            # identifier doesnt matter in this case
            self._change_content(rtype, name, new_content=content)
            return True
        else:
            return False

    def delete_record(
        self,
        identifier: Optional[str] = None,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ) -> bool:
        if identifier is None and (rtype is None or name is None):
            raise LexiconError(
                "Either identifier or both rtype and name need to be passed."
            )

        if identifier:
            record = self._find_record(identifier)
            if record is None:
                raise LexiconError(f"Record with the id {identifier} does not exist.")
            rtype = record["type"]
            name = record["name"]
        name = cast(str, name)
        rtype = cast(str, rtype)
        if content is None:
            # Entire record set should be deleted
            self._delete(self._rrset_url(name, rtype))
            return True
        else:
            # Record should be taken out of set
            self._post(
                f"{self._rrset_url(name, rtype)}/actions/remove_records",
                cast(
                    dict[str, Any],
                    RemoveRecordsRequest(
                        {"records": [self._record_from(rtype, content)]}
                    ),
                ),
            )
            return True

    # Helpers
    def _request(
        self,
        action: str = "GET",
        url: str = "/",
        data: Optional[dict[str, Any]] = {},
        query_params: Optional[dict[str, Any]] = None,
    ):
        data = data or {}
        query_params = query_params or {}
        response = requests.request(
            action,
            self.API_ENDPOINT + url,
            params=query_params,
            data=json.dumps(data),
            headers={
                "Authorization": f"Bearer {self._get_provider_option('auth_token')}",
                "Content-Type": "application/json",
            },
        )
        # if the request fails for any reason, throw an error.
        response.raise_for_status()
        return response.json()

    def _fetch_zone(self, domain: str) -> dict[str, Any]:
        try:
            return self._get(f"/{domain}")["zone"]
        except requests.HTTPError as err:
            if err.response.status_code == 401:
                raise AuthenticationError()
            elif err.response.status_code == 404:
                raise LexiconError(f"There is no zone for {domain}.")
            else:
                raise LexiconError(err)

    def _to_rrset_name(self, domain: str, record_name: str) -> str:
        """
        Hetzner record set (rrset) names have a different format.
        """
        if record_name.rstrip(".").endswith(domain):
            return self._relative_name(record_name)
        return record_name

    def _move_record(
        self, identifier: str, content: str, to_rtype: Optional[str], to_name: Optional[str]
    ):
        if to_rtype is None and to_name is None:
            raise LexiconError("Either rtype or name must be set.")

        original_record = self._find_record(identifier, content)
        if original_record is None:
            raise LexiconError("No record with identifier found")

        self.create_record(
            rtype=to_rtype or original_record["type"],
            name=to_name or original_record["name"],
            content=content,
        )

        self.delete_record(identifier=identifier, content=content)
        return

    def _change_content(self, rtype: str, name: str, new_content: str):
        self._post(
            f"{self._rrset_url(name, rtype)}/actions/set_records",
            cast(
                dict[str, Any],
                SetRecordsRequest(records=[self._record_from(rtype, new_content)]),
            ),
        )
        return

    def _find_record(
        self, identifier: str, content: Optional[str] = None
    ) -> Optional[dict[str, Any]]:
        return next(
            iter(
                [
                    record
                    for record in self.list_records(content=content)
                    if record["id"] == identifier
                ]
            )
        )

    def _get_ttl(self) -> Optional[int]:
        return int(ttl) if (ttl := self._get_lexicon_option("ttl")) else None

    def _zone_url(self) -> str:
        return f"/{self.domain_id}"

    def _rrset_url(self, name: str, rtype: str) -> str:
        rrset_name = self._to_rrset_name(self.domain, name)
        return f"{self._zone_url()}/rrsets/{rrset_name}/{rtype}"

    def _rrset_to_records(self, rrset: RecordSet) -> list[dict[str, Any]]:
        return [
            {
                "id": rrset["id"],
                "name": self._full_name(rrset["name"]),
                "content": record["value"]
                if rrset["type"] != "TXT"
                else record["value"].replace('""', " ").lstrip('"').rstrip('"'),
                "type": rrset["type"],
                "ttl": rrset["ttl"],
            }
            for record in rrset["records"]
        ]

    @staticmethod
    def _record_from(rtype: str, content: str) -> Record:
        escaped_content = (
            "".join(map(lambda part: f'"{part}"', content.split()))
            if rtype == "TXT"
            else content
        )
        return Record({"value": escaped_content})
