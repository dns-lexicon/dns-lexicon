"""Gransy provider for subreg.cz, regtons.com and regnames.eu."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, NoReturn

try:
    import zeep
except BaseException:
    pass

from lexicon.config import ConfigResolver
from lexicon.exceptions import AuthenticationError
from lexicon.interfaces import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)

SOAP_WSDL_URL = "https://subreg.cz/wsdl"
# Vendored copy of SOAP_WSDL_URL; a live test checks for drift
SOAP_WSDL = files("lexicon._private.providers") / "gransy.wsdl"


@dataclass(slots=True, kw_only=True)
class GransyRequest:
    """DNS record sent to the Gransy API."""

    type: str | None = None
    name: str | None = None
    content: str | None = None
    ttl: int | None = None
    prio: int | None = None

    def to_payload(self) -> dict[str, Any]:
        """Sparse dict for the SOAP API; ``type`` is always present."""
        body: dict[str, Any] = {"type": self.type}
        if self.name is not None:
            body["name"] = self.name
        if self.content is not None:
            body["content"] = self.content
        if self.ttl is not None:
            body["ttl"] = self.ttl
        if self.prio is not None:
            body["prio"] = self.prio
        return body


@dataclass(slots=True, kw_only=True)
class GransyResponse:
    """DNS record returned by the Gransy API."""

    id: int | str
    type: str
    name: str | None
    content: str | None = None
    ttl: int | None = None
    prio: int | None = None

    @classmethod
    def from_soap(cls, raw: Any) -> GransyResponse:
        """Build from a zeep record; zeep yields ``None`` for empty elements."""
        return cls(
            id=raw["id"],
            type=raw["type"],
            name=raw["name"],
            content=raw["content"],
            ttl=raw["ttl"],
            prio=raw["prio"],
        )


class Provider(BaseProvider):
    """Provider class for Gransy"""

    @staticmethod
    def get_nameservers() -> list[str]:
        return ["gransy.com"]

    @staticmethod
    def configure_parser(parser: ArgumentParser) -> None:
        parser.description = (
            "DNS manipulation provider for Gransy sites "
            + "subreg.cz, regtons.com and regnames.eu."
        )
        parser.add_argument(
            "--auth-username", help="specify username for authentication"
        )
        parser.add_argument(
            "--auth-password", help="specify password for authentication"
        )
        parser.add_argument(
            "--remote-api-definition",
            action="store_true",
            help=(
                "use the SOAP API definition served by subreg.cz instead of the "
                "bundled one (on every run, nothing is cached)"
            ),
        )

    def __init__(self, config: ConfigResolver | dict[str, Any]) -> None:
        super().__init__(config)
        self._api: _GransyApi = _SoapApi(self)

    # Authenticate against provider,
    # Make any requests required to get the domain's id for
    # this provider, so it can be used in subsequent calls.
    # Should throw an error if authentication fails for any reason,
    # of if the domain does not exist.
    def authenticate(self) -> None:
        """Authenticates the user and checks the domain name"""
        self._api.authenticate()
        domains = self._api.list_domains()
        if any(domain == self.domain for domain in domains):
            self.domain_id = self.domain  # type: ignore[assignment]
        else:
            raise AuthenticationError(f"Unknown domain {self.domain}")

    def cleanup(self) -> None:
        pass

    # Create record. If record already exists with the same content, do nothing.
    def create_record(self, rtype: str, name: str, content: str) -> bool:
        """Creates a new unique record"""
        found = self.list_records(rtype=rtype, name=name, content=content)
        if found:
            return True

        record = self._create_request_record(
            rtype,
            name,
            content,
            self._get_lexicon_option("ttl"),
            self._get_lexicon_option("priority"),
        )

        self._api.add_record(record)
        return True

    # Update a record. Identifier must be specified.
    def update_record(
        self,
        identifier: str | None = None,
        rtype: str | None = None,
        name: str | None = None,
        content: str | None = None,
    ) -> bool:
        """Updates a record. Name changes are allowed, but the record identifier will change"""
        if identifier is not None:
            if name is not None:
                records = self._list_records_internal(identifier=identifier)
                if len(records) == 1 and records[0]["name"] != self._full_name(name):
                    # API does not allow us to update name directly
                    self._update_record_with_name(records[0], rtype, name, content)
                else:
                    self._update_record_with_id(identifier, rtype, content)
            else:
                self._update_record_with_id(identifier, rtype, content)
        else:
            guessed_record = self._guess_record(rtype, name)
            self._update_record_with_id(guessed_record["id"], rtype, content)
        return True

    def _update_record_with_id(
        self, identifier: int | str, rtype: str | None, content: str | None
    ) -> None:
        """Updates existing record with no sub-domain name changes"""
        record = self._create_request_record(
            rtype,
            None,
            content,
            self._get_lexicon_option("ttl"),
            self._get_lexicon_option("priority"),
        )

        self._api.modify_record(identifier, record)

    def _update_record_with_name(
        self,
        old_record: dict[str, Any],
        rtype: str | None,
        new_name: str,
        content: str | None,
    ) -> None:
        """Updates existing record and changes its sub-domain name"""
        new_type = rtype if rtype else old_record["type"]

        new_ttl = self._get_lexicon_option("ttl")
        if new_ttl is None and "ttl" in old_record:
            new_ttl = old_record["ttl"]

        new_priority = self._get_lexicon_option("priority")
        if new_priority is None and "priority" in old_record:
            new_priority = old_record["priority"]

        new_content = content
        if new_content is None and "content" in old_record:
            new_content = old_record["content"]

        record = self._create_request_record(
            new_type, new_name, new_content, new_ttl, new_priority
        )

        # This will be a different domain name, so no name collision should
        # happen. First create a new entry and when it succeeds, delete the old
        # one.
        self._api.add_record(record)
        self._api.delete_record(old_record["id"])

    # Delete an existing record.
    # If record does not exist, do nothing.
    # If an identifier is specified, use it, otherwise do a lookup using type, name and content.
    def delete_record(
        self,
        identifier: str | None = None,
        rtype: str | None = None,
        name: str | None = None,
        content: str | None = None,
    ) -> bool:
        """Deletes an existing record"""
        to_delete_ids: list[int | str] = []
        if identifier:
            to_delete_ids.append(identifier)
        else:
            for record in self.list_records(rtype=rtype, name=name, content=content):
                to_delete_ids.append(record["id"])

        for to_delete_id in to_delete_ids:
            self._api.delete_record(to_delete_id)
        return True

    def _create_request_record(
        self,
        rtype: str | None,
        name: str | None,
        content: str | None,
        ttl: int | str | None,
        priority: int | str | None,
    ) -> GransyRequest:
        """Creates record for Subreg API calls"""
        return GransyRequest(
            type=rtype,
            # `name` only on creation, where both APIs require it; apex is ""
            name=(self._relative_name(name) or "") if name is not None else None,
            content=content,
            ttl=int(ttl) if ttl is not None else None,
            prio=int(priority) if priority is not None else None,
        )

    def _create_response_record(self, response: GransyResponse) -> dict[str, Any]:
        """Creates record for lexicon API calls"""
        record: dict[str, Any] = {
            "id": response.id,
            "type": response.type,
            "name": self._full_name(response.name),
            # Empty content arrives as None; lexicon expects the key
            "content": response.content or "",
        }
        if response.ttl is not None:
            record["ttl"] = response.ttl
        if response.prio is not None:
            record["priority"] = response.prio
        return record

    def _full_name(self, record_name: str | None) -> str:
        """Returns full domain name of a sub-domain name"""
        # Handle None and empty strings
        if not record_name:
            return self.domain
        return super()._full_name(record_name)

    def _relative_name(  # type: ignore[override]
        self, record_name: str | None
    ) -> str | None:
        """Returns sub-domain of a domain name"""
        # Handle None and empty strings as None
        if not record_name:
            return None
        subdomain = super()._relative_name(record_name)
        return subdomain if subdomain else None

    # List all records. Return an empty list if no records found
    # identifier, type, name and content are used to filter records.
    def list_records(
        self,
        rtype: str | None = None,
        name: str | None = None,
        content: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._list_records_internal(rtype=rtype, name=name, content=content)

    def _list_records_internal(
        self,
        identifier: str | None = None,
        rtype: str | None = None,
        name: str | None = None,
        content: str | None = None,
    ) -> list[dict[str, Any]]:
        """Lists all records by the specified criteria"""
        records = self._api.list_records()
        # Interpret empty string as None because zeep does so too
        content_check = content if content != "" else None
        name_check = self._relative_name(name)

        # Stringize the identifier to prevent any rtype differences
        identifier_check = str(identifier) if identifier is not None else None

        filtered = [
            record
            for record in records
            if (identifier is None or str(record.id) == identifier_check)
            and (rtype is None or record.type == rtype)
            and (name is None or record.name == name_check)
            and (content is None or record.content == content_check)
        ]
        return [self._create_response_record(record) for record in filtered]

    def _guess_record(
        self,
        rtype: str | None,
        name: str | None = None,
        content: str | None = None,
    ) -> dict[str, Any]:
        """Tries to find existing unique record by type, name and content"""
        records = self._list_records_internal(
            identifier=None, rtype=rtype, name=name, content=content
        )
        if len(records) == 1:
            return records[0]
        if len(records) > 1:
            raise Exception(
                "Identifier was not provided and several existing "
                f"records match the request for {rtype}/{name}"
            )
        raise Exception(
            "Identifier was not provided and no existing records match "
            f"the request for {rtype}/{name}"
        )

    def _request(
        self,
        action: str = "GET",
        url: str = "/",
        data: dict[str, Any] | None = None,
        query_params: dict[str, Any] | None = None,
    ) -> Any:
        # Default helper _request is not used in Gransy provider
        pass


class _GransyApi(ABC):
    """Common interface for Gransy API backends."""

    @abstractmethod
    def authenticate(self) -> None: ...

    @abstractmethod
    def list_domains(self) -> list[str]: ...

    @abstractmethod
    def list_records(self) -> list[GransyResponse]: ...

    @abstractmethod
    def add_record(self, record: GransyRequest) -> None: ...

    @abstractmethod
    def modify_record(self, identifier: int | str, record: GransyRequest) -> None: ...

    @abstractmethod
    def delete_record(self, identifier: int | str) -> None: ...


class _SoapApi(_GransyApi):
    """SOAP backend at subreg.cz/wsdl, authenticated with username + password."""

    def __init__(self, provider: Provider) -> None:
        self._provider = provider
        self._ssid: str | None = None
        # The definition is self-contained; never follow external references
        settings = zeep.Settings(forbid_external=True)
        if provider._get_provider_option("remote_api_definition"):
            client = zeep.Client(SOAP_WSDL_URL, settings=settings)
        else:
            with SOAP_WSDL.open("rb") as wsdl:
                client = zeep.Client(wsdl, settings=settings)
        self._service = client.service

    def authenticate(self) -> None:
        username = self._provider._get_provider_option("auth_username")
        password = self._provider._get_provider_option("auth_password")
        if not username or not password:
            raise Exception(
                "No valid authentication data passed, expected: auth-username and auth-password"
            )
        response = self._call("Login", login=username, password=password)
        if "ssid" not in response:
            raise AuthenticationError("No SSID provided by server")
        self._ssid = response["ssid"]

    def list_domains(self) -> list[str]:
        response = self._call("Domains_List")
        domains = response["domains"] if "domains" in response else []
        return [d["name"] for d in domains or []]

    def list_records(self) -> list[GransyResponse]:
        response = self._call("Get_DNS_Zone", domain=self._provider.domain)
        records = response["records"] if "records" in response else []
        return [GransyResponse.from_soap(r) for r in records or []]

    def add_record(self, record: GransyRequest) -> None:
        self._call(
            "Add_DNS_Record", domain=self._provider.domain, record=record.to_payload()
        )

    def modify_record(self, identifier: int | str, record: GransyRequest) -> None:
        body = {"id": identifier, **record.to_payload()}
        self._call("Modify_DNS_Record", domain=self._provider.domain, record=body)

    def delete_record(self, identifier: int | str) -> None:
        self._call(
            "Delete_DNS_Record",
            domain=self._provider.domain,
            record={"id": identifier},
        )

    def _call(self, command: str, **kwargs: Any) -> Any:
        args: dict[str, Any] = dict(kwargs)
        if self._ssid:
            args["ssid"] = self._ssid
        method = getattr(self._service, command)
        try:
            response = method(**args)
        except (
            zeep.exceptions.ValidationError,
            zeep.exceptions.XMLParseError,
            zeep.exceptions.UnexpectedElementError,
        ) as e:
            raise Exception(
                f"{e} - the bundled SOAP API definition may be outdated, "
                "try --remote-api-definition"
            ) from e
        if response and "status" in response:
            if response["status"] == "error":
                GransyError.raise_for(
                    major=response["error"]["errorcode"]["major"],
                    minor=response["error"]["errorcode"]["minor"],
                    message=response["error"]["errormsg"],
                )
            if response["status"] == "ok":
                return response["data"] if "data" in response else dict()
            raise Exception("Invalid status found in SOAP response")
        raise Exception("Invalid response")


class GransyError(Exception):
    """Specific error for Gransy provider"""

    def __init__(self, major: int | str, minor: int | str, message: str) -> None:
        self.major = int(major)
        self.minor = int(minor)
        self.message = message
        super().__init__()

    def __str__(self) -> str:
        return f"Major: {self.major} Minor: {self.minor} Message: {self.message}"

    @staticmethod
    def raise_for(*, major: int | str, minor: int | str, message: str) -> NoReturn:
        raise GransyError(major, minor, message)
