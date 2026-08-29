import contextlib
import importlib
import pkgutil
from argparse import ArgumentParser
from collections.abc import Iterator
from re import Pattern
from types import ModuleType
from typing import cast
from unittest import mock

import pytest


def pytest_addoption(parser):
    """Standard pytest hook invoked to add options to pytest CLI"""
    parser.addoption(
        "--xfail-providers-with-missing-deps",
        action="store_true",
        help="Skip tests on providers with optional dependencies",
    )


def pytest_runtest_setup(item):
    """Standard pytest hook invoked before each test execution"""
    try:
        skip_providers_with_optdeps = getattr(
            item.config.option, "xfail_providers_with_missing_deps"
        )
    except AttributeError:
        pass
    else:
        if skip_providers_with_optdeps:
            from lexicon._private.discovery import find_missing_extras, find_providers

            matching = [
                provider
                for provider in find_providers()
                if provider in item.parent.name.lower()
            ]
            if matching and find_missing_extras(matching[0]):
                pytest.xfail(
                    "Test expected to fail because --skip-providers-with-missing-deps "
                    "is set and provider has missing required dependencies."
                )


_FAKE_PROVIDERS: dict[str, type] = {}


@contextlib.contextmanager
def register_fake_provider(name: str, provider_cls: type) -> Iterator[None]:
    """Make ``provider_cls`` discoverable as Lexicon provider ``name`` for
    the duration of the context.

    The session-wide ``_fake_provider_patches`` fixture redirects
    ``pkgutil.iter_modules`` and ``importlib.import_module`` through this
    registry, so any code path that looks up a provider by name will see the
    fake class while the context is active.
    """
    if name in _FAKE_PROVIDERS:
        raise ValueError(f"Fake provider {name!r} is already registered")
    _FAKE_PROVIDERS[name] = provider_cls
    try:
        yield
    finally:
        _FAKE_PROVIDERS.pop(name, None)


@pytest.fixture(scope="session", autouse=True)
def _fake_provider_patches() -> Iterator[None]:
    """Route Lexicon's provider discovery through ``_FAKE_PROVIDERS`` for
    the whole test session. Inert when the registry is empty."""
    original_iter = pkgutil.iter_modules
    original_import = importlib.import_module

    def return_iter(path):
        return [*original_iter(path), *((None, name, None) for name in _FAKE_PROVIDERS)]

    def return_import(module_name):
        for name, cls in _FAKE_PROVIDERS.items():
            if module_name == f"lexicon._private.providers.{name}":
                module = ModuleType(module_name)
                module.Provider = cls
                return module
        return original_import(module_name)

    with (
        mock.patch(
            "lexicon._private.discovery.pkgutil.iter_modules", side_effect=return_iter
        ),
        mock.patch(
            "lexicon._private.discovery.importlib.import_module",
            side_effect=return_import,
        ),
    ):
        yield


@pytest.fixture(scope="session")
def mock_provider() -> Iterator[None]:
    """A ``fakeprovider`` with no extras, used by most Client tests."""
    from lexicon.interfaces import Provider as BaseProvider

    class Provider(BaseProvider):
        """
        Fake provider to simulate the provider resolution from configuration,
        and to have execution traces when lexicon client is invoked
        """

        @staticmethod
        def get_nameservers() -> list[str] | list[Pattern]:
            return cast(list[str], [])

        @staticmethod
        def configure_parser(parser: ArgumentParser) -> None:
            pass

        def authenticate(self):
            print("Authenticate action")

        def create_record(self, rtype, name, content):
            return {
                "action": "create",
                "domain": self.domain,
                "type": rtype,
                "name": name,
                "content": content,
            }

        def list_records(self, rtype=None, name=None, content=None):
            return {
                "action": "list",
                "domain": self.domain,
                "type": rtype,
                "name": name,
                "content": content,
            }

        def update_record(self, identifier=None, rtype=None, name=None, content=None):
            return {
                "action": "update",
                "domain": self.domain,
                "identifier": identifier,
                "type": rtype,
                "name": name,
                "content": content,
            }

        def delete_record(self, identifier=None, rtype=None, name=None, content=None):
            return {
                "action": "delete",
                "domain": self.domain,
                "identifier": identifier,
                "type": rtype,
                "name": name,
                "content": content,
            }

        def _request(self, action="GET", url="/", data=None, query_params=None):
            # Not use for tests
            pass

    with register_fake_provider("fakeprovider", Provider):
        yield


@pytest.fixture
def extras_provider(monkeypatch) -> Iterator[None]:
    """An ``extrasprovider`` that declares one fake extra and drops it from
    required extras when ``use_alt`` is set on the config."""
    from lexicon import client as client_module
    from lexicon._private import discovery
    from lexicon.interfaces import Provider as BaseProvider

    class Provider(BaseProvider):
        @staticmethod
        def get_nameservers() -> list[str] | list[Pattern]:
            return cast(list[str], [])

        @staticmethod
        def configure_parser(parser: ArgumentParser) -> None:
            pass

        def authenticate(self):
            pass

        def create_record(self, rtype, name, content):
            return True

        def list_records(self, rtype=None, name=None, content=None):
            return []

        def update_record(self, identifier=None, rtype=None, name=None, content=None):
            return True

        def delete_record(self, identifier=None, rtype=None, name=None, content=None):
            return True

        def _request(self, action="GET", url="/", data=None, query_params=None):
            pass

        @classmethod
        def filter_required_extras(cls, extras, config):
            if config.resolve("lexicon:extrasprovider:use_alt"):
                return []
            return extras

        @classmethod
        def missing_extras_error(cls, provider_name, missing):
            pkgs = ", ".join(f"`{m}`" for m in missing)
            return (
                f"Cannot use {provider_name}: {pkgs} not installed. "
                f"Either run `pip install {' '.join(missing)}`, "
                "or pass --use-alt."
            )

    real_list_extras = discovery.list_extras

    def patched_list_extras(provider: str) -> list[str]:
        if provider == "extrasprovider":
            return ["fake-pkg"]
        return real_list_extras(provider)

    monkeypatch.setattr(discovery, "list_extras", patched_list_extras)
    monkeypatch.setattr(client_module, "_list_extras", patched_list_extras)

    with register_fake_provider("extrasprovider", Provider):
        yield
