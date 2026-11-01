"""
This module takes care of finding information about the runtime of Lexicon:
* what are the providers installed, and available
* what is the version of Lexicon
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import sys
from types import ModuleType

from lexicon._private import providers as _providers

if sys.version_info >= (3, 10):  # pragma: no cover
    from importlib.metadata import Distribution, PackageNotFoundError
else:
    from importlib_metadata import Distribution, PackageNotFoundError


def find_providers() -> list[str]:
    """Return the sorted names of all providers registered in Lexicon."""
    return sorted(
        {
            modname
            for (_, modname, _) in pkgutil.iter_modules(_providers.__path__)
            if modname != "base"
        }
    )


def list_extras(provider: str) -> list[str]:
    """Return the PyPI package names declared for ``provider`` in the
    package's optional-dependencies. Empty list when no metadata is
    available."""
    try:
        distribution = Distribution.from_name("dns-lexicon")
    except PackageNotFoundError:
        return []

    requires = distribution.requires
    if requires is None:
        raise ValueError("Error while trying finding requirements.")

    extras: list[str] = []
    for require in requires:
        match = re.match(
            rf"^([\w-]+)\s*[<>=]+\s*[\d\.-]+\s*;\s*extra\s*==\s*(?:\"|'){provider}(?:\"|')$",
            require,
        )
        if match is not None:
            extras.append(match.group(1))
    return extras


def is_installed(package: str) -> bool:
    """Return True when ``package`` is installed."""
    try:
        Distribution.from_name(package)
    except PackageNotFoundError:
        return False
    return True


def find_missing_extras(provider: str) -> list[str]:
    """Return the entries of ``list_extras(provider)`` that are not
    installed. Empty list when no metadata is available."""
    return [extra for extra in list_extras(provider) if not is_installed(extra)]


def load_provider_module(provider_name: str) -> ModuleType:
    return importlib.import_module(f"{_providers.__name__}.{provider_name}")


def lexicon_version() -> str:
    """Retrieve current Lexicon version"""
    try:
        return Distribution.from_name("dns-lexicon").version
    except PackageNotFoundError:
        return "unknown"
