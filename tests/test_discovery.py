# pylint: disable=missing-docstring
from lexicon._private import discovery


def test_list_extras_resolves_known_provider_extras():
    # gransy declares `zeep` as an extra in pyproject.toml's optional-dependencies.
    assert "zeep" in discovery.list_extras("gransy")


def test_is_installed_positive_and_negative():
    assert discovery.is_installed("pytest")
    assert not discovery.is_installed("a-package-that-does-not-exist-12345")


def test_find_missing_extras_filters_by_install_status(monkeypatch):
    monkeypatch.setattr(discovery, "list_extras", lambda p: ["pkg-a", "pkg-b", "pkg-c"])
    monkeypatch.setattr(discovery, "is_installed", lambda pkg: pkg != "pkg-b")
    assert discovery.find_missing_extras("any-provider") == ["pkg-b"]
