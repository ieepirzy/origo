"""Behavior of OAuthProvider's storage_path default: persistence is on by
default (namespaced under ./.origo, or ORIGO_STORAGE_PATH if set), and
turning it off is an explicit action — storage_path=None in code, or
ORIGO_STORAGE_PATH="" as an operational escape hatch. See origo/provider.py.

The suite-wide autouse fixture in conftest.py sets ORIGO_STORAGE_PATH="" for
every other test file, so these tests explicitly override it back on to
exercise the real default.
"""

import os

import pytest

from origo import OAuthProvider
from origo.sqlite_storage import SQLiteOAuthStorage
from origo.storage import OAuthStorage


def test_omitted_storage_path_persists_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("ORIGO_STORAGE_PATH", str(tmp_path))
    provider = OAuthProvider(base_url="https://example.com", clients={"c": "s"})
    assert isinstance(provider.storage, SQLiteOAuthStorage)
    files = list(tmp_path.glob("*.db"))
    assert len(files) == 1


def test_default_path_is_namespaced_by_base_url_and_mcp_path(tmp_path, monkeypatch):
    monkeypatch.setenv("ORIGO_STORAGE_PATH", str(tmp_path))
    OAuthProvider(base_url="https://a.example.com", clients={"c": "s"})
    OAuthProvider(base_url="https://b.example.com", clients={"c": "s"})
    OAuthProvider(base_url="https://a.example.com", clients={"c": "s"}, mcp_path="/sse")
    # Three distinct (base_url, mcp_path) pairs -> three distinct files.
    assert len(list(tmp_path.glob("*.db"))) == 3


def test_default_path_is_stable_for_the_same_deployment(tmp_path, monkeypatch):
    """The other side of namespacing: the same (base_url, mcp_path) resolves
    to the same file across separate OAuthProvider instances (== restarts of
    the same logical deployment), which is what makes persistence work at
    all across a process restart."""
    monkeypatch.setenv("ORIGO_STORAGE_PATH", str(tmp_path))
    OAuthProvider(base_url="https://example.com", clients={"c": "s"})
    OAuthProvider(base_url="https://example.com", clients={"c": "s"})
    assert len(list(tmp_path.glob("*.db"))) == 1


def test_explicit_none_forces_in_memory_even_with_env_set(tmp_path, monkeypatch):
    monkeypatch.setenv("ORIGO_STORAGE_PATH", str(tmp_path))
    provider = OAuthProvider(base_url="https://example.com", clients={"c": "s"}, storage_path=None)
    assert isinstance(provider.storage, OAuthStorage)
    assert list(tmp_path.glob("*.db")) == []


def test_empty_env_var_forces_in_memory_without_code_change(tmp_path, monkeypatch):
    monkeypatch.setenv("ORIGO_STORAGE_PATH", "")
    provider = OAuthProvider(base_url="https://example.com", clients={"c": "s"})
    assert isinstance(provider.storage, OAuthStorage)


def test_explicit_path_overrides_env_var(tmp_path, monkeypatch):
    other_dir = tmp_path / "elsewhere"
    other_dir.mkdir()
    monkeypatch.setenv("ORIGO_STORAGE_PATH", str(tmp_path / "unused"))
    explicit = str(other_dir / "explicit.db")
    provider = OAuthProvider(base_url="https://example.com", clients={"c": "s"}, storage_path=explicit)
    assert isinstance(provider.storage, SQLiteOAuthStorage)
    assert os.path.exists(explicit)
    assert not (tmp_path / "unused").exists()


def test_unwritable_default_path_falls_back_to_memory_with_warning(tmp_path, monkeypatch):
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory")  # forces os.makedirs to fail
    monkeypatch.setenv("ORIGO_STORAGE_PATH", str(blocked))
    with pytest.warns(UserWarning, match="falling back to in-memory storage"):
        provider = OAuthProvider(base_url="https://example.com", clients={"c": "s"})
    assert isinstance(provider.storage, OAuthStorage)


def test_corrupt_db_at_default_path_falls_back_to_memory_with_warning(tmp_path, monkeypatch):
    """A file can exist and be perfectly writable but not be a usable SQLite
    database (corrupt, truncated, or just not SQLite at all) -- SQLite raises
    sqlite3.DatabaseError/OperationalError for that, not OSError, so the
    fallback has to catch both."""
    import hashlib

    monkeypatch.setenv("ORIGO_STORAGE_PATH", str(tmp_path))
    base_url, mcp_path = "https://example.com", "/mcp"
    digest = hashlib.sha256(f"{base_url}|{mcp_path}".encode()).hexdigest()[:16]
    (tmp_path / f"{digest}.db").write_bytes(b"not a sqlite database")

    with pytest.warns(UserWarning, match="falling back to in-memory storage"):
        provider = OAuthProvider(base_url=base_url, clients={"c": "s"}, mcp_path=mcp_path)
    assert isinstance(provider.storage, OAuthStorage)


def test_corrupt_db_at_explicit_path_raises_instead_of_falling_back(tmp_path):
    bad_db = tmp_path / "corrupt.db"
    bad_db.write_bytes(b"not a sqlite database")
    with pytest.raises(Exception):
        OAuthProvider(base_url="https://example.com", clients={"c": "s"}, storage_path=str(bad_db))


def test_unwritable_explicit_path_raises_instead_of_falling_back(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory")
    with pytest.raises(OSError):
        OAuthProvider(
            base_url="https://example.com",
            clients={"c": "s"},
            storage_path=str(blocked / "origo.db"),
        )


async def test_default_persisted_provider_survives_simulated_restart(tmp_path, monkeypatch):
    from httpx import ASGITransport, AsyncClient

    from .conftest import do_full_flow

    monkeypatch.setenv("ORIGO_STORAGE_PATH", str(tmp_path))

    def make_provider():
        return OAuthProvider(
            base_url="https://example.com",
            clients={"test-client": "test-secret"},
            client_redirect_uris={"test-client": ["https://example.com/cb"]},
            auto_approve=True,
        )

    provider = make_provider()
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="https://example.com"
    ) as client:
        access_token = await do_full_flow(client, provider, "test-client", "test-secret")
    provider.storage.close()

    restarted = make_provider()  # no storage_path passed here either
    assert restarted.verify_token(access_token) is not None
