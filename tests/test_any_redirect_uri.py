"""Tests for the ANY_REDIRECT_URI seeding sentinel and /authorize's
redirect-URI logging (origo#22/#26 follow-up: connector surfaces like
ChatGPT/Grok whose callback URLs are undocumented or churn).

The sentinel disables exact redirect-URI matching for one pre-seeded
confidential client. What must keep holding, and is pinned here:

- scheme validation still runs at /authorize (https / loopback / declared
  custom schemes only);
- the sentinel is a startup error for secret-less clients and when mixed
  with explicit URIs, and a bare non-sentinel string is a TypeError rather
  than silently becoming a set of characters;
- dynamically registered clients can never obtain wildcard behavior;
- rejected URIs (and wildcard-accepted ones) are logged with the client_id,
  which is the operator's way of harvesting a connector's real callback URL.
"""

import logging

import pytest
from httpx import ASGITransport, AsyncClient

from origo import ANY_REDIRECT_URI, OAuthProvider
from origo.endpoints import _build_redirect, _is_valid_redirect_uri, _uri_is_header_safe
from origo.sqlite_storage import SQLiteOAuthStorage
from origo.storage import OAuthStorage

from tests.conftest import do_full_flow, make_pkce_pair


def _wildcard_provider(**kwargs):
    return OAuthProvider(
        base_url="http://testserver",
        clients={"wild": "wild-secret"},
        client_redirect_uris={"wild": ANY_REDIRECT_URI},
        auto_approve=True,
        **kwargs,
    )


async def _authorize(client, redirect_uri, client_id="wild"):
    _, challenge = make_pkce_pair()
    return await client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
            "response_type": "code",
        },
        follow_redirects=False,
    )


# ── the wildcard accepts arbitrary https URIs, end to end ────────────────────


async def test_wildcard_full_flow_with_unregistered_https_uri():
    provider = _wildcard_provider()
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        token = await do_full_flow(
            client,
            provider,
            "wild",
            "wild-secret",
            redirect_uri="https://connector.example/oauth/cb-93f1?flow=2",
        )
    assert provider.verify_token(token) is not None


async def test_wildcard_accepts_two_different_uris_across_flows():
    # The point of the sentinel: ChatGPT and Grok can both connect without
    # either callback having been configured anywhere.
    provider = _wildcard_provider()
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        for uri in (
            "https://chatgpt.example/connector/oauth/abc",
            "https://grok.example/callback",
        ):
            resp = await _authorize(client, uri)
            assert resp.status_code == 302
            assert resp.headers["location"].startswith(uri)


# ── scheme validation still applies to wildcard clients ──────────────────────


@pytest.mark.parametrize(
    "bad_uri",
    [
        "http://attacker.example/cb",  # http, not loopback
        "javascript:alert(1)",
        "data:text/html,x",
        "myapp://callback",  # custom scheme not declared
        "https://ok.example/cb#fragment",
        "https://user:pw@ok.example/cb",
    ],
)
async def test_wildcard_still_rejects_invalid_schemes(bad_uri):
    provider = _wildcard_provider()
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        resp = await _authorize(client, bad_uri)
    assert resp.status_code == 400
    assert resp.json()["error_description"] == "redirect_uri not allowed."


async def test_wildcard_honors_declared_custom_schemes():
    provider = _wildcard_provider(custom_redirect_uri_schemes=["myapp"])
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        resp = await _authorize(client, "myapp://callback")
    assert resp.status_code == 302


# ── adversarial input hardening: control chars, surrogates, header injection ─
#
# The wildcard path is the first to let an arbitrary scheme-valid redirect_uri
# reach store_code/_build_redirect, so it's where a control character or a lone
# surrogate would otherwise turn into CR/LF header injection or a
# UnicodeEncodeError 500. These pin the server-independent rejection — origo
# must not rely on the fronting ASGI server to sanitize such input.


@pytest.mark.parametrize(
    "label,bad_uri",
    [
        ("raw-crlf", "https://ok.example/cb\r\nSet-Cookie: p=1"),
        ("bare-cr", "https://ok.example/cb\rX"),
        ("bare-lf", "https://ok.example/cb\nX"),
        ("nul", "https://ok.example/cb\x00evil"),
        ("tab", "https://ok.example/cb\tx"),
        ("us-control", "https://ok.example/cb\x1f"),
        ("del", "https://ok.example/cb\x7f"),
        ("lone-surrogate", "https://ok.example/\ud800"),
        ("tab-in-scheme", "htt\tps://ok.example/cb"),
    ],
)
def test_header_unsafe_uris_rejected_by_validator(label, bad_uri):
    # The shared validator is the primary gate, exercised directly so the raw
    # bytes reach it without an HTTP client re-encoding them first.
    assert _uri_is_header_safe(bad_uri) is False
    assert _is_valid_redirect_uri(bad_uri) is False


def test_build_redirect_refuses_surrogate_base_uri_as_valueerror():
    # A lone surrogate in the base URI must surface as ValueError (which
    # /authorize renders as a 400), never a bare UnicodeEncodeError 500.
    with pytest.raises(ValueError, match="Invalid characters in redirect URI"):
        _build_redirect("https://ok.example/\ud800", {"code": "x"})


def test_build_redirect_output_is_always_header_safe_for_crlf():
    # urlunparse strips \r\n\t (WHATWG), so for CRLF the function neutralizes by
    # sanitizing rather than raising. Either outcome is acceptable; what must
    # hold is that whatever it RETURNS carries no CR/LF into the Location header.
    out = _build_redirect("https://ok.example/cb\r\nX: 1", {"code": "x"})
    assert "\r" not in out and "\n" not in out
    assert _uri_is_header_safe(out)


@pytest.mark.parametrize(
    "label,bad_uri",
    [
        ("raw-crlf", "https://ok.example/cb\r\nX"),
        ("nul", "https://ok.example/cb\x00"),
        ("control", "https://ok.example/cb\x01\x1f"),
    ],
)
async def test_wildcard_authorize_rejects_control_chars_cleanly(label, bad_uri):
    # End to end through /authorize on the wildcard client: a clean 400, no
    # 500, and no control character reflected into a Location header.
    provider = _wildcard_provider()
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        resp = await _authorize(client, bad_uri)
    assert resp.status_code == 400
    assert resp.json()["error_description"] == "redirect_uri not allowed."
    assert "location" not in resp.headers


def test_percent_decoded_surrogate_is_header_safe_false():
    # %ED%A0%80 percent-decodes to U+D800; whatever a fronting server hands us,
    # origo's own guard classifies it as unsafe rather than trusting the server
    # to have replaced it.
    from urllib.parse import unquote

    decoded = unquote("https://ok.example/%ED%A0%80", errors="surrogatepass")
    assert _uri_is_header_safe(decoded) is False


def test_legitimate_uris_still_pass_the_hardened_validator():
    # The hardening must not reject normal callback URLs, including punycode
    # IDN hosts and query-bearing URLs.
    for good in (
        "https://connector.example/oauth/cb?flow=2&state=abc",
        "http://localhost/cb",
        "http://127.0.0.1:8765/callback",
        "https://xn--e1awd7f.example/cb",
    ):
        assert _uri_is_header_safe(good) is True
        assert _is_valid_redirect_uri(good) is True


# ── seeding guard rails ──────────────────────────────────────────────────────


def test_sentinel_requires_a_secret():
    with pytest.raises(ValueError, match="requires a confidential client"):
        OAuthProvider(
            base_url="http://testserver",
            clients={"wild": ""},
            client_redirect_uris={"wild": ANY_REDIRECT_URI},
        )


def test_sentinel_cannot_be_mixed_with_explicit_uris():
    with pytest.raises(ValueError, match="mixes"):
        OAuthProvider(
            base_url="http://testserver",
            clients={"wild": "s"},
            client_redirect_uris={"wild": [ANY_REDIRECT_URI, "https://example.com/cb"]},
        )


def test_bare_non_sentinel_string_is_a_type_error():
    # set("https://…") would silently become a set of characters — refuse it.
    with pytest.raises(TypeError, match="expected a list"):
        OAuthProvider(
            base_url="http://testserver",
            clients={"c": "s"},
            client_redirect_uris={"c": "https://example.com/cb"},
        )


async def test_sentinel_as_single_element_list_is_equivalent():
    provider = OAuthProvider(
        base_url="http://testserver",
        clients={"wild": "wild-secret"},
        client_redirect_uris={"wild": [ANY_REDIRECT_URI]},
        auto_approve=True,
    )
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        resp = await _authorize(client, "https://anything.example/cb")
    assert resp.status_code == 302


# ── non-wildcard behavior is unchanged ───────────────────────────────────────


async def test_exact_match_client_still_fails_closed():
    provider = OAuthProvider(
        base_url="http://testserver",
        clients={"strict": "s", "wild": "wild-secret"},
        client_redirect_uris={
            "strict": ["https://allowed.example/cb"],
            "wild": ANY_REDIRECT_URI,
        },
        auto_approve=True,
    )
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        resp = await _authorize(
            client, "https://other.example/cb", client_id="strict"
        )
    assert resp.status_code == 400
    assert resp.json()["error_description"] == "redirect_uri not allowed."


def test_sentinel_never_leaks_into_the_exact_match_allowlist():
    # A lone ["any"] is consumed as configuration (the wildcard), so the
    # literal string must not remain matchable as if it were a URI, and
    # is_redirect_uri_allowed itself must stay non-wildcarding.
    storage = OAuthStorage()
    storage.seed_clients({"c": "s"}, {"c": [ANY_REDIRECT_URI]})
    assert storage.allows_any_redirect_uri("c")
    assert not storage.is_redirect_uri_allowed("c", ANY_REDIRECT_URI)
    assert not storage.is_redirect_uri_allowed("c", "https://example.com/cb")


# ── dynamic clients can never obtain the wildcard ────────────────────────────


async def test_dcr_registration_cannot_smuggle_the_sentinel():
    provider = OAuthProvider(base_url="http://testserver", public_registration=True)
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        resp = await client.post(
            "/register",
            json={"redirect_uris": [ANY_REDIRECT_URI], "client_name": "sneaky"},
        )
    # "any" is not a valid URI, so registration-time scheme validation
    # rejects it before it could ever reach an allowlist.
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


def test_dynamic_client_never_wildcards_even_with_sentinel_in_storage():
    # Defense in depth: even if a registration path ever wrote the literal
    # sentinel into a dynamic client's allowlist, it must not wildcard.
    storage = OAuthStorage()
    storage.register_client("dyn", "s", [ANY_REDIRECT_URI])
    assert not storage.allows_any_redirect_uri("dyn")
    assert not storage.is_redirect_uri_allowed("dyn", "https://example.com/cb")


# ── SQLite storage parity ────────────────────────────────────────────────────


def test_sqlite_seeded_wildcard(tmp_path):
    storage = SQLiteOAuthStorage(str(tmp_path / "origo.db"))
    storage.seed_clients({"wild": "s"}, {"wild": ANY_REDIRECT_URI})
    assert storage.allows_any_redirect_uri("wild")
    assert not storage.is_redirect_uri_allowed("wild", "https://example.com/cb")


def test_sqlite_sentinel_requires_secret(tmp_path):
    storage = SQLiteOAuthStorage(str(tmp_path / "origo.db"))
    with pytest.raises(ValueError, match="requires a confidential client"):
        storage.seed_clients({"wild": None}, {"wild": ANY_REDIRECT_URI})


def test_sqlite_dynamic_client_never_wildcards(tmp_path):
    storage = SQLiteOAuthStorage(str(tmp_path / "origo.db"))
    storage.register_client("dyn", "s", [ANY_REDIRECT_URI])
    assert not storage.allows_any_redirect_uri("dyn")
    assert not storage.is_redirect_uri_allowed("dyn", "https://example.com/cb")


async def test_wildcard_flow_with_sqlite_storage(tmp_path):
    provider = OAuthProvider(
        base_url="http://testserver",
        clients={"wild": "wild-secret"},
        client_redirect_uris={"wild": ANY_REDIRECT_URI},
        auto_approve=True,
        storage_path=str(tmp_path / "origo.db"),
    )
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        token = await do_full_flow(
            client, provider, "wild", "wild-secret",
            redirect_uri="https://connector.example/cb",
        )
    assert provider.verify_token(token) is not None


# ── logging: how operators harvest connector callback URLs ───────────────────


async def test_rejected_redirect_uri_is_logged_with_client_id(caplog):
    provider = OAuthProvider(
        base_url="http://testserver",
        clients={"strict": "s"},
        client_redirect_uris={"strict": ["https://allowed.example/cb"]},
        auto_approve=True,
    )
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        with caplog.at_level(logging.WARNING, logger="origo"):
            await _authorize(
                client, "https://chatgpt.example/connector/oauth/xyz", client_id="strict"
            )
    [record] = [r for r in caplog.records if "rejected redirect_uri" in r.message]
    assert "'https://chatgpt.example/connector/oauth/xyz'" in record.message
    assert "'strict'" in record.message


async def test_wildcard_accepted_redirect_uri_is_logged(caplog):
    provider = _wildcard_provider()
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        with caplog.at_level(logging.INFO, logger="origo"):
            await _authorize(client, "https://grok.example/callback")
    [record] = [r for r in caplog.records if "wildcard" in r.message and "accepted" in r.message]
    assert "'https://grok.example/callback'" in record.message
    assert "'wild'" in record.message


async def test_wildcard_scheme_rejection_is_logged(caplog):
    provider = _wildcard_provider()
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        with caplog.at_level(logging.WARNING, logger="origo"):
            await _authorize(client, "http://attacker.example/cb")
    [record] = [r for r in caplog.records if "rejected redirect_uri" in r.message]
    assert "'http://attacker.example/cb'" in record.message
