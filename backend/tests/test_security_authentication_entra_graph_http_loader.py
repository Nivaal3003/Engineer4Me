"""Tests for the bounded Microsoft Graph inventory HTTPS transport."""

from __future__ import annotations

from dataclasses import replace
from urllib.error import URLError

import pytest

from app.security.authentication_entra_graph_http_loader import (
    ENTRA_GRAPH_BASE_URL,
    ENTRA_GRAPH_INVENTORY_REQUEST_TIMEOUT_SECONDS,
    MAX_ENTRA_GRAPH_BEARER_TOKEN_BYTES,
    MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES,
    BoundedHTTPSEntraGraphInventoryLoader,
    EntraGraphHTTPError,
    EntraGraphInventoryRequest,
    EntraGraphInventoryResponse,
)


OBJECT_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
TOKEN = "opaque.delegated.graph.token"
SELECT = "id,appId,deletedDateTime"


def request() -> EntraGraphInventoryRequest:
    return EntraGraphInventoryRequest(
        sequence=1,
        role="api",
        resource="application",
        method="GET",
        url=f"{ENTRA_GRAPH_BASE_URL}/applications/{OBJECT_ID}?$select={SELECT}",
        headers=(
            ("Accept", "application/json"),
            ("Accept-Encoding", "identity"),
        ),
        body=None,
        timeout_seconds=ENTRA_GRAPH_INVENTORY_REQUEST_TIMEOUT_SECONDS,
        maximum_response_bytes=MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES,
        follow_redirects=False,
        maximum_retries=0,
        proxy_allowed=False,
    )


class RawResponse:
    def __init__(
        self,
        *,
        source=None,
        status=200,
        content_type="application/json",
        content_encoding=None,
        body=b"{}",
        content_length=None,
    ):
        self.status = status
        self._source = source or request().url
        self._body = body
        self.read_amounts = []
        self.headers = {"Content-Type": content_type}
        if content_encoding is not None:
            self.headers["Content-Encoding"] = content_encoding
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def geturl(self):
        return self._source

    def read(self, amount=-1):
        self.read_amounts.append(amount)
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


def test_injected_https_opener_is_bounded_and_always_synthetic():
    calls = []
    raw = RawResponse(
        content_type=(
            "application/json;odata.metadata=minimal;odata.streaming=true;"
            "IEEE754Compatible=false;charset=utf-8"
        )
    )

    def open_url(http_request, timeout):
        calls.append((http_request, timeout))
        return raw

    loader = BoundedHTTPSEntraGraphInventoryLoader(
        delegated_access_token=TOKEN,
        open_url=open_url,
    )
    result = loader(request())
    assert result.live_https_attested is False
    assert result.tls_peer_verified is False
    assert result.redirect_count == 0
    assert result.attempt_count == 1
    assert result.body == b"{}"
    assert len(calls) == 1
    sent, timeout = calls[0]
    assert sent.full_url == request().url
    assert sent.method == "GET"
    assert sent.data is None
    assert sent.get_header("Accept") == "application/json"
    assert sent.get_header("Accept-encoding") == "identity"
    assert sent.get_header("Authorization") == f"Bearer {TOKEN}"
    assert timeout == ENTRA_GRAPH_INVENTORY_REQUEST_TIMEOUT_SECONDS
    assert raw.read_amounts == [MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES + 1]


def test_rebinding_default_opener_cannot_forge_live_attestation(monkeypatch):
    monkeypatch.setattr(
        "app.security.authentication_entra_graph_http_loader._default_open",
        lambda _request, _timeout: RawResponse(),
    )
    loader = BoundedHTTPSEntraGraphInventoryLoader(delegated_access_token=TOKEN)
    result = loader(request())
    assert result.live_https_attested is False
    assert result.tls_peer_verified is False


def test_unmodified_module_owned_default_is_the_only_live_eligible_opener():
    from app.security import authentication_entra_graph_http_loader as graph_http

    loader = BoundedHTTPSEntraGraphInventoryLoader(delegated_access_token=TOKEN)
    assert loader._open_url is graph_http._MODULE_OWNED_DEFAULT_OPEN
    assert loader._default_transport is True
    loader.close()


def test_public_response_construction_cannot_claim_tls_or_live_attestation():
    response = EntraGraphInventoryResponse(
        status_code=200,
        final_url=request().url,
        content_type="application/json",
        body=b"{}",
    )
    assert response.live_https_attested is False
    with pytest.raises(ValueError):
        EntraGraphInventoryResponse(
            status_code=200,
            final_url=request().url,
            content_type="application/json",
            body=b"{}",
            tls_peer_verified=True,
        )


@pytest.mark.parametrize(
    "token",
    [
        "",
        "Bearer opaque",
        "opaque token",
        "opaque\ttoken",
        "opaque\r\ntoken",
        "opaque\x00token",
        "tökén",
        "x" * (MAX_ENTRA_GRAPH_BEARER_TOKEN_BYTES + 1),
        None,
        b"opaque",
    ],
)
def test_loader_rejects_invalid_or_prefixed_opaque_tokens(token):
    with pytest.raises(ValueError, match="token"):
        BoundedHTTPSEntraGraphInventoryLoader(
            delegated_access_token=token,
            open_url=lambda _request, _timeout: RawResponse(),
        )


def test_close_releases_token_reference_and_prevents_reuse():
    loader = BoundedHTTPSEntraGraphInventoryLoader(
        delegated_access_token=TOKEN,
        open_url=lambda _request, _timeout: RawResponse(),
    )
    loader.close()
    assert loader._delegated_access_token is None
    with pytest.raises(EntraGraphHTTPError, match="no longer available"):
        loader(request())


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("sequence", 0),
        ("sequence", True),
        ("role", "owner"),
        ("method", "POST"),
        ("headers", (("Accept", "application/json"),)),
        ("body", b"{}"),
        ("timeout_seconds", 10),
        ("timeout_seconds", 5.0),
        ("maximum_response_bytes", 1),
        ("follow_redirects", True),
        ("maximum_retries", 1),
        ("proxy_allowed", True),
    ],
)
def test_request_rejects_any_widened_transport_authority(field, replacement):
    with pytest.raises(ValueError):
        replace(request(), **{field: replacement})


@pytest.mark.parametrize(
    "url",
    [
        f"http://graph.microsoft.com/v1.0/applications/{OBJECT_ID}?$select={SELECT}",
        f"https://graph.microsoft.com:443/v1.0/applications/{OBJECT_ID}?$select={SELECT}",
        f"https://user@graph.microsoft.com/v1.0/applications/{OBJECT_ID}?$select={SELECT}",
        f"https://graph.microsoft.com/beta/applications/{OBJECT_ID}?$select={SELECT}",
        f"https://graph.microsoft.com/v1.0/applications/{OBJECT_ID}/owners?$select={SELECT}",
        f"https://graph.microsoft.com/v1.0/applications/{OBJECT_ID}",
        f"https://graph.microsoft.com/v1.0/applications/{OBJECT_ID}?$select=id,appId",
        f"https://graph.microsoft.com/v1.0/applications/{OBJECT_ID}?$select={SELECT}&$expand=owners",
        f"https://graph.microsoft.com/v1.0/applications/{OBJECT_ID}?$select={SELECT}#fragment",
        f"https://graph.microsoft.com/v1.0/applications/%7B{OBJECT_ID}%7D?$select={SELECT}",
        f"https://graph.microsoft.com/v1.0/servicePrincipals/{OBJECT_ID}?$select={SELECT}",
        f"https://graph.microsoft.com/v1.0/applications/{OBJECT_ID.upper()}?$select={SELECT}",
        "https://graph.microsoft.com/v1.0/applications/00000000-0000-0000-0000-000000000000?$select=id,appId,deletedDateTime",
    ],
)
def test_request_rejects_noncanonical_or_widened_urls(url):
    with pytest.raises(ValueError):
        replace(request(), url=url)


@pytest.mark.parametrize(
    "changes",
    [
        {"status": 201},
        {"status": True},
        {"source": request().url + "&changed=true"},
        {"content_type": "text/json"},
        {"content_encoding": "gzip"},
        {"content_encoding": "br"},
        {"content_length": "not-a-number"},
        {"content_length": -1},
        {"content_length": MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES + 1},
        {"body": b"x" * (MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES + 1)},
        {"body": "not-bytes"},
    ],
)
def test_loader_rejects_untrusted_transport_responses(changes):
    loader = BoundedHTTPSEntraGraphInventoryLoader(
        delegated_access_token=TOKEN,
        open_url=lambda _request, _timeout: RawResponse(**changes),
    )
    with pytest.raises(EntraGraphHTTPError):
        loader(request())


@pytest.mark.parametrize(
    "error",
    [URLError("offline"), TimeoutError(), OSError("offline")],
)
def test_loader_sanitizes_expected_network_failures(error):
    def open_url(_request, _timeout):
        raise error

    loader = BoundedHTTPSEntraGraphInventoryLoader(
        delegated_access_token=TOKEN,
        open_url=open_url,
    )
    with pytest.raises(EntraGraphHTTPError, match="retrieval failed") as captured:
        loader(request())
    assert TOKEN not in str(captured.value)


def test_response_and_loader_representations_never_contain_token():
    loader = BoundedHTTPSEntraGraphInventoryLoader(
        delegated_access_token=TOKEN,
        open_url=lambda _request, _timeout: RawResponse(),
    )
    response = loader(request())
    assert TOKEN not in repr(loader)
    assert TOKEN not in repr(response)
