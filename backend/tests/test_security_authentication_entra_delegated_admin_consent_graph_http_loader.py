"""Tests for the bounded Step 210 Microsoft Graph consent loader."""

from __future__ import annotations

from dataclasses import replace
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import pytest

import app.security.authentication_entra_delegated_admin_consent_graph_http_loader as module
from app.security.authentication_entra_delegated_admin_consent_graph_http_loader import (
    ENTRA_DELEGATED_ADMIN_CONSENT_QUERY_TIMEOUT_SECONDS,
    ENTRA_GRAPH_BASE_URL,
    MAX_ENTRA_DELEGATED_ADMIN_CONSENT_BEARER_TOKEN_BYTES,
    MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES,
    BoundedHTTPSEntraDelegatedAdminConsentGraphLoader,
    EntraDelegatedAdminConsentGraphHTTPError,
    EntraDelegatedAdminConsentGraphRequest,
    EntraDelegatedAdminConsentGraphResponse,
    consent_grant_filter,
    consent_grant_query_url,
)


CLIENT_SP_ID = "44444444-5555-4666-8777-888888888888"
RESOURCE_SP_ID = "33333333-4444-4555-8666-777777777777"
TOKEN = "opaque-synthetic-graph-token"
BODY = b'{"value":[]}'


def request_value() -> EntraDelegatedAdminConsentGraphRequest:
    return EntraDelegatedAdminConsentGraphRequest(
        method="GET",
        url=consent_grant_query_url(
            client_service_principal_object_id=CLIENT_SP_ID,
            resource_service_principal_object_id=RESOURCE_SP_ID,
        ),
        headers=(("Accept", "application/json"), ("Accept-Encoding", "identity")),
        body=None,
        timeout_seconds=ENTRA_DELEGATED_ADMIN_CONSENT_QUERY_TIMEOUT_SECONDS,
        maximum_response_bytes=MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES,
        follow_redirects=False,
        maximum_retries=0,
        proxy_allowed=False,
    )


class RawResponse:
    def __init__(
        self,
        request: EntraDelegatedAdminConsentGraphRequest,
        *,
        status: int = 200,
        final_url: str | None = None,
        body: object = BODY,
        headers: dict[str, object] | None = None,
    ) -> None:
        self.status = status
        self._final_url = request.url if final_url is None else final_url
        self._body = body
        self.headers = headers or {
            "Content-Type": "application/json",
            "Content-Encoding": "identity",
            "Content-Length": str(len(BODY)),
        }
        self.read_amount: int | None = None

    def geturl(self) -> str:
        return self._final_url

    def read(self, amount: int = -1) -> bytes:
        self.read_amount = amount
        return self._body  # type: ignore[return-value]

    def __enter__(self) -> "RawResponse":
        return self

    def __exit__(self, *args: object) -> None:
        del args


def test_canonical_filter_and_url_are_one_exact_read_only_collection_query():
    expected_filter = (
        f"clientId eq '{CLIENT_SP_ID}' and resourceId eq '{RESOURCE_SP_ID}' and "
        "consentType eq 'AllPrincipals' and principalId eq null"
    )
    assert (
        consent_grant_filter(
            client_service_principal_object_id=CLIENT_SP_ID,
            resource_service_principal_object_id=RESOURCE_SP_ID,
        )
        == expected_filter
    )
    url = consent_grant_query_url(
        client_service_principal_object_id=CLIENT_SP_ID,
        resource_service_principal_object_id=RESOURCE_SP_ID,
    )
    split = urlsplit(url)
    assert f"{split.scheme}://{split.netloc}{split.path}" == (
        f"{ENTRA_GRAPH_BASE_URL}/oauth2PermissionGrants"
    )
    assert parse_qs(split.query, strict_parsing=True) == {"$filter": [expected_filter]}
    assert all(term not in url for term in ("$select", "$top", "$count", "$batch"))


@pytest.mark.parametrize(
    "client,resource",
    [
        ("", RESOURCE_SP_ID),
        ("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", RESOURCE_SP_ID),
        ("00000000-0000-0000-0000-000000000000", RESOURCE_SP_ID),
        (CLIENT_SP_ID, "not-a-uuid"),
        (CLIENT_SP_ID, RESOURCE_SP_ID + "' or id ne '"),
    ],
)
def test_filter_rejects_noncanonical_or_injectable_service_principal_ids(
    client, resource
):
    with pytest.raises(ValueError, match="canonical service-principal"):
        consent_grant_filter(
            client_service_principal_object_id=client,
            resource_service_principal_object_id=resource,
        )


def test_injected_opener_is_synthetic_one_shot_and_clears_ephemeral_token():
    request = request_value()
    raw = RawResponse(request)
    observed = {}

    def open_url(url_request, timeout):
        observed["method"] = url_request.get_method()
        observed["url"] = url_request.full_url
        observed["authorization"] = url_request.get_header("Authorization")
        observed["accept"] = url_request.get_header("Accept")
        observed["encoding"] = url_request.get_header("Accept-encoding")
        observed["timeout"] = timeout
        return raw

    loader = BoundedHTTPSEntraDelegatedAdminConsentGraphLoader(
        delegated_access_token=TOKEN,
        open_url=open_url,
    )
    response = loader(request)
    assert observed == {
        "method": "GET",
        "url": request.url,
        "authorization": f"Bearer {TOKEN}",
        "accept": "application/json",
        "encoding": "identity",
        "timeout": ENTRA_DELEGATED_ADMIN_CONSENT_QUERY_TIMEOUT_SECONDS,
    }
    assert response.body == BODY
    assert response.live_https_attested is False
    assert response.tls_peer_verified is False
    assert raw.read_amount == MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES + 1
    assert loader._delegated_access_token is None
    with pytest.raises(EntraDelegatedAdminConsentGraphHTTPError, match="consumed"):
        loader(request)


def test_failure_consumes_loader_and_clears_token_before_any_retry():
    request = request_value()
    calls = 0

    def fail(*args):
        nonlocal calls
        del args
        calls += 1
        raise URLError("secret upstream detail")

    loader = BoundedHTTPSEntraDelegatedAdminConsentGraphLoader(
        delegated_access_token=TOKEN,
        open_url=fail,
    )
    with pytest.raises(EntraDelegatedAdminConsentGraphHTTPError) as error:
        loader(request)
    assert TOKEN not in str(error.value)
    assert "secret upstream detail" not in str(error.value)
    assert loader._delegated_access_token is None
    with pytest.raises(EntraDelegatedAdminConsentGraphHTTPError, match="consumed"):
        loader(request)
    assert calls == 1


def test_close_before_use_consumes_loader_and_discards_token():
    loader = BoundedHTTPSEntraDelegatedAdminConsentGraphLoader(
        delegated_access_token=TOKEN,
        open_url=lambda *_: pytest.fail("network must not run"),
    )
    loader.close()
    assert loader._delegated_access_token is None
    with pytest.raises(EntraDelegatedAdminConsentGraphHTTPError, match="consumed"):
        loader(request_value())


def test_only_captured_module_owned_default_opener_is_live_eligible(monkeypatch):
    direct = BoundedHTTPSEntraDelegatedAdminConsentGraphLoader(
        delegated_access_token=TOKEN
    )
    assert direct._default_transport is True
    direct.close()

    request = request_value()
    monkeypatch.setattr(module, "_default_open", lambda *_: RawResponse(request))
    rebound = BoundedHTTPSEntraDelegatedAdminConsentGraphLoader(
        delegated_access_token=TOKEN
    )
    assert rebound._default_transport is False
    assert rebound(request).live_https_attested is False


def test_public_response_flags_cannot_forge_live_attestation():
    with pytest.raises(ValueError, match="response is invalid"):
        EntraDelegatedAdminConsentGraphResponse(
            status_code=200,
            final_url=request_value().url,
            content_type="application/json",
            body=BODY,
            tls_peer_verified=True,
        )
    response = EntraDelegatedAdminConsentGraphResponse(
        status_code=200,
        final_url=request_value().url,
        content_type="application/json",
        body=BODY,
    )
    response._attestation = object()
    assert response.live_https_attested is False


@pytest.mark.parametrize(
    "token",
    [
        "",
        "Bearer already-prefixed",
        "contains space",
        "contains\tcontrol",
        "contains\ncontrol",
        "contains\x01control",
        "contains\x0bcontrol",
        "contains\x1fcontrol",
        "contains\x7fcontrol",
        "snowman-\N{SNOWMAN}",
        "x" * (MAX_ENTRA_DELEGATED_ADMIN_CONSENT_BEARER_TOKEN_BYTES + 1),
        b"bytes",
        None,
    ],
)
def test_loader_rejects_invalid_opaque_tokens_without_echo(token):
    with pytest.raises(ValueError, match="token is invalid") as error:
        BoundedHTTPSEntraDelegatedAdminConsentGraphLoader(
            delegated_access_token=token  # type: ignore[arg-type]
        )
    if str(token):
        assert str(token) not in str(error.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "POST"},
        {"headers": (("Accept", "application/json"),)},
        {"timeout_seconds": 11.0},
        {"maximum_response_bytes": 32_767},
        {"follow_redirects": True},
        {"maximum_retries": 1},
        {"proxy_allowed": True},
        {"url": "https://graph.microsoft.com/beta/oauth2PermissionGrants"},
        {"url": "https://evil.invalid/v1.0/oauth2PermissionGrants?$filter=x"},
    ],
)
def test_request_rejects_any_authority_or_transport_widening(changes):
    with pytest.raises(ValueError, match="request is invalid"):
        replace(request_value(), **changes)


@pytest.mark.parametrize(
    "suffix",
    [
        "&$select=id",
        "&$top=1",
        "&$count=true",
        "#fragment",
        "%20or%20id%20ne%20null",
    ],
)
def test_request_rejects_query_widening(suffix):
    with pytest.raises(ValueError, match="request is invalid"):
        replace(request_value(), url=request_value().url + suffix)


@pytest.mark.parametrize(
    "response_kwargs",
    [
        {"status": 201},
        {"final_url": "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"},
        {"headers": {"Content-Type": "text/html"}},
        {"headers": {"Content-Type": "application/json", "Content-Encoding": "gzip"}},
        {"headers": {"Content-Type": "application/json", "Content-Length": "-1"}},
        {"headers": {"Content-Type": "application/json", "Content-Length": "nan"}},
        {
            "headers": {
                "Content-Type": "application/json",
                "Content-Length": str(MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES + 1),
            }
        },
        {"body": b"x" * (MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES + 1)},
        {"body": "not-bytes"},
    ],
)
def test_loader_fails_closed_on_response_transport_bounds(response_kwargs):
    request = request_value()
    loader = BoundedHTTPSEntraDelegatedAdminConsentGraphLoader(
        delegated_access_token=TOKEN,
        open_url=lambda *_: RawResponse(request, **response_kwargs),
    )
    with pytest.raises(EntraDelegatedAdminConsentGraphHTTPError):
        loader(request)


@pytest.mark.parametrize(
    "failure",
    [
        URLError("network"),
        TimeoutError("timeout"),
        OSError("socket"),
        HTTPError("https://graph.microsoft.com", 403, "denied", {}, None),
    ],
)
def test_loader_sanitizes_expected_network_failures(failure):
    def fail(*args):
        del args
        raise failure

    loader = BoundedHTTPSEntraDelegatedAdminConsentGraphLoader(
        delegated_access_token=TOKEN,
        open_url=fail,
    )
    with pytest.raises(EntraDelegatedAdminConsentGraphHTTPError) as error:
        loader(request_value())
    assert str(failure) not in str(error.value)
    assert TOKEN not in str(error.value)


def test_default_transport_disables_ambient_tls_key_logging(monkeypatch):
    class Context:
        check_hostname = False
        verify_mode = None
        keylog_filename = "/tmp/ambient-tls-secrets.log"

    context = Context()
    captured = {}

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            raise URLError("expected no network")

    def build_opener(*handlers):
        captured["handlers"] = handlers
        return Opener()

    monkeypatch.setenv("SSLKEYLOGFILE", "/tmp/ambient-tls-secrets.log")
    monkeypatch.setattr(module.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(module, "build_opener", build_opener)
    with pytest.raises(URLError):
        module._default_open(object(), 10.0)
    assert context.keylog_filename is None
    assert context.check_hostname is True
    assert context.verify_mode == module.ssl.CERT_REQUIRED
