"""Adversarial tests for the bounded Step 213 Graph HTTPS loader."""

from __future__ import annotations

from dataclasses import replace
from typing import Self

import app.security.authentication_entra_calling_client_registration_graph_http_loader as module
import pytest
from app.security.authentication_entra_calling_client_registration_graph_http_loader import (
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_SELECT,
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT,
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TIMEOUT_SECONDS,
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_USER_AGENT,
    ENTRA_GRAPH_BASE_URL,
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_RESPONSE_BYTES,
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_BEARER_TOKEN_BYTES,
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_FIC_RESPONSE_BYTES,
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_OWNERS_RESPONSE_BYTES,
    BoundedHTTPSEntraCallingClientRegistrationGraphLoader,
    EntraCallingClientRegistrationGraphHTTPError,
    EntraCallingClientRegistrationGraphRequest,
    EntraCallingClientRegistrationGraphResponse,
    entra_calling_client_registration_graph_url,
)

APPLICATION_OBJECT_ID = "22222222-3333-4444-8def-666666666666"
OTHER_APPLICATION_OBJECT_ID = "99999999-8888-4777-8abc-666666666666"
TOKEN = "step213-sentinel-opaque-token"
APPLICATION_BODY = b'{"id":"synthetic","appId":"synthetic"}'
OWNERS_BODY = b'{"value":[]}'
FIC_BODY = b'{"value":[]}'


def request_plan(application_object_id: str = APPLICATION_OBJECT_ID):
    definitions = (
        (
            1,
            "calling_client_application",
            MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_RESPONSE_BYTES,
        ),
        (
            2,
            "owners",
            MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_OWNERS_RESPONSE_BYTES,
        ),
        (
            3,
            "federated_identity_credentials",
            MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_FIC_RESPONSE_BYTES,
        ),
    )
    return tuple(
        EntraCallingClientRegistrationGraphRequest(
            sequence=sequence,
            resource=resource,
            method="GET",
            url=entra_calling_client_registration_graph_url(
                application_object_id=application_object_id,
                resource=resource,
            ),
            headers=(("Accept", "application/json"), ("Accept-Encoding", "identity")),
            body=None,
            timeout_seconds=ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TIMEOUT_SECONDS,
            maximum_response_bytes=maximum,
            follow_redirects=False,
            maximum_retries=0,
            proxy_allowed=False,
        )
        for sequence, resource, maximum in definitions
    )


def body_for(request):
    return {
        "calling_client_application": APPLICATION_BODY,
        "owners": OWNERS_BODY,
        "federated_identity_credentials": FIC_BODY,
    }[request.resource]


class RawResponse:
    def __init__(
        self,
        request,
        *,
        status: object = 200,
        final_url: object | None = None,
        body: object | None = None,
        headers: dict[str, object] | None = None,
    ) -> None:
        expected_body = body_for(request) if body is None else body
        self.status = status
        self._final_url = request.url if final_url is None else final_url
        self._body = expected_body
        self.headers = headers or {
            "Content-Type": "application/json",
            "Content-Encoding": "identity",
            "Content-Length": str(len(expected_body)),
        }
        self.read_amount = None

    def geturl(self) -> str:
        return self._final_url

    def read(self, amount: int = -1) -> bytes:
        self.read_amount = amount
        return self._body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        del args


def opener_for_plan(plan, *, overrides=None, observed=None, raised=None):
    by_url = {request.url: request for request in plan}
    calls = 0

    def open_url(url_request, timeout):
        nonlocal calls
        calls += 1
        if raised and calls in raised:
            error = raised[calls]
            if isinstance(error, BaseException):
                raise error
            raise error()
        request = by_url[url_request.full_url]
        if observed is not None:
            observed.append(
                {
                    "method": url_request.get_method(),
                    "url": url_request.full_url,
                    "authorization": url_request.get_header("Authorization"),
                    "accept": url_request.get_header("Accept"),
                    "encoding": url_request.get_header("Accept-encoding"),
                    "content_type": url_request.get_header("Content-type"),
                    "user_agent": url_request.get_header("User-agent"),
                    "timeout": timeout,
                }
            )
        return RawResponse(request, **(overrides or {}).get(calls, {}))

    open_url.calls = lambda: calls
    return open_url


def assert_no_token_in_production_exception_graph(error: BaseException, token: str):
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        assert token not in str(current)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if frame.f_globals.get("__name__") == module.__name__:
                values = list(frame.f_locals.values())
                inspected = set()
                while values:
                    value = values.pop()
                    if id(value) in inspected:
                        continue
                    inspected.add(id(value))
                    if isinstance(value, str):
                        assert token not in value
                    elif isinstance(value, bytes):
                        assert token.encode() not in value
                    elif isinstance(value, dict):
                        values.extend(value.keys())
                        values.extend(value.values())
                    elif isinstance(value, (list, tuple, set, frozenset)):
                        values.extend(value)
                    elif hasattr(value, "header_items"):
                        values.extend(value.header_items())
                    if hasattr(value, "_delegated_access_token"):
                        values.append(value._delegated_access_token)
            traceback = traceback.tb_next


def test_urls_and_three_read_plan_are_exact():
    plan = request_plan()
    assert ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT == 3
    assert plan[0].url == (
        f"{ENTRA_GRAPH_BASE_URL}/applications/{APPLICATION_OBJECT_ID}"
        f"?$select={ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_SELECT}"
    )
    assert plan[1].url == (
        f"{ENTRA_GRAPH_BASE_URL}/applications/{APPLICATION_OBJECT_ID}/owners?$select=id"
    )
    assert plan[2].url == (
        f"{ENTRA_GRAPH_BASE_URL}/applications/{APPLICATION_OBJECT_ID}"
        "/federatedIdentityCredentials?$select=id"
    )
    assert [request.resource for request in plan] == [
        "calling_client_application",
        "owners",
        "federated_identity_credentials",
    ]
    assert all(request.method == "GET" and request.body is None for request in plan)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "00000000-0000-0000-0000-000000000000",
        APPLICATION_OBJECT_ID.upper(),
        "{" + APPLICATION_OBJECT_ID + "}",
        APPLICATION_OBJECT_ID.replace("-", ""),
        APPLICATION_OBJECT_ID + "?$top=1",
        None,
        b"uuid",
    ],
)
def test_url_builder_rejects_noncanonical_or_injectable_ids(value):
    with pytest.raises(ValueError, match="canonical nonzero"):
        entra_calling_client_registration_graph_url(
            application_object_id=value,
            resource="calling_client_application",
        )


def test_url_builder_rejects_unknown_resource():
    with pytest.raises(ValueError, match="supported"):
        entra_calling_client_registration_graph_url(
            application_object_id=APPLICATION_OBJECT_ID,
            resource="service_principal",
        )


def test_triple_executes_exact_reads_and_irrevocably_clears_token():
    plan = request_plan()
    observed = []
    opener = opener_for_plan(plan, observed=observed)
    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=opener,
    )
    responses = loader(plan)
    assert [response.body for response in responses] == [
        APPLICATION_BODY,
        OWNERS_BODY,
        FIC_BODY,
    ]
    assert all(response.live_https_attested is False for response in responses)
    assert [entry["authorization"] for entry in observed] == [f"Bearer {TOKEN}"] * 3
    assert [entry["url"] for entry in observed] == [request.url for request in plan]
    assert all(entry["method"] == "GET" for entry in observed)
    assert all(entry["accept"] == "application/json" for entry in observed)
    assert all(entry["encoding"] == "identity" for entry in observed)
    assert all(entry["content_type"] is None for entry in observed)
    assert all(
        entry["user_agent"] == ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_USER_AGENT
        for entry in observed
    )
    assert loader._delegated_access_token is None
    assert opener.calls() == 3
    with pytest.raises(EntraCallingClientRegistrationGraphHTTPError, match="consumed"):
        loader(plan)
    assert opener.calls() == 3


@pytest.mark.parametrize("bad_index", [0, 1, 2])
@pytest.mark.parametrize("attribute,value", [("method", "POST"), ("body", b"x")])
def test_any_invalid_request_consumes_without_any_io(bad_index, attribute, value):
    plan = list(request_plan())
    object.__setattr__(plan[bad_index], attribute, value)
    calls = 0

    def no_io(*args):
        nonlocal calls
        calls += 1
        pytest.fail("entire plan must validate before I/O")

    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=no_io,
    )
    with pytest.raises(EntraCallingClientRegistrationGraphHTTPError, match="plan"):
        loader(tuple(plan))
    assert calls == 0
    assert loader._delegated_access_token is None


def test_mixed_object_plan_fails_before_io_and_consumes():
    plan = list(request_plan())
    plan[2] = request_plan(OTHER_APPLICATION_OBJECT_ID)[2]
    opener = opener_for_plan(tuple(plan))
    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=opener,
    )
    with pytest.raises(
        EntraCallingClientRegistrationGraphHTTPError, match="same application"
    ):
        loader(tuple(plan))
    assert opener.calls() == 0
    assert loader._delegated_access_token is None


@pytest.mark.parametrize(
    "plan_factory",
    [
        lambda p: p[:1],
        lambda p: p[:2],
        lambda p: p + (p[0],),
        lambda p: (p[1], p[0], p[2]),
        lambda p: list(p),
        lambda p: (object(), p[1], p[2]),
    ],
)
def test_partial_reordered_or_wrong_type_plan_fails_before_io(plan_factory):
    plan = request_plan()
    opener = opener_for_plan(plan)
    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=opener,
    )
    with pytest.raises(EntraCallingClientRegistrationGraphHTTPError, match="plan"):
        loader(plan_factory(plan))
    assert opener.calls() == 0
    assert loader._delegated_access_token is None


@pytest.mark.parametrize("failure_call", [1, 2, 3])
@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("Authorization: Bearer " + TOKEN),
        KeyboardInterrupt(TOKEN),
        SystemExit(TOKEN),
    ],
)
def test_every_failure_scrubs_token_sanitizes_and_seals(failure_call, failure):
    plan = request_plan()
    opener = opener_for_plan(plan, raised={failure_call: failure})
    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=opener,
    )
    expected = (
        KeyboardInterrupt
        if isinstance(failure, KeyboardInterrupt)
        else SystemExit
        if isinstance(failure, SystemExit)
        else EntraCallingClientRegistrationGraphHTTPError
    )
    with pytest.raises(expected) as raised:
        loader(plan)
    assert loader._delegated_access_token is None
    assert opener.calls() == failure_call
    assert_no_token_in_production_exception_graph(raised.value, TOKEN)
    with pytest.raises(EntraCallingClientRegistrationGraphHTTPError, match="consumed"):
        loader(plan)


def test_close_before_use_discards_token_and_seals():
    plan = request_plan()
    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=opener_for_plan(plan),
    )
    loader.close()
    assert loader._delegated_access_token is None
    with pytest.raises(EntraCallingClientRegistrationGraphHTTPError, match="consumed"):
        loader(plan)


def test_only_captured_default_opener_is_live_eligible(monkeypatch):
    plan = request_plan()
    fake = opener_for_plan(plan)
    monkeypatch.setattr(module, "_default_open", fake)
    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN
    )
    responses = loader(plan)
    assert all(response.live_https_attested is False for response in responses)
    assert all(response.tls_peer_verified is False for response in responses)


def test_public_response_cannot_forge_live_attestation():
    response = EntraCallingClientRegistrationGraphResponse(
        status_code=200,
        final_url=request_plan()[0].url,
        content_type="application/json",
        body=b"{}",
    )
    assert response.live_https_attested is False
    assert response.tls_peer_verified is False
    with pytest.raises(ValueError, match="invalid"):
        EntraCallingClientRegistrationGraphResponse(
            status_code=200,
            final_url=request_plan()[0].url,
            content_type="application/json",
            body=b"{}",
            tls_peer_verified=True,
        )


@pytest.mark.parametrize(
    "token",
    [
        None,
        b"token",
        "",
        "Bearer abc",
        "has space",
        "tab\there",
        "line\nfeed",
        "carriage\rreturn",
        "nul\x00byte",
        "nonascii-é",
        "x" * (MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_BEARER_TOKEN_BYTES + 1),
    ]
    + [f"prefix{chr(code)}suffix" for code in range(0x21)]
    + ["prefix\x7fsuffix"],
)
def test_invalid_tokens_rejected_without_echo(token):
    with pytest.raises(ValueError, match="invalid") as raised:
        BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
            delegated_access_token=token
        )
    if str(token):
        assert str(token) not in str(raised.value)


@pytest.mark.parametrize(
    "index,changes",
    [
        (0, {"sequence": True}),
        (1, {"sequence": 1}),
        (2, {"resource": "owners"}),
        (0, {"headers": (("Accept", "application/json"),)}),
        (1, {"headers": (("Accept", "*/*"), ("Accept-Encoding", "identity"))}),
        (2, {"timeout_seconds": 20.0}),
        (0, {"maximum_response_bytes": 1}),
        (1, {"follow_redirects": True}),
        (2, {"maximum_retries": 1}),
        (0, {"proxy_allowed": True}),
    ],
)
def test_request_rejects_transport_widening(index, changes):
    with pytest.raises(ValueError, match="invalid"):
        replace(request_plan()[index], **changes)


@pytest.mark.parametrize(
    "index,url",
    [
        (0, "http://graph.microsoft.com/v1.0/applications/" + APPLICATION_OBJECT_ID),
        (0, "https://graph.microsoft.us/v1.0/applications/" + APPLICATION_OBJECT_ID),
        (
            0,
            "https://microsoftgraph.chinacloudapi.cn/v1.0/applications/"
            + APPLICATION_OBJECT_ID,
        ),
        (0, "https://graph.microsoft.com/beta/applications/" + APPLICATION_OBJECT_ID),
        (
            0,
            "https://user@graph.microsoft.com/v1.0/applications/"
            + APPLICATION_OBJECT_ID,
        ),
        (
            0,
            "https://graph.microsoft.com:443/v1.0/applications/"
            + APPLICATION_OBJECT_ID,
        ),
        (0, request_plan()[0].url + "#fragment"),
        (0, request_plan()[0].url.replace("applications/", "applications/%2e%2e/")),
        (0, request_plan()[0].url.replace("?$select=", "?$SELECT=")),
        (1, request_plan()[1].url + "&$top=1"),
        (2, request_plan()[2].url.replace("?$select=id", "?$select=id,@odata.type")),
    ],
)
def test_request_rejects_authority_path_or_query_widening(index, url):
    with pytest.raises(ValueError, match="invalid"):
        replace(request_plan()[index], url=url)


@pytest.mark.parametrize("failure_call", [1, 2, 3])
@pytest.mark.parametrize(
    "overrides",
    [
        {"status": 201},
        {"final_url": "https://graph.microsoft.com/v1.0/other"},
        {"headers": {"Content-Type": "text/html"}},
        {"headers": {"Content-Type": "application/json\r\nX: y"}},
        {"headers": {"Content-Type": "application/json", "Content-Encoding": "gzip"}},
        {"headers": {"Content-Type": "application/json", "Content-Length": "-1"}},
        {"headers": {"Content-Type": "application/json", "Content-Length": "abc"}},
        {
            "headers": {"Content-Type": "application/json", "Content-Length": "9"},
            "body": b"{}",
        },
        {"body": "not-bytes"},
    ],
)
def test_each_response_transport_boundary_fails_closed(failure_call, overrides):
    plan = request_plan()
    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=opener_for_plan(plan, overrides={failure_call: overrides}),
    )
    with pytest.raises(EntraCallingClientRegistrationGraphHTTPError):
        loader(plan)
    assert loader._delegated_access_token is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status_code": True},
        {"final_url": b"url"},
        {"content_type": None},
        {"body": "body"},
        {"redirect_count": True},
        {"redirect_count": 1},
        {"attempt_count": True},
        {"attempt_count": 2},
    ],
)
def test_public_response_rejects_invalid_scalar_or_flags(kwargs):
    values = {
        "status_code": 200,
        "final_url": request_plan()[0].url,
        "content_type": "application/json",
        "body": b"{}",
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match="invalid"):
        EntraCallingClientRegistrationGraphResponse(**values)


def test_each_read_uses_its_exact_bounded_read_amount():
    plan = request_plan()
    raw = []

    def open_url(request, timeout):
        del timeout
        planned = next(item for item in plan if item.url == request.full_url)
        response = RawResponse(planned)
        raw.append(response)
        return response

    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=open_url,
    )
    loader(plan)
    assert [response.read_amount for response in raw] == [
        request.maximum_response_bytes + 1 for request in plan
    ]


@pytest.mark.parametrize("failure_call", [1, 2, 3])
def test_actual_body_over_each_resource_limit_rejects_at_that_read(failure_call):
    plan = request_plan()
    request = plan[failure_call - 1]
    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=opener_for_plan(
            plan,
            overrides={
                failure_call: {
                    "body": b"x" * (request.maximum_response_bytes + 1),
                    "headers": {"Content-Type": "application/json"},
                }
            },
        ),
    )
    with pytest.raises(EntraCallingClientRegistrationGraphHTTPError, match="retrieval"):
        loader(plan)
    assert loader._delegated_access_token is None


@pytest.mark.parametrize("failure_call", [1, 2, 3])
def test_declared_length_over_each_resource_limit_rejects_without_read(failure_call):
    plan = request_plan()
    raw = None

    def open_url(url_request, timeout):
        nonlocal raw
        del timeout
        planned = next(item for item in plan if item.url == url_request.full_url)
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(planned.maximum_response_bytes + 1),
        }
        raw = RawResponse(planned, headers=headers)
        return raw

    calls = 0

    def selective(url_request, timeout):
        nonlocal calls
        calls += 1
        if calls == failure_call:
            return open_url(url_request, timeout)
        planned = next(item for item in plan if item.url == url_request.full_url)
        return RawResponse(planned)

    loader = BoundedHTTPSEntraCallingClientRegistrationGraphLoader(
        delegated_access_token=TOKEN,
        open_url=selective,
    )
    with pytest.raises(EntraCallingClientRegistrationGraphHTTPError, match="retrieval"):
        loader(plan)
    assert calls == failure_call
    assert raw.read_amount is None


def test_default_transport_disables_proxy_redirect_and_tls_keylog(monkeypatch):
    captured = {}

    class Context:
        check_hostname = False
        verify_mode = None
        keylog_filename = "ambient"

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return RawResponse(request_plan()[0])

    context = Context()
    monkeypatch.setattr(module.ssl, "create_default_context", lambda: context)

    def build(*handlers):
        captured["handlers"] = handlers
        return Opener()

    monkeypatch.setattr(module, "build_opener", build)
    module._default_open(module.Request(request_plan()[0].url), 10.0)
    assert context.check_hostname is True
    assert context.verify_mode == module.ssl.CERT_REQUIRED
    assert context.keylog_filename is None
    assert any(type(handler) is module.ProxyHandler for handler in captured["handlers"])
    proxy = next(
        handler
        for handler in captured["handlers"]
        if type(handler) is module.ProxyHandler
    )
    assert proxy.proxies == {}
    assert any(
        type(handler) is module._DenyRedirects for handler in captured["handlers"]
    )
