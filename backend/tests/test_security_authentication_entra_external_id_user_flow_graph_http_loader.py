"""Tests for the bounded Step 212 Microsoft Graph user-flow loader."""

from __future__ import annotations

from dataclasses import replace
from typing import Self
from urllib.error import HTTPError, URLError

import app.security.authentication_entra_external_id_user_flow_graph_http_loader as module
import pytest
from app.security.authentication_entra_external_id_user_flow_graph_http_loader import (
    ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT,
    ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS,
    ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_USER_AGENT,
    ENTRA_GRAPH_BASE_URL,
    MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_BEARER_TOKEN_BYTES,
    MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES,
    BoundedHTTPSEntraExternalIdUserFlowGraphLoader,
    EntraExternalIdUserFlowGraphHTTPError,
    EntraExternalIdUserFlowGraphRequest,
    EntraExternalIdUserFlowGraphResponse,
    entra_external_id_user_flow_graph_url,
)

USER_FLOW_ID = "55555555-6666-4777-8abc-999999999999"
OTHER_USER_FLOW_ID = "66666666-7777-4888-9abc-aaaaaaaaaaaa"
TOKEN = "opaque-synthetic-graph-token"
FLOW_BODY = b'{"@odata.type":"flow","id":"synthetic","conditions":{}}'
APPLICATIONS_BODY = b'{"value":[{"appId":"synthetic"}]}'


def request_plan(
    user_flow_id: str = USER_FLOW_ID,
) -> tuple[
    EntraExternalIdUserFlowGraphRequest,
    EntraExternalIdUserFlowGraphRequest,
]:
    first = EntraExternalIdUserFlowGraphRequest(
        sequence=1,
        resource="user_flow",
        method="GET",
        url=entra_external_id_user_flow_graph_url(
            user_flow_id=user_flow_id,
            resource="user_flow",
        ),
        headers=(
            ("Accept", "application/json"),
            ("Accept-Encoding", "identity"),
        ),
        body=None,
        timeout_seconds=ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS,
        maximum_response_bytes=(MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES),
        follow_redirects=False,
        maximum_retries=0,
        proxy_allowed=False,
    )
    second = EntraExternalIdUserFlowGraphRequest(
        sequence=2,
        resource="include_applications",
        method="GET",
        url=entra_external_id_user_flow_graph_url(
            user_flow_id=user_flow_id,
            resource="include_applications",
        ),
        headers=(
            ("Accept", "application/json"),
            ("Accept-Encoding", "identity"),
            ("Content-Type", "application/json"),
        ),
        body=None,
        timeout_seconds=ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS,
        maximum_response_bytes=(MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES),
        follow_redirects=False,
        maximum_retries=0,
        proxy_allowed=False,
    )
    return first, second


def body_for(request: EntraExternalIdUserFlowGraphRequest) -> bytes:
    return FLOW_BODY if request.resource == "user_flow" else APPLICATIONS_BODY


class RawResponse:
    def __init__(
        self,
        request: EntraExternalIdUserFlowGraphRequest,
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
        self.read_amount: int | None = None

    def geturl(self) -> str:
        return self._final_url  # type: ignore[return-value]

    def read(self, amount: int = -1) -> bytes:
        self.read_amount = amount
        return self._body  # type: ignore[return-value]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        del args


def opener_for_plan(
    plan: tuple[
        EntraExternalIdUserFlowGraphRequest,
        EntraExternalIdUserFlowGraphRequest,
    ],
    *,
    response_overrides: dict[int, dict[str, object]] | None = None,
    observed: list[dict[str, object]] | None = None,
):
    by_url = {request.url: request for request in plan}
    calls = 0

    def open_url(url_request, timeout):
        nonlocal calls
        calls += 1
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
        overrides = (response_overrides or {}).get(calls, {})
        return RawResponse(request, **overrides)

    open_url.calls = lambda: calls
    return open_url


def assert_no_token_in_production_exception_graph(
    error: BaseException,
    token: str,
) -> None:
    """Inspect causes, contexts, and production traceback locals recursively."""

    pending = [error]
    seen_errors: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen_errors:
            continue
        seen_errors.add(id(current))
        assert token not in str(current)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if frame.f_globals.get("__name__") == module.__name__:
                values: list[object] = list(frame.f_locals.values())
                inspected: set[int] = set()
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


def test_canonical_urls_are_exact_selected_global_v1_reads():
    first, second = request_plan()
    assert first.url == (
        f"{ENTRA_GRAPH_BASE_URL}/identity/authenticationEventsFlows/"
        f"{USER_FLOW_ID}?$select=id,conditions"
    )
    assert second.url == (
        f"{ENTRA_GRAPH_BASE_URL}/identity/authenticationEventsFlows/"
        f"{USER_FLOW_ID}/conditions/applications/includeApplications?$select=appId"
    )
    assert (first.sequence, first.resource) == (1, "user_flow")
    assert (second.sequence, second.resource) == (2, "include_applications")
    assert ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_REQUEST_COUNT == 2
    for request in (first, second):
        assert request.method == "GET"
        assert request.body is None
        assert all(
            term not in request.url
            for term in ("$filter", "$expand", "$top", "$count", "$batch")
        )


@pytest.mark.parametrize(
    "user_flow_id",
    [
        "",
        "00000000-0000-0000-0000-000000000000",
        USER_FLOW_ID.upper(),
        "{55555555-6666-4777-8abc-999999999999}",
        "55555555666647778abc999999999999",
        USER_FLOW_ID + "' or id ne '",
        None,
        b"uuid",
    ],
)
def test_url_builder_rejects_noncanonical_or_injectable_flow_ids(user_flow_id):
    with pytest.raises(ValueError, match="canonical nonzero"):
        entra_external_id_user_flow_graph_url(
            user_flow_id=user_flow_id,  # type: ignore[arg-type]
            resource="user_flow",
        )


def test_url_builder_rejects_any_other_resource():
    with pytest.raises(ValueError, match="supported"):
        entra_external_id_user_flow_graph_url(
            user_flow_id=USER_FLOW_ID,
            resource="applications",  # type: ignore[arg-type]
        )


def test_pair_call_executes_both_exact_reads_and_clears_token():
    plan = request_plan()
    observed: list[dict[str, object]] = []
    opener = opener_for_plan(plan, observed=observed)
    loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN,
        open_url=opener,
    )
    responses = loader(plan)
    assert len(responses) == 2
    assert [response.body for response in responses] == [
        FLOW_BODY,
        APPLICATIONS_BODY,
    ]
    assert all(response.live_https_attested is False for response in responses)
    assert all(response.tls_peer_verified is False for response in responses)
    assert observed == [
        {
            "method": "GET",
            "url": plan[0].url,
            "authorization": f"Bearer {TOKEN}",
            "accept": "application/json",
            "encoding": "identity",
            "content_type": None,
            "user_agent": ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_USER_AGENT,
            "timeout": ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS,
        },
        {
            "method": "GET",
            "url": plan[1].url,
            "authorization": f"Bearer {TOKEN}",
            "accept": "application/json",
            "encoding": "identity",
            "content_type": "application/json",
            "user_agent": ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_USER_AGENT,
            "timeout": ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_TIMEOUT_SECONDS,
        },
    ]
    assert loader._delegated_access_token is None
    assert opener.calls() == 2
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError, match="consumed"):
        loader(plan)
    assert opener.calls() == 2


def test_mixed_flow_pair_is_rejected_before_io_and_consumes_token():
    first = request_plan(USER_FLOW_ID)[0]
    second = request_plan(OTHER_USER_FLOW_ID)[1]
    calls = 0

    def no_io(*args):
        nonlocal calls
        del args
        calls += 1
        pytest.fail("mixed-flow plan must fail before I/O")

    loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN,
        open_url=no_io,
    )
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError, match="same user flow"):
        loader((first, second))
    assert calls == 0
    assert loader._delegated_access_token is None
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError, match="consumed"):
        loader((first, second))


@pytest.mark.parametrize("mutation", ["method", "url", "headers"])
def test_invalid_second_request_is_rejected_before_first_io(mutation):
    first, second = request_plan()
    if mutation == "method":
        object.__setattr__(second, "method", "POST")
    elif mutation == "url":
        object.__setattr__(second, "url", second.url + "&$top=1")
    else:
        object.__setattr__(second, "headers", (("Accept", "application/json"),))
    calls = 0

    def no_io(*args):
        nonlocal calls
        del args
        calls += 1
        pytest.fail("invalid second request must fail before I/O")

    loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN,
        open_url=no_io,
    )
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError, match="plan"):
        loader((first, second))
    assert calls == 0
    assert loader._delegated_access_token is None


@pytest.mark.parametrize(
    "plan_factory",
    [
        lambda: (request_plan()[0],),
        lambda: tuple(reversed(request_plan())),
        lambda: list(request_plan()),
        lambda: (),
        lambda: None,
        lambda: "two requests",
    ],
)
def test_pair_api_rejects_partial_reordered_or_non_tuple_plan_without_io(plan_factory):
    calls = 0

    def no_io(*args):
        nonlocal calls
        del args
        calls += 1
        pytest.fail("invalid pair must fail before I/O")

    loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN,
        open_url=no_io,
    )
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError, match="plan"):
        loader(plan_factory())  # type: ignore[arg-type]
    assert calls == 0
    assert loader._delegated_access_token is None


@pytest.mark.parametrize("failure_call", [1, 2])
@pytest.mark.parametrize(
    "failure",
    [
        URLError("network-secret"),
        TimeoutError("timeout-secret"),
        OSError("socket-secret"),
        HTTPError("https://graph.microsoft.com", 403, "denied-secret", {}, None),
    ],
)
def test_network_failure_on_either_read_sanitizes_and_irrevocably_clears_token(
    failure_call, failure
):
    plan = request_plan()
    by_url = {request.url: request for request in plan}
    calls = 0

    def open_url(url_request, timeout):
        nonlocal calls
        del timeout
        calls += 1
        if calls == failure_call:
            raise failure
        return RawResponse(by_url[url_request.full_url])

    loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN,
        open_url=open_url,
    )
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError) as error:
        loader(plan)
    assert str(failure) not in str(error.value)
    assert TOKEN not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert_no_token_in_production_exception_graph(error.value, TOKEN)
    assert calls == failure_call
    assert loader._delegated_access_token is None
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError, match="consumed"):
        loader(plan)
    assert calls == failure_call


@pytest.mark.parametrize("failure_call", [1, 2])
def test_base_exception_on_either_read_still_clears_token_and_prevents_reuse(
    failure_call,
):
    plan = request_plan()
    by_url = {request.url: request for request in plan}
    calls = 0

    def open_url(url_request, timeout):
        nonlocal calls
        del timeout
        calls += 1
        if calls == failure_call:
            raise KeyboardInterrupt("operator interrupt")
        return RawResponse(by_url[url_request.full_url])

    loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN,
        open_url=open_url,
    )
    with pytest.raises(KeyboardInterrupt, match="retrieval interrupted") as error:
        loader(plan)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert_no_token_in_production_exception_graph(error.value, TOKEN)
    assert calls == failure_call
    assert loader._delegated_access_token is None
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError, match="consumed"):
        loader(plan)


def test_close_before_use_consumes_pair_loader_and_discards_token():
    loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN,
        open_url=lambda *_: pytest.fail("network must not run"),
    )
    loader.close()
    assert loader._delegated_access_token is None
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError, match="consumed"):
        loader(request_plan())


def test_only_captured_module_owned_default_opener_is_live_eligible(monkeypatch):
    direct = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN
    )
    assert direct._default_transport is True
    direct.close()

    plan = request_plan()
    rebound_open = opener_for_plan(plan)
    monkeypatch.setattr(module, "_default_open", rebound_open)
    rebound = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN
    )
    assert rebound._default_transport is False
    responses = rebound(plan)
    assert all(response.live_https_attested is False for response in responses)


def test_public_response_flags_cannot_forge_live_attestation():
    with pytest.raises(ValueError, match="response is invalid"):
        EntraExternalIdUserFlowGraphResponse(
            status_code=200,
            final_url=request_plan()[0].url,
            content_type="application/json",
            body=FLOW_BODY,
            tls_peer_verified=True,
        )
    response = EntraExternalIdUserFlowGraphResponse(
        status_code=200,
        final_url=request_plan()[0].url,
        content_type="application/json",
        body=FLOW_BODY,
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
        "x" * (MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_BEARER_TOKEN_BYTES + 1),
        b"bytes",
        None,
    ],
)
def test_loader_rejects_invalid_opaque_tokens_without_echo(token):
    with pytest.raises(ValueError, match="token is invalid") as error:
        BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
            delegated_access_token=token  # type: ignore[arg-type]
        )
    if str(token):
        assert str(token) not in str(error.value)
        if isinstance(token, str):
            assert_no_token_in_production_exception_graph(error.value, token)


@pytest.mark.parametrize(
    ("index", "changes"),
    [
        (0, {"sequence": 2}),
        (0, {"resource": "include_applications"}),
        (0, {"method": "POST"}),
        (0, {"headers": (("Accept", "application/json"),)}),
        (0, {"body": b"{}"}),
        (0, {"timeout_seconds": 11.0}),
        (0, {"maximum_response_bytes": 32_767}),
        (0, {"follow_redirects": True}),
        (0, {"maximum_retries": 1}),
        (0, {"proxy_allowed": True}),
        (1, {"sequence": 1}),
        (1, {"resource": "user_flow"}),
        (1, {"headers": (("Accept", "application/json"),)}),
        (1, {"body": b"{}"}),
    ],
)
def test_request_rejects_any_plan_or_transport_widening(index, changes):
    with pytest.raises(ValueError, match="request is invalid"):
        replace(request_plan()[index], **changes)


@pytest.mark.parametrize(
    ("index", "url"),
    [
        (
            0,
            f"https://graph.microsoft.com/beta/identity/authenticationEventsFlows/{USER_FLOW_ID}?$select=id,conditions",
        ),
        (
            0,
            f"http://graph.microsoft.com/v1.0/identity/authenticationEventsFlows/{USER_FLOW_ID}?$select=id,conditions",
        ),
        (
            0,
            f"https://evil.invalid/v1.0/identity/authenticationEventsFlows/{USER_FLOW_ID}?$select=id,conditions",
        ),
        (
            0,
            f"https://graph.microsoft.us/v1.0/identity/authenticationEventsFlows/{USER_FLOW_ID}?$select=id,conditions",
        ),
        (
            0,
            f"https://operator@graph.microsoft.com/v1.0/identity/authenticationEventsFlows/{USER_FLOW_ID}?$select=id,conditions",
        ),
        (
            0,
            f"https://graph.microsoft.com:443/v1.0/identity/authenticationEventsFlows/{USER_FLOW_ID}?$select=id,conditions",
        ),
        (
            0,
            f"https://graph.microsoft.com/v1.0/identity/authenticationEventsFlows/%2e%2e/{USER_FLOW_ID}?$select=id,conditions",
        ),
        (
            0,
            request_plan()[0].url.replace(
                USER_FLOW_ID, USER_FLOW_ID.replace("-", "%2d")
            ),
        ),
        (
            0,
            request_plan()[0].url.replace(
                "$select=id,conditions", "%24select=id%2Cconditions"
            ),
        ),
        (0, request_plan()[0].url + "&$top=1"),
        (0, request_plan()[0].url + "#fragment"),
        (1, request_plan()[1].url + "&$count=true"),
        (1, request_plan()[1].url.replace("?$select=appId", "/?$select=appId")),
        (
            1,
            request_plan()[1].url.replace("includeApplications", "excludeApplications"),
        ),
    ],
)
def test_request_rejects_authority_path_or_query_widening(index, url):
    with pytest.raises(ValueError, match="request is invalid"):
        replace(request_plan()[index], url=url)


@pytest.mark.parametrize("failure_call", [1, 2])
@pytest.mark.parametrize(
    "response_kwargs",
    [
        {"status": 201},
        {"status": True},
        {"final_url": "https://graph.microsoft.com/v1.0/other"},
        {"final_url": 1},
        {"headers": {"Content-Type": "text/html"}},
        {"headers": {"Content-Type": "application/json", "Content-Encoding": "gzip"}},
        {"headers": {"Content-Type": "application/json", "Content-Length": "-1"}},
        {"headers": {"Content-Type": "application/json", "Content-Length": "nan"}},
        {"headers": {"Content-Type": "application/json", "Content-Length": "1"}},
        {"headers": {"Content-Type": "application/json\r\nX: y"}},
        {"headers": {"Content-Type": "application/json", "Content-Encoding": "x" * 65}},
        {"headers": {"Content-Type": "application/json", "Content-Length": "1" * 21}},
        {
            "headers": {
                "Content-Type": "application/json",
                "Content-Length": str(
                    MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES + 1
                ),
            }
        },
        {"body": b"x" * (MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES + 1)},
        {"body": "not-bytes"},
    ],
)
def test_pair_loader_fails_closed_on_either_response_transport_boundary(
    failure_call, response_kwargs
):
    plan = request_plan()
    opener = opener_for_plan(
        plan,
        response_overrides={failure_call: response_kwargs},
    )
    loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN,
        open_url=opener,
    )
    with pytest.raises(EntraExternalIdUserFlowGraphHTTPError):
        loader(plan)
    assert opener.calls() == failure_call
    assert loader._delegated_access_token is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status_code": True},
        {"final_url": 1},
        {"content_type": None},
        {"body": "text"},
        {"tls_peer_verified": 1},
        {"redirect_count": True},
        {"redirect_count": 1},
        {"attempt_count": True},
        {"attempt_count": 0},
        {"attempt_count": 2},
    ],
)
def test_public_response_rejects_invalid_scalar_or_transport_flags(kwargs):
    values = {
        "status_code": 200,
        "final_url": request_plan()[0].url,
        "content_type": "application/json",
        "body": FLOW_BODY,
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match="response is invalid"):
        EntraExternalIdUserFlowGraphResponse(**values)


def test_each_read_uses_one_bounded_read_amount():
    plan = request_plan()
    raw_responses: list[RawResponse] = []
    by_url = {request.url: request for request in plan}

    def open_url(url_request, timeout):
        del timeout
        response = RawResponse(by_url[url_request.full_url])
        raw_responses.append(response)
        return response

    loader = BoundedHTTPSEntraExternalIdUserFlowGraphLoader(
        delegated_access_token=TOKEN,
        open_url=open_url,
    )
    loader(plan)
    assert len(raw_responses) == 2
    assert all(
        response.read_amount == MAX_ENTRA_EXTERNAL_ID_USER_FLOW_GRAPH_RESPONSE_BYTES + 1
        for response in raw_responses
    )


def test_default_transport_disables_proxy_redirect_and_tls_key_logging(monkeypatch):
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
    handler_names = {type(handler).__name__ for handler in captured["handlers"]}
    assert "ProxyHandler" in handler_names
    assert "HTTPSHandler" in handler_names
    assert "_DenyRedirects" in handler_names
