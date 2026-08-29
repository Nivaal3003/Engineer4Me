from __future__ import annotations

import ast
import contextlib
import io
import inspect
import json
import runpy
import sys
import types

import httpx
import pytest

from app.security import (
    authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_registry_http_loader
    as loader,
)


class _RecordingSyncByteStream(httpx.SyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = chunks
        self.yield_count = 0
        self.closed = False

    def __iter__(self):
        for chunk in self._chunks:
            self.yield_count += 1
            yield chunk

    def close(self) -> None:
        self.closed = True


def _unread_response(
    request: httpx.Request,
    *,
    body: bytes,
    headers: dict[str, str],
    status_code: int = 200,
) -> httpx.Response:
    response = httpx.Response(
        status_code,
        headers=headers,
        stream=_RecordingSyncByteStream((body,)),
        request=request,
    )
    assert not response.is_stream_consumed
    assert not response.is_closed
    return response


def _content_for(request: httpx.Request) -> tuple[bytes, str]:
    if request.url.path.endswith("/index.json"):
        return b"[]", "application/json"
    if request.url.path.endswith("/SHASUMS256.txt"):
        return (
            b"0000000000000000000000000000000000000000000000000000000000000000  node-v24.19.0.tar.gz\n",
            "text/plain",
        )
    return b"{}", "application/json"


def _successful_transport(
    observed: list[httpx.Request] | None = None,
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if observed is not None:
            observed.append(request)
        body, media_type = _content_for(request)
        return _unread_response(
            request,
            body=body,
            headers={"Content-Type": media_type},
        )

    return httpx.MockTransport(handler)


def _valid_authorization() -> bytes:
    from app.security import (
        authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_compatibility_probe
        as probe,
    )

    return json.dumps(
        {
            "document_type": probe.DOCUMENT_TYPE,
            "schema_version": probe.SCHEMA_VERSION,
            "source": probe.SOURCE,
            "approved_step235_package_manifest_sha256": probe.STEP235_PACKAGE_MANIFEST_SHA256,
            "approved_step235_accepted_state_manifest_sha256": probe.STEP235_ACCEPTED_STATE_MANIFEST_SHA256,
            "approved_step235_architecture_selection_readiness_sha256": probe.STEP235_ARCHITECTURE_SELECTION_READINESS_SHA256,
            "approved_step235_architecture_selection_test_sha256": probe.STEP235_ARCHITECTURE_SELECTION_TEST_SHA256,
            "approved_step235_canonical_receipt_sha256": probe.STEP235_CANONICAL_RECEIPT_SHA256,
            "approved_step235_readiness_document_sha256": probe.STEP235_READINESS_DOCUMENT_SHA256,
            "approved_step235_architecture_plan_sha256": probe.STEP235_ARCHITECTURE_PLAN_SHA256,
            "approved_step235_security_plan_sha256": probe.STEP235_SECURITY_PLAN_SHA256,
            "approved_step235_experience_and_test_plan_sha256": probe.STEP235_EXPERIENCE_AND_TEST_PLAN_SHA256,
            "approved_step235_deferred_gate_plan_sha256": probe.STEP235_DEFERRED_GATE_PLAN_SHA256,
            "selection_profile": probe.SELECTION_PROFILE,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def test_closed_request_inventory_is_exact_and_unique() -> None:
    contract = loader.official_request_contract_projection()
    assert len(contract) == loader.MAX_REQUEST_COUNT == 27
    assert len({item["request_id"] for item in contract}) == 27
    assert sum(item["request_id"].startswith("npm-package:") for item in contract) == 23
    assert sum(item["method"] == "POST" for item in contract) == 1
    assert {httpx.URL(item["url"]).host for item in contract} == {
        "registry.npmjs.org",
        "nodejs.org",
    }


def test_tuple_classification_and_versions_are_exact() -> None:
    assert len(loader.DIRECT_PACKAGES) == 19
    assert len(loader.TRANSITIVE_ANCHOR_PACKAGES) == 3
    assert len(loader.SELECTED_PACKAGES) == 22
    assert loader.NODE_VERSION == "24.19.0"
    assert loader.NPM_VERSION == "11.17.0"
    assert {item.name for item in loader.TRANSITIVE_ANCHOR_PACKAGES} == {
        "@azure/msal-common",
        "playwright",
        "playwright-core",
    }
    assert next(
        item.version for item in loader.DIRECT_PACKAGES if item.name == "react-router"
    ) == "8.3.0"


def test_live_loader_is_private_and_requires_validated_authorization() -> None:
    assert "load_live_ecosystem_registry_evidence" not in loader.__all__
    assert tuple(
        inspect.signature(loader._load_live_ecosystem_registry_evidence).parameters
    ) == ("validated_authorization",)
    with pytest.raises(loader.EcosystemRegistryHttpLoaderError):
        loader._load_live_ecosystem_registry_evidence(object())


def test_synthetic_transport_is_never_attested_live() -> None:
    evidence = loader.load_synthetic_ecosystem_registry_evidence(
        transport=_successful_transport()
    )
    assert evidence.evidence_source == "synthetic_mock_transport"
    assert not loader.is_attested_live_ecosystem_registry_evidence(evidence)
    assert evidence.request_count == 27
    assert evidence.automatic_retries == 0
    assert not evidence.environment_proxy_configuration_used
    assert not evidence.credentials_sent


def test_content_backed_mock_transport_response_is_rejected_as_preconsumed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body, media_type = _content_for(request)
        response = httpx.Response(
            200,
            headers={"Content-Type": media_type},
            content=body,
            request=request,
        )
        assert response.is_stream_consumed
        assert response.is_closed
        return response

    with pytest.raises(
        loader.EcosystemRegistryHttpLoaderError,
        match="^official registry response stream is not unread$",
    ):
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=httpx.MockTransport(handler)
        )


def test_closed_unconsumed_response_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        response = _unread_response(
            request,
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        response.close()
        assert not response.is_stream_consumed
        assert response.is_closed
        return response

    with pytest.raises(
        loader.EcosystemRegistryHttpLoaderError,
        match="^official registry response stream is not unread$",
    ):
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=httpx.MockTransport(handler)
        )


def test_mock_transport_observes_only_exact_header_and_method_contract() -> None:
    observed: list[httpx.Request] = []
    loader.load_synthetic_ecosystem_registry_evidence(
        transport=_successful_transport(observed)
    )
    assert len(observed) == 27
    assert all(request.headers["accept-encoding"] == "identity" for request in observed)
    assert all("authorization" not in request.headers for request in observed)
    assert all("proxy-authorization" not in request.headers for request in observed)
    assert all("cookie" not in request.headers for request in observed)
    advisory = next(request for request in observed if request.method == "POST")
    assert str(advisory.url) == (
        "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
    )
    body = json.loads(advisory.content)
    assert len(body) == 23
    assert body["npm"] == ["11.17.0"]
    assert body["react"] == ["19.2.8"]
    assert body["playwright-core"] == ["1.62.1"]


def test_response_request_method_correlation_is_exact() -> None:
    spec = loader._request_specs()[0]
    mismatched_request = httpx.Request("POST", spec.url)
    response = _unread_response(
        mismatched_request,
        body=b"{}",
        headers={"Content-Type": "application/json"},
    )

    class MismatchedResponseClient:
        def __init__(self) -> None:
            self.cookies = httpx.Cookies()

        def stream(
            self, *args: object, **kwargs: object
        ) -> contextlib.AbstractContextManager[httpx.Response]:
            return contextlib.closing(response)

    with pytest.raises(
        loader.EcosystemRegistryHttpLoaderError,
        match="^official registry response method is not exact$",
    ):
        loader._read_response(
            MismatchedResponseClient(),
            spec,
            deadline=loader.time.monotonic() + 1.0,
        )


@pytest.mark.parametrize(
    ("status", "headers", "body", "expected_error"),
    [
        (
            302,
            {"Content-Type": "application/json"},
            b"{}",
            "official registry response status is not accepted",
        ),
        (
            200,
            {"Content-Type": "text/html"},
            b"{}",
            "official registry response media type is not accepted",
        ),
        (
            200,
            {"Content-Type": "application/json", "Content-Encoding": "gzip"},
            b"{}",
            "encoded official registry response is forbidden",
        ),
        (
            200,
            {"Content-Type": "application/json"},
            b"",
            "official registry response body is empty",
        ),
    ],
)
def test_response_status_type_encoding_cookie_and_empty_body_fail_closed(
    status: int,
    headers: dict[str, str],
    body: bytes,
    expected_error: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _unread_response(
            request,
            status_code=status,
            headers=headers,
            body=body,
        )

    with pytest.raises(loader.EcosystemRegistryHttpLoaderError) as error:
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=httpx.MockTransport(handler)
        )
    assert str(error.value) == expected_error


def test_received_cookie_is_cleared_and_never_replayed() -> None:
    observed_cookie_headers: list[str | None] = []
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        observed_cookie_headers.append(request.headers.get("cookie"))
        body, media_type = _content_for(request)
        headers = {"Content-Type": media_type}
        if call_count == 0:
            headers["Set-Cookie"] = "cloudflare_state=received; Path=/; Secure"
        call_count += 1
        return _unread_response(request, body=body, headers=headers)

    evidence = loader.load_synthetic_ecosystem_registry_evidence(
        transport=httpx.MockTransport(handler)
    )
    assert evidence.request_count == 27
    assert observed_cookie_headers == [None] * 27


def test_missing_content_type_is_allowed_only_for_exact_advisory_response() -> None:
    def accepted_handler(request: httpx.Request) -> httpx.Response:
        body, media_type = _content_for(request)
        headers = (
            {}
            if request.url.path.endswith("/security/advisories/bulk")
            else {"Content-Type": media_type}
        )
        return _unread_response(request, body=body, headers=headers)

    evidence = loader.load_synthetic_ecosystem_registry_evidence(
        transport=httpx.MockTransport(accepted_handler)
    )
    advisory = next(
        response
        for response in evidence.requests
        if response.request_id == "npm-direct-advisories"
    )
    assert advisory.media_type == "absent"

    def rejected_handler(request: httpx.Request) -> httpx.Response:
        return _unread_response(request, body=b"{}", headers={})

    with pytest.raises(loader.EcosystemRegistryHttpLoaderError) as error:
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=httpx.MockTransport(rejected_handler)
        )
    assert str(error.value) == "official registry response media type is missing"


@pytest.mark.parametrize("content_type", [" ", "; charset=utf-8", "absent"])
def test_present_blank_or_malformed_advisory_content_type_fails_closed(
    content_type: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body, media_type = _content_for(request)
        if request.url.path.endswith("/security/advisories/bulk"):
            media_type = content_type
        return _unread_response(
            request,
            headers={"Content-Type": media_type},
            body=body,
        )

    with pytest.raises(loader.EcosystemRegistryHttpLoaderError) as error:
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=httpx.MockTransport(handler)
        )
    assert str(error.value) == "official registry response media type is not accepted"


def test_declared_oversized_body_fails_before_read() -> None:
    stream = _RecordingSyncByteStream((b"{}",))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(loader.MAX_NPM_METADATA_BYTES + 1),
            },
            stream=stream,
            request=request,
        )

    with pytest.raises(loader.EcosystemRegistryHttpLoaderError) as error:
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=httpx.MockTransport(handler)
        )
    assert str(error.value) == "official registry response exceeds its approved bound"
    assert stream.yield_count == 0
    assert stream.closed


def test_streamed_oversized_body_fails_closed() -> None:
    stream = _RecordingSyncByteStream(
        (
            b"x" * loader.MAX_NPM_METADATA_BYTES,
            b"y",
            b"must-not-be-read",
        )
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
            request=request,
        )

    with pytest.raises(loader.EcosystemRegistryHttpLoaderError) as error:
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=httpx.MockTransport(handler)
        )
    assert str(error.value) == "official registry response exceeds its approved bound"
    assert stream.yield_count == 2
    assert stream.closed


def test_live_path_streaming_read_stops_at_per_response_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.security import (
        authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_compatibility_probe
        as probe,
    )

    validated_authorization = probe.validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization(
        _valid_authorization()
    )
    stream = _RecordingSyncByteStream(
        (
            b"x" * loader.MAX_NPM_METADATA_BYTES,
            b"y",
            b"must-not-be-read",
        )
    )
    live_client_factory_calls = 0
    real_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        response = httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
            request=request,
        )
        assert not response.is_stream_consumed
        return response

    def client_factory(*args: object, **kwargs: object) -> httpx.Client:
        nonlocal live_client_factory_calls
        live_client_factory_calls += 1
        assert kwargs.get("transport") is None
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)
    with pytest.raises(loader.EcosystemRegistryHttpLoaderError) as error:
        loader._load_live_ecosystem_registry_evidence(validated_authorization)
    assert str(error.value) == "official registry response exceeds its approved bound"
    assert live_client_factory_calls == 1
    assert stream.yield_count == 2
    assert stream.closed


def test_httpx_stream_error_is_sanitized() -> None:
    class FailingSyncByteStream(httpx.SyncByteStream):
        def __iter__(self):
            raise httpx.StreamError("synthetic transport detail")

    stream = FailingSyncByteStream()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
            request=request,
        )

    with pytest.raises(loader.EcosystemRegistryHttpLoaderError) as error:
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=httpx.MockTransport(handler)
        )
    assert str(error.value) == "official registry request failed"
    assert "synthetic transport detail" not in str(error.value)


def test_response_header_count_is_bounded() -> None:
    headers = {f"X-Test-{index}": "v" for index in range(65)}
    headers["Content-Type"] = "application/json"

    def handler(request: httpx.Request) -> httpx.Response:
        return _unread_response(request, body=b"{}", headers=headers)

    with pytest.raises(loader.EcosystemRegistryHttpLoaderError) as error:
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=httpx.MockTransport(handler)
        )
    assert str(error.value) == (
        "official registry response header count exceeds its approved bound"
    )


@pytest.mark.parametrize("value", [b"\x7f", b"\x80"])
def test_response_header_del_and_obs_text_are_forbidden(value: bytes) -> None:
    request = httpx.Request("GET", "https://registry.npmjs.org/react/19.2.8")
    response = httpx.Response(
        200,
        headers=[(b"content-type", b"application/json"), (b"x-test", value)],
        stream=_RecordingSyncByteStream((b"{}",)),
        request=request,
    )
    with pytest.raises(loader.EcosystemRegistryHttpLoaderError):
        loader._validate_response_headers(response)


def test_aggregate_bound_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "MAX_AGGREGATE_RESPONSE_BYTES", 1)
    with pytest.raises(loader.EcosystemRegistryHttpLoaderError):
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=_successful_transport()
        )


def test_deadline_is_checked_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    values = iter((0.0, 100.0))
    monkeypatch.setattr(loader.time, "monotonic", lambda: next(values, 100.0))
    monkeypatch.setattr(loader, "EXECUTION_DEADLINE_SECONDS", 1.0)
    with pytest.raises(loader.EcosystemRegistryHttpLoaderError):
        loader.load_synthetic_ecosystem_registry_evidence(
            transport=_successful_transport()
        )


def test_invalid_authorization_prevents_live_loader_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def forbidden_live_call(_: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("network path must not be reached")

    monkeypatch.setattr(loader, "_read_authorization", lambda: b"{}")
    monkeypatch.setattr(loader, "_load_live_ecosystem_registry_evidence", forbidden_live_call)
    assert loader.main() == 1
    assert calls == 0


def test_module_execution_binds_one_canonical_loader_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.security import (
        authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_compatibility_probe
        as canonical_probe,
    )

    authorization = _valid_authorization()
    observed: list[httpx.Request] = []
    real_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        active_loader = sys.modules[canonical_loader_name]
        assert active_loader is sys.modules["__main__"]
        observed.append(request)
        body, media_type = _content_for(request)
        return _unread_response(
            request,
            headers={"Content-Type": media_type},
            body=body,
        )

    def client_factory(*args: object, **kwargs: object) -> httpx.Client:
        if kwargs.get("transport") is None:
            kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)
    monkeypatch.setattr(
        sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(authorization))
    )
    captured_stdout = types.SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(sys, "stdout", captured_stdout)
    canonical_loader_name = loader.__name__
    canonical_probe_name = canonical_probe.__name__
    security_package = sys.modules["app.security"]
    loader_attribute = canonical_loader_name.rsplit(".", 1)[-1]
    probe_attribute = canonical_probe_name.rsplit(".", 1)[-1]
    saved_loader_attribute = getattr(security_package, loader_attribute)
    saved_probe_attribute = getattr(security_package, probe_attribute)
    saved_loader = sys.modules.pop(canonical_loader_name)
    saved_probe = sys.modules.pop(canonical_probe_name)
    fake_probe = types.ModuleType(canonical_probe_name)

    class FakeAuthorization:
        pass

    FakeAuthorization.__module__ = canonical_probe_name
    receipt_sentinel = object()

    def validate_authorization(value: bytes) -> FakeAuthorization:
        assert value == authorization
        validated = canonical_probe.validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization(
            value
        )
        assert type(validated) is (
            canonical_probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityAuthorization
        )
        return FakeAuthorization()

    def load_receipt(value: bytes, evidence: object) -> object:
        active_loader = sys.modules[canonical_loader_name]
        assert active_loader is sys.modules["__main__"]
        assert type(evidence) is active_loader.LiveEcosystemRegistryEvidence
        assert active_loader.is_attested_live_ecosystem_registry_evidence(evidence)
        assert value == authorization
        return receipt_sentinel

    def render_receipt(value: object) -> bytes:
        assert value is receipt_sentinel
        return b"{}"

    fake_probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityAuthorization = (
        FakeAuthorization
    )
    fake_probe.validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization = (
        validate_authorization
    )
    fake_probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility = (
        load_receipt
    )
    fake_probe.render_entra_calling_client_msal_frontend_host_ecosystem_compatibility_receipt = (
        render_receipt
    )
    sys.modules[canonical_probe_name] = fake_probe
    setattr(security_package, probe_attribute, fake_probe)
    try:
        try:
            runpy.run_module(canonical_loader_name, run_name="__main__", alter_sys=True)
        except SystemExit as error:
            assert error.code == 0
        else:
            raise AssertionError("module execution did not terminate")
        assert len(observed) == loader.MAX_REQUEST_COUNT
        assert captured_stdout.buffer.getvalue() == b"{}\n"
    finally:
        sys.modules.pop(canonical_loader_name, None)
        sys.modules.pop(canonical_probe_name, None)
        sys.modules[canonical_loader_name] = saved_loader
        sys.modules[canonical_probe_name] = saved_probe
        setattr(security_package, loader_attribute, saved_loader_attribute)
        setattr(security_package, probe_attribute, saved_probe_attribute)


def test_loader_source_has_no_filesystem_subprocess_cache_or_retry_path() -> None:
    source = inspect.getsource(loader)
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not {"os", "pathlib", "subprocess", "requests", "urllib.request"}.intersection(
        imports
    )
    assert "follow_redirects=False" in source
    assert "trust_env=False" in source
    assert "Accept-Encoding\": \"identity" in source
    assert "response.is_stream_consumed or response.is_closed" in source
    assert "response.iter_raw()" in source
    assert "response.iter_bytes()" not in source
    assert "httpx.StreamError" in source
    assert "retry" not in {node.id.lower() for node in ast.walk(tree) if isinstance(node, ast.Name)}
