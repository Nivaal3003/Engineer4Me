"""Focused tests for bounded HTTPS JWKS retrieval."""

from urllib.error import URLError

import pytest
from pydantic import ValidationError

from app.security.jwks_http_loader import (
    BoundedHTTPSJWKSLoader,
    JWKSHTTPError,
    JWKSHTTPPolicy,
)
from app.security.jwks_resolver import JWKSConfiguration


SOURCE = "https://identity.engineer4me.test/.well-known/jwks.json"
DOCUMENT = b'{"keys":[{"kid":"key-132","kty":"RSA","alg":"RS256","use":"sig","n":"value","e":"AQAB"}]}'


class FakeResponse:
    def __init__(
        self,
        *,
        body=DOCUMENT,
        status=200,
        url=SOURCE,
        content_type="application/jwk-set+json",
        content_length=None
    ):
        self.body = body
        self.status = status
        self.url = url
        self.headers = {"Content-Type": content_type}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def geturl(self):
        return self.url

    def read(self, amount=-1):
        return self.body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


def policy(**overrides):
    values = dict(
        source=JWKSConfiguration(source_url=SOURCE),
        timeout_seconds=3.0,
        maximum_response_bytes=1024,
    )
    values.update(overrides)
    return JWKSHTTPPolicy(**values)


def loader_for(response, calls=None):
    calls = [] if calls is None else calls

    def open_url(request, timeout):
        calls.append((request, timeout))
        if isinstance(response, Exception):
            raise response
        return response

    return BoundedHTTPSJWKSLoader(policy=policy(), open_url=open_url), calls


def test_loader_returns_trusted_response_from_exact_configured_source():
    loader, calls = loader_for(FakeResponse(content_length=str(len(DOCUMENT))))
    result = loader(SOURCE)
    assert result.source_url == SOURCE
    assert result.document["keys"][0]["kid"] == "key-132"
    request, timeout = calls[0]
    assert request.full_url == SOURCE
    assert request.get_method() == "GET"
    assert request.get_header("Accept") == "application/jwk-set+json, application/json"
    assert timeout == 3.0


def test_loader_performs_no_eager_networking():
    calls = []
    loader, _ = loader_for(FakeResponse(), calls)
    assert calls == []
    loader(SOURCE)
    assert len(calls) == 1


def test_loader_rejects_source_substitution_before_transport():
    loader, calls = loader_for(FakeResponse())
    with pytest.raises(JWKSHTTPError, match="configured source"):
        loader("https://attacker.invalid/jwks")
    assert calls == []


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(status=204),
        FakeResponse(url="https://identity.engineer4me.test/redirected"),
        FakeResponse(content_type="text/html"),
        FakeResponse(content_length="invalid"),
        FakeResponse(content_length="2048"),
        FakeResponse(body=b"x" * 1025),
        FakeResponse(body=b"not-json"),
        FakeResponse(body=b"[]"),
    ],
)
def test_loader_rejects_untrusted_or_unbounded_responses(response):
    loader, _ = loader_for(response)
    with pytest.raises(JWKSHTTPError):
        loader(SOURCE)


def test_loader_sanitizes_transport_failures():
    loader, _ = loader_for(URLError("sensitive internal detail"))
    with pytest.raises(JWKSHTTPError, match="retrieval failed") as error:
        loader(SOURCE)
    assert "sensitive" not in str(error.value)
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "body",
    [
        b'{"keys":[],"keys":[]}',
        b'{"keys":[{"kid":"one","kid":"two"}]}',
    ],
)
def test_duplicate_json_keys_are_rejected_at_every_object_depth(body):
    loader, _ = loader_for(FakeResponse(body=body))
    with pytest.raises(JWKSHTTPError, match="duplicate JSON key") as error:
        loader(SOURCE)
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "number",
    [b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"],
)
def test_non_finite_json_numbers_are_rejected(number):
    body = b'{"keys":[],"metadata":' + number + b"}"
    loader, _ = loader_for(FakeResponse(body=body))
    with pytest.raises(JWKSHTTPError, match="non-finite") as error:
        loader(SOURCE)
    assert error.value.__cause__ is None


def test_non_bytes_response_body_is_rejected():
    loader, _ = loader_for(FakeResponse(body="not-bytes"))
    with pytest.raises(JWKSHTTPError, match="body must be bytes"):
        loader(SOURCE)


@pytest.mark.parametrize("timeout", [0.1, 31.0])
def test_policy_rejects_timeout_outside_bounds(timeout):
    with pytest.raises(ValidationError):
        policy(timeout_seconds=timeout)


def test_policy_rejects_header_injection_in_user_agent():
    with pytest.raises(ValidationError):
        policy(user_agent="Engineer4Me\r\nInjected: yes")
