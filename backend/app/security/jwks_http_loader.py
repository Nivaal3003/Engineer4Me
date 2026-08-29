"""Bounded HTTPS transport for controlled JWKS retrieval."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from math import isfinite
from typing import BinaryIO, Protocol, Self
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from pydantic import Field, model_validator

from app.security.identity_models import IdentityText, SecurityModel
from app.security.jwks_resolver import JWKSConfiguration, TrustedJWKSResponse


class JWKSHTTPError(RuntimeError):
    """Sanitized failure at the controlled JWKS transport boundary."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise JWKSHTTPError("JWKS response contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    del value
    raise JWKSHTTPError("JWKS response contains a non-finite number")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise JWKSHTTPError("JWKS response contains a non-finite number")
    return parsed


class JWKSHTTPPolicy(SecurityModel):
    source: JWKSConfiguration
    timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0)
    maximum_response_bytes: int = Field(default=131072, ge=1024, le=1048576)
    user_agent: IdentityText = "Engineer4Me-JWKS/1.0"

    @model_validator(mode="after")
    def validate_user_agent(self) -> Self:
        if any(character in self.user_agent for character in "\r\n"):
            raise ValueError("JWKS user agent cannot contain line breaks")
        return self


class HTTPSResponse(Protocol):
    status: int
    headers: object

    def geturl(self) -> str: ...
    def read(self, amount: int = -1) -> bytes: ...
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...


OpenURL = Callable[[Request, float], HTTPSResponse]


class _DenyRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers,
        new_url: str,
    ):
        raise JWKSHTTPError("JWKS redirects are not permitted")


def _default_open(request: Request, timeout: float) -> HTTPSResponse:
    opener = build_opener(ProxyHandler({}), HTTPSHandler(), _DenyRedirects())
    return opener.open(request, timeout=timeout)


class BoundedHTTPSJWKSLoader:
    """Fetch exactly one configured HTTPS JWKS document under strict bounds."""

    _CONTENT_TYPES = frozenset({"application/json", "application/jwk-set+json"})

    def __init__(
        self, *, policy: JWKSHTTPPolicy, open_url: OpenURL | None = None
    ) -> None:
        self._policy = policy
        self._open_url = open_url or _default_open

    def __call__(self, source_url: str) -> TrustedJWKSResponse:
        if source_url != self._policy.source.source_url:
            raise JWKSHTTPError("JWKS source does not match configured source")
        request = Request(
            source_url,
            method="GET",
            headers={
                "Accept": "application/jwk-set+json, application/json",
                "User-Agent": self._policy.user_agent,
            },
        )
        try:
            with self._open_url(request, self._policy.timeout_seconds) as response:
                if response.status != 200:
                    raise JWKSHTTPError("JWKS endpoint returned a non-success status")
                if response.geturl() != source_url:
                    raise JWKSHTTPError("JWKS response source changed")
                content_type = (
                    str(response.headers.get("Content-Type", ""))
                    .split(";", 1)[0]
                    .strip()
                    .lower()
                )
                if content_type not in self._CONTENT_TYPES:
                    raise JWKSHTTPError("JWKS response content type is not accepted")
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except (TypeError, ValueError):
                        raise JWKSHTTPError(
                            "JWKS response content length is invalid"
                        ) from None
                    if (
                        declared_length < 0
                        or declared_length > self._policy.maximum_response_bytes
                    ):
                        raise JWKSHTTPError(
                            "JWKS response exceeds the configured size limit"
                        )
                body = response.read(self._policy.maximum_response_bytes + 1)
                if not isinstance(body, bytes):
                    raise JWKSHTTPError("JWKS response body must be bytes")
                if len(body) > self._policy.maximum_response_bytes:
                    raise JWKSHTTPError(
                        "JWKS response exceeds the configured size limit"
                    )
        except JWKSHTTPError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError):
            raise JWKSHTTPError("JWKS HTTPS retrieval failed") from None
        try:
            document = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_non_finite_number,
                parse_float=_parse_finite_float,
            )
        except JWKSHTTPError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise JWKSHTTPError("JWKS response is not valid UTF-8 JSON") from None
        if not isinstance(document, dict):
            raise JWKSHTTPError("JWKS response must be a JSON object")
        return TrustedJWKSResponse(
            source_url=source_url, fetched_at=datetime.now(UTC), document=document
        )
