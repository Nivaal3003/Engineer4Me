"""Controlled, injected JWKS caching and key-resolution boundary."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Self
from urllib.parse import urlsplit

import jwt
from jwt.exceptions import InvalidKeyError
from pydantic import AwareDatetime, Field, model_validator

from app.security.identity_models import IdentityText, SecurityModel
from app.security.token_verifier import ASYMMETRIC_ALGORITHMS


class JWKSConfiguration(SecurityModel):
    source_url: IdentityText
    cache_seconds: int = Field(default=300, ge=30, le=3600)
    maximum_keys: int = Field(default=20, ge=1, le=100)

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if any(
            character == "\\"
            or character.isspace()
            or ord(character) < 0x20
            or ord(character) == 0x7F
            for character in self.source_url
        ):
            raise ValueError("JWKS source must be a controlled HTTPS URL")
        try:
            parsed = urlsplit(self.source_url)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            raise ValueError("JWKS source must be a controlled HTTPS URL") from None
        if (
            parsed.scheme != "https"
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or port == 0
            or parsed.netloc.endswith(":")
        ):
            raise ValueError("JWKS source must be an absolute HTTPS URL")
        if "?" in self.source_url or "#" in self.source_url:
            raise ValueError(
                "JWKS source cannot contain credentials, queries, or fragments"
            )
        return self


class TrustedJWKSResponse(SecurityModel):
    source_url: IdentityText
    fetched_at: AwareDatetime
    document: dict[str, Any]


class JWKSResolutionError(RuntimeError):
    pass


JWKSLoader = Callable[[str], TrustedJWKSResponse]


class ControlledJWKSResolver:
    """Resolve verification keys from bounded trusted-loader responses."""

    def __init__(self, *, config: JWKSConfiguration, loader: JWKSLoader) -> None:
        self._config = config
        self._loader = loader
        self._keys: dict[tuple[str, str], object] = {}
        self._expires_at: datetime | None = None

    def resolve(self, *, key_id: str, algorithm: str) -> object | None:
        if algorithm not in ASYMMETRIC_ALGORITHMS:
            return None
        now = datetime.now(UTC)
        if self._expires_at is None or now >= self._expires_at:
            self._refresh(now)
        key = self._keys.get((key_id, algorithm))
        if key is not None:
            return key
        self._refresh(now)
        return self._keys.get((key_id, algorithm))

    def _refresh(self, now: datetime) -> None:
        response = self._loader(self._config.source_url)
        if response.source_url != self._config.source_url:
            raise JWKSResolutionError("JWKS loader returned an unexpected source")
        if response.fetched_at > now + timedelta(seconds=30):
            raise JWKSResolutionError("JWKS response timestamp is in the future")
        raw_keys = response.document.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys or len(raw_keys) > self._config.maximum_keys:
            raise JWKSResolutionError("JWKS keys collection is missing or outside bounds")
        resolved: dict[tuple[str, str], object] = {}
        seen_kids: set[str] = set()
        for raw in raw_keys:
            if not isinstance(raw, dict):
                raise JWKSResolutionError("JWKS key must be an object")
            kid = raw.get("kid")
            alg = raw.get("alg")
            use = raw.get("use")
            kty = raw.get("kty")
            if not isinstance(kid, str) or not kid or len(kid) > 300:
                raise JWKSResolutionError("every JWKS key requires a bounded kid")
            if kid in seen_kids:
                raise JWKSResolutionError("JWKS kid values must be unique")
            seen_kids.add(kid)
            if alg not in ASYMMETRIC_ALGORITHMS or use not in (None, "sig"):
                continue
            if (alg.startswith("RS") and kty != "RSA") or (alg.startswith("ES") and kty != "EC"):
                raise JWKSResolutionError("JWKS key type and algorithm are inconsistent")
            try:
                resolved[(kid, alg)] = jwt.PyJWK.from_dict(raw, algorithm=alg).key
            except (InvalidKeyError, ValueError) as exc:
                raise JWKSResolutionError("JWKS key could not be constructed") from exc
        if not resolved:
            raise JWKSResolutionError("JWKS contains no usable asymmetric signing keys")
        self._keys = resolved
        self._expires_at = now + timedelta(seconds=self._config.cache_seconds)
