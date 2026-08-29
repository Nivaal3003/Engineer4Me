"""Fail-closed deployment configuration for the authentication runtime."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Self
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import ValidationError, model_validator

from app.security.authentication_runtime import (
    AuthenticationRuntimeConfiguration,
    build_bearer_authentication_dependency,
)
from app.security.jwks_http_loader import (
    BoundedHTTPSJWKSLoader,
    JWKSHTTPPolicy,
    OpenURL,
)
from app.security.jwks_resolver import JWKSConfiguration
from app.security.identity_models import SecurityModel
from app.security.token_verifier import (
    MICROSOFT_ENTRA_ACCESS_AS_USER_SCOPE,
    MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR,
)

if TYPE_CHECKING:
    from app.security.authentication import BearerAuthenticationDependency


class AuthenticationDeploymentError(RuntimeError):
    """Sanitized invalid or incomplete deployment configuration."""


class AuthenticationDeploymentConfiguration(SecurityModel):
    runtime: AuthenticationRuntimeConfiguration
    transport: JWKSHTTPPolicy

    @model_validator(mode="after")
    def validate_shared_jwks_source(self) -> Self:
        if self.runtime.jwks != self.transport.source:
            raise ValueError(
                "authentication runtime and transport JWKS configuration must match"
            )
        return self


_PREFIX = "E4M_AUTH_"
_REQUIRED = frozenset(
    {"E4M_AUTH_ISSUER", "E4M_AUTH_AUDIENCE", "E4M_AUTH_JWKS_URL", "E4M_AUTH_ALGORITHMS"}
)
_OPTIONAL = frozenset(
    {
        "E4M_AUTH_CLOCK_SKEW_SECONDS",
        "E4M_AUTH_MAXIMUM_TOKEN_AGE_SECONDS",
        "E4M_AUTH_JWKS_CACHE_SECONDS",
        "E4M_AUTH_JWKS_MAXIMUM_KEYS",
        "E4M_AUTH_JWKS_TIMEOUT_SECONDS",
        "E4M_AUTH_JWKS_MAXIMUM_RESPONSE_BYTES",
        "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM",
        "E4M_AUTH_TOKEN_PROFILE",
        "E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID",
        "E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID",
        "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE",
        "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID",
        "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR",
    }
)


def _required_text(environment: Mapping[str, str], key: str) -> str:
    value = environment.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AuthenticationDeploymentError(
            "required authentication deployment configuration is missing"
        )
    return value.strip()


def _required_issuer(environment: Mapping[str, str]) -> str:
    value = _required_text(environment, "E4M_AUTH_ISSUER")
    if any(
        character == "\\"
        or character.isspace()
        or ord(character) < 0x20
        or ord(character) == 0x7F
        for character in value
    ):
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        )
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        ) from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port == 0
        or parsed.netloc.endswith(":")
        or "?" in value
        or "#" in value
    ):
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        )
    return value


def _integer(environment: Mapping[str, str], key: str, default: int) -> int:
    value = environment.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        ) from None


def _number(environment: Mapping[str, str], key: str, default: float) -> float:
    value = environment.get(key)
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        ) from None


def _token_identifier_claim(environment: Mapping[str, str]) -> str:
    value = environment.get("E4M_AUTH_TOKEN_IDENTIFIER_CLAIM", "jti")
    if type(value) is not str or value not in {"jti", "uti"}:
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        )
    return value


def _token_profile(environment: Mapping[str, str]) -> str:
    value = environment.get("E4M_AUTH_TOKEN_PROFILE", "provider_neutral")
    if type(value) is not str or value not in {
        "provider_neutral",
        "microsoft_entra_v2",
    }:
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        )
    return value


def _optional_canonical_uuid(
    environment: Mapping[str, str],
    key: str,
) -> UUID | None:
    value = environment.get(key)
    if value is None:
        return None
    if type(value) is not str or not value:
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        )
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        ) from None
    if str(parsed) != value:
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        )
    return parsed


def _optional_microsoft_entra_delegated_scope(
    environment: Mapping[str, str],
) -> str | None:
    value = environment.get(
        "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE"
    )
    if value is None:
        return None
    if type(value) is not str or value != MICROSOFT_ENTRA_ACCESS_AS_USER_SCOPE:
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        )
    return value


def _optional_microsoft_entra_azpacr(
    environment: Mapping[str, str],
) -> str | None:
    value = environment.get("E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR")
    if value is None:
        return None
    if (
        type(value) is not str
        or value != MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR
    ):
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        )
    return value


def load_authentication_deployment(
    environment: Mapping[str, str],
) -> AuthenticationDeploymentConfiguration:
    """Parse an explicit mapping; never read process-global environment implicitly."""

    unexpected = {
        key
        for key in environment
        if key.startswith(_PREFIX) and key not in _REQUIRED | _OPTIONAL
    }
    if unexpected:
        raise AuthenticationDeploymentError(
            "unknown authentication deployment configuration was supplied"
        )
    algorithms_text = _required_text(environment, "E4M_AUTH_ALGORITHMS")
    algorithms = tuple(item.strip() for item in algorithms_text.split(","))
    if any(not item for item in algorithms):
        raise AuthenticationDeploymentError(
            "authentication algorithm configuration is invalid"
        )
    try:
        jwks = JWKSConfiguration(
            source_url=_required_text(environment, "E4M_AUTH_JWKS_URL"),
            cache_seconds=_integer(environment, "E4M_AUTH_JWKS_CACHE_SECONDS", 300),
            maximum_keys=_integer(environment, "E4M_AUTH_JWKS_MAXIMUM_KEYS", 20),
        )
        runtime = AuthenticationRuntimeConfiguration(
            issuer=_required_issuer(environment),
            audience=_required_text(environment, "E4M_AUTH_AUDIENCE"),
            algorithms=algorithms,
            jwks=jwks,
            clock_skew_seconds=_integer(environment, "E4M_AUTH_CLOCK_SKEW_SECONDS", 30),
            maximum_token_age_seconds=_integer(
                environment, "E4M_AUTH_MAXIMUM_TOKEN_AGE_SECONDS", 3600
            ),
            token_identifier_claim=_token_identifier_claim(environment),
            token_profile=_token_profile(environment),
            microsoft_entra_tenant_id=_optional_canonical_uuid(
                environment,
                "E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID",
            ),
            microsoft_entra_api_application_id=_optional_canonical_uuid(
                environment,
                "E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID",
            ),
            microsoft_entra_required_delegated_scope=(
                _optional_microsoft_entra_delegated_scope(environment)
            ),
            microsoft_entra_calling_client_application_id=(
                _optional_canonical_uuid(
                    environment,
                    "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID",
                )
            ),
            microsoft_entra_required_azpacr=(
                _optional_microsoft_entra_azpacr(environment)
            ),
        )
        transport = JWKSHTTPPolicy(
            source=jwks,
            timeout_seconds=_number(environment, "E4M_AUTH_JWKS_TIMEOUT_SECONDS", 5.0),
            maximum_response_bytes=_integer(
                environment, "E4M_AUTH_JWKS_MAXIMUM_RESPONSE_BYTES", 131072
            ),
        )
        return AuthenticationDeploymentConfiguration(
            runtime=runtime, transport=transport
        )
    except ValidationError:
        raise AuthenticationDeploymentError(
            "authentication deployment configuration is invalid"
        ) from None


def build_deployment_bearer_dependency(
    *,
    environment: Mapping[str, str],
    open_url: OpenURL | None = None,
) -> BearerAuthenticationDependency:
    """Compose deployment configuration without eager network access."""

    deployment = load_authentication_deployment(environment)
    loader = BoundedHTTPSJWKSLoader(policy=deployment.transport, open_url=open_url)
    return build_bearer_authentication_dependency(
        config=deployment.runtime, jwks_loader=loader
    )
