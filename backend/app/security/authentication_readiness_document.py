"""Pure validation and canonical preview for authentication readiness documents.

The document contains public provider metadata only.  Parsing performs no file,
environment, network, database, bootstrap, or application I/O and does not make
the operational application ready for activation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, ValidationError

from app.security.authentication_deployment import (
    AuthenticationDeploymentConfiguration,
    AuthenticationDeploymentError,
    load_authentication_deployment,
)
from app.security.identity_models import IdentityText, SecurityModel
from app.security.token_verifier import (
    DEFAULT_AUTHENTICATION_TOKEN_PROFILE,
    DEFAULT_TOKEN_IDENTIFIER_CLAIM,
    AuthenticationTokenProfile,
    MicrosoftEntraDelegatedScope,
    MicrosoftEntraPublicClientAzpacr,
    TokenIdentifierClaim,
    required_token_claims,
)


AUTHENTICATION_READINESS_DOCUMENT_TYPE = "engineer4me_authentication_readiness"
AUTHENTICATION_READINESS_SCHEMA_VERSION = 1
AUTHENTICATION_READINESS_VALIDATION_SCOPE = "local_configuration_only"
MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES = 16_384


class AuthenticationReadinessDocumentError(ValueError):
    """Sanitized rejection of an untrusted readiness document."""


class AuthenticationReadinessConfiguration(SecurityModel):
    """Strict public inputs whose defaults resolve to deployment defaults."""

    issuer: IdentityText
    audience: IdentityText
    jwks_url: IdentityText
    algorithms: tuple[str, ...] = Field(min_length=1, max_length=6)
    token_identifier_claim: TokenIdentifierClaim = DEFAULT_TOKEN_IDENTIFIER_CLAIM
    token_profile: AuthenticationTokenProfile = DEFAULT_AUTHENTICATION_TOKEN_PROFILE
    microsoft_entra_tenant_id: UUID | None = None
    microsoft_entra_api_application_id: UUID | None = None
    microsoft_entra_required_delegated_scope: MicrosoftEntraDelegatedScope | None = (
        None
    )
    microsoft_entra_calling_client_application_id: UUID | None = None
    microsoft_entra_required_azpacr: MicrosoftEntraPublicClientAzpacr | None = None
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    maximum_token_age_seconds: int = Field(default=3_600, ge=60, le=86_400)
    jwks_cache_seconds: int = Field(default=300, ge=30, le=3_600)
    jwks_maximum_keys: int = Field(default=20, ge=1, le=100)
    jwks_timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0)
    jwks_maximum_response_bytes: int = Field(
        default=131_072,
        ge=1_024,
        le=1_048_576,
    )


class AuthenticationReadinessDocument(SecurityModel):
    """Versioned discriminator preventing a different JSON document being used."""

    document_type: Literal["engineer4me_authentication_readiness"]
    schema_version: int = Field(ge=1, le=1)
    authentication: AuthenticationReadinessConfiguration


@dataclass(frozen=True, slots=True)
class AuthenticationReadinessPreview:
    """Immutable public preview of the exact effective local configuration."""

    configuration_sha256: str
    document_type: str
    schema_version: int
    issuer: str
    audience: str
    jwks_url: str
    algorithms: tuple[str, ...]
    token_identifier_claim: str
    token_profile: str
    microsoft_entra_tenant_id: str | None
    microsoft_entra_api_application_id: str | None
    microsoft_entra_required_delegated_scope: str | None
    microsoft_entra_calling_client_application_id: str | None
    microsoft_entra_required_azpacr: str | None
    clock_skew_seconds: int
    maximum_token_age_seconds: int
    jwks_cache_seconds: int
    jwks_maximum_keys: int
    jwks_timeout_seconds: float
    jwks_maximum_response_bytes: int
    required_claims: tuple[str, ...]
    configuration_validated: bool
    jwks_reachability_checked: bool
    signed_token_checked: bool
    activation_ready: bool


@dataclass(frozen=True, slots=True)
class ValidatedAuthenticationReadinessDocument:
    """Authoritatively loaded deployment values and their canonical preview."""

    deployment: AuthenticationDeploymentConfiguration
    preview: AuthenticationReadinessPreview


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthenticationReadinessDocumentError(
                "authentication readiness document contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    del value
    raise AuthenticationReadinessDocumentError(
        "authentication readiness document contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document contains a non-finite number"
        )
    return parsed


def _require_canonical_calling_client_input(parsed: dict[str, Any]) -> None:
    authentication = parsed.get("authentication")
    if not isinstance(authentication, dict):
        return
    value = authentication.get("microsoft_entra_calling_client_application_id")
    if value is None:
        return
    if type(value) is not str:
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document contains an invalid client identifier"
        )
    try:
        identifier = UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document contains an invalid client identifier"
        ) from None
    if identifier.int == 0 or str(identifier) != value:
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document contains an invalid client identifier"
        )


def _require_exact_azpacr_input(parsed: dict[str, Any]) -> None:
    authentication = parsed.get("authentication")
    if not isinstance(authentication, dict):
        return
    value = authentication.get("microsoft_entra_required_azpacr")
    if value is None:
        return
    if type(value) is not str or value != "0":
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document contains an invalid azpacr contract"
        )


def _deployment_environment(
    value: AuthenticationReadinessConfiguration,
) -> dict[str, str]:
    """Translate strict document fields to the one authoritative loader shape."""

    environment = {
        "E4M_AUTH_ISSUER": value.issuer,
        "E4M_AUTH_AUDIENCE": value.audience,
        "E4M_AUTH_JWKS_URL": value.jwks_url,
        "E4M_AUTH_ALGORITHMS": ",".join(value.algorithms),
        "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": value.token_identifier_claim,
        "E4M_AUTH_TOKEN_PROFILE": value.token_profile,
        "E4M_AUTH_CLOCK_SKEW_SECONDS": str(value.clock_skew_seconds),
        "E4M_AUTH_MAXIMUM_TOKEN_AGE_SECONDS": str(value.maximum_token_age_seconds),
        "E4M_AUTH_JWKS_CACHE_SECONDS": str(value.jwks_cache_seconds),
        "E4M_AUTH_JWKS_MAXIMUM_KEYS": str(value.jwks_maximum_keys),
        "E4M_AUTH_JWKS_TIMEOUT_SECONDS": str(value.jwks_timeout_seconds),
        "E4M_AUTH_JWKS_MAXIMUM_RESPONSE_BYTES": str(value.jwks_maximum_response_bytes),
    }
    if value.microsoft_entra_tenant_id is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID"] = str(
            value.microsoft_entra_tenant_id
        )
    if value.microsoft_entra_api_application_id is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID"] = str(
            value.microsoft_entra_api_application_id
        )
    if value.microsoft_entra_required_delegated_scope is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE"] = (
            value.microsoft_entra_required_delegated_scope
        )
    if value.microsoft_entra_calling_client_application_id is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID"] = str(
            value.microsoft_entra_calling_client_application_id
        )
    if value.microsoft_entra_required_azpacr is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR"] = (
            value.microsoft_entra_required_azpacr
        )
    return environment


def _resolved_configuration(
    deployment: AuthenticationDeploymentConfiguration,
) -> dict[str, object]:
    """Return one canonical representation of the effective security settings."""

    return {
        "document_type": AUTHENTICATION_READINESS_DOCUMENT_TYPE,
        "schema_version": AUTHENTICATION_READINESS_SCHEMA_VERSION,
        "authentication": {
            "issuer": deployment.runtime.issuer,
            "audience": deployment.runtime.audience,
            "jwks_url": deployment.runtime.jwks.source_url,
            "algorithms": sorted(deployment.runtime.algorithms),
            "token_identifier_claim": (deployment.runtime.token_identifier_claim),
            "token_profile": deployment.runtime.token_profile,
            "microsoft_entra_tenant_id": (
                str(deployment.runtime.microsoft_entra_tenant_id)
                if deployment.runtime.microsoft_entra_tenant_id is not None
                else None
            ),
            "microsoft_entra_api_application_id": (
                str(deployment.runtime.microsoft_entra_api_application_id)
                if deployment.runtime.microsoft_entra_api_application_id is not None
                else None
            ),
            "microsoft_entra_required_delegated_scope": (
                deployment.runtime.microsoft_entra_required_delegated_scope
            ),
            "microsoft_entra_calling_client_application_id": (
                str(deployment.runtime.microsoft_entra_calling_client_application_id)
                if deployment.runtime.microsoft_entra_calling_client_application_id
                is not None
                else None
            ),
            "microsoft_entra_required_azpacr": (
                deployment.runtime.microsoft_entra_required_azpacr
            ),
            "clock_skew_seconds": deployment.runtime.clock_skew_seconds,
            "maximum_token_age_seconds": (deployment.runtime.maximum_token_age_seconds),
            "jwks_cache_seconds": deployment.runtime.jwks.cache_seconds,
            "jwks_maximum_keys": deployment.runtime.jwks.maximum_keys,
            "jwks_timeout_seconds": deployment.transport.timeout_seconds,
            "jwks_maximum_response_bytes": (
                deployment.transport.maximum_response_bytes
            ),
            "required_claims": list(
                required_token_claims(
                    deployment.runtime.token_identifier_claim,
                    deployment.runtime.token_profile,
                )
            ),
        },
    }


def _canonical_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def load_authentication_readiness_document(
    document: bytes,
) -> ValidatedAuthenticationReadinessDocument:
    """Validate bounded JSON and resolve it without external or global inputs."""

    if not isinstance(document, bytes):
        raise TypeError("authentication readiness document must be bytes")
    if not document:
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document is empty"
        )
    if len(document) > MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES:
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document exceeds the byte limit"
        )
    try:
        decoded = document.decode("utf-8")
    except UnicodeDecodeError:
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document must be UTF-8"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
            parse_float=_parse_finite_float,
        )
    except AuthenticationReadinessDocumentError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document root must be an object"
        )
    _require_canonical_calling_client_input(parsed)
    _require_exact_azpacr_input(parsed)
    try:
        canonical_input = json.dumps(
            parsed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document contains a non-finite number"
        ) from None
    try:
        validated = AuthenticationReadinessDocument.model_validate_json(canonical_input)
    except ValidationError:
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document failed contract validation"
        ) from None
    try:
        deployment = load_authentication_deployment(
            _deployment_environment(validated.authentication)
        )
    except AuthenticationDeploymentError:
        raise AuthenticationReadinessDocumentError(
            "authentication readiness document failed deployment validation"
        ) from None

    resolved = _resolved_configuration(deployment)
    digest = hashlib.sha256(_canonical_bytes(resolved)).hexdigest()
    authentication = resolved["authentication"]
    if not isinstance(authentication, dict):  # defensive internal invariant
        raise RuntimeError("authentication readiness canonicalization failed")
    preview = AuthenticationReadinessPreview(
        configuration_sha256=digest,
        document_type=AUTHENTICATION_READINESS_DOCUMENT_TYPE,
        schema_version=AUTHENTICATION_READINESS_SCHEMA_VERSION,
        issuer=str(authentication["issuer"]),
        audience=str(authentication["audience"]),
        jwks_url=str(authentication["jwks_url"]),
        algorithms=tuple(authentication["algorithms"]),
        token_identifier_claim=str(authentication["token_identifier_claim"]),
        token_profile=str(authentication["token_profile"]),
        microsoft_entra_tenant_id=(
            str(authentication["microsoft_entra_tenant_id"])
            if authentication["microsoft_entra_tenant_id"] is not None
            else None
        ),
        microsoft_entra_api_application_id=(
            str(authentication["microsoft_entra_api_application_id"])
            if authentication["microsoft_entra_api_application_id"] is not None
            else None
        ),
        microsoft_entra_required_delegated_scope=(
            str(authentication["microsoft_entra_required_delegated_scope"])
            if authentication["microsoft_entra_required_delegated_scope"] is not None
            else None
        ),
        microsoft_entra_calling_client_application_id=(
            str(authentication["microsoft_entra_calling_client_application_id"])
            if authentication["microsoft_entra_calling_client_application_id"]
            is not None
            else None
        ),
        microsoft_entra_required_azpacr=(
            str(authentication["microsoft_entra_required_azpacr"])
            if authentication["microsoft_entra_required_azpacr"] is not None
            else None
        ),
        clock_skew_seconds=int(authentication["clock_skew_seconds"]),
        maximum_token_age_seconds=int(authentication["maximum_token_age_seconds"]),
        jwks_cache_seconds=int(authentication["jwks_cache_seconds"]),
        jwks_maximum_keys=int(authentication["jwks_maximum_keys"]),
        jwks_timeout_seconds=float(authentication["jwks_timeout_seconds"]),
        jwks_maximum_response_bytes=int(authentication["jwks_maximum_response_bytes"]),
        required_claims=tuple(authentication["required_claims"]),
        configuration_validated=True,
        jwks_reachability_checked=False,
        signed_token_checked=False,
        activation_ready=False,
    )
    return ValidatedAuthenticationReadinessDocument(
        deployment=deployment,
        preview=preview,
    )


def _validate_preview(preview: AuthenticationReadinessPreview) -> None:
    if (
        preview.document_type != AUTHENTICATION_READINESS_DOCUMENT_TYPE
        or type(preview.schema_version) is not int
        or preview.schema_version != AUTHENTICATION_READINESS_SCHEMA_VERSION
        or type(preview.token_identifier_claim) is not str
        or preview.token_identifier_claim not in {"jti", "uti"}
        or type(preview.token_profile) is not str
        or preview.token_profile not in {"provider_neutral", "microsoft_entra_v2"}
        or (
            preview.microsoft_entra_tenant_id is not None
            and type(preview.microsoft_entra_tenant_id) is not str
        )
        or (
            preview.microsoft_entra_api_application_id is not None
            and type(preview.microsoft_entra_api_application_id) is not str
        )
        or (
            preview.microsoft_entra_required_delegated_scope is not None
            and type(preview.microsoft_entra_required_delegated_scope) is not str
        )
        or (
            preview.microsoft_entra_calling_client_application_id is not None
            and type(preview.microsoft_entra_calling_client_application_id) is not str
        )
        or (
            preview.microsoft_entra_required_azpacr is not None
            and type(preview.microsoft_entra_required_azpacr) is not str
        )
        or preview.required_claims
        != required_token_claims(
            preview.token_identifier_claim,
            preview.token_profile,
        )
        or preview.configuration_validated is not True
        or preview.jwks_reachability_checked is not False
        or preview.signed_token_checked is not False
        or preview.activation_ready is not False
    ):
        raise ValueError("authentication readiness preview is not locally validated")
    try:
        configuration = AuthenticationReadinessConfiguration(
            issuer=preview.issuer,
            audience=preview.audience,
            jwks_url=preview.jwks_url,
            algorithms=preview.algorithms,
            token_identifier_claim=preview.token_identifier_claim,
            token_profile=preview.token_profile,
            microsoft_entra_tenant_id=(
                UUID(preview.microsoft_entra_tenant_id)
                if preview.microsoft_entra_tenant_id is not None
                else None
            ),
            microsoft_entra_api_application_id=(
                UUID(preview.microsoft_entra_api_application_id)
                if preview.microsoft_entra_api_application_id is not None
                else None
            ),
            microsoft_entra_required_delegated_scope=(
                preview.microsoft_entra_required_delegated_scope
            ),
            microsoft_entra_calling_client_application_id=(
                UUID(preview.microsoft_entra_calling_client_application_id)
                if preview.microsoft_entra_calling_client_application_id is not None
                else None
            ),
            microsoft_entra_required_azpacr=(
                preview.microsoft_entra_required_azpacr
            ),
            clock_skew_seconds=preview.clock_skew_seconds,
            maximum_token_age_seconds=preview.maximum_token_age_seconds,
            jwks_cache_seconds=preview.jwks_cache_seconds,
            jwks_maximum_keys=preview.jwks_maximum_keys,
            jwks_timeout_seconds=preview.jwks_timeout_seconds,
            jwks_maximum_response_bytes=preview.jwks_maximum_response_bytes,
        )
        deployment = load_authentication_deployment(
            _deployment_environment(configuration)
        )
        resolved = _resolved_configuration(deployment)
        authentication = resolved["authentication"]
        if not isinstance(authentication, dict):
            raise ValueError("invalid canonical authentication readiness state")
    except (
        AuthenticationDeploymentError,
        ValidationError,
        TypeError,
        ValueError,
    ):
        raise ValueError(
            "authentication readiness preview is not locally validated"
        ) from None
    if (
        type(preview.issuer) is not str
        or preview.issuer != authentication["issuer"]
        or type(preview.audience) is not str
        or preview.audience != authentication["audience"]
        or type(preview.jwks_url) is not str
        or preview.jwks_url != authentication["jwks_url"]
        or type(preview.algorithms) is not tuple
        or preview.algorithms != tuple(authentication["algorithms"])
        or type(preview.token_identifier_claim) is not str
        or preview.token_identifier_claim != authentication["token_identifier_claim"]
        or type(preview.token_profile) is not str
        or preview.token_profile != authentication["token_profile"]
        or preview.microsoft_entra_tenant_id
        != authentication["microsoft_entra_tenant_id"]
        or preview.microsoft_entra_api_application_id
        != authentication["microsoft_entra_api_application_id"]
        or preview.microsoft_entra_required_delegated_scope
        != authentication["microsoft_entra_required_delegated_scope"]
        or preview.microsoft_entra_calling_client_application_id
        != authentication["microsoft_entra_calling_client_application_id"]
        or preview.microsoft_entra_required_azpacr
        != authentication["microsoft_entra_required_azpacr"]
        or type(preview.clock_skew_seconds) is not int
        or preview.clock_skew_seconds != authentication["clock_skew_seconds"]
        or type(preview.maximum_token_age_seconds) is not int
        or preview.maximum_token_age_seconds
        != authentication["maximum_token_age_seconds"]
        or type(preview.jwks_cache_seconds) is not int
        or preview.jwks_cache_seconds != authentication["jwks_cache_seconds"]
        or type(preview.jwks_maximum_keys) is not int
        or preview.jwks_maximum_keys != authentication["jwks_maximum_keys"]
        or type(preview.jwks_timeout_seconds) is not float
        or preview.jwks_timeout_seconds != authentication["jwks_timeout_seconds"]
        or type(preview.jwks_maximum_response_bytes) is not int
        or preview.jwks_maximum_response_bytes
        != authentication["jwks_maximum_response_bytes"]
    ):
        raise ValueError("authentication readiness preview is not locally validated")
    expected_digest = hashlib.sha256(_canonical_bytes(resolved)).hexdigest()
    if (
        type(preview.configuration_sha256) is not str
        or preview.configuration_sha256 != expected_digest
    ):
        raise ValueError("authentication readiness preview is not locally validated")


def render_authentication_readiness_preview(
    preview: AuthenticationReadinessPreview,
) -> str:
    """Render canonical public JSON that cannot be mistaken for activation."""

    if type(preview) is not AuthenticationReadinessPreview:
        raise TypeError("authentication readiness preview is required")
    _validate_preview(preview)
    output = {
        "activation_ready": preview.activation_ready,
        "algorithms": list(preview.algorithms),
        "audience": preview.audience,
        "clock_skew_seconds": preview.clock_skew_seconds,
        "configuration_validated": preview.configuration_validated,
        "configuration_sha256": preview.configuration_sha256,
        "document_type": preview.document_type,
        "issuer": preview.issuer,
        "jwks_cache_seconds": preview.jwks_cache_seconds,
        "jwks_maximum_keys": preview.jwks_maximum_keys,
        "jwks_maximum_response_bytes": preview.jwks_maximum_response_bytes,
        "jwks_timeout_seconds": preview.jwks_timeout_seconds,
        "jwks_url": preview.jwks_url,
        "jwks_reachability_checked": preview.jwks_reachability_checked,
        "maximum_token_age_seconds": preview.maximum_token_age_seconds,
        "required_claims": list(preview.required_claims),
        "schema_version": preview.schema_version,
        "signed_token_checked": preview.signed_token_checked,
        "token_identifier_claim": preview.token_identifier_claim,
        "token_profile": preview.token_profile,
        "microsoft_entra_tenant_id": preview.microsoft_entra_tenant_id,
        "microsoft_entra_api_application_id": (
            preview.microsoft_entra_api_application_id
        ),
        "microsoft_entra_required_delegated_scope": (
            preview.microsoft_entra_required_delegated_scope
        ),
        "microsoft_entra_calling_client_application_id": (
            preview.microsoft_entra_calling_client_application_id
        ),
        "microsoft_entra_required_azpacr": (
            preview.microsoft_entra_required_azpacr
        ),
        "validation_scope": AUTHENTICATION_READINESS_VALIDATION_SCOPE,
    }
    return json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "AUTHENTICATION_READINESS_DOCUMENT_TYPE",
    "AUTHENTICATION_READINESS_SCHEMA_VERSION",
    "AUTHENTICATION_READINESS_VALIDATION_SCOPE",
    "MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES",
    "AuthenticationReadinessConfiguration",
    "AuthenticationReadinessDocument",
    "AuthenticationReadinessDocumentError",
    "AuthenticationReadinessPreview",
    "ValidatedAuthenticationReadinessDocument",
    "load_authentication_readiness_document",
    "render_authentication_readiness_preview",
]
