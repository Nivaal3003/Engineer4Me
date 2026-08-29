"""Digest-confirmed bounded JWKS readiness probe without application activation."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from app.security.authentication_deployment import (
    AuthenticationDeploymentConfiguration,
    AuthenticationDeploymentError,
    load_authentication_deployment,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessDocumentError,
    AuthenticationReadinessPreview,
)
from app.security.authentication_readiness_preview import (
    AuthenticationReadinessPreviewFileError,
    read_authentication_readiness_preview,
)
from app.security.jwks_http_loader import (
    BoundedHTTPSJWKSLoader,
    JWKSHTTPError,
    OpenURL,
)
from app.security.jwks_resolver import (
    ControlledJWKSResolver,
    JWKSResolutionError,
    TrustedJWKSResponse,
)
from app.security.token_verifier import ASYMMETRIC_ALGORITHMS


AUTHENTICATION_JWKS_READINESS_SCOPE = "live_jwks_only"
SHA256_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")


class AuthenticationJWKSReadinessApprovalError(ValueError):
    """Sanitized rejection of an absent, malformed, or stale approval digest."""


class AuthenticationJWKSReadinessError(RuntimeError):
    """Sanitized failure of the bounded JWKS readiness proof."""


@dataclass(frozen=True, slots=True)
class AuthenticationJWKSReadinessReceipt:
    """Non-secret evidence from one exact approved JWKS readiness request."""

    configuration_sha256: str
    jwks_source_sha256: str
    jwks_document_sha256: str
    checked_at: datetime
    configured_algorithms: tuple[str, ...]
    usable_algorithms: tuple[str, ...]
    usable_signing_keys: int

    def __post_init__(self) -> None:
        if (
            type(self.configuration_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.configuration_sha256) is None
            or type(self.jwks_source_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.jwks_source_sha256) is None
            or type(self.jwks_document_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.jwks_document_sha256) is None
            or not isinstance(self.checked_at, datetime)
            or self.checked_at.tzinfo is None
            or self.checked_at.utcoffset() is None
            or type(self.configured_algorithms) is not tuple
            or not self.configured_algorithms
            or self.configured_algorithms
            != tuple(sorted(set(self.configured_algorithms)))
            or any(
                algorithm not in ASYMMETRIC_ALGORITHMS
                for algorithm in self.configured_algorithms
            )
            or type(self.usable_algorithms) is not tuple
            or not self.usable_algorithms
            or self.usable_algorithms != tuple(sorted(set(self.usable_algorithms)))
            or not set(self.usable_algorithms).issubset(self.configured_algorithms)
            or type(self.usable_signing_keys) is not int
            or self.usable_signing_keys < len(self.usable_algorithms)
        ):
            raise ValueError("authentication JWKS readiness receipt is invalid")


def authentication_deployment_from_preview(
    preview: AuthenticationReadinessPreview,
) -> AuthenticationDeploymentConfiguration:
    try:
        environment = {
                "E4M_AUTH_ISSUER": preview.issuer,
                "E4M_AUTH_AUDIENCE": preview.audience,
                "E4M_AUTH_JWKS_URL": preview.jwks_url,
                "E4M_AUTH_ALGORITHMS": ",".join(preview.algorithms),
                "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": (preview.token_identifier_claim),
                "E4M_AUTH_TOKEN_PROFILE": preview.token_profile,
                "E4M_AUTH_CLOCK_SKEW_SECONDS": str(preview.clock_skew_seconds),
                "E4M_AUTH_MAXIMUM_TOKEN_AGE_SECONDS": str(
                    preview.maximum_token_age_seconds
                ),
                "E4M_AUTH_JWKS_CACHE_SECONDS": str(preview.jwks_cache_seconds),
                "E4M_AUTH_JWKS_MAXIMUM_KEYS": str(preview.jwks_maximum_keys),
                "E4M_AUTH_JWKS_TIMEOUT_SECONDS": str(preview.jwks_timeout_seconds),
                "E4M_AUTH_JWKS_MAXIMUM_RESPONSE_BYTES": str(
                    preview.jwks_maximum_response_bytes
                ),
            }
        if preview.microsoft_entra_tenant_id is not None:
            environment["E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID"] = (
                preview.microsoft_entra_tenant_id
            )
        if preview.microsoft_entra_api_application_id is not None:
            environment["E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID"] = (
                preview.microsoft_entra_api_application_id
            )
        if preview.microsoft_entra_required_delegated_scope is not None:
            environment[
                "E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE"
            ] = preview.microsoft_entra_required_delegated_scope
        if preview.microsoft_entra_calling_client_application_id is not None:
            environment[
                "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID"
            ] = preview.microsoft_entra_calling_client_application_id
        if preview.microsoft_entra_required_azpacr is not None:
            environment["E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR"] = (
                preview.microsoft_entra_required_azpacr
            )
        return load_authentication_deployment(environment)
    except AuthenticationDeploymentError:
        raise AuthenticationJWKSReadinessError(
            "authentication JWKS readiness configuration is invalid"
        ) from None


def canonical_jwks_document_sha256(response: TrustedJWKSResponse) -> str:
    try:
        canonical = json.dumps(
            response.document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise AuthenticationJWKSReadinessError(
            "authentication JWKS readiness response is invalid"
        ) from None
    return hashlib.sha256(canonical).hexdigest()


def _usable_signing_keys(
    *,
    response: TrustedJWKSResponse,
    deployment: AuthenticationDeploymentConfiguration,
) -> tuple[tuple[str, ...], int]:
    def trusted_loader(source_url: str) -> TrustedJWKSResponse:
        if source_url != response.source_url:
            raise JWKSResolutionError("JWKS source changed during readiness proof")
        return response

    resolver = ControlledJWKSResolver(
        config=deployment.runtime.jwks,
        loader=trusted_loader,
    )
    try:
        resolver.resolve(
            key_id="__engineer4me_jwks_readiness_validation__",
            algorithm="RS256",
        )
        raw_keys = response.document.get("keys")
        if not isinstance(raw_keys, list):
            raise JWKSResolutionError("JWKS keys collection is missing")
        usable_algorithms: set[str] = set()
        usable_count = 0
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                raise JWKSResolutionError("JWKS key must be an object")
            algorithm = raw_key.get("alg")
            key_id = raw_key.get("kid")
            if (
                algorithm in deployment.runtime.algorithms
                and isinstance(key_id, str)
                and resolver.resolve(key_id=key_id, algorithm=algorithm) is not None
            ):
                usable_algorithms.add(algorithm)
                usable_count += 1
    except (JWKSResolutionError, KeyError, TypeError, ValueError):
        raise AuthenticationJWKSReadinessError(
            "authentication JWKS signing keys failed validation"
        ) from None
    if not usable_algorithms or usable_count < 1:
        raise AuthenticationJWKSReadinessError(
            "authentication JWKS has no usable configured signing key"
        )
    return tuple(sorted(usable_algorithms)), usable_count


def probe_authentication_jwks_readiness(
    *,
    document_path: str,
    approved_configuration_sha256: str,
    open_url: OpenURL | None = None,
) -> AuthenticationJWKSReadinessReceipt:
    """Fetch and validate one exact approved JWKS without checking a token."""

    if (
        not isinstance(approved_configuration_sha256, str)
        or SHA256_PATTERN.fullmatch(approved_configuration_sha256) is None
    ):
        raise AuthenticationJWKSReadinessApprovalError(
            "approved authentication configuration digest is invalid"
        )
    preview = read_authentication_readiness_preview(document_path)
    if not hmac.compare_digest(
        preview.configuration_sha256,
        approved_configuration_sha256,
    ):
        raise AuthenticationJWKSReadinessApprovalError(
            "authentication configuration does not match the approved digest"
        )
    deployment = authentication_deployment_from_preview(preview)
    loader = BoundedHTTPSJWKSLoader(
        policy=deployment.transport,
        open_url=open_url,
    )
    try:
        response = loader(deployment.runtime.jwks.source_url)
    except JWKSHTTPError:
        raise AuthenticationJWKSReadinessError(
            "authentication JWKS readiness request failed"
        ) from None
    usable_algorithms, usable_count = _usable_signing_keys(
        response=response,
        deployment=deployment,
    )
    return AuthenticationJWKSReadinessReceipt(
        configuration_sha256=preview.configuration_sha256,
        jwks_source_sha256=hashlib.sha256(
            deployment.runtime.jwks.source_url.encode("utf-8")
        ).hexdigest(),
        jwks_document_sha256=canonical_jwks_document_sha256(response),
        checked_at=response.fetched_at,
        configured_algorithms=tuple(sorted(deployment.runtime.algorithms)),
        usable_algorithms=usable_algorithms,
        usable_signing_keys=usable_count,
    )


def render_authentication_jwks_readiness_receipt(
    receipt: AuthenticationJWKSReadinessReceipt,
) -> str:
    """Render canonical evidence without URLs, key IDs, or JWK material."""

    if type(receipt) is not AuthenticationJWKSReadinessReceipt:
        raise TypeError("authentication JWKS readiness receipt is required")
    output = {
        "activation_ready": False,
        "checked_at": receipt.checked_at.isoformat(),
        "configuration_digest_approved": True,
        "configuration_sha256": receipt.configuration_sha256,
        "configuration_validated": True,
        "configured_algorithms": list(receipt.configured_algorithms),
        "discovery_consistency_checked": False,
        "jwks_document_sha256": receipt.jwks_document_sha256,
        "jwks_reachability_checked": True,
        "jwks_source_sha256": receipt.jwks_source_sha256,
        "provider_ownership_checked": False,
        "signed_token_checked": False,
        "signing_keys_checked": True,
        "usable_algorithms": list(receipt.usable_algorithms),
        "usable_signing_keys": receipt.usable_signing_keys,
        "validation_scope": AUTHENTICATION_JWKS_READINESS_SCOPE,
    }
    return json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one explicit digest-confirmed JWKS probe or fail sanitarily."""

    parser = argparse.ArgumentParser(
        description=("Run a bounded Engineer4Me authentication JWKS readiness probe.")
    )
    parser.add_argument(
        "document",
        help="explicit local path to the reviewed public-metadata JSON document",
    )
    parser.add_argument(
        "--approve-sha256",
        required=True,
        help="exact lowercase configuration_sha256 from the local preview",
    )
    options = parser.parse_args(arguments)
    try:
        receipt = probe_authentication_jwks_readiness(
            document_path=options.document,
            approved_configuration_sha256=options.approve_sha256,
        )
        rendered = render_authentication_jwks_readiness_receipt(receipt)
    except (
        AuthenticationJWKSReadinessApprovalError,
        AuthenticationJWKSReadinessError,
        AuthenticationReadinessDocumentError,
        AuthenticationReadinessPreviewFileError,
    ):
        parser.exit(2, "authentication JWKS readiness probe failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AUTHENTICATION_JWKS_READINESS_SCOPE",
    "AuthenticationJWKSReadinessApprovalError",
    "AuthenticationJWKSReadinessError",
    "AuthenticationJWKSReadinessReceipt",
    "authentication_deployment_from_preview",
    "canonical_jwks_document_sha256",
    "main",
    "probe_authentication_jwks_readiness",
    "render_authentication_jwks_readiness_receipt",
]
