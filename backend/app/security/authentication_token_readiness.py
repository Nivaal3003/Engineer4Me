"""Digest-confirmed local signed-token readiness without application activation."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from app.security.authentication_jwks_readiness import (
    SHA256_PATTERN,
    authentication_deployment_from_preview,
    canonical_jwks_document_sha256,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessDocumentError,
)
from app.security.authentication_readiness_preview import (
    AuthenticationReadinessPreviewFileError,
    read_authentication_readiness_preview,
)
from app.security.jwks_http_loader import BoundedHTTPSJWKSLoader, JWKSHTTPError, OpenURL
from app.security.jwks_resolver import ControlledJWKSResolver, JWKSResolutionError
from app.security.token_verifier import (
    DEFAULT_AUTHENTICATION_TOKEN_PROFILE,
    DEFAULT_TOKEN_IDENTIFIER_CLAIM,
    MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR,
    OIDCTokenVerifier,
    OIDCTokenVerifierConfig,
    TokenVerificationError,
    required_token_claims,
)


AUTHENTICATION_TOKEN_READINESS_SCOPE = "local_signed_token_only"
MAX_AUTHENTICATION_TOKEN_BYTES = 16_384
_COMPACT_JWT_PATTERN = re.compile(
    rb"\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z"
)


class AuthenticationTokenReadinessApprovalError(ValueError):
    """Sanitized rejection of absent, malformed, or stale approval evidence."""


class AuthenticationTokenFileError(ValueError):
    """Sanitized rejection of an unsafe or malformed local token file."""


class AuthenticationTokenReadinessError(RuntimeError):
    """Sanitized failure of the local signed-token readiness proof."""


@dataclass(frozen=True, slots=True)
class AuthenticationTokenReadinessReceipt:
    """Privacy-minimised evidence from one exact signed-token proof."""

    configuration_sha256: str
    jwks_document_sha256: str
    checked_at: datetime
    token_algorithm: str
    issuer_sha256: str
    audience_sha256: str
    subject_sha256: str
    required_claims: tuple[str, ...]
    token_identifier_claim: str = DEFAULT_TOKEN_IDENTIFIER_CLAIM
    token_profile: str = DEFAULT_AUTHENTICATION_TOKEN_PROFILE
    microsoft_entra_tenant_id_sha256: str | None = None
    microsoft_entra_api_application_id_sha256: str | None = None
    token_version: str | None = None
    microsoft_entra_delegated_scope_sha256: str | None = None
    microsoft_entra_delegated_scope_verified: bool = False
    microsoft_entra_roles_claim_absent: bool = False
    microsoft_entra_app_only_token_rejection_enforced: bool = False
    microsoft_entra_calling_client_application_id_sha256: str | None = None
    microsoft_entra_azp_verified: bool = False
    microsoft_entra_azpacr_sha256: str | None = None
    microsoft_entra_azpacr_public_client_verified: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.configuration_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.configuration_sha256) is None
            or type(self.jwks_document_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.jwks_document_sha256) is None
            or not isinstance(self.checked_at, datetime)
            or self.checked_at.tzinfo is None
            or self.checked_at.utcoffset() is None
            or type(self.token_algorithm) is not str
            or self.token_algorithm
            not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
            or type(self.issuer_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.issuer_sha256) is None
            or type(self.audience_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.audience_sha256) is None
            or type(self.subject_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.subject_sha256) is None
            or type(self.required_claims) is not tuple
            or type(self.token_identifier_claim) is not str
            or self.token_identifier_claim not in {"jti", "uti"}
            or type(self.token_profile) is not str
            or self.token_profile
            not in {"provider_neutral", "microsoft_entra_v2"}
            or self.required_claims
            != required_token_claims(
                self.token_identifier_claim,
                self.token_profile,
            )
            or (
                self.token_profile == "microsoft_entra_v2"
                and (
                    type(self.microsoft_entra_tenant_id_sha256) is not str
                    or SHA256_PATTERN.fullmatch(
                        self.microsoft_entra_tenant_id_sha256
                    )
                    is None
                    or self.token_version != "2.0"
                    or type(self.microsoft_entra_api_application_id_sha256) is not str
                    or SHA256_PATTERN.fullmatch(
                        self.microsoft_entra_api_application_id_sha256
                    )
                    is None
                    or type(self.microsoft_entra_delegated_scope_sha256) is not str
                    or SHA256_PATTERN.fullmatch(
                        self.microsoft_entra_delegated_scope_sha256
                    )
                    is None
                    or self.microsoft_entra_delegated_scope_sha256
                    != authentication_identity_sha256(
                        "microsoft_entra_delegated_scope",
                        "access_as_user",
                    )
                    or self.microsoft_entra_delegated_scope_verified is not True
                    or self.microsoft_entra_roles_claim_absent is not True
                    or self.microsoft_entra_app_only_token_rejection_enforced
                    is not True
                    or type(
                        self.microsoft_entra_calling_client_application_id_sha256
                    )
                    is not str
                    or SHA256_PATTERN.fullmatch(
                        self.microsoft_entra_calling_client_application_id_sha256
                    )
                    is None
                    or self.microsoft_entra_azp_verified is not True
                    or type(self.microsoft_entra_azpacr_sha256) is not str
                    or SHA256_PATTERN.fullmatch(
                        self.microsoft_entra_azpacr_sha256
                    )
                    is None
                    or self.microsoft_entra_azpacr_sha256
                    != authentication_identity_sha256(
                        "microsoft_entra_azpacr",
                        MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR,
                    )
                    or self.microsoft_entra_azpacr_public_client_verified is not True
                )
            )
            or (
                self.token_profile == "provider_neutral"
                and (
                    self.microsoft_entra_tenant_id_sha256 is not None
                    or self.microsoft_entra_api_application_id_sha256 is not None
                    or self.token_version is not None
                    or self.microsoft_entra_delegated_scope_sha256 is not None
                    or self.microsoft_entra_delegated_scope_verified is not False
                    or self.microsoft_entra_roles_claim_absent is not False
                    or self.microsoft_entra_app_only_token_rejection_enforced
                    is not False
                    or self.microsoft_entra_calling_client_application_id_sha256
                    is not None
                    or self.microsoft_entra_azp_verified is not False
                    or self.microsoft_entra_azpacr_sha256 is not None
                    or self.microsoft_entra_azpacr_public_client_verified is not False
                )
            )
        ):
            raise ValueError("authentication token readiness receipt is invalid")


def _approved_digest(value: str, *, label: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise AuthenticationTokenReadinessApprovalError(
            f"approved authentication {label} digest is invalid"
        )
    return value


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
    )


def _unchanged_file(left: os.stat_result, right: os.stat_result) -> bool:
    unchanged = (
        _same_file(left, right)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )
    if os.name == "nt":
        return unchanged
    return unchanged and left.st_ctime_ns == right.st_ctime_ns


def _read_local_compact_token(path: str | os.PathLike[str]) -> str:
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("authentication token path must be path-like")
    try:
        initial = os.lstat(path)
    except (OSError, ValueError):
        raise AuthenticationTokenFileError(
            "authentication token file could not be opened safely"
        ) from None
    if not stat.S_ISREG(initial.st_mode):
        raise AuthenticationTokenFileError(
            "authentication token input must be a regular non-symlink file"
        )
    if initial.st_size == 0:
        raise AuthenticationTokenFileError("authentication token file is empty")
    if initial.st_size > MAX_AUTHENTICATION_TOKEN_BYTES:
        raise AuthenticationTokenFileError(
            "authentication token file exceeds the byte limit"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except (OSError, ValueError):
        if "descriptor" in locals():
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise AuthenticationTokenFileError(
            "authentication token file could not be opened safely"
        ) from None
    if not stat.S_ISREG(opened.st_mode) or not _same_file(initial, opened):
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise AuthenticationTokenFileError(
            "authentication token file changed before it was opened"
        )
    try:
        chunks: list[bytes] = []
        remaining = MAX_AUTHENTICATION_TOKEN_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(8_192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        final = os.fstat(descriptor)
    except OSError:
        raise AuthenticationTokenFileError(
            "authentication token file could not be read safely"
        ) from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise AuthenticationTokenFileError(
                "authentication token file could not be closed safely"
            ) from None
    if len(document) > MAX_AUTHENTICATION_TOKEN_BYTES:
        raise AuthenticationTokenFileError(
            "authentication token file exceeds the byte limit"
        )
    if not document:
        raise AuthenticationTokenFileError("authentication token file is empty")
    if not _unchanged_file(initial, final):
        raise AuthenticationTokenFileError(
            "authentication token file changed while it was read"
        )
    if _COMPACT_JWT_PATTERN.fullmatch(document) is None:
        raise AuthenticationTokenFileError(
            "authentication token file is not one exact compact JWT"
        )
    try:
        return document.decode("ascii")
    except UnicodeDecodeError:
        raise AuthenticationTokenFileError(
            "authentication token file is not one exact compact JWT"
        ) from None


def authentication_identity_sha256(*values: str) -> str:
    """Build a deterministic length-delimited pseudonym for reviewed identity text."""

    if not values or any(type(value) is not str or not value for value in values):
        raise TypeError("authentication identity values must be non-empty strings")
    material = "".join(f"{len(value)}:{value}" for value in values).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def probe_authentication_token_readiness(
    *,
    document_path: str | os.PathLike[str],
    token_path: str | os.PathLike[str],
    approved_configuration_sha256: str,
    approved_jwks_document_sha256: str,
    open_url: OpenURL | None = None,
) -> AuthenticationTokenReadinessReceipt:
    """Verify one local token against one exact approved configuration and JWKS."""

    configuration_digest = _approved_digest(
        approved_configuration_sha256,
        label="configuration",
    )
    jwks_digest = _approved_digest(
        approved_jwks_document_sha256,
        label="JWKS document",
    )
    preview = read_authentication_readiness_preview(document_path)
    if not hmac.compare_digest(preview.configuration_sha256, configuration_digest):
        raise AuthenticationTokenReadinessApprovalError(
            "authentication configuration does not match the approved digest"
        )
    deployment = authentication_deployment_from_preview(preview)
    loader = BoundedHTTPSJWKSLoader(policy=deployment.transport, open_url=open_url)
    try:
        response = loader(deployment.runtime.jwks.source_url)
    except JWKSHTTPError:
        raise AuthenticationTokenReadinessError(
            "authentication token readiness JWKS request failed"
        ) from None
    actual_jwks_digest = canonical_jwks_document_sha256(response)
    if not hmac.compare_digest(actual_jwks_digest, jwks_digest):
        raise AuthenticationTokenReadinessApprovalError(
            "authentication JWKS does not match the approved digest"
        )
    token = _read_local_compact_token(token_path)

    def trusted_loader(source_url: str):
        if source_url != response.source_url:
            raise JWKSResolutionError("JWKS source changed during token proof")
        return response

    resolver = ControlledJWKSResolver(
        config=deployment.runtime.jwks,
        loader=trusted_loader,
    )
    verifier = OIDCTokenVerifier(
        config=OIDCTokenVerifierConfig(
            issuer=deployment.runtime.issuer,
            audience=deployment.runtime.audience,
            algorithms=deployment.runtime.algorithms,
            clock_skew_seconds=deployment.runtime.clock_skew_seconds,
            maximum_token_age_seconds=deployment.runtime.maximum_token_age_seconds,
            token_identifier_claim=deployment.runtime.token_identifier_claim,
            token_profile=deployment.runtime.token_profile,
            microsoft_entra_tenant_id=deployment.runtime.microsoft_entra_tenant_id,
            microsoft_entra_api_application_id=(
                deployment.runtime.microsoft_entra_api_application_id
            ),
            microsoft_entra_required_delegated_scope=(
                deployment.runtime.microsoft_entra_required_delegated_scope
            ),
            microsoft_entra_calling_client_application_id=(
                deployment.runtime.microsoft_entra_calling_client_application_id
            ),
            microsoft_entra_required_azpacr=(
                deployment.runtime.microsoft_entra_required_azpacr
            ),
        ),
        key_resolver=resolver,
    )
    try:
        claims = verifier.verify(token)
    except (
        TokenVerificationError,
        JWKSResolutionError,
        KeyError,
        TypeError,
        ValueError,
    ):
        raise AuthenticationTokenReadinessError(
            "authentication signed token failed readiness validation"
        ) from None
    return AuthenticationTokenReadinessReceipt(
        configuration_sha256=configuration_digest,
        jwks_document_sha256=actual_jwks_digest,
        checked_at=datetime.now(UTC),
        token_algorithm=claims.algorithm,
        issuer_sha256=authentication_identity_sha256(claims.issuer),
        audience_sha256=authentication_identity_sha256(*claims.audiences),
        subject_sha256=authentication_identity_sha256(claims.issuer, claims.subject),
        required_claims=required_token_claims(
            deployment.runtime.token_identifier_claim,
            deployment.runtime.token_profile,
        ),
        token_identifier_claim=deployment.runtime.token_identifier_claim,
        token_profile=deployment.runtime.token_profile,
        microsoft_entra_tenant_id_sha256=(
            authentication_identity_sha256(str(claims.microsoft_entra_tenant_id))
            if claims.microsoft_entra_tenant_id is not None
            else None
        ),
        microsoft_entra_api_application_id_sha256=(
            authentication_identity_sha256(
                str(claims.microsoft_entra_api_application_id)
            )
            if claims.microsoft_entra_api_application_id is not None
            else None
        ),
        token_version=claims.token_version,
        microsoft_entra_delegated_scope_sha256=(
            authentication_identity_sha256(
                "microsoft_entra_delegated_scope",
                claims.microsoft_entra_delegated_scope,
            )
            if claims.microsoft_entra_delegated_scope is not None
            else None
        ),
        microsoft_entra_delegated_scope_verified=(
            claims.microsoft_entra_delegated_scope is not None
        ),
        microsoft_entra_roles_claim_absent=(
            claims.microsoft_entra_delegated_scope is not None
        ),
        microsoft_entra_app_only_token_rejection_enforced=(
            claims.microsoft_entra_delegated_scope is not None
        ),
        microsoft_entra_calling_client_application_id_sha256=(
            authentication_identity_sha256(
                "microsoft_entra_calling_client_application_id",
                str(claims.microsoft_entra_calling_client_application_id),
            )
            if claims.microsoft_entra_calling_client_application_id is not None
            else None
        ),
        microsoft_entra_azp_verified=(
            claims.microsoft_entra_calling_client_application_id is not None
        ),
        microsoft_entra_azpacr_sha256=(
            authentication_identity_sha256(
                "microsoft_entra_azpacr",
                claims.microsoft_entra_azpacr,
            )
            if claims.microsoft_entra_azpacr is not None
            else None
        ),
        microsoft_entra_azpacr_public_client_verified=(
            claims.microsoft_entra_azpacr
            == MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR
        ),
    )


def render_authentication_token_readiness_receipt(
    receipt: AuthenticationTokenReadinessReceipt,
) -> str:
    """Render canonical evidence without token, identity, key, or source material."""

    if type(receipt) is not AuthenticationTokenReadinessReceipt:
        raise TypeError("authentication token readiness receipt is required")
    output = {
        "activation_ready": False,
        "audience_checked": True,
        "audience_sha256": receipt.audience_sha256,
        "bootstrap_ready": False,
        "checked_at": receipt.checked_at.isoformat(),
        "configuration_digest_approved": True,
        "configuration_sha256": receipt.configuration_sha256,
        "discovery_consistency_checked": False,
        "issuer_checked": True,
        "issuer_sha256": receipt.issuer_sha256,
        "jwks_document_digest_approved": True,
        "jwks_document_sha256": receipt.jwks_document_sha256,
        "provider_ownership_checked": False,
        "required_claims": list(receipt.required_claims),
        "signature_checked": True,
        "signed_token_checked": True,
        "subject_sha256": receipt.subject_sha256,
        "token_algorithm": receipt.token_algorithm,
        "token_identifier_claim": receipt.token_identifier_claim,
        "token_profile": receipt.token_profile,
        "microsoft_entra_tenant_id_sha256": (
            receipt.microsoft_entra_tenant_id_sha256
        ),
        "microsoft_entra_api_application_id_sha256": (
            receipt.microsoft_entra_api_application_id_sha256
        ),
        "microsoft_entra_delegated_scope_sha256": (
            receipt.microsoft_entra_delegated_scope_sha256
        ),
        "microsoft_entra_delegated_scope_verified": (
            receipt.microsoft_entra_delegated_scope_verified
        ),
        "microsoft_entra_roles_claim_absent": (
            receipt.microsoft_entra_roles_claim_absent
        ),
        "microsoft_entra_app_only_token_rejection_enforced": (
            receipt.microsoft_entra_app_only_token_rejection_enforced
        ),
        "microsoft_entra_calling_client_application_id_sha256": (
            receipt.microsoft_entra_calling_client_application_id_sha256
        ),
        "microsoft_entra_azp_verified": receipt.microsoft_entra_azp_verified,
        "microsoft_entra_azpacr_sha256": receipt.microsoft_entra_azpacr_sha256,
        "microsoft_entra_azpacr_public_client_verified": (
            receipt.microsoft_entra_azpacr_public_client_verified
        ),
        "token_version": receipt.token_version,
        "validation_scope": AUTHENTICATION_TOKEN_READINESS_SCOPE,
    }
    return json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one explicit token proof or exit with a sanitized error."""

    parser = argparse.ArgumentParser(
        description="Verify one local Engineer4Me authentication readiness token."
    )
    parser.add_argument("document", help="local public-metadata readiness document")
    parser.add_argument("token", help="local file containing one compact JWT")
    parser.add_argument(
        "--approve-configuration-sha256",
        required=True,
        help="exact lowercase configuration_sha256 from the local preview",
    )
    parser.add_argument(
        "--approve-jwks-sha256",
        required=True,
        help="exact lowercase jwks_document_sha256 from the JWKS readiness receipt",
    )
    options = parser.parse_args(arguments)
    try:
        receipt = probe_authentication_token_readiness(
            document_path=options.document,
            token_path=options.token,
            approved_configuration_sha256=options.approve_configuration_sha256,
            approved_jwks_document_sha256=options.approve_jwks_sha256,
        )
        rendered = render_authentication_token_readiness_receipt(receipt)
    except (
        AuthenticationReadinessDocumentError,
        AuthenticationReadinessPreviewFileError,
        AuthenticationTokenFileError,
        AuthenticationTokenReadinessApprovalError,
        AuthenticationTokenReadinessError,
    ):
        parser.exit(2, "authentication token readiness probe failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AUTHENTICATION_TOKEN_READINESS_SCOPE",
    "MAX_AUTHENTICATION_TOKEN_BYTES",
    "AuthenticationTokenFileError",
    "AuthenticationTokenReadinessApprovalError",
    "AuthenticationTokenReadinessError",
    "AuthenticationTokenReadinessReceipt",
    "authentication_identity_sha256",
    "main",
    "probe_authentication_token_readiness",
    "render_authentication_token_readiness_receipt",
]
