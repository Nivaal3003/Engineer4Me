"""Offline binding of signed-token evidence to a reviewed bootstrap document."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from uuid import UUID

from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_token_readiness import (
    AuthenticationTokenReadinessReceipt,
    authentication_identity_sha256,
)
from app.security.bootstrap_document import (
    SecurityBootstrapDocumentError,
    load_security_bootstrap_document,
)
from app.security.entitlements import ControlledFeature, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole


AUTHENTICATION_BOOTSTRAP_READINESS_SCOPE = "provider_bound_bootstrap_document_only"


class AuthenticationBootstrapReadinessError(ValueError):
    """Sanitized rejection of unbound or malformed bootstrap readiness input."""


@dataclass(frozen=True, slots=True)
class AuthenticationBootstrapReadinessReceipt:
    """Privacy-minimised evidence that bootstrap identity matches token evidence."""

    configuration_sha256: str
    jwks_document_sha256: str
    bootstrap_document_sha256: str
    issuer_sha256: str
    subject_sha256: str
    bootstrap_id: UUID
    request_id: UUID
    user_id: UUID
    organisation_id: UUID
    membership_id: UUID
    entitlement_snapshot_id: UUID
    initial_role: OrganisationRole
    entitlement_plan: str
    subscription_status: SubscriptionStatus
    features: tuple[ControlledFeature, ...]
    quota_kinds: tuple[QuotaKind, ...]

    def __post_init__(self) -> None:
        hashes = (
            self.configuration_sha256,
            self.jwks_document_sha256,
            self.bootstrap_document_sha256,
            self.issuer_sha256,
            self.subject_sha256,
        )
        identifiers = (
            self.bootstrap_id,
            self.request_id,
            self.user_id,
            self.organisation_id,
            self.membership_id,
            self.entitlement_snapshot_id,
        )
        if (
            any(
                type(value) is not str or SHA256_PATTERN.fullmatch(value) is None
                for value in hashes
            )
            or any(type(value) is not UUID for value in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or self.initial_role is not OrganisationRole.OWNER
            or type(self.entitlement_plan) is not str
            or not self.entitlement_plan
            or self.subscription_status
            not in {SubscriptionStatus.TRIAL, SubscriptionStatus.ACTIVE}
            or type(self.features) is not tuple
            or len(self.features) != len(set(self.features))
            or any(type(value) is not ControlledFeature for value in self.features)
            or type(self.quota_kinds) is not tuple
            or len(self.quota_kinds) != len(set(self.quota_kinds))
            or any(type(value) is not QuotaKind for value in self.quota_kinds)
        ):
            raise ValueError("authentication bootstrap readiness receipt is invalid")


def bind_authentication_bootstrap_readiness(
    *,
    token_readiness: AuthenticationTokenReadinessReceipt,
    bootstrap_document: bytes,
) -> AuthenticationBootstrapReadinessReceipt:
    """Bind exact bootstrap issuer and subject to prior signed-token evidence."""

    if type(token_readiness) is not AuthenticationTokenReadinessReceipt:
        raise TypeError("authentication token readiness receipt is required")
    try:
        validated = load_security_bootstrap_document(bootstrap_document)
    except SecurityBootstrapDocumentError:
        raise AuthenticationBootstrapReadinessError(
            "authentication bootstrap readiness document is invalid"
        ) from None
    command = validated.command
    issuer_sha256 = authentication_identity_sha256(command.issuer)
    subject_sha256 = authentication_identity_sha256(command.issuer, command.subject)
    if not hmac.compare_digest(issuer_sha256, token_readiness.issuer_sha256):
        raise AuthenticationBootstrapReadinessError(
            "bootstrap issuer does not match signed-token evidence"
        )
    if not hmac.compare_digest(subject_sha256, token_readiness.subject_sha256):
        raise AuthenticationBootstrapReadinessError(
            "bootstrap subject does not match signed-token evidence"
        )
    preview = validated.preview
    return AuthenticationBootstrapReadinessReceipt(
        configuration_sha256=token_readiness.configuration_sha256,
        jwks_document_sha256=token_readiness.jwks_document_sha256,
        bootstrap_document_sha256=preview.document_sha256,
        issuer_sha256=issuer_sha256,
        subject_sha256=subject_sha256,
        bootstrap_id=preview.bootstrap_id,
        request_id=preview.request_id,
        user_id=preview.user_id,
        organisation_id=preview.organisation_id,
        membership_id=preview.membership_id,
        entitlement_snapshot_id=preview.entitlement_snapshot_id,
        initial_role=preview.initial_role,
        entitlement_plan=preview.entitlement_plan,
        subscription_status=preview.subscription_status,
        features=preview.features,
        quota_kinds=preview.quota_kinds,
    )


def render_authentication_bootstrap_readiness_receipt(
    receipt: AuthenticationBootstrapReadinessReceipt,
) -> str:
    """Render canonical binding evidence without raw identity or personal data."""

    if type(receipt) is not AuthenticationBootstrapReadinessReceipt:
        raise TypeError("authentication bootstrap readiness receipt is required")
    output = {
        "activation_ready": False,
        "bootstrap_document_sha256": receipt.bootstrap_document_sha256,
        "bootstrap_execution_ready": False,
        "bootstrap_id": str(receipt.bootstrap_id),
        "configuration_sha256": receipt.configuration_sha256,
        "entitlement_plan": receipt.entitlement_plan,
        "entitlement_snapshot_id": str(receipt.entitlement_snapshot_id),
        "features": [value.value for value in receipt.features],
        "identity_binding_checked": True,
        "initial_role": receipt.initial_role.value,
        "issuer_sha256": receipt.issuer_sha256,
        "jwks_document_sha256": receipt.jwks_document_sha256,
        "membership_id": str(receipt.membership_id),
        "operational_empty_domain_rechecked": False,
        "organisation_id": str(receipt.organisation_id),
        "provider_ownership_checked": False,
        "quota_kinds": [value.value for value in receipt.quota_kinds],
        "request_id": str(receipt.request_id),
        "signed_token_evidence_bound": True,
        "subject_sha256": receipt.subject_sha256,
        "subscription_status": receipt.subscription_status.value,
        "user_id": str(receipt.user_id),
        "validation_scope": AUTHENTICATION_BOOTSTRAP_READINESS_SCOPE,
    }
    return json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "AUTHENTICATION_BOOTSTRAP_READINESS_SCOPE",
    "AuthenticationBootstrapReadinessError",
    "AuthenticationBootstrapReadinessReceipt",
    "bind_authentication_bootstrap_readiness",
    "render_authentication_bootstrap_readiness_receipt",
]
