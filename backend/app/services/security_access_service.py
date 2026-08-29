"""Trusted Phase 8 identity, RBAC, and entitlement orchestration."""

from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, model_validator

from app.repositories.security_repository import SecurityRepository
from app.security.authorization import AuthorizationDecision, AuthorizationRequest, ResourceKind, authorize
from app.security.entitlements import ControlledFeature, EntitlementDecision, EntitlementRequest, QuotaKind, evaluate_entitlement
from app.security.identity_models import AuthenticatedPrincipal, IdentityStatus, IdentityText, Permission, SecurityModel, SubjectText


class AccessOutcomeReason(StrEnum):
    ALLOWED = "allowed"
    IDENTITY_NOT_FOUND = "identity_not_found"
    IDENTITY_NOT_ACTIVE = "identity_not_active"
    AUTHORIZATION_DENIED = "authorization_denied"
    ENTITLEMENT_NOT_FOUND = "entitlement_not_found"
    ENTITLEMENT_DENIED = "entitlement_denied"


class TrustedAuthenticationContext(SecurityModel):
    issuer: IdentityText
    subject: SubjectText
    authenticated_at: AwareDatetime
    session_id: UUID


class SecurityAccessCommand(SecurityModel):
    request_id: UUID
    organisation_id: UUID
    permission: Permission
    resource_kind: ResourceKind
    resource_id: str | None = None
    feature: ControlledFeature | None = None
    quota_kind: QuotaKind | None = None
    current_usage: int | None = None

    @model_validator(mode="after")
    def validate_entitlement_fields(self) -> Self:
        if self.feature is None and (self.quota_kind is not None or self.current_usage is not None):
            raise ValueError("quota evaluation requires a controlled feature")
        if (self.quota_kind is None) != (self.current_usage is None):
            raise ValueError("quota_kind and current_usage must be supplied together")
        if self.current_usage is not None and self.current_usage < 0:
            raise ValueError("current_usage cannot be negative")
        return self


class SecurityAccessOutcome(SecurityModel):
    request_id: UUID
    organisation_id: UUID
    user_id: UUID | None = None
    allowed: bool
    reason: AccessOutcomeReason
    authorization: AuthorizationDecision | None = None
    entitlement: EntitlementDecision | None = None
    audit_required: bool = True

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.allowed != (self.reason is AccessOutcomeReason.ALLOWED):
            raise ValueError("allowed state and outcome reason are inconsistent")
        if self.allowed and (self.user_id is None or self.authorization is None):
            raise ValueError("allowed outcome requires identity and authorization")
        if self.authorization is not None and self.authorization.request_id != self.request_id:
            raise ValueError("authorization request identity mismatch")
        if self.entitlement is not None and self.entitlement.request_id != self.request_id:
            raise ValueError("entitlement request identity mismatch")
        if not self.audit_required:
            raise ValueError("security access outcomes must remain auditable")
        return self


class SecurityAccessService:
    def __init__(self, repository: SecurityRepository) -> None:
        self._repository = repository

    def evaluate(self, authentication: TrustedAuthenticationContext, command: SecurityAccessCommand) -> SecurityAccessOutcome:
        user = self._repository.user_by_external_identity(issuer=authentication.issuer, subject=authentication.subject)
        if user is None:
            return self._outcome(command, allowed=False, reason=AccessOutcomeReason.IDENTITY_NOT_FOUND)
        try:
            status = IdentityStatus(user.status)
        except ValueError:
            return self._outcome(command, user_id=user.id, allowed=False, reason=AccessOutcomeReason.IDENTITY_NOT_ACTIVE)
        membership = self._repository.active_membership_contract(user_id=user.id, organisation_id=command.organisation_id)
        principal = AuthenticatedPrincipal(
            user_id=user.id,
            email=user.email,
            display_name=user.display_name,
            status=status,
            issuer=authentication.issuer,
            subject=authentication.subject,
            authenticated_at=authentication.authenticated_at,
            session_id=authentication.session_id,
            memberships=() if membership is None else (membership,),
        )
        authorization = authorize(
            principal,
            AuthorizationRequest(
                organisation_id=command.organisation_id,
                permission=command.permission,
                resource_kind=command.resource_kind,
                resource_id=command.resource_id,
                request_id=command.request_id,
            ),
        )
        if not authorization.allowed:
            reason = AccessOutcomeReason.IDENTITY_NOT_ACTIVE if status is not IdentityStatus.ACTIVE else AccessOutcomeReason.AUTHORIZATION_DENIED
            return self._outcome(command, user_id=user.id, allowed=False, reason=reason, authorization=authorization)
        if command.feature is None:
            return self._outcome(command, user_id=user.id, allowed=True, reason=AccessOutcomeReason.ALLOWED, authorization=authorization)
        snapshot = self._repository.current_entitlement(organisation_id=command.organisation_id, effective_at=authentication.authenticated_at)
        if snapshot is None:
            return self._outcome(command, user_id=user.id, allowed=False, reason=AccessOutcomeReason.ENTITLEMENT_NOT_FOUND, authorization=authorization)
        entitlement = evaluate_entitlement(
            snapshot,
            EntitlementRequest(
                organisation_id=command.organisation_id,
                feature=command.feature,
                request_id=command.request_id,
                quota_kind=command.quota_kind,
                current_usage=command.current_usage,
            ),
            evaluated_at=authentication.authenticated_at,
        )
        if not entitlement.allowed:
            return self._outcome(command, user_id=user.id, allowed=False, reason=AccessOutcomeReason.ENTITLEMENT_DENIED, authorization=authorization, entitlement=entitlement)
        return self._outcome(command, user_id=user.id, allowed=True, reason=AccessOutcomeReason.ALLOWED, authorization=authorization, entitlement=entitlement)

    @staticmethod
    def _outcome(command: SecurityAccessCommand, *, allowed: bool, reason: AccessOutcomeReason, user_id: UUID | None = None, authorization: AuthorizationDecision | None = None, entitlement: EntitlementDecision | None = None) -> SecurityAccessOutcome:
        return SecurityAccessOutcome(request_id=command.request_id, organisation_id=command.organisation_id, user_id=user_id, allowed=allowed, reason=reason, authorization=authorization, entitlement=entitlement)
