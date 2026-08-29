"""Integration tests for audited path- and header-scoped FastAPI boundaries."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.repositories.security_audit_repository import SecurityAuditPersistenceError
from app.security.access_dependency import ORGANISATION_HEADER_NAME, OrganisationAccessRequirement
from app.security.audited_access_dependency import build_audited_header_organisation_access_dependency, build_audited_organisation_access_dependency
from app.security.audit_models import SecurityAuditEventType
from app.security.authorization import AuthorizationDecision, AuthorizationReason, ResourceKind
from app.security.identity_models import OrganisationRole, Permission
from app.services.security_access_service import AccessOutcomeReason, SecurityAccessOutcome, TrustedAuthenticationContext
from app.services.security_audit_service import AuditedSecurityAccessService


NOW = datetime(2026, 8, 8, 20, 0, tzinfo=UTC)
ORGANISATION_ID = uuid4()
USER_ID = uuid4()
REQUEST_ID = uuid4()


class Authentication:
    def __call__(self):
        return TrustedAuthenticationContext(issuer="issuer", subject="subject", authenticated_at=NOW, session_id=uuid4())


class Unauthenticated:
    def __call__(self):
        raise HTTPException(status_code=401, detail="Authentication required.", headers={"WWW-Authenticate": "Bearer"})


class AccessService:
    def __init__(self, *, allowed=True, reason=AccessOutcomeReason.ALLOWED):
        self.allowed = allowed
        self.reason = reason
        self.calls = []

    def evaluate(self, authentication, command):
        self.calls.append((authentication, command))
        authorization = None
        user_id = USER_ID
        if self.allowed:
            authorization = AuthorizationDecision(
                request_id=command.request_id,
                user_id=USER_ID,
                organisation_id=command.organisation_id,
                permission=command.permission,
                resource_kind=command.resource_kind,
                resource_id=command.resource_id,
                allowed=True,
                reason=AuthorizationReason.ALLOWED,
                role=OrganisationRole.ENGINEER,
            )
        elif self.reason is AccessOutcomeReason.IDENTITY_NOT_FOUND:
            user_id = None
        return SecurityAccessOutcome(
            request_id=command.request_id,
            organisation_id=command.organisation_id,
            user_id=user_id,
            allowed=self.allowed,
            reason=self.reason,
            authorization=authorization,
        )


class AuditRepository:
    def __init__(self, error=None):
        self.events = []
        self.error = error

    def append(self, event):
        if self.error is not None:
            raise self.error
        self.events.append(event)
        return event


def build_client(*, allowed=True, reason=AccessOutcomeReason.ALLOWED, authentication=None, audit_error=None, header_scoped=False):
    access = AccessService(allowed=allowed, reason=reason)
    audit = AuditRepository(audit_error)
    audited = AuditedSecurityAccessService(
        access_service=access,
        audit_repository=audit,
        clock=lambda: NOW,
        event_id_factory=uuid4,
    )
    builder = build_audited_header_organisation_access_dependency if header_scoped else build_audited_organisation_access_dependency
    dependency = builder(
        authentication=authentication or Authentication(),
        audited_access_service=audited,
        requirement=OrganisationAccessRequirement(
            permission=Permission.ENGINEERING_READ,
            resource_kind=ResourceKind.ENGINEERING_CASE,
            resource_id="case-141",
        ),
        request_id_factory=lambda: REQUEST_ID,
    )
    app = FastAPI()
    if header_scoped:

        @app.get("/existing-api/audited-probe")
        def header_probe(outcome=Depends(dependency)):
            return {"allowed": outcome.allowed, "request_id": str(outcome.request_id)}

    else:

        @app.get("/organisations/{organisation_id}/audited-probe")
        def path_probe(outcome=Depends(dependency)):
            return {"allowed": outcome.allowed, "request_id": str(outcome.request_id)}

    return TestClient(app), access, audit


def test_allowed_request_is_audited_before_route_handler_returns():
    client, access, audit = build_client()
    response = client.get(f"/organisations/{ORGANISATION_ID}/audited-probe")
    assert response.status_code == 200 and response.json() == {"allowed": True, "request_id": str(REQUEST_ID)}
    assert len(access.calls) == 1 and len(audit.events) == 1
    assert audit.events[0].event_type is SecurityAuditEventType.ACCESS_ALLOWED
    assert audit.events[0].request_id == REQUEST_ID and audit.events[0].organisation_id == ORGANISATION_ID


@pytest.mark.parametrize(
    "reason",
    [AccessOutcomeReason.IDENTITY_NOT_FOUND, AccessOutcomeReason.AUTHORIZATION_DENIED, AccessOutcomeReason.ENTITLEMENT_DENIED],
)
def test_denied_request_is_audited_before_uniform_403(reason):
    client, _, audit = build_client(allowed=False, reason=reason)
    response = client.get(f"/organisations/{ORGANISATION_ID}/audited-probe")
    assert response.status_code == 403 and response.json() == {"detail": "Access denied."}
    assert len(audit.events) == 1 and audit.events[0].event_type is SecurityAuditEventType.ACCESS_DENIED
    assert audit.events[0].reason_code == reason.value


def test_audit_failure_prevents_allowed_route_execution():
    client, _, audit = build_client(audit_error=SecurityAuditPersistenceError("storage unavailable"))
    with pytest.raises(SecurityAuditPersistenceError, match="storage unavailable"):
        client.get(f"/organisations/{ORGANISATION_ID}/audited-probe")
    assert audit.events == []


def test_authentication_failure_prevents_access_and_audit_evaluation():
    client, access, audit = build_client(authentication=Unauthenticated())
    response = client.get(f"/organisations/{ORGANISATION_ID}/audited-probe")
    assert response.status_code == 401 and response.headers["www-authenticate"] == "Bearer"
    assert access.calls == [] and audit.events == []


def test_raw_unaudited_access_service_is_rejected_at_composition_boundary():
    with pytest.raises(TypeError, match="requires AuditedSecurityAccessService"):
        build_audited_organisation_access_dependency(
            authentication=Authentication(),
            audited_access_service=AccessService(),
            requirement=OrganisationAccessRequirement(
                permission=Permission.ENGINEERING_READ,
                resource_kind=ResourceKind.ENGINEERING_CASE,
            ),
        )


def test_header_scoped_allowed_request_is_audited_with_exact_organisation():
    client, access, audit = build_client(header_scoped=True)
    response = client.get("/existing-api/audited-probe", headers={ORGANISATION_HEADER_NAME: str(ORGANISATION_ID)})
    assert response.status_code == 200 and response.json()["allowed"] is True
    assert access.calls[0][1].organisation_id == ORGANISATION_ID
    assert audit.events[0].organisation_id == ORGANISATION_ID
    assert audit.events[0].request_id == REQUEST_ID


def test_missing_header_prevents_access_and_audit_evaluation():
    client, access, audit = build_client(header_scoped=True)
    response = client.get("/existing-api/audited-probe")
    assert response.status_code == 422
    assert access.calls == [] and audit.events == []


def test_header_scoped_audit_failure_prevents_route_outcome():
    client, access, audit = build_client(header_scoped=True, audit_error=SecurityAuditPersistenceError("storage unavailable"))
    with pytest.raises(SecurityAuditPersistenceError, match="storage unavailable"):
        client.get("/existing-api/audited-probe", headers={ORGANISATION_HEADER_NAME: str(ORGANISATION_ID)})
    assert len(access.calls) == 1 and audit.events == []


def test_raw_service_is_rejected_for_header_scoped_composition_too():
    with pytest.raises(TypeError, match="requires AuditedSecurityAccessService"):
        build_audited_header_organisation_access_dependency(
            authentication=Authentication(),
            audited_access_service=AccessService(),
            requirement=OrganisationAccessRequirement(
                permission=Permission.ENGINEERING_READ,
                resource_kind=ResourceKind.ENGINEERING_CASE,
            ),
        )
