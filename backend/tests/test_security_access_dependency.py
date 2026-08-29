"""Focused tests for path- and header-scoped FastAPI access enforcement."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.security.access_dependency import ORGANISATION_HEADER_NAME, OrganisationAccessRequirement, build_header_organisation_access_dependency, build_organisation_access_dependency
from app.security.authorization import AuthorizationDecision, AuthorizationReason, ResourceKind
from app.security.entitlements import ControlledFeature
from app.security.identity_models import OrganisationRole, Permission
from app.services.security_access_service import AccessOutcomeReason, SecurityAccessOutcome, TrustedAuthenticationContext


ORGANISATION_ID = uuid4()
USER_ID = uuid4()
AUTHENTICATED_AT = datetime(2026, 8, 8, 15, 30, tzinfo=UTC)


def authentication_context():
    return TrustedAuthenticationContext(
        issuer="https://identity.engineer4me.test",
        subject="subject-135",
        authenticated_at=AUTHENTICATED_AT,
        session_id=uuid4(),
    )


class Authentication:
    def __call__(self):
        return authentication_context()


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
        return SecurityAccessOutcome(
            request_id=command.request_id,
            organisation_id=command.organisation_id,
            user_id=USER_ID,
            allowed=self.allowed,
            reason=self.reason,
            authorization=authorization,
        )


def requirement():
    return OrganisationAccessRequirement(
        permission=Permission.ENGINEERING_READ,
        resource_kind=ResourceKind.ENGINEERING_CASE,
        resource_id="case-135",
    )


def client_for(service, authentication=None, access_requirement=None):
    access = build_organisation_access_dependency(
        authentication=authentication or Authentication(),
        access_service=service,
        requirement=access_requirement or requirement(),
    )
    app = FastAPI()

    @app.get("/organisations/{organisation_id}/probe")
    def probe(outcome=Depends(access)):
        return {"request_id": str(outcome.request_id), "organisation_id": str(outcome.organisation_id), "allowed": outcome.allowed}

    return TestClient(app)


def header_client_for(service, authentication=None, access_requirement=None):
    access = build_header_organisation_access_dependency(
        authentication=authentication or Authentication(),
        access_service=service,
        requirement=access_requirement or requirement(),
    )
    app = FastAPI()

    @app.get("/existing-api/probe")
    def probe(outcome=Depends(access)):
        return {"request_id": str(outcome.request_id), "organisation_id": str(outcome.organisation_id), "allowed": outcome.allowed}

    return TestClient(app)


def test_allowed_policy_returns_correlated_organisation_outcome():
    service = AccessService()
    response = client_for(service).get(f"/organisations/{ORGANISATION_ID}/probe")
    assert response.status_code == 200
    assert response.json()["organisation_id"] == str(ORGANISATION_ID)
    assert response.json()["allowed"] is True
    authentication, command = service.calls[0]
    assert authentication.subject == "subject-135"
    assert command.organisation_id == ORGANISATION_ID
    assert command.permission is Permission.ENGINEERING_READ
    assert command.resource_id == "case-135"


@pytest.mark.parametrize(
    "reason",
    [
        AccessOutcomeReason.IDENTITY_NOT_FOUND,
        AccessOutcomeReason.IDENTITY_NOT_ACTIVE,
        AccessOutcomeReason.AUTHORIZATION_DENIED,
        AccessOutcomeReason.ENTITLEMENT_NOT_FOUND,
        AccessOutcomeReason.ENTITLEMENT_DENIED,
    ],
)
def test_all_policy_denials_are_uniform_non_disclosing_403(reason):
    response = client_for(AccessService(allowed=False, reason=reason)).get(f"/organisations/{ORGANISATION_ID}/probe")
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied."}
    assert reason.value not in response.text


def test_authentication_failure_is_preserved_before_access_evaluation():
    service = AccessService()
    response = client_for(service, authentication=Unauthenticated()).get(f"/organisations/{ORGANISATION_ID}/probe")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert service.calls == []


def test_entitlement_requirement_is_forwarded_explicitly():
    service = AccessService()
    access_requirement = OrganisationAccessRequirement(
        permission=Permission.ENGINEERING_EXECUTE,
        resource_kind=ResourceKind.CALCULATION,
        feature=ControlledFeature.ENGINEERING_CALCULATIONS,
    )
    response = client_for(service, access_requirement=access_requirement).get(f"/organisations/{ORGANISATION_ID}/probe")
    assert response.status_code == 200
    command = service.calls[0][1]
    assert command.feature is ControlledFeature.ENGINEERING_CALCULATIONS
    assert command.permission is Permission.ENGINEERING_EXECUTE


def test_each_request_receives_a_distinct_auditable_request_id():
    service = AccessService()
    client = client_for(service)
    first = client.get(f"/organisations/{ORGANISATION_ID}/probe").json()["request_id"]
    second = client.get(f"/organisations/{ORGANISATION_ID}/probe").json()["request_id"]
    assert UUID(first) != UUID(second)


def test_invalid_organisation_identifier_is_rejected_before_service_evaluation():
    service = AccessService()
    response = client_for(service).get("/organisations/not-a-uuid/probe")
    assert response.status_code == 422
    assert service.calls == []


def test_unexpected_service_failure_is_not_misreported_as_access_denial():
    class BrokenService:
        def evaluate(self, authentication, command):
            raise RuntimeError("programming defect")

    client = client_for(BrokenService())
    with pytest.raises(RuntimeError, match="programming defect"):
        client.get(f"/organisations/{ORGANISATION_ID}/probe")


def test_header_scope_forwards_exact_tenant_context_without_changing_route_path():
    service = AccessService()
    response = header_client_for(service).get("/existing-api/probe", headers={ORGANISATION_HEADER_NAME: str(ORGANISATION_ID)})
    assert response.status_code == 200
    assert response.json()["organisation_id"] == str(ORGANISATION_ID)
    assert service.calls[0][1].organisation_id == ORGANISATION_ID


@pytest.mark.parametrize("headers", [{}, {ORGANISATION_HEADER_NAME: "not-a-uuid"}])
def test_missing_or_invalid_header_context_is_rejected_before_policy_evaluation(headers):
    service = AccessService()
    response = header_client_for(service).get("/existing-api/probe", headers=headers)
    assert response.status_code == 422
    assert service.calls == []


def test_query_parameter_cannot_substitute_for_required_organisation_header():
    service = AccessService()
    response = header_client_for(service).get(f"/existing-api/probe?organisation_id={ORGANISATION_ID}")
    assert response.status_code == 422
    assert service.calls == []


def test_header_scoped_denial_remains_uniform_non_disclosing_403():
    service = AccessService(allowed=False, reason=AccessOutcomeReason.ENTITLEMENT_DENIED)
    response = header_client_for(service).get("/existing-api/probe", headers={ORGANISATION_HEADER_NAME: str(ORGANISATION_ID)})
    assert response.status_code == 403 and response.json() == {"detail": "Access denied."}
    assert "entitlement" not in response.text.lower()


def test_header_scoped_authentication_failure_prevents_policy_evaluation():
    service = AccessService()
    response = header_client_for(service, authentication=Unauthenticated()).get(
        "/existing-api/probe", headers={ORGANISATION_HEADER_NAME: str(ORGANISATION_ID)}
    )
    assert response.status_code == 401 and response.headers["www-authenticate"] == "Bearer"
    assert service.calls == []


def test_openapi_declares_one_required_exact_organisation_header():
    schema = header_client_for(AccessService()).get("/openapi.json").json()
    parameters = schema["paths"]["/existing-api/probe"]["get"]["parameters"]
    assert [(item["name"], item["in"], item["required"]) for item in parameters] == [(ORGANISATION_HEADER_NAME, "header", True)]
