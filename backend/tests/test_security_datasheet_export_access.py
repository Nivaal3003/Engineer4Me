"""Format-specific entitlement and audit tests for datasheet exports."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import app.security.security_deployment as deployment_module
from app.security.application_route_policy import APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY
from app.security.audit_models import SecurityAuditEventType
from app.security.authentication_availability import AvailabilityAwareAuthenticationDependency
from app.security.authorization import AuthorizationDecision, AuthorizationReason, ResourceKind
from app.security.datasheet_export_access import (
    DATASHEET_EXPORT_FEATURE_BY_FORMAT,
    DATASHEET_EXPORT_OPERATION_ID,
    DATASHEET_EXPORT_PATH_TEMPLATE,
    DatasheetExportAccessConfigurationError,
    DatasheetExportAccessFormat,
    build_audited_datasheet_export_access_dependency,
)
from app.security.entitlements import ControlledFeature
from app.security.identity_models import OrganisationRole, Permission
from app.security.route_policy import RouteAccessScope, RouteHTTPMethod, RouteSecurityPolicy
from app.security.security_deployment import DeploymentSecurityRuntime
from app.services.security_access_service import AccessOutcomeReason, SecurityAccessOutcome, TrustedAuthenticationContext
from app.services.security_audit_service import AuditedSecurityAccessService


NOW = datetime(2026, 8, 8, 22, 0, tzinfo=UTC)
ORGANISATION_ID = uuid4()
USER_ID = uuid4()
SESSION_ID = uuid4()
REQUEST_ID = uuid4()
ORGANISATION_HEADER = "X-Engineer4Me-Organisation-ID"


class Authentication:
    def __call__(self):
        return TrustedAuthenticationContext(
            issuer="issuer",
            subject="subject",
            authenticated_at=NOW,
            session_id=SESSION_ID,
        )


class AccessService:
    def __init__(self, *, allowed=True):
        self.allowed = allowed
        self.calls = []

    def evaluate(self, authentication, command):
        self.calls.append((authentication, command))
        authorization = AuthorizationDecision(
            request_id=command.request_id,
            user_id=USER_ID,
            organisation_id=command.organisation_id,
            permission=command.permission,
            resource_kind=command.resource_kind,
            allowed=True,
            reason=AuthorizationReason.ALLOWED,
            role=OrganisationRole.ENGINEER,
        )
        return SecurityAccessOutcome(
            request_id=command.request_id,
            organisation_id=command.organisation_id,
            user_id=USER_ID,
            allowed=self.allowed,
            reason=AccessOutcomeReason.ALLOWED if self.allowed else AccessOutcomeReason.ENTITLEMENT_DENIED,
            authorization=authorization,
        )


class AuditRepository:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)
        return event


def export_policy():
    return APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY.resolve(
        operation_id=DATASHEET_EXPORT_OPERATION_ID,
        method=RouteHTTPMethod.GET,
        path_template=DATASHEET_EXPORT_PATH_TEMPLATE,
    )


def build_client(*, allowed=True):
    access = AccessService(allowed=allowed)
    audit = AuditRepository()
    audited = AuditedSecurityAccessService(
        access_service=access,
        audit_repository=audit,
        clock=lambda: NOW,
        event_id_factory=uuid4,
    )
    dependency = build_audited_datasheet_export_access_dependency(
        authentication=Authentication(),
        audited_access_service=audited,
        policy=export_policy(),
        request_id_factory=lambda: REQUEST_ID,
    )
    application = FastAPI()

    @application.get("/exports/{export_format}")
    def probe(outcome=Depends(dependency)):
        return {"allowed": outcome.allowed}

    return TestClient(application), access, audit


def test_exact_export_formats_map_to_distinct_existing_entitlements():
    assert dict(DATASHEET_EXPORT_FEATURE_BY_FORMAT) == {
        DatasheetExportAccessFormat.JSON: ControlledFeature.DATASHEET_JSON_EXPORT,
        DatasheetExportAccessFormat.XLSX: ControlledFeature.DATASHEET_XLSX_EXPORT,
    }


@pytest.mark.parametrize(
    ("export_format", "expected_feature"),
    [
        ("json", ControlledFeature.DATASHEET_JSON_EXPORT),
        ("xlsx", ControlledFeature.DATASHEET_XLSX_EXPORT),
    ],
)
def test_allowed_format_is_entitlement_checked_and_audited_before_route_execution(export_format, expected_feature):
    client, access, audit = build_client()
    response = client.get(
        f"/exports/{export_format}",
        headers={ORGANISATION_HEADER: str(ORGANISATION_ID)},
    )
    assert response.status_code == 200 and response.json() == {"allowed": True}
    assert len(access.calls) == 1 and access.calls[0][1].feature is expected_feature
    assert access.calls[0][1].permission is Permission.DATASHEET_EXPORT
    assert access.calls[0][1].resource_kind is ResourceKind.DATASHEET
    assert len(audit.events) == 1 and audit.events[0].event_type is SecurityAuditEventType.ACCESS_ALLOWED


def test_denied_entitlement_is_audited_before_uniform_403():
    client, access, audit = build_client(allowed=False)
    response = client.get(
        "/exports/xlsx",
        headers={ORGANISATION_HEADER: str(ORGANISATION_ID)},
    )
    assert response.status_code == 403 and response.json() == {"detail": "Access denied."}
    assert len(access.calls) == 1
    assert len(audit.events) == 1 and audit.events[0].event_type is SecurityAuditEventType.ACCESS_DENIED


@pytest.mark.parametrize("export_format", ["pdf", "JSON", "xls", "xlsx%20"])
def test_unknown_or_noncanonical_format_fails_before_access_or_audit(export_format):
    client, access, audit = build_client()
    response = client.get(
        f"/exports/{export_format}",
        headers={ORGANISATION_HEADER: str(ORGANISATION_ID)},
    )
    assert response.status_code == 422
    assert access.calls == [] and audit.events == []


def test_missing_or_invalid_organisation_header_fails_before_access_or_audit():
    client, access, audit = build_client()
    assert client.get("/exports/json").status_code == 422
    assert client.get("/exports/json", headers={ORGANISATION_HEADER: "not-a-uuid"}).status_code == 422
    assert access.calls == [] and audit.events == []


def test_builder_accepts_only_the_exact_reviewed_export_policy():
    policy = export_policy()
    invalid = policy.model_copy(update={"scope": RouteAccessScope.PUBLIC})
    audited = AuditedSecurityAccessService(
        access_service=AccessService(),
        audit_repository=AuditRepository(),
    )
    with pytest.raises(DatasheetExportAccessConfigurationError, match="does not match"):
        build_audited_datasheet_export_access_dependency(
            authentication=Authentication(),
            audited_access_service=audited,
            policy=invalid,
        )


def test_builder_rejects_raw_unaudited_access_service():
    with pytest.raises(TypeError, match="requires AuditedSecurityAccessService"):
        build_audited_datasheet_export_access_dependency(
            authentication=Authentication(),
            audited_access_service=AccessService(),
            policy=export_policy(),
        )


def test_deployment_runtime_forwards_exact_export_composition(monkeypatch):
    authentication = AvailabilityAwareAuthenticationDependency(Authentication())
    audited = AuditedSecurityAccessService(
        access_service=AccessService(),
        audit_repository=AuditRepository(),
    )
    runtime = DeploymentSecurityRuntime(
        authentication=authentication,
        audited_access_service=audited,
    )
    captured = {}
    sentinel = object()
    factory = lambda: REQUEST_ID

    def fake_builder(**values):
        captured.update(values)
        return sentinel

    monkeypatch.setattr(
        deployment_module,
        "build_audited_datasheet_export_access_dependency",
        fake_builder,
    )
    assert runtime.datasheet_export_header_access(export_policy(), request_id_factory=factory) is sentinel
    assert captured == {
        "authentication": authentication,
        "audited_access_service": audited,
        "policy": export_policy(),
        "request_id_factory": factory,
    }


def test_building_dependency_performs_no_authentication_access_or_audit_io():
    access = AccessService()
    audit = AuditRepository()
    audited = AuditedSecurityAccessService(access_service=access, audit_repository=audit)
    dependency = build_audited_datasheet_export_access_dependency(
        authentication=Authentication(),
        audited_access_service=audited,
        policy=export_policy(),
    )
    assert callable(dependency)
    assert access.calls == [] and audit.events == []
