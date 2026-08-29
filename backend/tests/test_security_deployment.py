"""Focused tests for controlled deployment security composition."""

import os
from uuid import uuid4

import pytest

import app.security.security_deployment as deployment_module
from app.repositories.security_audit_writer import DurableSecurityAuditWriter
from app.security.access_dependency import OrganisationAccessRequirement
from app.security.authentication_deployment import AuthenticationDeploymentError
from app.security.authorization import ResourceKind
from app.security.identity_models import Permission
from app.security.security_deployment import (
    DeploymentSecurityRuntime,
    build_deployment_security_runtime,
    build_session_factory_deployment_security_runtime,
)
from app.services.security_access_reader import SessionFactorySecurityAccessService


ENVIRONMENT = {
    "E4M_AUTH_ISSUER": "https://identity.engineer4me.test",
    "E4M_AUTH_AUDIENCE": "engineer4me-api",
    "E4M_AUTH_JWKS_URL": "https://identity.engineer4me.test/.well-known/jwks.json",
    "E4M_AUTH_ALGORITHMS": "RS256",
}


class InertSession:
    def __init__(self):
        self.accesses = []

    def __getattr__(self, name):
        self.accesses.append(name)
        raise AssertionError(f"unexpected eager database access: {name}")


class SessionFactory:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return InertSession()


def requirement():
    return OrganisationAccessRequirement(
        permission=Permission.ENGINEERING_READ,
        resource_kind=ResourceKind.ENGINEERING_CASE,
        resource_id="case-166",
    )


def build(*, environment=ENVIRONMENT, session=None, audit_factory=None, open_url=None):
    return build_deployment_security_runtime(
        environment=environment,
        session=session or InertSession(),
        audit_session_factory=audit_factory or SessionFactory(),
        open_url=open_url,
    )


def build_factory_runtime(
    *,
    environment=ENVIRONMENT,
    access_factory=None,
    audit_factory=None,
    open_url=None,
):
    return build_session_factory_deployment_security_runtime(
        environment=environment,
        access_session_factory=access_factory or SessionFactory(),
        audit_session_factory=audit_factory or SessionFactory(),
        open_url=open_url,
    )


def test_explicit_session_runtime_remains_compatible_and_lazy():
    session = InertSession()
    audit_factory = SessionFactory()

    def forbidden_network(*args, **kwargs):
        raise AssertionError("unexpected eager JWKS request")

    runtime = build(
        session=session,
        audit_factory=audit_factory,
        open_url=forbidden_network,
    )
    assert isinstance(runtime, DeploymentSecurityRuntime)
    assert callable(runtime.organisation_access(requirement()))
    assert callable(runtime.organisation_header_access(requirement()))
    assert session.accesses == [] and audit_factory.calls == 0


def test_factory_runtime_composes_without_eager_network_or_database_io():
    access_factory = SessionFactory()
    audit_factory = SessionFactory()

    def forbidden_network(*args, **kwargs):
        raise AssertionError("unexpected eager JWKS request")

    runtime = build_factory_runtime(
        access_factory=access_factory,
        audit_factory=audit_factory,
        open_url=forbidden_network,
    )
    assert isinstance(runtime, DeploymentSecurityRuntime)
    assert callable(runtime.organisation_header_access(requirement()))
    assert access_factory.calls == 0
    assert audit_factory.calls == 0


def test_factory_runtime_uses_short_lived_reads_and_isolated_audit_writer():
    access_factory = SessionFactory()
    audit_factory = SessionFactory()
    runtime = build_factory_runtime(
        access_factory=access_factory,
        audit_factory=audit_factory,
    )
    audited = runtime._audited_access_service
    assert isinstance(audited._access_service, SessionFactorySecurityAccessService)
    assert audited._access_service._session_factory is access_factory
    assert isinstance(audited._audit_repository, DurableSecurityAuditWriter)
    assert audited._audit_repository._session_factory is audit_factory
    assert access_factory.calls == 0 and audit_factory.calls == 0


def test_explicit_request_reads_and_audit_writes_remain_separate():
    session = InertSession()
    audit_factory = SessionFactory()
    runtime = build(session=session, audit_factory=audit_factory)
    audited = runtime._audited_access_service
    assert audited._access_service._repository._session is session
    assert isinstance(audited._audit_repository, DurableSecurityAuditWriter)
    assert audited._audit_repository._session_factory is audit_factory


def test_runtime_builds_distinct_dependencies_without_registering_routes():
    runtime = build_factory_runtime()
    path_first = runtime.organisation_access(
        requirement(), request_id_factory=lambda: uuid4()
    )
    path_second = runtime.organisation_access(
        requirement(), request_id_factory=lambda: uuid4()
    )
    header_first = runtime.organisation_header_access(
        requirement(), request_id_factory=lambda: uuid4()
    )
    header_second = runtime.organisation_header_access(
        requirement(), request_id_factory=lambda: uuid4()
    )
    assert callable(path_first) and callable(path_second) and path_first is not path_second
    assert callable(header_first) and callable(header_second) and header_first is not header_second


def test_header_runtime_method_forwards_exact_dependencies_and_requirement(monkeypatch):
    runtime = build_factory_runtime()
    access_requirement = requirement()
    request_id_factory = lambda: uuid4()
    captured = {}
    sentinel = object()

    def fake_builder(**values):
        captured.update(values)
        return sentinel

    monkeypatch.setattr(
        deployment_module,
        "build_audited_header_organisation_access_dependency",
        fake_builder,
    )
    result = runtime.organisation_header_access(
        access_requirement,
        request_id_factory=request_id_factory,
    )
    assert result is sentinel
    assert captured == {
        "authentication": runtime._authentication,
        "audited_access_service": runtime._audited_access_service,
        "requirement": access_requirement,
        "request_id_factory": request_id_factory,
    }


def test_path_and_header_runtime_methods_use_distinct_composition_builders(monkeypatch):
    runtime = build_factory_runtime()
    calls = []
    monkeypatch.setattr(
        deployment_module,
        "build_audited_organisation_access_dependency",
        lambda **values: calls.append(("path", values)) or object(),
    )
    monkeypatch.setattr(
        deployment_module,
        "build_audited_header_organisation_access_dependency",
        lambda **values: calls.append(("header", values)) or object(),
    )
    runtime.organisation_access(requirement())
    runtime.organisation_header_access(requirement())
    assert [name for name, _ in calls] == ["path", "header"]


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {**ENVIRONMENT, "E4M_AUTH_ALGORITHMS": "HS256"},
        {**ENVIRONMENT, "E4M_AUTH_JWKS_URL": "http://identity.invalid/jwks"},
        {**ENVIRONMENT, "E4M_AUTH_UNREVIEWED_OPTION": "true"},
    ],
)
def test_invalid_configuration_fails_before_any_factory_use(environment):
    access_factory = SessionFactory()
    audit_factory = SessionFactory()
    with pytest.raises(AuthenticationDeploymentError):
        build_factory_runtime(
            environment=environment,
            access_factory=access_factory,
            audit_factory=audit_factory,
        )
    assert access_factory.calls == 0 and audit_factory.calls == 0


def test_factory_runtime_uses_only_caller_supplied_environment_mapping(monkeypatch):
    for key, value in ENVIRONMENT.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(AuthenticationDeploymentError):
        build_factory_runtime(environment={})
    assert os.environ["E4M_AUTH_ISSUER"] == ENVIRONMENT["E4M_AUTH_ISSUER"]
