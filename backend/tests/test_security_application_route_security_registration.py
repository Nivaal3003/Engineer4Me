"""Pre-registration coverage tests for the exact FastAPI route surface."""

from dataclasses import FrozenInstanceError

import pytest
from fastapi import FastAPI

from app.main import app
from app.security.application_route_security_plan import (
    ApplicationRouteSecurityBinding,
    ApplicationRouteSecurityPlan,
    ApplicationRouteSecurityPlanError,
    build_application_route_security_plan,
)
from app.security.application_route_security_registration import (
    ApplicationRouteSecurityRegistration,
    ApplicationRouteSecurityRegistrationError,
    ApplicationRouteSecurityRegistrationManifest,
    build_application_route_security_registration_manifest,
)
from app.security.route_inventory import ApplicationRouteInventoryError
from app.security.route_policy import RouteAccessScope
from app.security.security_deployment import DeploymentSecurityRuntime


class InertRuntime(DeploymentSecurityRuntime):
    def __init__(self):
        self.calls = []

    @staticmethod
    def _dependency():
        return None

    def organisation_access(self, requirement, *, request_id_factory=None):
        self.calls.append(("path", requirement))
        return self._dependency

    def organisation_header_access(self, requirement, *, request_id_factory=None):
        self.calls.append(("header", requirement))
        return self._dependency

    def datasheet_export_header_access(self, policy, *, request_id_factory=None):
        self.calls.append(("datasheet_export", policy))
        return self._dependency


def build_manifest(application=app):
    plan = build_application_route_security_plan(InertRuntime())
    return build_application_route_security_registration_manifest(application, plan)


def route_state(application):
    return tuple(
        (
            id(route),
            tuple(getattr(route, "dependencies", ())),
            id(getattr(route, "dependant", None)),
        )
        for route in application.routes
    )


def test_manifest_covers_all_93_runtime_routes_exactly_once():
    manifest = build_manifest()
    assert len(manifest.registrations) == 93
    assert len({item.key for item in manifest.registrations}) == 93
    assert all(item.key == item.binding.key for item in manifest.registrations)


def test_manifest_preserves_two_public_and_91_protected_boundaries():
    manifest = build_manifest()
    public = manifest.public_registrations()
    protected = manifest.protected_registrations()
    assert {(item.identity.operation_id, item.identity.path_template) for item in public} == {
        ("root", "/"),
        ("health", "/health"),
    }
    assert len(protected) == 91
    assert all(item.binding.policy.scope is not RouteAccessScope.PUBLIC for item in protected)
    assert all(callable(item.binding.dependency) for item in protected)


def test_manifest_build_is_observational_and_does_not_mutate_fastapi_routes():
    before_routes = route_state(app)
    before_schema = app.openapi()
    manifest = build_manifest()
    assert len(manifest.registrations) == 93
    assert route_state(app) == before_routes
    assert app.openapi() is before_schema


def test_framework_routes_are_never_security_registration_entries():
    paths = {item.identity.path_template for item in build_manifest().registrations}
    assert not paths & {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def test_registration_manifest_is_immutable():
    manifest = build_manifest()
    with pytest.raises(FrozenInstanceError):
        manifest.registrations = ()
    with pytest.raises(FrozenInstanceError):
        manifest.registrations[0].binding = manifest.registrations[0].binding


def test_incomplete_runtime_inventory_fails_closed_before_manifest_creation():
    incomplete = FastAPI()

    @incomplete.get("/health")
    def health():
        return {"status": "healthy"}

    with pytest.raises(ApplicationRouteInventoryError, match="declared 93, discovered 1"):
        build_manifest(incomplete)


def test_manifest_rejects_duplicate_and_binding_conflict():
    manifest = build_manifest()
    duplicate = manifest.registrations[:-1] + (manifest.registrations[0],)
    with pytest.raises(ApplicationRouteSecurityRegistrationError, match="duplicate"):
        ApplicationRouteSecurityRegistrationManifest(duplicate)
    first = manifest.registrations[0]
    conflicting_binding = manifest.registrations[1].binding
    conflicting = (
        ApplicationRouteSecurityRegistration(first.identity, conflicting_binding),
        *manifest.registrations[1:],
    )
    with pytest.raises(ApplicationRouteSecurityRegistrationError, match="conflicts"):
        ApplicationRouteSecurityRegistrationManifest(conflicting)


def test_manifest_rejects_missing_or_invalid_entries():
    manifest = build_manifest()
    with pytest.raises(ApplicationRouteSecurityRegistrationError, match="exactly 93"):
        ApplicationRouteSecurityRegistrationManifest(manifest.registrations[:-1])
    invalid = (object(), *manifest.registrations[1:])
    with pytest.raises(TypeError, match="invalid entry"):
        ApplicationRouteSecurityRegistrationManifest(invalid)


def test_builder_requires_exact_fastapi_and_security_plan_contracts():
    plan = build_application_route_security_plan(InertRuntime())
    with pytest.raises(TypeError, match="requires FastAPI"):
        build_application_route_security_registration_manifest(object(), plan)
    with pytest.raises(TypeError, match="requires ApplicationRouteSecurityPlan"):
        build_application_route_security_registration_manifest(app, object())


def test_manifest_cannot_accept_scope_dependency_conflicts_from_an_invalid_plan():
    plan = build_application_route_security_plan(InertRuntime())
    public = plan.public_bindings()[0]
    conflicting = tuple(
        ApplicationRouteSecurityBinding(public.policy, lambda: None)
        if item is public
        else item
        for item in plan.bindings
    )
    with pytest.raises(ApplicationRouteSecurityPlanError, match="conflicts"):
        ApplicationRouteSecurityPlan(conflicting)
