"""Deterministic coverage tests for the unregistered route security plan."""

from collections import Counter

import pytest

from app.security.application_route_policy import (
    APPLICATION_ROUTE_SECURITY_POLICIES,
)
from app.security.application_route_security_plan import (
    ApplicationRouteSecurityBinding,
    ApplicationRouteSecurityPlan,
    ApplicationRouteSecurityPlanError,
    build_application_route_security_plan,
)
from app.security.authorization import ResourceKind
from app.security.datasheet_export_access import DATASHEET_EXPORT_OPERATION_ID
from app.security.entitlements import ControlledFeature
from app.security.identity_models import Permission
from app.security.route_policy import RouteAccessScope, RouteHTTPMethod
from app.security.security_deployment import DeploymentSecurityRuntime


class RecordingRuntime(DeploymentSecurityRuntime):
    def __init__(self):
        self.calls = []

    @staticmethod
    def _dependency(name, value):
        def dependency():
            return (name, value)

        return dependency

    def organisation_access(self, requirement, *, request_id_factory=None):
        self.calls.append(("path", requirement))
        return self._dependency("path", requirement)

    def organisation_header_access(self, requirement, *, request_id_factory=None):
        self.calls.append(("header", requirement))
        return self._dependency("header", requirement)

    def datasheet_export_header_access(self, policy, *, request_id_factory=None):
        self.calls.append(("datasheet_export", policy))
        return self._dependency("datasheet_export", policy)


def build():
    runtime = RecordingRuntime()
    return build_application_route_security_plan(runtime), runtime


def test_plan_contains_exactly_93_reviewed_unique_policy_bindings():
    plan, _ = build()
    assert len(plan.bindings) == 93
    assert tuple(binding.policy for binding in plan.bindings) == APPLICATION_ROUTE_SECURITY_POLICIES
    assert len({binding.key for binding in plan.bindings}) == 93


def test_only_two_public_routes_have_no_dependency():
    plan, _ = build()
    public = plan.public_bindings()
    assert {(binding.policy.operation_id, binding.policy.path_template) for binding in public} == {
        ("root", "/"),
        ("health", "/health"),
    }
    assert all(binding.policy.scope is RouteAccessScope.PUBLIC for binding in public)
    assert all(binding.dependency is None for binding in public)


def test_all_91_protected_routes_have_callable_dependencies():
    plan, _ = build()
    protected = plan.protected_bindings()
    assert len(protected) == 91
    assert all(callable(binding.dependency) for binding in protected)
    assert all(binding.policy.scope is not RouteAccessScope.PUBLIC for binding in protected)


def test_current_route_surface_builds_90_standard_header_and_one_export_dependency():
    _, runtime = build()
    assert Counter(name for name, _ in runtime.calls) == {
        "header": 90,
        "datasheet_export": 1,
    }
    assert all(name != "path" for name, _ in runtime.calls)


def test_standard_dependencies_preserve_exact_permission_resource_and_feature():
    _, runtime = build()
    requirements = tuple(value for name, value in runtime.calls if name == "header")
    assert Counter(requirement.permission for requirement in requirements) == {
        Permission.ENGINEERING_READ: 32,
        Permission.ENGINEERING_EXECUTE: 14,
        Permission.ENGINEERING_CREATE: 4,
        Permission.DOCUMENT_READ: 14,
        Permission.DOCUMENT_INGEST: 9,
        Permission.ENGINEERING_REVIEW: 17,
    }
    assert Counter(requirement.resource_kind for requirement in requirements) == {
        ResourceKind.CALCULATION: 26,
        ResourceKind.ENGINEERING_CASE: 30,
        ResourceKind.DATASHEET: 6,
        ResourceKind.DOCUMENT: 28,
    }
    assert Counter(requirement.feature for requirement in requirements) == {
        None: 54,
        ControlledFeature.ENGINEERING_CALCULATIONS: 11,
        ControlledFeature.DESIGN_PERSISTENCE: 16,
        ControlledFeature.DOCUMENT_INGESTION: 9,
    }


def test_format_scoped_export_uses_only_the_dedicated_dependency_builder():
    plan, runtime = build()
    export_calls = tuple(value for name, value in runtime.calls if name == "datasheet_export")
    assert len(export_calls) == 1
    policy = export_calls[0]
    assert policy.operation_id == DATASHEET_EXPORT_OPERATION_ID
    binding = plan.resolve(
        operation_id=policy.operation_id,
        method=policy.method,
        path_template=policy.path_template,
    )
    assert binding.policy is policy and callable(binding.dependency)


def test_exact_resolution_returns_each_binding_without_default_grant():
    plan, _ = build()
    for binding in plan.bindings:
        assert plan.resolve(
            operation_id=binding.policy.operation_id,
            method=binding.policy.method,
            path_template=binding.policy.path_template,
        ) is binding


@pytest.mark.parametrize(
    "lookup",
    [
        {"operation_id": "unknown", "method": "GET", "path_template": "/health"},
        {"operation_id": "health", "method": "POST", "path_template": "/health"},
        {"operation_id": "health", "method": "GET", "path_template": "/unknown"},
        {"operation_id": "health", "method": "OPTIONS", "path_template": "/health"},
    ],
)
def test_unknown_or_partial_binding_lookup_fails_closed_without_route_disclosure(lookup):
    plan, _ = build()
    with pytest.raises(ApplicationRouteSecurityPlanError, match="not registered") as captured:
        plan.resolve(**lookup)
    assert "unknown" not in str(captured.value)
    assert "/health" not in str(captured.value)


def test_plan_rejects_missing_duplicate_and_scope_dependency_conflicts():
    plan, _ = build()
    with pytest.raises(ApplicationRouteSecurityPlanError, match="exactly 93"):
        ApplicationRouteSecurityPlan(plan.bindings[:-1])
    duplicate = plan.bindings[:-1] + (plan.bindings[0],)
    with pytest.raises(ApplicationRouteSecurityPlanError, match="duplicate"):
        ApplicationRouteSecurityPlan(duplicate)
    public = plan.public_bindings()[0]
    conflicting = tuple(
        ApplicationRouteSecurityBinding(public.policy, lambda: None)
        if binding is public
        else binding
        for binding in plan.bindings
    )
    with pytest.raises(ApplicationRouteSecurityPlanError, match="conflicts"):
        ApplicationRouteSecurityPlan(conflicting)


def test_builder_requires_controlled_deployment_runtime():
    with pytest.raises(TypeError, match="requires DeploymentSecurityRuntime"):
        build_application_route_security_plan(object())
