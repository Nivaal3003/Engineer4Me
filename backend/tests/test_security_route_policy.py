"""Focused tests for strict fail-closed API route security policy contracts."""

import pytest
from pydantic import ValidationError

from app.security.authorization import ResourceKind
from app.security.entitlements import ControlledFeature
from app.security.identity_models import Permission
from app.security.route_policy import RouteAccessScope, RouteHTTPMethod, RouteSecurityPolicy, RouteSecurityPolicyError, RouteSecurityPolicyRegistry


def header_policy(**changes):
    values = dict(
        operation_id="executeEngineeringCalculation",
        method=RouteHTTPMethod.POST,
        path_template="/api/v1/calculations/execute",
        scope=RouteAccessScope.ORGANISATION_HEADER,
        permission=Permission.ENGINEERING_EXECUTE,
        resource_kind=ResourceKind.CALCULATION,
        feature=ControlledFeature.ENGINEERING_CALCULATIONS,
    )
    values.update(changes)
    return RouteSecurityPolicy(**values)


def path_policy(**changes):
    values = dict(
        operation_id="readOrganisation",
        method=RouteHTTPMethod.GET,
        path_template="/api/v1/organisations/{organisation_id}",
        scope=RouteAccessScope.ORGANISATION_PATH,
        permission=Permission.ORGANISATION_READ,
        resource_kind=ResourceKind.ORGANISATION,
    )
    values.update(changes)
    return RouteSecurityPolicy(**values)


def public_policy(**changes):
    values = dict(
        operation_id="health",
        method=RouteHTTPMethod.GET,
        path_template="/health",
        scope=RouteAccessScope.PUBLIC,
    )
    values.update(changes)
    return RouteSecurityPolicy(**values)


def test_header_policy_builds_exact_permission_resource_and_entitlement_requirement():
    policy = header_policy()
    requirement = policy.access_requirement()
    assert requirement.permission is Permission.ENGINEERING_EXECUTE
    assert requirement.resource_kind is ResourceKind.CALCULATION
    assert requirement.feature is ControlledFeature.ENGINEERING_CALCULATIONS


def test_path_policy_requires_and_preserves_explicit_organisation_path_context():
    policy = path_policy()
    assert policy.scope is RouteAccessScope.ORGANISATION_PATH
    assert "{organisation_id}" in policy.path_template
    assert policy.access_requirement().permission is Permission.ORGANISATION_READ


def test_public_policy_is_read_only_and_has_no_access_requirement():
    policy = public_policy()
    with pytest.raises(RouteSecurityPolicyError, match="no organisation access requirement"):
        policy.access_requirement()


@pytest.mark.parametrize("field", ["permission", "resource_kind", "feature"])
def test_public_policy_cannot_smuggle_protected_grants(field):
    values = {
        "permission": Permission.ORGANISATION_READ,
        "resource_kind": ResourceKind.ORGANISATION,
        "feature": ControlledFeature.ENGINEERING_CALCULATIONS,
    }
    with pytest.raises(ValidationError, match="cannot contain protected"):
        public_policy(**{field: values[field]})


@pytest.mark.parametrize("method", [RouteHTTPMethod.POST, RouteHTTPMethod.PUT, RouteHTTPMethod.PATCH, RouteHTTPMethod.DELETE])
def test_public_policy_cannot_expose_mutating_methods(method):
    with pytest.raises(ValidationError, match="read-only GET"):
        public_policy(method=method)


@pytest.mark.parametrize("missing", ["permission", "resource_kind"])
def test_protected_policy_requires_complete_authorization_contract(missing):
    with pytest.raises(ValidationError, match="requires permission and resource kind"):
        header_policy(**{missing: None})


def test_path_scope_without_organisation_parameter_is_rejected():
    with pytest.raises(ValidationError, match=r"requires \{organisation_id\}"):
        path_policy(path_template="/api/v1/organisations/current")


def test_header_scope_cannot_duplicate_organisation_path_context():
    with pytest.raises(ValidationError, match="cannot duplicate"):
        header_policy(path_template="/api/v1/organisations/{organisation_id}/calculations")


def test_contract_is_strict_frozen_and_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        header_policy(method="POST")
    with pytest.raises(ValidationError):
        header_policy(implicit_admin=True)
    policy = header_policy()
    with pytest.raises(ValidationError):
        policy.permission = Permission.ORGANISATION_MANAGE


def test_registry_resolves_only_the_exact_operation_method_and_path_tuple():
    expected = header_policy()
    registry = RouteSecurityPolicyRegistry((public_policy(), expected, path_policy()))
    assert registry.resolve(operation_id=expected.operation_id, method="POST", path_template=expected.path_template) is expected
    assert registry.public_policies() == (registry.policies[0],)
    assert registry.protected_policies() == registry.policies[1:]


@pytest.mark.parametrize(
    "lookup",
    [
        {"operation_id": "unknown", "method": "POST", "path_template": "/api/v1/calculations/execute"},
        {"operation_id": "executeEngineeringCalculation", "method": "GET", "path_template": "/api/v1/calculations/execute"},
        {"operation_id": "executeEngineeringCalculation", "method": "POST", "path_template": "/api/v1/calculations/other"},
        {"operation_id": "executeEngineeringCalculation", "method": "OPTIONS", "path_template": "/api/v1/calculations/execute"},
    ],
)
def test_unknown_or_partially_matching_route_fails_closed(lookup):
    registry = RouteSecurityPolicyRegistry((header_policy(),))
    with pytest.raises(RouteSecurityPolicyError, match="not registered") as captured:
        registry.resolve(**lookup)
    assert "unknown" not in str(captured.value)
    assert "/api/" not in str(captured.value)


def test_registry_rejects_duplicate_operation_identifiers():
    first = header_policy()
    second = path_policy(operation_id=first.operation_id)
    with pytest.raises(RouteSecurityPolicyError, match="operation identifiers must be unique"):
        RouteSecurityPolicyRegistry((first, second))


def test_registry_rejects_duplicate_method_and_path_pairs():
    first = header_policy()
    second = header_policy(operation_id="secondOperation")
    with pytest.raises(RouteSecurityPolicyError, match="method and path pairs must be unique"):
        RouteSecurityPolicyRegistry((first, second))


@pytest.mark.parametrize("policies", [None, (), [], ("not-a-policy",)])
def test_registry_requires_a_nonempty_tuple_of_validated_policies(policies):
    with pytest.raises(TypeError):
        RouteSecurityPolicyRegistry(policies)


def test_registry_has_a_fixed_bounded_capacity():
    policy = public_policy()
    with pytest.raises(ValueError, match="bounded policy limit"):
        RouteSecurityPolicyRegistry(tuple(policy.model_copy(update={"operation_id": f"health{index}", "path_template": f"/health/{index}"}) for index in range(501)))
