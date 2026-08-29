"""Concrete request matching tests for the exact application security plan."""

import re

import pytest

from app.security.application_route_policy import APPLICATION_ROUTE_SECURITY_POLICIES
from app.security.application_route_security_matcher import (
    MAX_CONCRETE_ROUTE_PATH_LENGTH,
    ApplicationRouteSecurityMatchError,
    ApplicationRouteSecurityMatcher,
)
from app.security.application_route_security_plan import (
    build_application_route_security_plan,
)
from app.security.route_policy import RouteHTTPMethod
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


def matcher():
    return ApplicationRouteSecurityMatcher(
        build_application_route_security_plan(InertRuntime())
    )


def concrete_path(path_template):
    replacements = {
        "revision_number": "1",
        "export_format": "json",
    }

    def replace(match):
        name = match.group(1)
        return replacements.get(name, "00000000-0000-0000-0000-000000000001")

    return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", replace, path_template)


@pytest.mark.parametrize("policy", APPLICATION_ROUTE_SECURITY_POLICIES)
def test_every_reviewed_policy_matches_one_representative_concrete_request(policy):
    result = matcher().match(
        method=policy.method,
        concrete_path=concrete_path(policy.path_template),
    )
    assert result.policy is policy


def test_static_and_parameterized_routes_resolve_by_method_and_shape():
    security_matcher = matcher()
    static = security_matcher.match(
        method="POST",
        concrete_path="/api/v1/knowledge/search",
    )
    parameterized = security_matcher.match(
        method="GET",
        concrete_path="/api/v1/knowledge/00000000-0000-0000-0000-000000000001",
    )
    assert static.policy.operation_id == "search_knowledge"
    assert parameterized.policy.operation_id == "get_knowledge"


def test_method_is_part_of_the_exact_match_without_implicit_fallback():
    security_matcher = matcher()
    assert security_matcher.match(method="GET", concrete_path="/health").policy.operation_id == "health"
    with pytest.raises(ApplicationRouteSecurityMatchError, match="not uniquely matched"):
        security_matcher.match(method="POST", concrete_path="/health")


def test_trailing_slash_is_preserved_as_part_of_the_reviewed_path():
    security_matcher = matcher()
    assert security_matcher.match(
        method="GET",
        concrete_path="/api/v1/measurements/",
    ).policy.operation_id == "list_measurements"
    with pytest.raises(ApplicationRouteSecurityMatchError):
        security_matcher.match(method="GET", concrete_path="/api/v1/measurements")


@pytest.mark.parametrize(
    "concrete_path",
    [
        "",
        "api/v1/products",
        "/api/v1/products?limit=1",
        "/api/v1/products#fragment",
        "/api\\v1\\products",
        "/api/v1/products\n",
        "/" + ("a" * MAX_CONCRETE_ROUTE_PATH_LENGTH),
    ],
)
def test_malformed_or_oversized_concrete_paths_fail_closed(concrete_path):
    with pytest.raises(ApplicationRouteSecurityMatchError, match="not uniquely matched") as captured:
        matcher().match(method="GET", concrete_path=concrete_path)
    assert str(captured.value) == "application route security binding is not uniquely matched"


@pytest.mark.parametrize("method", ["OPTIONS", "HEAD", "TRACE", "get", ""])
def test_unreviewed_or_noncanonical_methods_fail_closed(method):
    with pytest.raises(ApplicationRouteSecurityMatchError, match="not uniquely matched"):
        matcher().match(method=method, concrete_path="/health")


def test_unknown_concrete_path_fails_without_disclosure():
    path = "/api/v1/unreviewed/secret"
    with pytest.raises(ApplicationRouteSecurityMatchError, match="not uniquely matched") as captured:
        matcher().match(method="GET", concrete_path=path)
    assert path not in str(captured.value)


def test_public_binding_cannot_be_resolved_through_protected_matcher():
    with pytest.raises(ApplicationRouteSecurityMatchError, match="not protected"):
        matcher().match_protected(method=RouteHTTPMethod.GET, concrete_path="/health")


def test_all_api_bindings_are_resolvable_through_protected_matcher():
    security_matcher = matcher()
    for policy in APPLICATION_ROUTE_SECURITY_POLICIES:
        if policy.path_template.startswith("/api/v1/"):
            binding = security_matcher.match_protected(
                method=policy.method,
                concrete_path=concrete_path(policy.path_template),
            )
            assert binding.policy is policy and callable(binding.dependency)


def test_matcher_requires_a_complete_application_security_plan():
    with pytest.raises(TypeError, match="requires ApplicationRouteSecurityPlan"):
        ApplicationRouteSecurityMatcher(object())
