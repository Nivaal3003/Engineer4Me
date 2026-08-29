"""Deterministic unregistered security dependencies for every application route."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.security.application_route_policy import (
    APPLICATION_ROUTE_SECURITY_POLICIES,
    FORMAT_SCOPED_ENTITLEMENT_OPERATIONS,
)
from app.security.route_policy import (
    RouteAccessScope,
    RouteHTTPMethod,
    RouteSecurityPolicy,
)
from app.security.security_deployment import DeploymentSecurityRuntime


RouteDependency = Callable[..., object]


class ApplicationRouteSecurityPlanError(RuntimeError):
    """Sanitized failure for an incomplete, unsupported, or unknown binding."""


@dataclass(frozen=True, slots=True)
class ApplicationRouteSecurityBinding:
    policy: RouteSecurityPolicy
    dependency: RouteDependency | None

    @property
    def key(self) -> tuple[str, RouteHTTPMethod, str]:
        return (
            self.policy.operation_id,
            self.policy.method,
            self.policy.path_template,
        )


class ApplicationRouteSecurityPlan:
    """Immutable exact-match plan; construction performs no route mutation."""

    def __init__(self, bindings: tuple[ApplicationRouteSecurityBinding, ...]) -> None:
        if not isinstance(bindings, tuple) or len(bindings) != 93:
            raise ApplicationRouteSecurityPlanError(
                "application route security plan requires exactly 93 bindings"
            )
        if any(not isinstance(binding, ApplicationRouteSecurityBinding) for binding in bindings):
            raise TypeError("application route security plan contains an invalid binding")
        keys = tuple(binding.key for binding in bindings)
        if len(keys) != len(set(keys)):
            raise ApplicationRouteSecurityPlanError(
                "application route security plan contains a duplicate binding"
            )
        expected = {
            (policy.operation_id, policy.method, policy.path_template)
            for policy in APPLICATION_ROUTE_SECURITY_POLICIES
        }
        if set(keys) != expected:
            raise ApplicationRouteSecurityPlanError(
                "application route security plan does not match reviewed policies"
            )
        for binding in bindings:
            public = binding.policy.scope is RouteAccessScope.PUBLIC
            if public != (binding.dependency is None):
                raise ApplicationRouteSecurityPlanError(
                    "application route dependency presence conflicts with policy scope"
                )
            if binding.dependency is not None and not callable(binding.dependency):
                raise TypeError("protected application route dependency must be callable")
        self._bindings = bindings
        self._by_key = {binding.key: binding for binding in bindings}

    @property
    def bindings(self) -> tuple[ApplicationRouteSecurityBinding, ...]:
        return self._bindings

    def public_bindings(self) -> tuple[ApplicationRouteSecurityBinding, ...]:
        return tuple(binding for binding in self._bindings if binding.dependency is None)

    def protected_bindings(self) -> tuple[ApplicationRouteSecurityBinding, ...]:
        return tuple(binding for binding in self._bindings if binding.dependency is not None)

    def resolve(
        self,
        *,
        operation_id: str,
        method: str | RouteHTTPMethod,
        path_template: str,
    ) -> ApplicationRouteSecurityBinding:
        try:
            normalized_method = RouteHTTPMethod(method)
        except (TypeError, ValueError) as error:
            raise ApplicationRouteSecurityPlanError(
                "application route security binding is not registered"
            ) from error
        binding = self._by_key.get((operation_id, normalized_method, path_template))
        if binding is None:
            raise ApplicationRouteSecurityPlanError(
                "application route security binding is not registered"
            )
        return binding


def build_application_route_security_plan(
    runtime: DeploymentSecurityRuntime,
) -> ApplicationRouteSecurityPlan:
    """Build all dependencies without modifying the FastAPI application."""

    if not isinstance(runtime, DeploymentSecurityRuntime):
        raise TypeError("application route security plan requires DeploymentSecurityRuntime")
    bindings: list[ApplicationRouteSecurityBinding] = []
    for policy in APPLICATION_ROUTE_SECURITY_POLICIES:
        if policy.scope is RouteAccessScope.PUBLIC:
            dependency = None
        elif policy.operation_id in FORMAT_SCOPED_ENTITLEMENT_OPERATIONS:
            dependency = runtime.datasheet_export_header_access(policy)
        elif policy.scope is RouteAccessScope.ORGANISATION_HEADER:
            dependency = runtime.organisation_header_access(policy.access_requirement())
        elif policy.scope is RouteAccessScope.ORGANISATION_PATH:
            dependency = runtime.organisation_access(policy.access_requirement())
        else:
            raise ApplicationRouteSecurityPlanError(
                "application route policy scope is unsupported"
            )
        bindings.append(
            ApplicationRouteSecurityBinding(policy=policy, dependency=dependency)
        )
    return ApplicationRouteSecurityPlan(tuple(bindings))


__all__ = [
    "ApplicationRouteSecurityBinding",
    "ApplicationRouteSecurityPlan",
    "ApplicationRouteSecurityPlanError",
    "build_application_route_security_plan",
]
