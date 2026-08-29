"""Fail-closed contracts and registry for explicit API route security policy."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, StringConstraints, model_validator

from app.security.access_dependency import OrganisationAccessRequirement
from app.security.authorization import ResourceKind
from app.security.entitlements import ControlledFeature
from app.security.identity_models import Permission, SecurityModel


OperationIdentifier = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=200, pattern=r"^[A-Za-z][A-Za-z0-9_]*$"),
]
RoutePathTemplate = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=500, pattern=r"^/[A-Za-z0-9_./{}:-]*$"),
]


class RouteHTTPMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class RouteAccessScope(StrEnum):
    PUBLIC = "public"
    ORGANISATION_HEADER = "organisation_header"
    ORGANISATION_PATH = "organisation_path"


class RouteSecurityPolicy(SecurityModel):
    operation_id: OperationIdentifier
    method: RouteHTTPMethod
    path_template: RoutePathTemplate
    scope: RouteAccessScope
    permission: Permission | None = None
    resource_kind: ResourceKind | None = None
    feature: ControlledFeature | None = None

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        protected_values = (self.permission, self.resource_kind, self.feature)
        if self.scope is RouteAccessScope.PUBLIC:
            if any(value is not None for value in protected_values):
                raise ValueError("public route policy cannot contain protected access grants")
            if self.method is not RouteHTTPMethod.GET:
                raise ValueError("public route policy is limited to explicit read-only GET operations")
            return self
        if self.permission is None or self.resource_kind is None:
            raise ValueError("protected route policy requires permission and resource kind")
        contains_organisation_path = "{organisation_id}" in self.path_template
        if self.scope is RouteAccessScope.ORGANISATION_PATH and not contains_organisation_path:
            raise ValueError("organisation-path policy requires {organisation_id} in the route")
        if self.scope is RouteAccessScope.ORGANISATION_HEADER and contains_organisation_path:
            raise ValueError("organisation-header policy cannot duplicate organisation path context")
        return self

    def access_requirement(self) -> OrganisationAccessRequirement:
        if self.scope is RouteAccessScope.PUBLIC:
            raise RouteSecurityPolicyError("public route has no organisation access requirement")
        return OrganisationAccessRequirement(
            permission=self.permission,
            resource_kind=self.resource_kind,
            feature=self.feature,
        )


class RouteSecurityPolicyError(RuntimeError):
    """Sanitized failure for missing, conflicting, or invalid route policy."""


class RouteSecurityPolicyRegistry:
    """Immutable exact-match registry; unknown routes never receive a default grant."""

    def __init__(self, policies: tuple[RouteSecurityPolicy, ...]) -> None:
        if not isinstance(policies, tuple) or not policies:
            raise TypeError("route security policy registry requires a non-empty tuple")
        if len(policies) > 500:
            raise ValueError("route security policy registry exceeds the bounded policy limit")
        if any(not isinstance(policy, RouteSecurityPolicy) for policy in policies):
            raise TypeError("route security policy registry contains an invalid policy")
        operation_ids = [policy.operation_id for policy in policies]
        route_keys = [(policy.method, policy.path_template) for policy in policies]
        if len(operation_ids) != len(set(operation_ids)):
            raise RouteSecurityPolicyError("route security policy operation identifiers must be unique")
        if len(route_keys) != len(set(route_keys)):
            raise RouteSecurityPolicyError("route security policy method and path pairs must be unique")
        self._policies = policies
        self._by_key = {
            (policy.operation_id, policy.method, policy.path_template): policy
            for policy in policies
        }

    @property
    def policies(self) -> tuple[RouteSecurityPolicy, ...]:
        return self._policies

    def resolve(self, *, operation_id: str, method: str | RouteHTTPMethod, path_template: str) -> RouteSecurityPolicy:
        try:
            normalized_method = RouteHTTPMethod(method)
        except (TypeError, ValueError) as exc:
            raise RouteSecurityPolicyError("route security policy is not registered") from exc
        policy = self._by_key.get((operation_id, normalized_method, path_template))
        if policy is None:
            raise RouteSecurityPolicyError("route security policy is not registered")
        return policy

    def protected_policies(self) -> tuple[RouteSecurityPolicy, ...]:
        return tuple(policy for policy in self._policies if policy.scope is not RouteAccessScope.PUBLIC)

    def public_policies(self) -> tuple[RouteSecurityPolicy, ...]:
        return tuple(policy for policy in self._policies if policy.scope is RouteAccessScope.PUBLIC)
