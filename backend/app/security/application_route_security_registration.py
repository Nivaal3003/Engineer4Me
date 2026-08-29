"""Validated pre-registration manifest for the reviewed FastAPI route surface."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import FastAPI

from app.security.application_route_security_plan import (
    ApplicationRouteSecurityBinding,
    ApplicationRouteSecurityPlan,
)
from app.security.route_inventory import (
    APPLICATION_ROUTE_INVENTORY,
    ApplicationRouteIdentity,
    validate_application_route_inventory,
)


class ApplicationRouteSecurityRegistrationError(RuntimeError):
    """Sanitized failure for an incomplete or conflicting registration manifest."""


@dataclass(frozen=True, slots=True)
class ApplicationRouteSecurityRegistration:
    identity: ApplicationRouteIdentity
    binding: ApplicationRouteSecurityBinding

    @property
    def key(self) -> tuple[str, object, str]:
        return (
            self.identity.operation_id,
            self.identity.method,
            self.identity.path_template,
        )

    @property
    def protected(self) -> bool:
        return self.binding.dependency is not None


@dataclass(frozen=True, slots=True)
class ApplicationRouteSecurityRegistrationManifest:
    """Immutable exact manifest; construction never mutates application routes."""

    registrations: tuple[ApplicationRouteSecurityRegistration, ...]

    def __post_init__(self) -> None:
        registrations = self.registrations
        if not isinstance(registrations, tuple) or len(registrations) != 93:
            raise ApplicationRouteSecurityRegistrationError(
                "application route security registration requires exactly 93 routes"
            )
        if any(
            not isinstance(item, ApplicationRouteSecurityRegistration)
            for item in registrations
        ):
            raise TypeError(
                "application route security registration contains an invalid entry"
            )
        keys = tuple(item.key for item in registrations)
        if len(keys) != len(set(keys)):
            raise ApplicationRouteSecurityRegistrationError(
                "application route security registration contains a duplicate route"
            )
        expected = {
            (identity.operation_id, identity.method, identity.path_template)
            for identity in APPLICATION_ROUTE_INVENTORY
        }
        if set(keys) != expected:
            raise ApplicationRouteSecurityRegistrationError(
                "application route security registration does not match reviewed inventory"
            )
        for item in registrations:
            if item.key != item.binding.key:
                raise ApplicationRouteSecurityRegistrationError(
                    "application route security registration conflicts with its binding"
                )
            if item.protected != callable(item.binding.dependency):
                raise ApplicationRouteSecurityRegistrationError(
                    "application route security dependency is invalid"
                )

    def public_registrations(
        self,
    ) -> tuple[ApplicationRouteSecurityRegistration, ...]:
        return tuple(item for item in self.registrations if not item.protected)

    def protected_registrations(
        self,
    ) -> tuple[ApplicationRouteSecurityRegistration, ...]:
        return tuple(item for item in self.registrations if item.protected)


def build_application_route_security_registration_manifest(
    application: FastAPI,
    plan: ApplicationRouteSecurityPlan,
) -> ApplicationRouteSecurityRegistrationManifest:
    """Bind the authoritative runtime inventory to a plan without registration."""

    if not isinstance(application, FastAPI):
        raise TypeError("application route security registration requires FastAPI")
    if not isinstance(plan, ApplicationRouteSecurityPlan):
        raise TypeError(
            "application route security registration requires ApplicationRouteSecurityPlan"
        )
    inventory = validate_application_route_inventory(application)
    registrations = tuple(
        ApplicationRouteSecurityRegistration(
            identity=identity,
            binding=plan.resolve(
                operation_id=identity.operation_id,
                method=identity.method,
                path_template=identity.path_template,
            ),
        )
        for identity in inventory
    )
    return ApplicationRouteSecurityRegistrationManifest(registrations)


__all__ = [
    "ApplicationRouteSecurityRegistration",
    "ApplicationRouteSecurityRegistrationError",
    "ApplicationRouteSecurityRegistrationManifest",
    "build_application_route_security_registration_manifest",
]
