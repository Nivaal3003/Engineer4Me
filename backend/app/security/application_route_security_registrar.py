"""Controlled FastAPI inclusion of reviewed protected route dependencies."""

from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI
from fastapi.routing import APIRoute

from app.security.application_route_security_plan import ApplicationRouteSecurityPlan
from app.security.application_route_security_registration import (
    ApplicationRouteSecurityRegistrationManifest,
    build_application_route_security_registration_manifest,
)
from app.security.route_policy import RouteHTTPMethod


class ApplicationRouteSecurityRegistrarError(RuntimeError):
    """Sanitized failure for incomplete, repeated, or unsafe route registration."""


RoutePair = tuple[RouteHTTPMethod, str]


def _route_pair(route: APIRoute, *, prefix: str) -> RoutePair:
    methods = tuple(route.methods or ())
    if len(methods) != 1:
        raise ApplicationRouteSecurityRegistrarError(
            "application security registration requires one reviewed HTTP method"
        )
    try:
        method = RouteHTTPMethod(methods[0])
    except (TypeError, ValueError) as error:
        raise ApplicationRouteSecurityRegistrarError(
            "application security registration contains an unsupported HTTP method"
        ) from error
    full_path = f"{prefix}{route.path}"
    return method, full_path


class ApplicationRouteSecurityRegistrar:
    """Stateful one-use registrar for an exact immutable security plan."""

    def __init__(self, plan: ApplicationRouteSecurityPlan) -> None:
        if not isinstance(plan, ApplicationRouteSecurityPlan):
            raise TypeError(
                "application route security registrar requires ApplicationRouteSecurityPlan"
            )
        protected = plan.protected_bindings()
        self._plan = plan
        self._protected_by_pair = {
            (binding.policy.method, binding.policy.path_template): binding
            for binding in protected
        }
        if len(self._protected_by_pair) != 91:
            raise ApplicationRouteSecurityRegistrarError(
                "application route security registrar requires exactly 91 protected routes"
            )
        self._included: set[RoutePair] = set()
        self._finalized = False

    @property
    def included_count(self) -> int:
        return len(self._included)

    @property
    def finalized(self) -> bool:
        return self._finalized

    def include_router(
        self,
        application: FastAPI,
        router: APIRouter,
        *,
        prefix: str,
    ) -> None:
        """Copy one router through FastAPI with one exact dependency per route."""

        if self._finalized:
            raise ApplicationRouteSecurityRegistrarError(
                "application route security registration is already finalized"
            )
        if not isinstance(application, FastAPI):
            raise TypeError("application route security registrar requires FastAPI")
        if not isinstance(router, APIRouter):
            raise TypeError("application route security registrar requires APIRouter")
        if not isinstance(prefix, str) or (
            prefix and (not prefix.startswith("/") or prefix.endswith("/"))
        ):
            raise ApplicationRouteSecurityRegistrarError(
                "application route security registration prefix is invalid"
            )
        if application.openapi_schema is not None:
            raise ApplicationRouteSecurityRegistrarError(
                "application route security registration requires uncached OpenAPI state"
            )

        routes = tuple(router.routes)
        if not routes:
            raise ApplicationRouteSecurityRegistrarError(
                "application route security registration router is empty"
            )
        pending: list[tuple[APIRoute, RoutePair, object]] = []
        pending_pairs: set[RoutePair] = set()
        for route in routes:
            if not isinstance(route, APIRoute):
                raise ApplicationRouteSecurityRegistrarError(
                    "application route security registration contains an unsupported route"
                )
            pair = _route_pair(route, prefix=prefix)
            binding = self._protected_by_pair.get(pair)
            if binding is None or binding.dependency is None:
                raise ApplicationRouteSecurityRegistrarError(
                    "application route is outside the reviewed protected registration"
                )
            if pair in self._included or pair in pending_pairs:
                raise ApplicationRouteSecurityRegistrarError(
                    "application route security registration contains a duplicate route"
                )
            pending_pairs.add(pair)
            pending.append((route, pair, binding.dependency))

        existing_pairs: set[RoutePair] = set()
        for existing in application.routes:
            if isinstance(existing, APIRoute):
                try:
                    existing_pairs.add(_route_pair(existing, prefix=""))
                except ApplicationRouteSecurityRegistrarError:
                    continue
        if existing_pairs & pending_pairs:
            raise ApplicationRouteSecurityRegistrarError(
                "application already contains a reviewed protected route"
            )

        staged = APIRouter()
        for route, _, dependency in pending:
            fragment = APIRouter()
            fragment.routes.append(route)
            staged.include_router(
                fragment,
                prefix=prefix,
                dependencies=[Depends(dependency)],
            )
        application.include_router(staged)
        self._included.update(pending_pairs)

    def finalize(
        self,
        application: FastAPI,
    ) -> ApplicationRouteSecurityRegistrationManifest:
        """Verify exact runtime attachment and permanently close this registrar."""

        if self._finalized:
            raise ApplicationRouteSecurityRegistrarError(
                "application route security registration is already finalized"
            )
        if not isinstance(application, FastAPI):
            raise TypeError("application route security registrar requires FastAPI")
        if self._included != set(self._protected_by_pair):
            raise ApplicationRouteSecurityRegistrarError(
                "application route security registration is incomplete"
            )

        manifest = build_application_route_security_registration_manifest(
            application,
            self._plan,
        )
        self._finalized = True
        return manifest


__all__ = [
    "ApplicationRouteSecurityRegistrar",
    "ApplicationRouteSecurityRegistrarError",
]
