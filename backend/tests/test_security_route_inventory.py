"""Exact coverage tests for the reviewed Engineer4Me application routes."""

from collections import Counter

import pytest
from fastapi import FastAPI

from app.main import app
from app.security.route_inventory import APPLICATION_ROUTE_INVENTORY, PUBLIC_ROUTE_IDENTITIES, ApplicationRouteInventoryError, discover_application_route_inventory, validate_application_route_inventory
from app.security.route_policy import RouteHTTPMethod


def keys(inventory):
    return {(item.operation_id, item.method, item.path_template) for item in inventory}


def test_reviewed_inventory_matches_every_runtime_application_route_exactly():
    discovered = validate_application_route_inventory(app)
    assert discovered == discover_application_route_inventory(app)
    assert keys(discovered) == keys(APPLICATION_ROUTE_INVENTORY)


def test_inventory_contains_exactly_93_unique_operations_and_route_pairs():
    assert len(APPLICATION_ROUTE_INVENTORY) == 93
    assert len({item.operation_id for item in APPLICATION_ROUTE_INVENTORY}) == 93
    assert len({(item.method, item.path_template) for item in APPLICATION_ROUTE_INVENTORY}) == 93


def test_only_root_and_health_are_declared_public_candidates():
    assert PUBLIC_ROUTE_IDENTITIES == {
        ("root", RouteHTTPMethod.GET, "/"),
        ("health", RouteHTTPMethod.GET, "/health"),
    }
    assert PUBLIC_ROUTE_IDENTITIES <= keys(APPLICATION_ROUTE_INVENTORY)
    assert len(keys(APPLICATION_ROUTE_INVENTORY) - PUBLIC_ROUTE_IDENTITIES) == 91


def test_every_nonpublic_candidate_is_under_the_versioned_api_boundary():
    for identity in APPLICATION_ROUTE_INVENTORY:
        if (identity.operation_id, identity.method, identity.path_template) not in PUBLIC_ROUTE_IDENTITIES:
            assert identity.path_template.startswith("/api/v1/")


def test_reviewed_http_method_distribution_is_stable():
    assert Counter(identity.method for identity in APPLICATION_ROUTE_INVENTORY) == {
        RouteHTTPMethod.GET: 44,
        RouteHTTPMethod.POST: 38,
        RouteHTTPMethod.PUT: 2,
        RouteHTTPMethod.PATCH: 4,
        RouteHTTPMethod.DELETE: 5,
    }


def test_framework_documentation_routes_are_outside_application_inventory():
    paths = {identity.path_template for identity in APPLICATION_ROUTE_INVENTORY}
    assert not paths & {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def test_schema_discovery_does_not_depend_on_mutable_direct_route_iteration():
    application = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    @application.get("/health")
    def health():
        return {"status": "healthy"}

    application.openapi()
    application.router.routes.clear()
    discovered = discover_application_route_inventory(application)
    assert [(item.operation_id, item.method, item.path_template) for item in discovered] == [
        ("health", RouteHTTPMethod.GET, "/health")
    ]


def test_incomplete_or_extra_runtime_surface_fails_closed_without_route_disclosure():
    incomplete = FastAPI()

    @incomplete.get("/health")
    def health():
        return {"status": "healthy"}

    with pytest.raises(ApplicationRouteInventoryError, match="declared 93, discovered 1") as captured:
        validate_application_route_inventory(incomplete)
    assert "/health" not in str(captured.value)


def test_inventory_discovery_rejects_non_fastapi_objects():
    with pytest.raises(TypeError, match="requires FastAPI"):
        discover_application_route_inventory(object())
