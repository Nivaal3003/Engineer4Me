"""Exact policy coverage for every reviewed Engineer4Me application route."""

from collections import Counter

import pytest

from app.main import app
from app.security.application_route_policy import (
    APPLICATION_ROUTE_SECURITY_POLICIES,
    APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY,
    FORMAT_SCOPED_ENTITLEMENT_OPERATIONS,
    resolve_application_route_policy,
)
from app.security.authorization import ResourceKind
from app.security.entitlements import ControlledFeature
from app.security.identity_models import Permission
from app.security.route_inventory import (
    APPLICATION_ROUTE_INVENTORY,
    PUBLIC_ROUTE_IDENTITIES,
    ApplicationRouteIdentity,
    validate_application_route_inventory,
)
from app.security.route_policy import RouteAccessScope, RouteHTTPMethod


def _policies(*operation_ids):
    selected = set(operation_ids)
    return tuple(
        policy
        for policy in APPLICATION_ROUTE_SECURITY_POLICIES
        if policy.operation_id in selected
    )


def test_policy_registry_exactly_covers_the_validated_runtime_inventory():
    discovered = validate_application_route_inventory(app)
    assert discovered == APPLICATION_ROUTE_INVENTORY
    assert len(APPLICATION_ROUTE_SECURITY_POLICIES) == 93
    assert {
        (policy.operation_id, policy.method, policy.path_template)
        for policy in APPLICATION_ROUTE_SECURITY_POLICIES
    } == {
        (identity.operation_id, identity.method, identity.path_template)
        for identity in discovered
    }
    assert all(resolve_application_route_policy(identity) for identity in discovered)


def test_only_root_and_health_are_public_and_have_no_protected_grants():
    public = APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY.public_policies()
    assert {
        (policy.operation_id, policy.method, policy.path_template) for policy in public
    } == PUBLIC_ROUTE_IDENTITIES
    assert len(public) == 2
    assert all(policy.scope is RouteAccessScope.PUBLIC for policy in public)
    assert all(policy.permission is None and policy.resource_kind is None and policy.feature is None for policy in public)


def test_all_91_nonpublic_routes_require_exact_organisation_header_context():
    protected = APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY.protected_policies()
    assert len(protected) == 91
    assert all(policy.scope is RouteAccessScope.ORGANISATION_HEADER for policy in protected)
    assert all(policy.permission is not None and policy.resource_kind is not None for policy in protected)
    assert all("{organisation_id}" not in policy.path_template for policy in protected)


def test_permission_distribution_is_explicit_and_stable():
    assert Counter(policy.permission for policy in APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY.protected_policies()) == {
        Permission.ENGINEERING_READ: 32,
        Permission.ENGINEERING_EXECUTE: 14,
        Permission.ENGINEERING_CREATE: 4,
        Permission.DOCUMENT_READ: 14,
        Permission.DOCUMENT_INGEST: 9,
        Permission.ENGINEERING_REVIEW: 17,
        Permission.DATASHEET_EXPORT: 1,
    }


def test_resource_distribution_is_explicit_and_stable():
    assert Counter(policy.resource_kind for policy in APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY.protected_policies()) == {
        ResourceKind.CALCULATION: 26,
        ResourceKind.ENGINEERING_CASE: 30,
        ResourceKind.DATASHEET: 7,
        ResourceKind.DOCUMENT: 28,
    }


def test_entitlements_are_attached_only_to_existing_controlled_capabilities():
    assert Counter(policy.feature for policy in APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY.protected_policies()) == {
        None: 55,
        ControlledFeature.ENGINEERING_CALCULATIONS: 11,
        ControlledFeature.DESIGN_PERSISTENCE: 16,
        ControlledFeature.DOCUMENT_INGESTION: 9,
    }


def test_calculation_catalogues_are_readable_but_execution_requires_entitlement():
    catalogue = _policies("getDPFlowCatalogue")[0]
    execution = _policies("executeDPFlowCalculation")[0]
    assert (catalogue.permission, catalogue.resource_kind, catalogue.feature) == (
        Permission.ENGINEERING_READ,
        ResourceKind.CALCULATION,
        None,
    )
    assert (execution.permission, execution.resource_kind, execution.feature) == (
        Permission.ENGINEERING_EXECUTE,
        ResourceKind.CALCULATION,
        ControlledFeature.ENGINEERING_CALCULATIONS,
    )


def test_design_reads_creates_and_persisted_execution_use_distinct_permissions():
    read, create, execute = _policies(
        "listDesignCases",
        "createDesignCase",
        "executeAndPersistDesignCalculation",
    )
    assert read.permission is Permission.ENGINEERING_READ
    assert create.permission is Permission.ENGINEERING_CREATE
    assert execute.permission is Permission.ENGINEERING_EXECUTE
    assert {read.feature, create.feature, execute.feature} == {ControlledFeature.DESIGN_PERSISTENCE}


def test_datasheet_export_requires_permission_without_inventing_format_entitlement():
    assert FORMAT_SCOPED_ENTITLEMENT_OPERATIONS == {"downloadDesignDatasheetRevision"}
    policy = _policies("downloadDesignDatasheetRevision")[0]
    assert policy.permission is Permission.DATASHEET_EXPORT
    assert policy.resource_kind is ResourceKind.DATASHEET
    assert policy.feature is None


def test_ingestion_reads_and_mutations_have_separate_permissions():
    read = _policies("get_ingestion_job")[0]
    ingest = _policies("upload_ingestion_documents")[0]
    assert (read.permission, read.feature) == (Permission.DOCUMENT_READ, None)
    assert (ingest.permission, ingest.feature) == (
        Permission.DOCUMENT_INGEST,
        ControlledFeature.DOCUMENT_INGESTION,
    )


def test_semantic_knowledge_search_remains_a_read_policy_despite_post_method():
    policy = _policies("search_knowledge")[0]
    assert policy.method is RouteHTTPMethod.POST
    assert policy.permission is Permission.DOCUMENT_READ
    assert policy.resource_kind is ResourceKind.DOCUMENT


def test_knowledge_and_catalogue_mutations_require_engineering_review():
    policies = _policies("revise_knowledge", "update_product", "delete_protocol")
    assert len(policies) == 3
    assert all(policy.permission is Permission.ENGINEERING_REVIEW for policy in policies)


def test_product_selection_is_an_engineering_execution_without_invented_entitlement():
    policy = _policies("select_products")[0]
    assert (policy.permission, policy.resource_kind, policy.feature) == (
        Permission.ENGINEERING_EXECUTE,
        ResourceKind.ENGINEERING_CASE,
        None,
    )


def test_resolution_rejects_nonidentity_inputs():
    with pytest.raises(TypeError, match="requires ApplicationRouteIdentity"):
        resolve_application_route_policy(object())


def test_registry_resolution_is_exact_for_every_declared_policy():
    for identity in APPLICATION_ROUTE_INVENTORY:
        policy = APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY.resolve(
            operation_id=identity.operation_id,
            method=identity.method,
            path_template=identity.path_template,
        )
        assert policy.operation_id == identity.operation_id
        assert policy.method is identity.method
        assert policy.path_template == identity.path_template
