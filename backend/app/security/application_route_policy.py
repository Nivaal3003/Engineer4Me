"""Reviewed fail-closed policy mapping for the exact Engineer4Me route surface."""

from __future__ import annotations

from dataclasses import dataclass

from app.security.authorization import ResourceKind
from app.security.entitlements import ControlledFeature
from app.security.identity_models import Permission
from app.security.route_inventory import (
    APPLICATION_ROUTE_INVENTORY,
    PUBLIC_ROUTE_IDENTITIES,
    ApplicationRouteIdentity,
)
from app.security.route_policy import (
    RouteAccessScope,
    RouteSecurityPolicy,
    RouteSecurityPolicyRegistry,
)


@dataclass(frozen=True, slots=True)
class _ProtectedPolicyProfile:
    permission: Permission
    resource_kind: ResourceKind
    feature: ControlledFeature | None
    operation_ids: frozenset[str]


_PROTECTED_POLICY_PROFILES = (
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_READ,
        resource_kind=ResourceKind.CALCULATION,
        feature=None,
        operation_ids=frozenset(
            {
                "getAnalyzerTechnologyCatalogue",
                "listAnalyzerDesignCaseExamples",
                "listAnalyzerKnowledgeLinks",
                "getControlValveCatalogue",
                "listControlValveKnowledgeLinks",
                "getDPFlowCatalogue",
                "listDPFlowDesignCaseExamples",
                "listDPFlowKnowledgeLinks",
                "listCalculationMethods",
                "getCalculationMethodDefinition",
                "listCalculationMethodVersions",
                "getPressureReliefCatalogue",
                "listPressureReliefKnowledgeLinks",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_EXECUTE,
        resource_kind=ResourceKind.CALCULATION,
        feature=ControlledFeature.ENGINEERING_CALCULATIONS,
        operation_ids=frozenset(
            {
                "assessAnalyzerApplication",
                "evaluateControlValveDesignCase",
                "executeControlValveCalculation",
                "assessDPFlowApplication",
                "evaluateDPFlowDesignCase",
                "evaluateStoredDPFlowDesignCase",
                "executeDPFlowCalculation",
                "executeCalculation",
                "assessLevelApplication",
                "executePressureReliefCalculation",
                "assessPressureReliefReadiness",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_READ,
        resource_kind=ResourceKind.ENGINEERING_CASE,
        feature=ControlledFeature.DESIGN_PERSISTENCE,
        operation_ids=frozenset(
            {
                "getEngineeringRun",
                "listDesignCases",
                "getDesignCase",
                "listDesignCaseRevisions",
                "getDesignCaseRevision",
                "listDesignEngineeringRuns",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_CREATE,
        resource_kind=ResourceKind.ENGINEERING_CASE,
        feature=ControlledFeature.DESIGN_PERSISTENCE,
        operation_ids=frozenset({"createDesignCase", "reviseDesignCase"}),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_EXECUTE,
        resource_kind=ResourceKind.CALCULATION,
        feature=ControlledFeature.DESIGN_PERSISTENCE,
        operation_ids=frozenset(
            {
                "assessAndPersistDesignAnalyzerApplication",
                "executeAndPersistDesignCalculation",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_READ,
        resource_kind=ResourceKind.DATASHEET,
        feature=ControlledFeature.DESIGN_PERSISTENCE,
        operation_ids=frozenset(
            {
                "listDesignDatasheets",
                "getDesignDatasheet",
                "listDesignDatasheetRevisions",
                "getDesignDatasheetRevision",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_CREATE,
        resource_kind=ResourceKind.DATASHEET,
        feature=ControlledFeature.DESIGN_PERSISTENCE,
        operation_ids=frozenset({"createDesignDatasheet", "reviseDesignDatasheet"}),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.DATASHEET_EXPORT,
        resource_kind=ResourceKind.DATASHEET,
        feature=None,
        operation_ids=frozenset({"downloadDesignDatasheetRevision"}),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.DOCUMENT_READ,
        resource_kind=ResourceKind.DOCUMENT,
        feature=None,
        operation_ids=frozenset(
            {
                "search_ingestion_jobs",
                "get_ingestion_job",
                "get_ingestion_statistics",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.DOCUMENT_INGEST,
        resource_kind=ResourceKind.DOCUMENT,
        feature=ControlledFeature.DOCUMENT_INGESTION,
        operation_ids=frozenset(
            {
                "submit_ingestion_job",
                "cancel_ingestion_job",
                "request_ingestion_job_cancellation",
                "retry_ingestion_document",
                "execute_filesystem_ingestion_job",
                "queue_ingestion_job",
                "retry_ingestion_job",
                "start_ingestion_job",
                "upload_ingestion_documents",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.DOCUMENT_READ,
        resource_kind=ResourceKind.DOCUMENT,
        feature=None,
        operation_ids=frozenset(
            {
                "list_knowledge",
                "search_knowledge",
                "search_safety_guidance",
                "search_knowledge_text",
                "search_verified_knowledge",
                "get_knowledge_statistics",
                "list_knowledge_summaries",
                "get_knowledge",
                "get_knowledge_history",
                "get_publication_readiness",
                "get_knowledge_summary",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_REVIEW,
        resource_kind=ResourceKind.DOCUMENT,
        feature=None,
        operation_ids=frozenset(
            {
                "register_knowledge",
                "upsert_knowledge",
                "assess_publication_readiness",
                "delete_knowledge",
                "revise_knowledge",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_READ,
        resource_kind=ResourceKind.ENGINEERING_CASE,
        feature=None,
        operation_ids=frozenset(
            {
                "list_manufacturers",
                "get_manufacturer",
                "list_measurements",
                "list_product_families",
                "get_product_family",
                "list_products",
                "get_product",
                "list_protocols",
                "get_protocol",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_REVIEW,
        resource_kind=ResourceKind.ENGINEERING_CASE,
        feature=None,
        operation_ids=frozenset(
            {
                "create_manufacturer",
                "delete_manufacturer",
                "update_manufacturer",
                "create_product_family",
                "delete_product_family",
                "update_product_family",
                "create_product",
                "delete_product",
                "update_product",
                "create_protocol",
                "delete_protocol",
                "update_protocol",
            }
        ),
    ),
    _ProtectedPolicyProfile(
        permission=Permission.ENGINEERING_EXECUTE,
        resource_kind=ResourceKind.ENGINEERING_CASE,
        feature=None,
        operation_ids=frozenset({"select_products"}),
    ),
)


FORMAT_SCOPED_ENTITLEMENT_OPERATIONS = frozenset({"downloadDesignDatasheetRevision"})


def _profile_index() -> dict[str, _ProtectedPolicyProfile]:
    index: dict[str, _ProtectedPolicyProfile] = {}
    for profile in _PROTECTED_POLICY_PROFILES:
        for operation_id in profile.operation_ids:
            if operation_id in index:
                raise RuntimeError("application route policy mapping contains a duplicate operation")
            index[operation_id] = profile
    return index


_PROFILE_BY_OPERATION = _profile_index()
_INVENTORY_OPERATION_IDS = frozenset(identity.operation_id for identity in APPLICATION_ROUTE_INVENTORY)
_PUBLIC_OPERATION_IDS = frozenset(identity[0] for identity in PUBLIC_ROUTE_IDENTITIES)
if _PUBLIC_OPERATION_IDS | frozenset(_PROFILE_BY_OPERATION) != _INVENTORY_OPERATION_IDS:
    raise RuntimeError("application route policy mapping is incomplete or contains an unknown operation")
if _PUBLIC_OPERATION_IDS & frozenset(_PROFILE_BY_OPERATION):
    raise RuntimeError("public and protected application route policies overlap")
if FORMAT_SCOPED_ENTITLEMENT_OPERATIONS - frozenset(_PROFILE_BY_OPERATION):
    raise RuntimeError("format-scoped entitlement operation is not protected")


def _build_policy(identity: ApplicationRouteIdentity) -> RouteSecurityPolicy:
    identity_key = (identity.operation_id, identity.method, identity.path_template)
    if identity_key in PUBLIC_ROUTE_IDENTITIES:
        return RouteSecurityPolicy(
            operation_id=identity.operation_id,
            method=identity.method,
            path_template=identity.path_template,
            scope=RouteAccessScope.PUBLIC,
        )
    profile = _PROFILE_BY_OPERATION.get(identity.operation_id)
    if profile is None:
        raise RuntimeError("application route policy mapping is incomplete")
    return RouteSecurityPolicy(
        operation_id=identity.operation_id,
        method=identity.method,
        path_template=identity.path_template,
        scope=RouteAccessScope.ORGANISATION_HEADER,
        permission=profile.permission,
        resource_kind=profile.resource_kind,
        feature=profile.feature,
    )


APPLICATION_ROUTE_SECURITY_POLICIES = tuple(
    _build_policy(identity) for identity in APPLICATION_ROUTE_INVENTORY
)
APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY = RouteSecurityPolicyRegistry(
    APPLICATION_ROUTE_SECURITY_POLICIES
)


def resolve_application_route_policy(identity: ApplicationRouteIdentity) -> RouteSecurityPolicy:
    """Resolve one exact reviewed identity without a default policy."""

    if not isinstance(identity, ApplicationRouteIdentity):
        raise TypeError("application route policy resolution requires ApplicationRouteIdentity")
    return APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY.resolve(
        operation_id=identity.operation_id,
        method=identity.method,
        path_template=identity.path_template,
    )


__all__ = [
    "APPLICATION_ROUTE_SECURITY_POLICIES",
    "APPLICATION_ROUTE_SECURITY_POLICY_REGISTRY",
    "FORMAT_SCOPED_ENTITLEMENT_OPERATIONS",
    "resolve_application_route_policy",
]
